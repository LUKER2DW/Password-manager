# Sync — design

> Status: **M6.1–M6.3 built**: format v7 and `Vault::merge` in `vault-core`
> (`crates/core/tests/sync.rs`); the folder, server and WebDAV targets in `vault-platform`
> (`sync.rs`, `sync/`); `vault-server` (`apps/server`, tested end to end in
> `apps/server/tests/sync.rs` and `apps/cli/tests/cli.rs`); the request protocol in
> `crates/sync-wire`. Setting the server up: [../SERVER.md](../SERVER.md). The phone's sync
> (M6.4) is in `apps/mobile/src/controller/syncing.rs`. Byte layouts are in [VAULT_FORMAT.md](VAULT_FORMAT.md) §3. This replaces
> the earlier sketch in ARCHITECTURE.md §6.

## 1. What sync has to do

The same vault on the Windows app, the phone and later Linux, without the person copying
files by hand, and without trusting anything between the devices.

- **Local-first stays true.** Every device keeps a full vault file and works offline. Sync
  only moves sealed copies between devices; it is never needed to open or use the vault.
- **Nothing between devices is trusted** (THREAT_MODEL A2, A3). A cloud folder, a WebDAV
  host or our own server can read, drop, reorder, replay and roll back what it stores. It must
  learn nothing beyond sizes and timing, and every trick must end in a refusal or a warning,
  never in a wrong password shown to the person. The ETH Zurich 2026 study ("Zero Knowledge
  (About) Encryption", USENIX Security 2026) broke three hosted managers mostly through keys,
  parameters or item fields the server could swap. Here the server never supplies a key, a KDF
  parameter or an unauthenticated byte.
- **No data is lost to a conflict.** Two devices that changed the same login offline both
  keep what they typed: the newer version wins, and the other password goes into the
  history; with the item lock closed, each keeps its own version until it is opened (§4.3).
- **The browser extension does not sync.** It holds no secrets and talks only to the desktop
  app on the same computer (ARCHITECTURE.md §5). On the phone, the Autofill Service of the phone
  app plays that role. So "PC ↔ phone ↔ extension" is really "PC ↔ phone". The extension
  follows the PC app.

## 2. Do we need a server?

**No, not to start.** A server is one of three places a vault can sync through. All three
hold the same thing: sealed vault files, one per device.

| Target | Who runs it | Good for | Limits |
|---|---|---|---|
| **Folder** | The person's existing sync (OneDrive, Google Drive for desktop, Dropbox, Syncthing, a NAS share, a USB stick) | Several PCs, zero setup | On Android only Syncthing gives a real folder; Drive and OneDrive on the phone don't keep a folder in step |
| **WebDAV** | Nextcloud, a NAS, any WebDAV host the person already has | PC + phone | Needs an account there; the host keeps the files' version history |
| **Own server** (`vault-server`) | The person, on a small Linux box, reached over Tailscale | PC + phone with nothing else to run, near-instant updates | Something to install and keep up to date |
| **Nearby** (later) | Nobody: the PC and the phone talk directly on the same Wi-Fi | People without any cloud or server | Both devices must be on and on the same network |

The vault engine does not know which one it talks to: they all implement the same four
operations (§5). That keeps the server optional and simple. It is a store for sealed files
with a list of devices, not a second implementation of the vault.

Recommended order to build: **Folder** (desktop, the fastest way to prove the merge), then
**own server** and **WebDAV** for the phone, then **Nearby**.

## 3. What is stored where

```
Each device (unchanged from today)
  Windows   %APPDATA%\…\vault.vault      (or the file the person chose), + vault.bak
  Android   app-private storage (files/vault.vault), + .bak
  device state: highest revision seen per vault, sync settings, per-device sync key cache

Sync target (folder, WebDAV collection or server)
  <vault_id hex>/
    devices/<device_id hex>.vault      one whole vault file, written ONLY by that device
    devices/<device_id hex>.vault.tmp  (folder/WebDAV: written, then renamed)
```

- **One writer per file.** Each device writes only its own `devices/<own id>.vault` and reads
  everybody else's. Two devices never write the same file, so a cloud drive never makes a
  "conflicted copy" and a half-uploaded file is never read as the vault. This is the main
  difference from pointing two apps at one shared `.vault` (the usual KeePass setup, where
  conflicts and lost edits are a known problem on Android).
- **Whole files, not item records.** Each file is an ordinary vault file (VAULT_FORMAT.md):
  the body layer hides how many items there are, their sizes and ids. Storing items one by
  one would let the target count logins and see which one changed. A vault is small
  (kilobytes to a few MB; pictures stay in the per-device cache), so whole files cost little.
- The files carry the same key slots as the vault itself. A copy on the target is exactly as
  useless without the master password **and** the Secret Key as the file on disk (A1).

## 4. The merge (vault-core, no network)

Everything that decides what the vault looks like after sync is one pure function in
`vault-core`, tested on its own:

```rust
impl Vault {
    /// Folds another copy of this vault into this one. `other` is a whole vault file.
    pub fn merge(&mut self, other: &[u8], seen: &mut SeenRevisions) -> Result<MergeReport>;
}
```

### 4.1 Opening the other copy

1. Parse it with the same rules as opening a file: same magic, a known version, KDF parameters
   inside the floor and ceiling, no trailing bytes. Anything else is an error (fail closed).
2. Its `vault_id` must equal ours. Another vault is never merged in.
3. Open its body with **our vault key** (it never changes, CRYPTO.md §3). No password, no
   Argon2id, no key from the other copy. A file that wasn't sealed by a holder of this vault's key
   fails the AEAD and is refused. The body is bound to that copy's header bytes, so a header
   can't be swapped either.
4. The body says which device wrote it (`writer`, §6) and its `revision`. The writer must be
   the device named in the file name. The revision must not be lower than the highest one
   already seen from that writer (`SeenRevisions`, kept in device state). A lower one is a
   replay or a rollback: refused, and the person is told. The same revision with other bytes is
   refused too (a fork: someone holding the key wrote two different files as one device).

### 4.2 Items

Items are matched by id. Each copy remembers, per item, the last few versions (up to 8) its
current one was made from (`lineage`: a short digest of each earlier record, CRYPTO.md §6.1).
A record is copied between devices byte for byte, so the digest names the same version on
every device. For each id:

| Here | There | Result |
|---|---|---|
| item | nothing | keep ours, unless a tombstone covers it (below) |
| nothing | item | add theirs, same rule |
| the same record | | unchanged |
| item | made from ours (ours is in its lineage) | take theirs as it is |
| made from theirs | item | keep ours |
| item | neither made from the other | both changed: §4.3 |

**Deleting leaves a tombstone** (`id`, `deleted_at`). A missing item never means "deleted":
a copy that simply doesn't have an item adds nothing and removes nothing. Tombstones are
merged by id (latest `deleted_at`). A tombstone removes an item only if the item was not
changed after the deletion (`updated_at <= deleted_at`). An edit made on one device while
another deleted the item keeps the item: losing an edit is worse than a login that has to be
deleted twice. Tombstones are dropped after 400 days. A device offline for longer could bring
an item back. Asking such a device to start again from another copy is not built yet.

### 4.3 Two devices changed the same item

Both versions are read in full (with the item lock open when they are sealed).

- "Newer" is a total order, so every device reaches the same result in any order:
  `(revision, updated_at, SHA-256 of the item's contents without its password history)`.
  The newer one wins.
- Every password of the other version that the winner doesn't know (its password and its
  history) is added to the winner's `password_history`, oldest first, cut to
  `history_limit`. The result keeps the winner's revision and change time, so it ranks as the
  winner did: a third device's concurrent edit compares with it exactly as with the winner.
- Two devices that folded the same edits each made their own record with the same contents.
  When two versions have equal contents, every device keeps the one with the smaller digest.
- The lineage of the result lists both versions, so neither comes back as "concurrent".
- `MergeReport.conflicts` lists the ids, so the app can show "Changed on two devices: kept the
  newer version" with a link to each.
- **The item lock is closed and a version is sealed:** the passwords can't be read, so this
  copy keeps its own version and counts it in `MergeReport.waiting_for_lock`. The app asks
  for the PIN and merges the same copy again (`SeenRevisions` accepts a copy it has seen once
  more). Nothing is lost while it waits: each device still has its own version. An item that
  was edited more than 8 times on one device between two syncs looks concurrent too. It is
  then folded, which is harmless, or waits for the lock.

Tested as a property: whatever three devices do offline (add, edit, delete), after their
copies have gone round they hold the same items, and every password typed into an item that
is still there is its password or in its history.

### 4.4 The rest of the body

| Part | Rule |
|---|---|
| Folders | By id, newer wins by `(folder_times, bytes)`, folder tombstones. An item whose folder is gone keeps the dangling id and shows under no folder |
| Folder order | The whole list, newer `order_changed_at` wins; folders missing from it go to the end |
| Settings (`name`, `history_limit`) | Newer `settings_changed_at` wins |
| Item lock (`guard`) | Newer `guard_revision` wins (see §4.5) |
| Key slots (master password, keyfile, recovery) | Newer `unlock_revision` wins (see §4.5) |
| Drop box key (CRYPTO.md §3.5) | Per vault, kept as is (it never changes after creation) |

### 4.5 The master password and the item lock changed on another device

The vault key stays the same when the master password, Secret Key, keyfile or KDF changes
(CRYPTO.md §3). Only the key slots in the header change. So device B can merge A's copy
after A changed the master password: B opens A's body with the vault key it already holds,
sees a higher `unlock_revision` and takes A's header. B's next unlock needs the **new**
password. B says so right after the merge ("The master password was changed on another
device"). A rollback to an older header (an old, maybe leaked, password) needs a lower
`unlock_revision`, which §4.1 already refuses.

The same holds for the item lock: changing the PIN or password **rewraps** the guard key
while it is open (`set_item_guard` keeps the key it has), so guarded items sealed on either
device open with the same key. `guard_key_id` says which key a copy's items are sealed
under. When a newer item lock arrives with another key (the lock was turned on, or set up
again with the lock closed):

- this copy's sealed items are opened with the key open here and stored waiting for the new
  key. They are sealed again the next time the lock is opened, as new items are. Merging
  fails with `SecretsLocked` while this copy's lock is closed, and nothing changes;
- the other copy's sealed items can't be read here. They wait (`waiting_for_lock`) until that
  device has taken this copy's lock and stored them again.

A new Secret Key is the same: the vault key is unchanged and the slots follow.

### 4.6 What the server can still do

It can withhold files (a device sees no news) and show different devices different subsets
(a delay, not a fork: every copy that does arrive is merged). It can delete everything, but
every device still has the full vault. It sees how big each file is and when each device
writes. None of this reveals or changes a password. The app shows each device's last
successful sync, so an "it's been days" is visible.

## 5. Targets

Each target implements:

```rust
trait Target: Send + Sync {
    fn list(&self) -> Result<Vec<Listed>>;                // each copy, with a tag that changes with it
    fn get(&self, device: DeviceId) -> Result<Vec<u8>>;
    fn put(&self, own: DeviceId, bytes: &[u8]) -> Result<()>;  // whole, never half-visible
    fn remove(&self, device: DeviceId) -> Result<()>;     // a removed device's copy
    fn wait(&self, after: u64, seconds: u64) -> Option<Result<u64>>;  // long-poll, server only
}
```

A sync round: `list` → `get` the copies whose tag changed since the last merge in this
session (`fetch` with the known tags; the first round after an unlock reads them all) →
`merge` each one → `save` locally (the usual atomic write and `changed_outside` check) →
`put` our own copy if our revision moved. Rounds run at unlock, after each save (debounced a few seconds), every few minutes while
unlocked, and on demand. With the vault locked nothing is merged: merging needs the vault key.

- **Folder**: a directory the person picks. `put` writes `.tmp` and renames it. The app
  watches the directory for changes. Desktop only (Android: only with Syncthing's real folder,
  through the system file picker's directory access).
- **WebDAV** (`sync/webdav.rs`): `PROPFIND` (depth 1) for `list` (ETags as tags), `GET`,
  `PUT` to a temporary name then `MOVE` over the copy (a plain `PUT` where `MOVE` isn't
  supported), `MKCOL` for the folders, `DELETE`. Basic auth over HTTPS only. The password is
  stored in the OS credential store, never in the vault file or in device state; Settings
  checks it answers before keeping it.
- **Own server** (`apps/server`, `vault-server`, AGPL-3.0, axum, one SQLite file or plain
  files on disk, Docker image + Compose):
  - the same four calls over HTTPS (`GET /v1/vaults/{id}/devices`, `GET|PUT|DELETE
    /v1/vaults/{id}/devices/{device}`) plus a long-poll `GET /v1/vaults/{id}/changes?after=`
    so the phone learns of a change in seconds without polling;
  - **authentication without a password at the server.** Each device has an Ed25519 key made
    on the device (Keystore/TPM-backed where possible). Its public key is enrolled once with a
    one-time token, and every request is signed (method, path, body hash, timestamp, nonce).
    No master password, no derived password hash, nothing worth stealing reaches the server.
    OPAQUE (in the earlier plan) solves logging in with a low-entropy password. Here the device
    keys are random 256-bit keys, so it adds nothing;
  - the list of allowed device keys is also kept **inside the vault body** (`devices`, §6),
    where the server can't edit it. A device refuses files from a writer that isn't in
    the merged device list. Removing a lost phone removes its key from both. The phone can
    still read its own old copy, but it gets nothing new;
  - **removing a device doesn't bar it for good.** Its id stays buried in the vault (a
    tombstone), so copies written under that id are refused everywhere. A device that learns
    it was removed stops, forgets its keys and takes a new id for that vault (kept in device
    state per vault, `device_id_for`). A join with an invite enrolls under a new id too, unless
    the device is still enrolled at that server under the one it has (a join tried again);
    the id it synced as before is *retired*: it leaves the vault's device list at its next
    round (it is the same device's old entry, not another device). So a phone removed while
    it synced elsewhere, or one moved to a new server, comes back as a new device with a new
    invite, which is the person's consent. A folder or WebDAV place has no invite; there a
    removed device joins again by being pointed at the place once more;
  - reachable only over Tailscale/WireGuard, TLS on top. It never sees a key or a KDF
    parameter it could hand back. A small box runs it: it does no hashing.
- **Nearby** (later): the PC shows a QR code (its address on the LAN, a one-time key and its
  device id); the phone scans it, both run a Noise `NNpsk0` handshake keyed by the QR, then a
  sync round with the PC acting as the target. Needs the phone's `INTERNET` permission and a
  Windows firewall prompt the first time.

### 5.3 The server protocol (`vault-sync-wire`, `vault-server`)

Every route but `GET /v1/health` and `POST /v1/enroll` takes a signed request:

```text
x-vault-device: <device id, 32 hex>
x-vault-time: <Unix seconds>
x-vault-nonce: <128 random bits, 32 hex>
x-vault-signature: Ed25519 over
    "vault-sync-v1/request\n" METHOD "\n" PATH?QUERY "\n" DEVICE "\n" TIME "\n" NONCE "\n" hex(SHA-256(body))
x-vault-body-sha256: hex(SHA-256(body))   (not signed itself: it is the last line above)
```

`x-vault-body-sha256` lets the server check the whole signature before it reads a large
body; a body that doesn't match it is refused (400 `not_what_was_signed`). Requests without
it (older apps) are still taken, a copy with a lighter check first (see `PUT` below).

The server refuses a request when the device isn't enrolled for that vault, the signature
doesn't verify (strict verification, no weak keys), the time is more than 5 minutes off, or
the nonce was already seen (nonces are kept for longer than the allowed skew, and only after
the signature verified, so strangers can't fill the cache).

| Route | What |
|---|---|
| `POST /v1/enroll` | `{invite, vault, device, key, name, time, signature}`: the new device signs `"vault-sync-v1/enroll\n" vault device key name time hex(digest(invite))` with the key it enrolls, proving it holds it. The invite is used up. A device id already enrolled is refused (409 `already_enrolled`): a device that lost its key joins as a new device, so an invite can't take another device's place. |
| `GET /v1/vaults/{v}/devices` | `{copies: [{device, tag, size}], seq}` |
| `GET /v1/vaults/{v}/devices/{d}` | the copy (`ETag`, `If-None-Match` → 304) |
| `PUT /v1/vaults/{v}/devices/{d}` | only `d` = the signer; optional `If-Match`. With `x-vault-body-sha256` the copy is read only once the signature verifies, one upload per device at a time. Without it, only once the headers name `d`, enrolled, at a time close to now, one such upload at a time in all; then the signature over it is checked |
| `DELETE /v1/vaults/{v}/devices/{d}` | takes device `d` out: its key and its copy |
| `GET /v1/vaults/{v}/enrolled` | the devices allowed in, with when each was last heard from |
| `POST /v1/vaults/{v}/invites` | a one-time invite for one more device, good for an hour |
| `GET /v1/vaults/{v}/changes?after=N&wait=S` | answers as soon as the change counter isn't `N`, or after `S` ≤ 60 seconds |

Invites are 128 random bits; the server stores only `SHA-256("vault-sync-v1/invite\n" ‖
invite)` and compares in constant time. An admin invite (`vault-server invite`) starts any
new vault, one with no device enrolled yet: it is how the first device of a vault gets in.
Offered for a vault that has devices it is refused (403 `new_vault_only`) and left unused,
so a leaked one can't put a stranger's device into a vault in use. Made with `--vault` it is
for that vault, devices or not.
The text another device joins with is `vaultsync:1?server=<url>&vault=<id>&invite=<invite>`
(also shown as a QR code); nothing in it opens the vault. `server` carries the certificate's
pin when the server has its own HTTPS (`#pin=`, escaped), so no one types it. A line from
`vault-server invite --address` leaves `vault` out when its invite is good for any vault: it
joins the vault that is open where it is used.

The change counter starts at the server's start time in milliseconds and only grows, so a
restart never makes it go back and devices keep nothing about the server between sessions.

The device's Ed25519 key is made on the device and kept in the OS credential store (per vault
and device); the server only gets the public half. Limits (per device, per failing address,
sizes, devices, invites) are listed in [../SERVER.md](../SERVER.md). The client refuses
redirects, `http://` except to this computer or a Tailscale address, and answers bigger than
a copy can be.

A server with HTTPS of its own (`serve --tls`, for a home network without a domain name) is
reached at `https://host:port#pin=<hex SHA-256 of its certificate authority, DER>`. The
fragment never goes on the wire. The client first fetches `GET /v1/certificate` without
checking the certificate (the request carries nothing but its path), compares the hash of
the answer with the pin in constant time and refuses on a mismatch; then every request
trusts that authority as its only root, with the usual name and address checks. The pin
travels inside the server address of `vaultsync:` invites.

### 5.4 A backup place

A device can sync through two places: the main one and a backup (in the apps, a second
vault-server). Both are ordinary targets with their own enrollment (the device has a key for
each, `sync-key:<vault>:<device>` and `…:backup` in the credential store). Each round:

1. Both places are read at the same time. A place that doesn't answer is reported; the round
   goes on with the other. Only when neither answers does the round fail.
2. For each other device, the newest copy from either place is merged. A copy older than one
   already merged from that device is passed over without a warning: a place that was down
   holds older copies until it catches up. (It is never merged either way; with one place,
   such a copy is still reported as a rollback.)
3. This device's copy goes to every place that answered and doesn't have the current revision
   yet (`published` and `published_backup` in the device state), so a place that comes back
   gets it in its first round.

While a place doesn't answer, a round runs every minute instead of every five. The apps say
once when a place stops answering and once when it is back, and the Sync settings show
which one is down. Add a device puts an invite for the backup into the same `vaultsync:`
line (`&backup=<url>&backup_invite=<invite>`), so a new device joins both; apps that don't
know these parameters join the main one.

## 6. Format v7

The body gains one `SyncState` (VAULT_FORMAT.md §3): the writer, tombstones, when each folder,
the folder order and the settings last changed, the unlock and item lock revisions, the guard
key id, the devices, and each item's lineage. `Folder` and `ItemData` are unchanged. An
upgraded v0–v6 body has no writer and nothing synced yet.

Every change records itself:
- an item replaced by a new version notes the old one in its lineage;
- a deletion leaves a tombstone;
- folder, order and settings changes stamp a time that never goes backwards
  (`max(now, last + 1)`);
- password, keyfile, hashing and Recovery Key changes bump `unlock_revision`;
- item lock changes bump `guard_revision`.

`Vault::change_unlock` restores all of it when the write that makes an unlock change real
fails.

Clocks: `updated_at` and `deleted_at` come from the device clock, which can be wrong. They
only rank versions that were changed on both devices, after `revision`. The other password
still lands in the history, so a wrong clock changes which password is current, not what is
kept.

## 7. Adding a device

1. On the PC: Settings → Sync → "Add a phone". The PC shows a QR code holding the target
   (server address or WebDAV link), a one-time enrollment token, and nothing secret about the
   vault. The **Secret Key** is typed from the emergency kit or, by choice, scanned from a
   second QR shown only on request (MOBILE.md §6.3).
2. The phone fetches the copies, asks for the master password, and unlocks with password +
   Secret Key: the same check as opening any file.
3. The phone makes its device id and key, is added to `devices` by the next merge on the
   PC, and from then on writes its own copy.

The Secret Key never travels through the target. A target that holds every copy still can't
open one.

## 8. What the person sees

- Settings → Sync: off (default) / Folder / WebDAV / Server; the devices that sync this vault,
  each with its last sync time; "Remove this device"; "Sync now". A device in the vault's
  list without a copy where the vault syncs now (it synced through another place, or hasn't
  joined this one yet) says so ("No copy here yet"). Removing a device, stopping, adding a
  device and (on the desktop) disconnecting the extension each ask first, with the master
  password.
- The corner of the vault window: a small "Synced 2 min ago" / "Not synced since …" when sync
  is on, and nothing when it's off.
- After a merge with conflicts: one line, "2 items were changed on two devices; the newer
  version was kept", linking to them. After a master password change elsewhere: the notice of
  §4.5.
- Refusals (§4.1) say what happened and what to do: "A copy from Phone is older than one
  already seen. It was not used. If you restored a backup on that phone, remove it and add it
  again."

## 9. Tests that must exist before it ships

- Merge is commutative and idempotent: proptest over random edit/delete scripts on two and
  three copies, every merge order ends in the same items.
- Edit vs delete, edit vs edit (with and without the item lock), password change on one side,
  guard change on one side, folder deleted with items in it.
- Malicious target (A2), each refused or harmless: another vault's file, a file sealed with
  another key, a swapped header, a replayed older copy, a fork (same revision, other bytes),
  a copy whose writer doesn't match its file name or isn't a known device, a truncated file, a
  file with a lower `unlock_revision` carrying an old password.
- The ETH Zurich group's ZK-AE-Tester style checks against the server build.
- Two real devices converge (desktop + phone in the headless tests, a folder target in a temp
  directory).

## 10. Milestones

1. ✅ **M6.1 Core**: format v7 (tombstones, revisions, writer, devices, lineage), `Vault::merge`, the
   tests of §9 except the server ones.
2. ✅ **M6.2 Folder target** in the desktop app and CLI (`vault sync <dir>`), Settings → Sync.
   Removing a device and watching the folder came with M6.3.
3. ✅ **M6.3 `vault-server`** (axum, Docker, signed requests, long-poll) and its client in
   `vault-platform`; WebDAV client. Settings → Sync: Use a server… (join with an invite or a
   `vaultsync:` line), Use WebDAV…, Add a device (QR code), Remove a device; the CLI's
   `vault sync --server/--invite/--join/--webdav/--add-device/--devices/--remove`. The desktop
   waits on the server's long-poll while the vault is open, so a change on another device
   arrives within seconds.
4. ✅ **M6.4 Phone** (the controller; running on a real phone is M7.1): Settings → Sync on the
   phone joins with the `vaultsync:` line from Add a device on a computer, then rounds at
   unlock, after saves, every 5 minutes, on the server's long-poll and on demand; Stop
   syncing forgets its key. WebDAV works there too. Not yet: scanning the QR code with the
   camera (M7), syncing while the vault is locked (download only, then merge at unlock).
5. **M6.5 Nearby** sync over the LAN.
6. **M6.6 Cloud drive APIs** for the phone (§11): Google Drive and OneDrive app folders,
   Dropbox app folder.

## 11. OneDrive, Google Drive and Dropbox on the phone

On a computer these already work: their desktop programs keep a real folder in step, and
the folder target uses it (§5). On Android they don't: the Drive and OneDrive apps open files
on demand and offer no folder that stays in step, so the phone has to talk to the drive's own
web API. That is viable, with these choices:

| | Google Drive | OneDrive (personal) | Dropbox |
|---|---|---|---|
| Where the copies go | the app's hidden `appDataFolder` | the app folder (`/drive/special/approot`, "Apps/<app>") | the app folder ("Apps/<app>") |
| Permission asked | `drive.appdata` only: the app sees nothing else of the drive | `Files.ReadWrite.AppFolder` only | "App folder" access type |
| Review by the provider | non-sensitive scope: basic app verification, no security assessment | app registration in Microsoft Entra | production approval once past the development-mode user cap |
| Sign-in | OAuth with PKCE (no client secret on the device); on the PC the loopback redirect, on Android the system browser or Google's sign-in | OAuth with PKCE | OAuth with PKCE |
| Seeing changes | `changes.list` with a page token (one cheap call) | `delta` | `list_folder/longpoll` (a real long-poll) |
| Limits | per-minute quotas per user and project, far above this use (see the Cloud console) | throttled with `429` + `Retry-After` | per app and user, `429` + `Retry-After` |

Each would be one more `Target` in `vault-platform` (list, get, put, remove, and `wait` for
Dropbox), with the refresh token in the credential store (Android Keystore on the phone),
never in the vault. The drive holds exactly what a folder holds: sealed copies, one per
device. A sync round is one listing call plus one download per changed copy and one upload,
so the limits are far away (a busy day is tens of calls); every `429` is retried after the
`Retry-After` the provider asks for.

What it needs that code can't do: an OAuth app registered with each provider (a Google Cloud
project, a Microsoft Entra app, a Dropbox app), whose client ids ship with the app, and the
providers' review before the app is offered to many people. A self-built copy can use the
person's own registration. Until then the phone syncs through the own server or WebDAV, and
computers can already use any drive through its folder.
