# Sharing and emergency access — design

Status: **design, not built** (IMPLEMENTATION_PLAN F13). Nothing here changes the vault file yet;
each part that does follows AGENTS.md §5.1 when it is built, and CRYPTO.md gains its exact
section then. This document says what is shared, how, what each party can and can't do, and in
which order it gets built.

## 1. What people need

1. **Share some logins with another person** (a partner, a family member, a colleague): the
   Wi-Fi, the streaming service, the bank both use. Both see the same items; a change by one
   reaches the other; either can stop sharing.
2. **Emergency access**: someone trusted gets into the vault, or part of it, when the owner can't
   (illness, death), after a waiting time the owner can stop.
3. **Hand over one secret once** (a password sent to a new colleague) without a chat app
   keeping it forever.

The project's limits stay: local first, no hosted service, nothing readable outside the
people's own devices, no home-made cryptography (THREAT_MODEL.md, AGENTS.md §4.1).

## 2. Who can see what

| Party | Can | Can't |
|---|---|---|
| A member of a shared folder | read its items; change them when made an editor | read the rest of the owner's vault; add members |
| The folder's owner | add and remove members, make editors | take back what a removed member already read |
| The place the shared copy is kept (a folder, WebDAV, the sync server) | keep, withhold or hand back an older copy | read it, change it unseen, add a member |
| A trusted contact (emergency access) | ask; after the waiting time with no "no" from the owner, open what the owner chose | open anything before the waiting time, or after the owner said no |
| Malware on a member's computer | what that member can read, while their vault is open | the other members' vaults |

The honest limit, said in the app: **a removed member keeps whatever they already saw or copied**.
Removing them stops new changes from reaching them; the passwords themselves should be changed
afterwards, and the app offers to (Password health lists the shared items a removed member saw).

## 3. Building blocks

All from CRYPTO.md §1, used as they are already used:

- **Sealing:** `seal`/`open` (CRYPTO.md §5): XChaCha20-Poly1305 with key commitment.
- **Sealing to a person:** the libsodium sealed box (X25519 + XSalsa20-Poly1305, `crypto_box`),
  today used by the drop box (§3.5).
- **Signing:** Ed25519 (`ed25519-dalek`, strict verification), today used by the sync server's
  requests.
- **Derivation:** HKDF-SHA-256.

### 3.1 A person's sharing keys

Each vault that shares gets, once, a **sharing identity**: an X25519 key pair (to be sealed to)
and an Ed25519 key pair (to sign with), made from the OS CSPRNG and kept in the vault body
(sealed under the vault key like everything else, synced to the person's devices). The public
halves, with the vault's display name, are the person's **sharing card**.

A card is trusted only after the two people compare its **safety words**: six words from the
bundled EFF list, from `SHA-256("vault-share/card" ‖ x25519_pk ‖ ed25519_pk)`, read out in
person or over a call. The app shows both people's words side by side; "They match" marks the
card verified. An unverified card can't be shared with. (Without this step, whoever carries the
invite could swap the keys: the sync server, a mail provider, a chat app.)

### 3.2 A shared folder

A shared folder is a **small vault of its own** with a random 256-bit **folder key**, kept as one
file at a place every member can reach (§4). It holds:

```
header   = folder_id (16 bytes) ‖ revision (u64) ‖ owner's ed25519_pk
members  = [ (ed25519_pk, x25519_pk, role, sealed_folder_key) ]   role: read | edit
           sealed_folder_key = crypto_box_seal(member x25519_pk, folder_id ‖ folder_key)
items    = [ (item_id, revision, seal(item_key, pad(item))) ]  item_key wrapped by folder_key
                                                                 as the vault wraps its own
signature = Ed25519 over everything above, by the owner (members list) and by the
            editor who wrote this revision (items)
```

The folder's items are ordinary `ItemData` (same serialization and padding as vault items), so
the editor, health, filling and export treat them as any item, marked "shared with …".

**Writing.** An editor writes a new revision: items changed, revision + 1, signed with their own
key. The owner alone signs the members list; a members list signed by anyone else is refused.

**Reading.** A member checks, in this order: the owner's signature on the members list against
the owner's verified card; that the writer of the items is a member with `edit`; that the
revision is not lower than the highest this device has seen for that folder (rollback, as the
vault's own copies, kept in device state); then opens their sealed folder key. Any failure
leaves the folder as it was and says so (as SYNC.md §4.6 for the vault).

**Merging.** Two editors' changes are merged as two devices' copies are (SYNC.md §4.2–4.3:
per-item revisions, tombstones, the older version kept in the item's history), so neither edit
is lost.

**Removing a member.** The owner makes a new folder key, seals every item again under it, writes
the members list without the removed member, and signs it. The old key opens only old copies.

### 3.3 Emergency access

The owner chooses a trusted contact (a verified card), what they may open (the whole vault, or
some folders) and a waiting time (1 to 30 days).

What is prepared: an **emergency copy**, the chosen items sealed under a random key (as an export
sealed by `sealed_export.rs`, but under a key instead of a password), that key sealed to the
contact's X25519 key **and** split so that neither the contact alone nor the keeping place alone
can open it:

```
release_key = random 32 bytes
contact_half  = crypto_box_seal(contact x25519_pk, share_1)       (given to the contact)
keeper_half   = share_2, held by the keeping place, handed over only after the waiting time
share_1 ⊕ share_2 = release_key        (two shares of a 2-of-2 XOR split: no new primitive)
```

The waiting time needs a party that keeps time and can't be talked into hurrying: the person's
**own sync server** (docs/SERVER.md). It keeps `keeper_half`, and a request from the contact
starts the clock; each of the owner's devices that syncs sees the request at once and can answer
"no", which the server records (signed by the owner) and which ends it. Only after the waiting
time with no "no" does the server hand `keeper_half` over. The server alone has one share and
can open nothing; the contact alone has the other.

Without a sync server there is no clock, and the app says so: the emergency kit's recovery
parts (CRYPTO.md §3.6) are then the way, one part kept by the trusted person, as today.

### 3.4 One secret, once

A **sealed note**: one item sealed to a verified card (`crypto_box_seal`), carried as a text the
person pastes anywhere (mail, chat). Only the recipient's vault opens it; it is added to their
vault on "Keep", never kept in the clear by the carrier. A note not meant for this vault fails
closed with nothing shown.

## 4. Where shared copies live

The same places as sync (SYNC.md §5), the members choosing one together:

- **A shared folder on disk** that both people's computers reach (a NAS, a folder synced by
  another program).
- **WebDAV**, one account both can write to.
- **The sync server**, which gains a *shared space*: a folder file addressed by its `folder_id`,
  written by members whose Ed25519 key the members list names (the server checks the request's
  signature against the list it last stored, and keeps nothing else about the people).

What the keeping place sees: the folder's id, its size, how often it changes, and the members'
public keys. Not names (the display names are inside the sealed part), not items.

## 5. What changes in the apps

- **Vault body**: the sharing identity; for each shared folder, its id, the place, the members'
  verified cards; the emergency choices (format version bump, §5.1).
- **Desktop**: Settings → Sharing (my sharing card and its safety words, verified people);
  a folder's "Share…" (choose people, read or edit); a shared folder's items marked with who
  shares them; "Stop sharing"; emergency access: choose the contact and wait, and the contact's
  "Ask for access".
- **Phone**: the same reading and writing; sharing settings later.
- **Extension**: shared items fill as any item; the setting that keeps a folder out of the
  browser applies.
- **CLI**: `vault share card | verify | folder …` for testing and scripting.

## 6. Tests that must exist before it ships

- A members list signed by a non-owner, an item revision signed by a reader, a removed member's
  write, a revision lower than seen, a folder key sealed to someone else: each refused, the
  folder left as it was.
- Two editors changing the same item on two devices: both versions kept.
- Removal: the removed member's old key opens no copy written after.
- Emergency access: the contact's half alone, the server's half alone, a request after the
  owner's "no", a request before the waiting time: none opens anything.
- A hostile keeping place (SYNC.md §9's hostile tests, for folder files): altered bytes, cut
  files, another folder's file, an old copy.
- A sealed note opened by the wrong vault: nothing shown.

## 7. Order of work

1. The sharing identity, cards and safety words; sealed notes (§3.4): the smallest useful
   piece, no keeping place needed.
2. Shared folders through a folder or WebDAV, read and edit, with removal.
3. The sync server's shared space.
4. Emergency access through the sync server.

Each step is a release of its own, with its CRYPTO.md section, its format version and its tests.
