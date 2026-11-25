# Running your own sync server

`vault-server` lets the phone, the PC and every other device sync one vault without a cloud
drive. It is small (one binary that needs little memory), does no hashing, and **never sees
anything that opens the vault**. Design and protocol: [spec/SYNC.md](spec/SYNC.md) §5.3.

## What it keeps

```text
/data/store.lock                             locked while the files below are changed
/data/admin-invites.json                     invites made with `vault-server invite` (digests)
/data/vaults/<vault id>/enrolled.json        each device's id, name and Ed25519 public key
/data/vaults/<vault id>/invites.json         invites made by a device already in (digests, and who made each)
/data/vaults/<vault id>/generation           changes whenever a copy is written or removed
/data/vaults/<vault id>/copies/<device>.vault  each device's sealed copy of the vault
```

There is no password, no password hash, no Secret Key, no vault key and no KDF parameter in
there. The copies are the same sealed files as the vault on your devices: they open only with
the master password **and** the Secret Key, and the Secret Key never travels through the
server.

## What it can and can't do if someone takes it over

| They try | What happens |
|---|---|
| Read the passwords | They can't: sealed copies and public keys only |
| Put an older copy back (undo a password change) | Every device refuses it: each remembers the last version it saw from every other device |
| Hand two devices two different copies | Refused as a fork |
| Swap in a weaker password hashing or a key of their own | Refused: a device opens another device's copy with its own vault key, and the server never supplies a key or a parameter |
| Add a device of their own | It can't open anything without the master password and the Secret Key, and the vault's own device list (inside the sealed copy, where the server can't edit it) doesn't have it, so its copies are refused |
| Delete everything | Nothing is lost: every device has the whole vault. Sync again and the copies come back |
| Stop answering | Sync waits; the apps say "Not synced since …" |

What it does see: how big each copy is, when each device writes, and how many devices there
are.

## Set it up (Docker + Tailscale)

The server should not be on the open internet. [Tailscale](https://tailscale.com) (free for
personal use) gives your devices a private network and real HTTPS certificates.

1. On the machine that will run it (a mini PC, a Raspberry Pi, a NAS, a small VPS), install
   Docker and Tailscale and sign Tailscale in.
2. From a copy of this repository:

   ```sh
   docker compose -f apps/server/compose.yaml up -d --build
   ```

   It listens on `127.0.0.1:8750` of that machine only.
3. Put HTTPS in front of it, for your tailnet only:

   ```sh
   tailscale serve --bg --https=443 http://127.0.0.1:8750
   ```

   The address is then `https://<machine>.<your-tailnet>.ts.net`. Install Tailscale on the
   PC and the phone too, signed in to the same account.
4. Make an invite for the first device:

   ```sh
   docker compose -f apps/server/compose.yaml exec vault-server vault-server invite \
     --address https://<machine>.<your-tailnet>.ts.net
   ```

   It prints the invite (32 letters and digits, good once for 24 hours) and, with
   `--address`, one `vaultsync:` link that holds the address, the certificate's pin (with
   `serve --tls`) and the invite, and that link's QR code. Without `--vault` it starts a new
   vault: the first device of a vault joins with it, whichever vault is open there. For a
   vault already on the server, use **Add a device** on a device that syncs it (step 6), or
   make the invite with `--vault <id>` (`vault-server list` shows the ids; the command lists
   them too), which also sets up a phone that has no vault yet. `--no-pin` leaves the pin out
   (a server reached through a proxy with a certificate of its own).
5. On the PC: **Settings → Sync → Use a server…**, paste the link (or type the address, the
   pin if there is one, and the invite, each in its own field), **Join**. On the phone:
   **Settings → Sync**, scan the code or paste the link, or **Type the address**.
   (CLI: `vault sync --join "<link>"`, or
   `vault sync --server https://<machine>.<tailnet>.ts.net --invite <invite>`.)
6. More devices: **Settings → Sync → Add a device** on the PC shows a QR code and a
   `vaultsync:` line, good once for an hour. Scan it on the phone, or paste the line into
   **Invite** on another computer. (CLI: `vault sync --add-device`, then
   `vault sync --join "<line>"` on the other device.) The new device still needs your master
   password and Secret Key to open the vault.

Without Docker: `cargo build --release -p vault-server`, then
`vault-server --data /var/lib/vault-server serve` under a service manager, with the same
`tailscale serve` in front.

Plain `http://` is accepted by the apps only to this computer or to a Tailscale address
(`100.64.0.0/10`), where WireGuard already encrypts the traffic. Anything else must be
`https://`. (That is for this server, whose requests are signed and carry no password. A
WebDAV place, which sends its password with every request, must be `https://` unless it is on
this computer.)

## Or on your home network, with its own HTTPS

No Tailscale and no domain name: the server can do HTTPS itself, with a certificate the
devices pin.

```powershell
vault-server --data D:\vault-server serve --listen 0.0.0.0:8750 --tls
```

On first start it makes a small certificate authority in `<data>/tls/` (keep that folder:
replacing it changes the pin, and every device must join again). It prints the addresses to
give the app, one per network address of the computer:

```
  https://192.168.1.10:8750#pin=3f1c…e09a
```

It prints the pin on its own too. In **Settings → Sync → Use a server…** the address goes in
**Server address** and the pin in **Certificate pin**; or `vault-server invite --address
https://192.168.1.10:8750` prints one link with both and the invite, to paste or scan. The
`vaultsync:` line from **Add a device** carries the pin on to the phone. The pin is
the SHA-256 of that authority. A device fetches the authority from `/v1/certificate`, refuses
it unless its hash is the pin, and then trusts only it for this server: someone else on the
network can't stand in for the server, and the system's certificate roots play no part. The
server's own certificate is made again at each start for the computer's current addresses
(`--tls-name` adds a name), so the pin stays when the address changes; the address typed in
the app has to be changed by hand then.

The computer's firewall asks once whether the server may take connections: allow it on
private networks only. Keep the port closed on the router: this is for your own network.

## A second server as a backup

A vault can sync through two servers: if the main one is down (the computer it runs on is
off, the network is out), every device keeps syncing through the other, and the main one
catches up in the first round after it answers again. Run a second `vault-server` anywhere
(another computer, a NAS, a cheap VPS behind Tailscale), make an invite there with
`vault-server invite`, then on a computer that already syncs: **Settings → Sync → Add a
backup server**, with its address and that invite. From then on **Add a device** puts an
invite for both servers in the line it shows, and a phone set up with it joins both.

Each server keeps its own list of devices and its own copies; removing a device from the
vault (Settings → Sync → Remove) makes every device refuse its copies wherever they come
from.

## Updates of the phone app

The server can hand the phone app's updates to the phones that sync through it, so an update
doesn't have to be copied to each phone by hand. Build the APK
(`apps/mobile-android/build.ps1`, which takes its version from `apps/mobile-android/Cargo.toml`),
then on the server:

```bash
vault-server publish-app vault-mobile-android.apk --version 0.2.0
# Docker: copy it in first
docker compose -f apps/server/compose.yaml cp vault-mobile-android.apk vault-server:/data/
docker compose -f apps/server/compose.yaml exec vault-server vault-server publish-app /data/vault-mobile-android.apk --version 0.2.0
```

On the phone, **Settings → Updates → Check for updates**, then **Install**. The phone fetches
the package with its device key, checks its size and SHA-256 against the release, checks that
it is this app, newer, and signed with the same certificate, and hands it
to Android, which asks you and installs it only if it is signed with the same key as the app
already there. Someone who took the server over can offer an old or a broken package; Android
refuses one signed with another key, and the phone never installs anything without you.
The APKs are signed with the Android debug key of the computer that built them, so whoever has
that key file can make updates; a key for distribution is still to be chosen, and changing it
means installing the app anew.

## Look after it

- **List devices:** `vault-server list` (in Docker: `docker compose … exec vault-server
  vault-server list`).
- **A lost phone:** remove it from the PC (**Settings → Sync → Remove**, or
  `vault sync --remove <id>`; on the server, `vault-server remove` is safe to run while it
  serves). That takes its key off the server and puts it in the vault's
  list of removed devices, so every device refuses its copies. The phone still has the copy
  it had, which opens only with the master password and the Secret Key; if you want to be
  sure, change the master password too, and every device follows.
- **Backups:** not needed for safety (every device has the whole vault), but a copy of the
  volume does no harm and holds nothing that opens the vault.
- **Updates:** `git pull`, then the same `docker compose … up -d --build`.

## Limits it enforces

| What | Limit |
|---|---|
| One copy | 64 MiB |
| Devices per vault | 32 |
| Invites waiting, per vault | 8 |
| Requests per device | a burst of 120, then 2 a second |
| Failed or unsigned requests per address | a burst of 20, then 10 a minute (then 429) |
| Clock difference allowed | 5 minutes (a device with a wrong clock is told so) |
| Long-polls open per device | 4, each up to 60 seconds |
| Connections open | 512 in all, 128 from one address (an IPv6 /64 is one address; a proxy in front is one for all its devices) |
| A request's headers | must arrive within 30 seconds; an idle connection is closed after 30 seconds |
| An answer the client stops reading | the connection is closed after 60 seconds |
| TLS handshakes (`serve --tls`) | 64 at once, 16 from one address, each within 10 seconds |
| Requests in flight, all together | 256 (then 503, "busy") |
| How long one request may take | 90 seconds (then 408) |
| Copies being uploaded at once | 4, one per device; one must arrive within 60 seconds |
| Copies and app packages being sent at once | 4, two per device |
| An enrollment's body | 4 KiB |
| Any other request's body | 64 KiB |

A device that syncs normally makes a handful of requests a minute: one waiting long-poll,
and a list plus one upload after each change.

## How it holds up

- **Nothing big from strangers.** An upload is read only once its whole signature is checked:
  the app sends the copy's SHA-256 with the request (it is what the signature covers), and
  the copy that arrives must match it. (An older app that doesn't send it gets the lighter
  check first, its device named and enrolled and its clock right, then waits for the one
  slot such copies share and costs its address one try until its signature is checked.)
  Every other body is at most 64 KiB, so an address that isn't a device can make the server
  read almost nothing, and its failures count against its allowance.
- **No connection held forever.** A client has 30 seconds to send a request's headers and is
  dropped when it stops reading an answer for a minute; connections are capped in all and
  per address, TLS handshakes too. Rate limits count an IPv6 /64 as one address, since one
  home or phone network may pick any address in it.
- **A leaked admin invite can't get into a vault in use.** `vault-server invite` without
  `--vault` only starts a vault (one with no device yet): offered for a vault that has
  devices, it is refused and left unused. Devices join a vault in use with an invite from a
  device already in (Add a device) or one made with `--vault <id>`.
- **Memory for answers.** Copies and app packages are held in memory four at a time while
  they are sent, two per device, so many downloads at once can't fill the memory. A vault's
  live state is made only for an enrolled device, never for a stranger's enrollment try.
- **One change at a time to the files.** The devices, the invites and the copies are
  changed under one lock, held in memory and on `store.lock`, so the admin commands run
  beside a serving server wait their turn: two changes at once never undo each other (a
  removed device can't come back because a request was answered meanwhile), and an invite is
  used once even when two devices try it together.
- **A removal holds at once.** A device taken out while one of its requests was under way
  changes nothing after it: its copy, a removal or an invite it asked for is made only if it
  is still enrolled at that moment, and nothing read for it is handed over once it is gone.
  The next listing agrees with the removal, also one made by `vault-server remove`, which is
  safe to run beside a serving server (if it is cut short, running it again finishes it).
  The invites a device made end with its place in the vault, also those made before it was
  removed. (Invites made for a vault with `vault-server invite --vault` by an older version
  record no maker and are no longer taken: make them again. Admin invites for a new vault are
  not affected.)
- **Strangers learn nothing.** Without a good invite an enrollment always gets the same
  answer; whether a device id is enrolled or a vault is full is told only to someone holding
  one. A signed request that no enrolled key verifies gets 401 `unknown_device` whether the
  device is unknown or the signature is wrong, so no one can find out which device ids are
  enrolled.
- **A device's place can't be taken.** An invite enrolls a new device id only; one already
  enrolled is refused (409). A device that lost its key joins again as a new device.
- **Files only the server reads.** On Linux (and in the image) the data folder's files are
  0600 and its folders 0700, written beside their place and renamed over it, with the folder
  synced too, so a power cut leaves the old file or the new one.
- **Answers no one keeps.** Every answer says `Cache-Control: no-store`, `nosniff`, no
  referrer and a content policy that allows nothing.
- **Stopping.** Ctrl+C or the SIGTERM Docker sends lets the requests under way finish.
- **The container** runs as a user that isn't root, on a read-only file system with no
  capabilities, at most 512 MiB of memory (four 64 MiB uploads fit), 128 processes and 4096
  open files, its logs capped at 30 MB.
