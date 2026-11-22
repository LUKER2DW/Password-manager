# vault-server

The self-hosted sync server: it keeps each device's sealed copy of a vault and the devices'
public keys, and never anything that opens the vault.

```bash
cargo run -p vault-server -- serve            # or: serve --tls, for a home network
cargo run -p vault-server -- invite           # a one-time invite for the first device
cargo run -p vault-server -- list             # vaults and their devices
cargo test -p vault-server                    # two devices through a running server
```

With Docker, from the repository root:

```bash
docker compose -f apps/server/compose.yaml up -d --build
```

Setting it up (Tailscale or its own HTTPS, a backup server, what it can see):
[docs/SERVER.md](../../docs/SERVER.md). Protocol: [docs/spec/SYNC.md](../../docs/spec/SYNC.md) §5.3.

Licensed under the GNU Affero General Public License, version 3 or later ([LICENSE](LICENSE)):
if you offer a modified version as a network service, you must offer its source to its users.
