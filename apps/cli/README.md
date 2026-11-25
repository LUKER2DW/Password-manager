# vault-cli

`vault`, the command-line client. It opens the same vault, with the same device state, as the
desktop app.

```bash
cargo run -p vault-cli -- --help
cargo run -p vault-cli -- init          # create a vault, prints the emergency kit
cargo run -p vault-cli -- add GitHub -u me --url https://github.com --generate
cargo run -p vault-cli -- show GitHub --copy
cargo run -p vault-cli -- sync --server https://… --invite …   # docs/SERVER.md
cargo test -p vault-cli                 # runs the binary, sync through a real server included
```

Commands: `init`, `info`, `list`, `add`, `show`, `edit`, `rm`, `generate`, `totp`, `passwd`,
`renew-key`, `recover`, `kit`, `part-picture`, `forget`, `keyfile`, `import`, `sync`.
`VAULT_FILE` and `VAULT_HOME` point it at test files.

`vault renew-key` gives the vault a new key, a new Secret Key and a new emergency kit, with the
same master password (it asks to type RENEW; `--yes` skips that), and prints the new kit. An
older copy of the file, the old kit and the old Secret Key no longer open what is written from
then on (docs/spec/CRYPTO.md §3.8). Each other device takes the new key once:
`vault sync --take-new-key` asks for the new Secret Key (docs/spec/SYNC.md §4.7). On a
computer where the desktop app keeps logins saved from the browser while locked, or the index
for filling while locked, both are refused: renew from the app, which seals those files again.
