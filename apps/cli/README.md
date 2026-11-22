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
`recover`, `kit`, `part-picture`, `forget`, `keyfile`, `import`, `sync`. `VAULT_FILE` and
`VAULT_HOME` point it at test files.
