# Test keys

Private keys made for `vault_core::ssh`'s tests only (`openssl genrsa 2048`,
`openssl pkcs8 -topk8 -nocrypt`, `openssl ecparam -name secp384r1 -genkey`; the `-openssh`
files are the same keys converted by `ssh-keygen -p`). They protect
nothing and are used nowhere else; they are kept as `.txt` so the repository's `*.pem` rule
leaves them in.
