//! `vault-release`: the release manifest (CRYPTO.md §9). The release workflow
//! (`.github/workflows/release.yml`) writes `manifest.json` with it, signs it with the key in
//! the `android-release` environment, and checks the signature against the keys the apps carry
//! (`vault_sync_wire::releases::RELEASE_KEYS`) before anything is published; the maintainer
//! makes the keys with it (`tools/release/make-manifest-keys.ps1`).
//!
//! The signature is minisign's (prehashed: Ed25519 over the manifest's BLAKE2b-512, then over
//! that signature and the trusted comment `vault-release v<version>`), made here with
//! `ed25519-dalek` and `blake2` and checked with minisign's own verifier, as the apps check it.
//! A secret key is kept as a file sealed under a password of its own, the way an export is
//! (`vault_core::sealed_export`, CRYPTO.md §3.3); the password comes from the environment
//! (`VAULT_RELEASE_KEY_PASSWORD`), never from the command line, which other programs can read.

use std::{
    fs,
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use blake2::{Blake2b512, Digest};
use clap::Parser;
use ed25519_dalek::{Signer, SigningKey};
use sha2::Sha256;
use vault_sync_wire::releases::{self, Manifest};
use zeroize::Zeroizing;

/// Every block of Rust's heap is wiped before it is freed (`vault_platform::wiping_alloc`).
#[global_allocator]
static ALLOCATOR: vault_platform::wiping_alloc::WipingAllocator =
    vault_platform::wiping_alloc::WipingAllocator;

/// Where a secret key's password is read from.
const PASSWORD_VAR: &str = "VAULT_RELEASE_KEY_PASSWORD";
/// The shortest password a new key is sealed under.
const MIN_PASSWORD_CHARS: usize = 12;
/// The largest key file read (one is about 4 KiB: sealed and padded like an export).
const MAX_KEY_FILE_BYTES: usize = 64 * 1024;

#[derive(Debug, Parser)]
#[command(about = "The release manifest: its keys, writing it, signing it, checking it")]
enum Command {
    /// Makes a key pair: the secret half sealed under the password in
    /// VAULT_RELEASE_KEY_PASSWORD (`--key`), the public half as minisign writes it
    /// (`--public`). Prints the public key and its id.
    NewKey {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        public: PathBuf,
        /// What the key is, in the public file's comment ("primary", "backup").
        #[arg(long, default_value = "primary")]
        name: String,
    },
    /// Prints the public half of a secret key (opened with VAULT_RELEASE_KEY_PASSWORD).
    PublicKey {
        #[arg(long)]
        key: PathBuf,
    },
    /// Writes the manifest of a release's files.
    Manifest {
        #[arg(long)]
        version: String,
        /// When the release was built (UTC, `2026-11-27T12:00:00Z`).
        #[arg(long)]
        date: String,
        /// The commit it was built from.
        #[arg(long)]
        commit: String,
        /// SHA-256 of the certificate the APK is signed with.
        #[arg(long)]
        certificate: String,
        #[arg(long)]
        out: PathBuf,
        files: Vec<PathBuf>,
    },
    /// Signs a manifest with a secret key (opened with VAULT_RELEASE_KEY_PASSWORD): writes
    /// `<manifest>.minisig`.
    Sign {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        version: String,
    },
    /// Checks a signed manifest the way the apps do, with the keys they carry, and, with
    /// `--files`, that folder's files against it.
    Verify {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        version: String,
        #[arg(long)]
        files: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    match run(Command::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("vault-release: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(command: Command) -> Result<()> {
    match command {
        Command::NewKey { key, public, name } => {
            for path in [&key, &public] {
                if fs::symlink_metadata(path).is_ok() {
                    bail!(
                        "{} exists already: a key is never made over another",
                        path.display()
                    );
                }
            }
            let password = password()?;
            if password.chars().count() < MIN_PASSWORD_CHARS {
                bail!("the password is shorter than {MIN_PASSWORD_CHARS} characters");
            }
            let secret = SecretKey::generate()?;
            write_new(&key, &secret.seal(&password)?)?;
            write_new(&public, secret.public_file(&name).as_bytes())?;
            println!("{} {}", secret.public(), secret.id());
            Ok(())
        }
        Command::PublicKey { key } => {
            let secret = SecretKey::open(&read(&key, MAX_KEY_FILE_BYTES)?, &password()?)?;
            println!("{} {}", secret.public(), secret.id());
            Ok(())
        }
        Command::Manifest {
            version,
            date,
            commit,
            certificate,
            out,
            files,
        } => {
            let manifest = write_manifest(&version, &date, &commit, &certificate, &files)?;
            fs::write(&out, manifest).with_context(|| format!("writing {}", out.display()))
        }
        Command::Sign {
            key,
            manifest,
            version,
        } => {
            let secret = SecretKey::open(&read(&key, MAX_KEY_FILE_BYTES)?, &password()?)?;
            let bytes = read(&manifest, releases::MAX_MANIFEST_BYTES)?;
            let signature = sign_manifest(&secret, &bytes, &version)?;
            let path = signature_path(&manifest);
            fs::write(&path, signature).with_context(|| format!("writing {}", path.display()))?;
            println!(
                "Signed {} as \"{}\" with key {}",
                manifest.display(),
                releases::trusted_comment(&version),
                secret.id()
            );
            Ok(())
        }
        Command::Verify {
            manifest,
            version,
            files,
        } => {
            let bytes = read(&manifest, releases::MAX_MANIFEST_BYTES)?;
            let signature = read(&signature_path(&manifest), releases::MAX_SIGNATURE_BYTES)?;
            let checked = verify(&bytes, &signature, &version, &releases::RELEASE_KEYS)?;
            if let Some(dir) = files {
                check_files(&checked, &dir)?;
            }
            println!(
                "{} is signed by a key the apps take, for version {version}: {} files",
                manifest.display(),
                checked.files.len()
            );
            Ok(())
        }
    }
}

/// The password in [`PASSWORD_VAR`], without the line break a pipe may have added.
fn password() -> Result<Zeroizing<String>> {
    let mut password = Zeroizing::new(
        std::env::var(PASSWORD_VAR).with_context(|| format!("{PASSWORD_VAR} isn't set"))?,
    );
    while password.ends_with(['\n', '\r']) {
        password.pop();
    }
    if password.is_empty() {
        bail!("{PASSWORD_VAR} is empty");
    }
    Ok(password)
}

fn read(path: &Path, max: usize) -> Result<Vec<u8>> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    if bytes.len() > max {
        bail!("{} is larger than it could be", path.display());
    }
    Ok(bytes)
}

/// Writes a file that must not exist yet.
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("writing {}", path.display()))
}

fn signature_path(manifest: &Path) -> PathBuf {
    let mut path = manifest.as_os_str().to_owned();
    path.push(".minisig");
    PathBuf::from(path)
}

// ---- the key ----

/// What a sealed key file holds: this, the key id and the Ed25519 seed.
const KEY_MAGIC: &[u8] = b"vault-release-key-v1\0";

/// A release key's secret half and its id (minisign's key number).
struct SecretKey {
    id: [u8; 8],
    signing: SigningKey,
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretKey({})", self.id())
    }
}

impl SecretKey {
    fn generate() -> Result<Self> {
        let mut seed = Zeroizing::new([0u8; 32]);
        let mut id = [0u8; 8];
        getrandom::fill(seed.as_mut_slice()).context("the system's randomness")?;
        getrandom::fill(&mut id).context("the system's randomness")?;
        Ok(Self {
            id,
            signing: SigningKey::from_bytes(&seed),
        })
    }

    /// The key file: its id and seed sealed under `password` (CRYPTO.md §3.3).
    fn seal(&self, password: &str) -> Result<Vec<u8>> {
        let mut contents = Zeroizing::new(Vec::with_capacity(KEY_MAGIC.len() + 8 + 32));
        contents.extend_from_slice(KEY_MAGIC);
        contents.extend_from_slice(&self.id);
        contents.extend_from_slice(self.signing.as_bytes());
        vault_core::sealed_export::seal(password, &contents).context("sealing the key")
    }

    fn open(bytes: &[u8], password: &str) -> Result<Self> {
        let contents = vault_core::sealed_export::open(password, bytes)
            .context("the key doesn't open with that password (or isn't a release key)")?;
        let rest = contents
            .strip_prefix(KEY_MAGIC)
            .filter(|rest| rest.len() == 8 + 32)
            .context("that file isn't a release key")?;
        let id: [u8; 8] = rest[..8].try_into()?;
        let seed: Zeroizing<[u8; 32]> = Zeroizing::new(rest[8..].try_into()?);
        Ok(Self {
            id,
            signing: SigningKey::from_bytes(&seed),
        })
    }

    /// The public key as minisign writes it: base64 of `Ed` ‖ key id ‖ Ed25519 public key.
    fn public(&self) -> String {
        let mut bytes = Vec::with_capacity(42);
        bytes.extend_from_slice(b"Ed");
        bytes.extend_from_slice(&self.id);
        bytes.extend_from_slice(self.signing.verifying_key().as_bytes());
        STANDARD.encode(bytes)
    }

    /// The key id as minisign prints it.
    fn id(&self) -> String {
        format!("{:016X}", u64::from_le_bytes(self.id))
    }

    /// minisign's public key file.
    fn public_file(&self, name: &str) -> String {
        format!(
            "untrusted comment: vault release key {} ({name})\n{}\n",
            self.id(),
            self.public()
        )
    }

    /// `data` signed as `minisign -Sm` does (prehashed), with trusted comment `comment`.
    fn sign(&self, data: &[u8], comment: &str) -> String {
        let hash = Blake2b512::digest(data);
        let signature = self.signing.sign(&hash).to_bytes();
        let mut line = Vec::with_capacity(74);
        line.extend_from_slice(b"ED");
        line.extend_from_slice(&self.id);
        line.extend_from_slice(&signature);
        let mut global = Vec::with_capacity(64 + comment.len());
        global.extend_from_slice(&signature);
        global.extend_from_slice(comment.as_bytes());
        let global = self.signing.sign(&global).to_bytes();
        format!(
            "untrusted comment: signature from the vault release key {}\n{}\ntrusted comment: \
             {comment}\n{}\n",
            self.id(),
            STANDARD.encode(line),
            STANDARD.encode(global)
        )
    }
}

// ---- the manifest ----

fn is_lower_hex(text: &str, lengths: &[usize]) -> bool {
    lengths.contains(&text.len()) && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The manifest of `files` (each named by its file name, sorted), in the layout
/// `vault_sync_wire::releases` reads (schema 1).
fn write_manifest(
    version: &str,
    date: &str,
    commit: &str,
    certificate: &str,
    files: &[PathBuf],
) -> Result<String> {
    if vault_sync_wire::parse_version(version).is_none() || version.trim() != version {
        bail!("{version} isn't a version (1.2.3)");
    }
    if date.is_empty() || date.len() > 64 || !date.bytes().all(|b| b.is_ascii_graphic()) {
        bail!("{date:?} isn't a date");
    }
    if !is_lower_hex(commit, &[40, 64]) {
        bail!("{commit} isn't a commit");
    }
    if !is_lower_hex(certificate, &[64]) {
        bail!("{certificate} isn't a certificate's SHA-256");
    }
    if files.is_empty() {
        bail!("no files");
    }
    let mut listed = Vec::with_capacity(files.len());
    for path in files {
        let meta = fs::symlink_metadata(path).with_context(|| format!("{}", path.display()))?;
        if !meta.is_file() {
            bail!("{} isn't a file", path.display());
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .with_context(|| format!("{} has no name", path.display()))?
            .to_owned();
        let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        listed.push((
            name,
            bytes.len() as u64,
            vault_sync_wire::hex(&Sha256::digest(&bytes)),
        ));
    }
    listed.sort();
    if listed.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        bail!("two files have the same name");
    }
    let files: Vec<serde_json::Value> = listed
        .into_iter()
        .map(|(name, size, sha256)| serde_json::json!({ "name": name, "size": size, "sha256": sha256 }))
        .collect();
    let mut text = serde_json::to_string_pretty(&serde_json::json!({
        "schema": releases::MANIFEST_SCHEMA,
        "project": releases::PROJECT,
        "version": version,
        "date": date,
        "commit": commit,
        "android_certificate_sha256": certificate,
        "files": files,
    }))?;
    text.push('\n');
    Ok(text)
}

/// `manifest` signed with `key` for `version`, and checked with the key's own public half the
/// way the apps check one (it is a manifest of that version, signed as such) before it is
/// handed back.
fn sign_manifest(key: &SecretKey, manifest: &[u8], version: &str) -> Result<String> {
    let signature = key.sign(manifest, &releases::trusted_comment(version));
    verify(manifest, signature.as_bytes(), version, &[&key.public()])
        .context("the manifest signed doesn't check out")?;
    Ok(signature)
}

/// The apps' check of a signed manifest with `keys`, and its version `version`.
fn verify(manifest: &[u8], signature: &[u8], version: &str, keys: &[&str]) -> Result<Manifest> {
    let checked = releases::verify_manifest(manifest, signature, keys)
        .map_err(|err| anyhow::anyhow!("release {version}: {err}"))?;
    if checked.version != version {
        bail!(
            "the manifest is for version {}, not {version}",
            checked.version
        );
    }
    Ok(checked)
}

/// Every file `manifest` lists is in `dir` as it lists it, and every file in `dir` (but the
/// manifest and its signature) is listed.
fn check_files(manifest: &Manifest, dir: &Path) -> Result<()> {
    for file in &manifest.files {
        let path = dir.join(&file.name);
        let bytes = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        if bytes.len() as u64 != file.size
            || vault_sync_wire::hex(&Sha256::digest(&bytes)) != file.sha256
        {
            bail!("{} isn't the file the manifest lists", file.name);
        }
    }
    for entry in fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let name = entry?.file_name();
        let name = name.to_string_lossy();
        if name != releases::MANIFEST
            && name != releases::MANIFEST_SIGNATURE
            && manifest.file(&name).is_none()
        {
            bail!("{name} is in {} but not in the manifest", dir.display());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

    #[test]
    fn a_key_opens_only_with_its_password() {
        let key = SecretKey::generate().unwrap();
        let sealed = key.seal("a test password for the key").unwrap();
        assert!(sealed.len() <= MAX_KEY_FILE_BYTES, "read back whole");
        assert!(!sealed.windows(32).any(|w| w == key.signing.as_bytes()));
        let opened = SecretKey::open(&sealed, "a test password for the key").unwrap();
        assert_eq!((opened.public(), opened.id()), (key.public(), key.id()));
        assert!(SecretKey::open(&sealed, "another password").is_err());
        assert!(!format!("{key:?}").contains(&STANDARD.encode(key.signing.as_bytes())));
        // A key's public file is minisign's, and its key the apps' form.
        let public = key.public_file("primary");
        assert_eq!(public.lines().nth(1), Some(key.public().as_str()));
        assert_eq!(key.public().len(), 56);
    }

    /// What this signs, minisign's verifier (the apps') and minisign itself take, and only
    /// for the version signed.
    #[test]
    fn a_signature_is_minisigns() {
        let key = SecretKey::generate().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let apk = dir.path().join("vault-mobile-android-1.2.3.apk");
        let exe = dir.path().join("vault-desktop.exe");
        fs::write(&apk, b"PK a test package").unwrap();
        fs::write(&exe, b"MZ a test program").unwrap();
        let manifest = write_manifest(
            "1.2.3",
            "2026-11-27T12:00:00Z",
            COMMIT,
            &"ab".repeat(32),
            &[exe.clone(), apk.clone()],
        )
        .unwrap();
        let signature = sign_manifest(&key, manifest.as_bytes(), "1.2.3").unwrap();
        let public = key.public();
        let checked = verify(
            manifest.as_bytes(),
            signature.as_bytes(),
            "1.2.3",
            &[&public],
        )
        .unwrap();
        assert_eq!(checked.files.len(), 2);
        assert_eq!(checked.files[0].name, "vault-desktop.exe", "sorted by name");
        check_files(&checked, dir.path()).unwrap();

        // The reference implementation agrees.
        let reference = minisign::PublicKey::from_base64(&public).unwrap();
        let signature_box = minisign::SignatureBox::from_string(&signature).unwrap();
        minisign::verify(
            &reference,
            &signature_box,
            std::io::Cursor::new(manifest.as_bytes()),
            true,
            false,
            false,
        )
        .unwrap();

        // Another version, another key, a changed manifest, a file changed or added.
        assert!(
            verify(
                manifest.as_bytes(),
                signature.as_bytes(),
                "1.2.4",
                &[&public]
            )
            .is_err()
        );
        let other = SecretKey::generate().unwrap().public();
        assert!(
            verify(
                manifest.as_bytes(),
                signature.as_bytes(),
                "1.2.3",
                &[&other]
            )
            .is_err()
        );
        let changed = manifest.replace("1.2.3", "1.2.4");
        assert!(
            verify(
                changed.as_bytes(),
                signature.as_bytes(),
                "1.2.4",
                &[&public]
            )
            .is_err()
        );
        assert!(
            sign_manifest(&key, manifest.as_bytes(), "1.2.4").is_err(),
            "signed as another version"
        );
        fs::write(&exe, b"MZ another program").unwrap();
        assert!(check_files(&checked, dir.path()).is_err());
        fs::write(&exe, b"MZ a test program").unwrap();
        fs::write(dir.path().join("extra.zip"), b"PK").unwrap();
        assert!(check_files(&checked, dir.path()).is_err());
    }

    #[test]
    fn a_manifest_is_written_only_from_what_it_needs() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("a.zip");
        fs::write(&file, b"PK").unwrap();
        let files = [file.clone()];
        let certificate = "ab".repeat(32);
        assert!(
            write_manifest(
                "1.2.3",
                "2026-11-27T12:00:00Z",
                COMMIT,
                &certificate,
                &files
            )
            .is_ok()
        );
        for (version, date, commit, certificate) in [
            ("1.2", "2026-11-27T12:00:00Z", COMMIT, certificate.as_str()),
            ("1.2.3", "", COMMIT, certificate.as_str()),
            ("1.2.3", "2026-11-27 12:00", COMMIT, certificate.as_str()),
            (
                "1.2.3",
                "2026-11-27T12:00:00Z",
                "main",
                certificate.as_str(),
            ),
            ("1.2.3", "2026-11-27T12:00:00Z", COMMIT, "none"),
        ] {
            assert!(write_manifest(version, date, commit, certificate, &files).is_err());
        }
        assert!(
            write_manifest("1.2.3", "2026-11-27T12:00:00Z", COMMIT, &certificate, &[]).is_err()
        );
        assert!(
            write_manifest(
                "1.2.3",
                "2026-11-27T12:00:00Z",
                COMMIT,
                &certificate,
                &[file.clone(), file]
            )
            .is_err(),
            "a name twice"
        );
    }
}
