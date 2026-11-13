/// Errors returned by `vault-core`.
///
/// Decryption failures deliberately carry no detail: a wrong password, a wrong Secret Key and a
/// tampered file all look the same to the caller (and to an attacker).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("not a vault file")]
    NotAVault,
    #[error("unsupported vault format version {0}")]
    UnsupportedVersion(u16),
    #[error("malformed vault data")]
    Malformed,
    #[error("key derivation parameters are outside the allowed range")]
    KdfParamsOutOfRange,
    #[error("wrong credentials or the vault has been tampered with")]
    DecryptionFailed,
    #[error("the vault has no key slot for this unlock method")]
    NoMatchingSlot,
    #[error("invalid key format")]
    InvalidKeyFormat,
    #[error("key checksum mismatch (typo?)")]
    KeyChecksumMismatch,
    #[error("the master password must not be empty")]
    EmptyPassword,
    #[error("item not found")]
    ItemNotFound,
    #[error("folder not found")]
    FolderNotFound,
    #[error("the name must not be empty")]
    InvalidName,
    #[error("invalid TOTP secret or otpauth URI")]
    InvalidTotp,
    #[error("password generator options are invalid")]
    InvalidGeneratorOptions,
    #[error("the operating system random number generator failed")]
    Rng,
    #[error("key derivation failed")]
    Kdf,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
