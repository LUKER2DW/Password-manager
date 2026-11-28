//! An export protected by a password of its own (spec: CRYPTO.md §3.3).
//!
//! For carrying items to another device or keeping a copy that does not depend on the Secret
//! Key: the whole export is sealed under a key stretched from a password chosen for that
//! file. Unlike the vault file it has one factor only, so the password must be a strong one:
//! [`seal`] refuses one below the one-factor floor (`health::ONE_FACTOR_MIN_GUESSES_LOG10`,
//! CRYPTO.md §3.3.1). [`open`] doesn't ask: an export made before the floor still opens.
//!
//! Layout: magic (8 bytes) ‖ header length (u16, little-endian) ‖ header (postcard
//! `KdfParams`: Argon2id cost and salt) ‖ sealed, padded contents. Everything before the
//! sealed part is its associated data, so the cost can't be lowered by editing the file.

use zeroize::Zeroizing;

use crate::{Error, KdfParams, KdfStrength, Result, aead, format, kdf, keys, padding};

/// "PMVEXP", a zero byte and the layout version.
const MAGIC: &[u8; 8] = b"PMVEXP\0\x01";
const MAX_HEADER_LEN: usize = 1024;

/// Whether these bytes are an export made by [`seal`].
pub fn is_sealed_export(bytes: &[u8]) -> bool {
    bytes.starts_with(MAGIC)
}

/// Words an attacker would try first on an export's password.
pub const CONTEXT: [&str; 4] = ["vault", "export", "vaultx", "password"];

/// Whether `password` may protect an export: at least the one-factor floor
/// (`health::holds_alone`, with [`CONTEXT`]). Apps ask before the slow work; [`seal`] asks
/// again.
pub fn password_holds(password: &str) -> bool {
    crate::health::holds_alone(password, &CONTEXT)
}

/// Seals `contents` under `password` (Argon2id at the standard level, fresh salt). A password
/// below the one-factor floor is refused ([`Error::WeakPassword`]): it would be all a thief
/// of the file has to guess.
pub fn seal(password: &str, contents: &[u8]) -> Result<Vec<u8>> {
    if password.is_empty() {
        return Err(Error::EmptyPassword);
    }
    if !password_holds(password) {
        return Err(Error::WeakPassword);
    }
    let params = KdfStrength::Standard.params()?;
    let header = postcard::to_allocvec(&params).map_err(|_| Error::Malformed)?;
    let header_len = u16::try_from(header.len()).map_err(|_| Error::Malformed)?;
    let mut out = Vec::with_capacity(MAGIC.len() + 2 + header.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&header_len.to_le_bytes());
    out.extend_from_slice(&header);

    let stretched = kdf::derive_password_key(password, &params)?;
    let key = keys::export_key(&stretched);
    let padded = padding::pad(contents, padding::body_bucket)?;
    let sealed = aead::seal(&key, &padded, &out)?;
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Opens an export made by [`seal`]. A wrong password and a damaged file look the same:
/// [`Error::DecryptionFailed`].
pub fn open(password: &str, bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if !is_sealed_export(bytes) {
        return Err(Error::NotAVault);
    }
    let rest = &bytes[MAGIC.len()..];
    let header_len = rest
        .get(..2)
        .map(|raw| usize::from(u16::from_le_bytes([raw[0], raw[1]])))
        .filter(|len| *len <= MAX_HEADER_LEN)
        .ok_or(Error::Malformed)?;
    let header = rest.get(2..2 + header_len).ok_or(Error::Malformed)?;
    let params: KdfParams = format::decode_exact(header)?;
    // Before any slow work: a file can't ask for less than the floor or more than the ceiling.
    params.validate()?;
    let prefix_len = MAGIC.len() + 2 + header_len;

    let stretched = kdf::derive_password_key(password, &params)?;
    let key = keys::export_key(&stretched);
    let padded = aead::open(&key, &bytes[prefix_len..], &bytes[..prefix_len])?;
    let contents = padding::unpad(&padded)?;
    Ok(Zeroizing::new(contents.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Strong enough alone (the floor); `WEAK` is not.
    const PASSWORD: &str = "pale lantern under quiet orchards";
    const WEAK: &str = "export password";

    #[test]
    fn a_password_below_the_floor_is_refused_but_still_opens_what_it_sealed_before() {
        let contents = b"{}";
        assert!(matches!(seal(WEAK, contents), Err(Error::WeakPassword)));
        assert!(matches!(seal("", contents), Err(Error::EmptyPassword)));
        // A file sealed before the floor (built here as `seal` built it then) still opens.
        let params = KdfStrength::Standard.params().unwrap();
        let header = postcard::to_allocvec(&params).unwrap();
        let mut older = MAGIC.to_vec();
        older.extend_from_slice(&u16::try_from(header.len()).unwrap().to_le_bytes());
        older.extend_from_slice(&header);
        let key = keys::export_key(&kdf::derive_password_key(WEAK, &params).unwrap());
        let padded = padding::pad(contents, padding::body_bucket).unwrap();
        let sealed = aead::seal(&key, &padded, &older).unwrap();
        older.extend_from_slice(&sealed);
        assert_eq!(&*open(WEAK, &older).unwrap(), contents);
    }

    #[test]
    fn opens_only_with_its_password_and_untouched() {
        let contents = br#"{"items":[{"name":"Bank","login":{"password":"s3cret"}}]}"#;
        let sealed = seal(PASSWORD, contents).unwrap();
        assert!(is_sealed_export(&sealed));
        assert!(!is_sealed_export(contents));
        assert!(
            !sealed.windows(6).any(|w| w == b"s3cret"),
            "nothing readable in the file"
        );
        assert_eq!(&*open(PASSWORD, &sealed).unwrap(), contents);
        assert!(matches!(
            open("another password", &sealed),
            Err(Error::DecryptionFailed)
        ));
        assert!(matches!(open("", &sealed), Err(Error::EmptyPassword)));
        assert!(matches!(open("x", contents), Err(Error::NotAVault)));

        // Two exports of the same contents differ (fresh salt and nonce), and hide the length.
        let again = seal(PASSWORD, contents).unwrap();
        assert_ne!(again, sealed);
        assert_eq!(seal(PASSWORD, b"short").unwrap().len(), sealed.len());

        // Any change is caught: the header (cost, salt), the contents, a cut or a tail.
        for index in [8, 9, 12, MAGIC.len() + 2 + 20, sealed.len() - 1] {
            let mut bad = sealed.clone();
            bad[index] ^= 1;
            assert!(open(PASSWORD, &bad).is_err(), "byte {index}");
        }
        assert!(open(PASSWORD, &sealed[..sealed.len() - 1]).is_err());
        assert!(open(PASSWORD, &sealed[..9]).is_err());
        let mut longer = sealed.clone();
        longer.push(0);
        assert!(open(PASSWORD, &longer).is_err());
    }
}
