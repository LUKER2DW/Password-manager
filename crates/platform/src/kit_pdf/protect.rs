//! The PDF standard security handler, revision 6 (ISO 32000-2:2020 §7.6.4; CRYPTO.md §3.10):
//! the kit's saved files encrypted with AES-256 under a password, as every current PDF viewer
//! reads them. Written by hand like the rest of the file, on RustCrypto's `aes`, `cbc` and
//! `sha2`; nothing here is ours but the order the standard gives.

use std::fmt::Write as _;

use aes::cipher::{
    BlockCipherDecrypt, BlockCipherEncrypt, BlockModeDecrypt, BlockModeEncrypt, KeyInit, KeyIvInit,
    block_padding::{NoPadding, Pkcs7},
};
use anyhow::{Context, Result};
use sha2::{Digest, Sha256, Sha384, Sha512};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// What a viewer lets the person do once the file is open (ISO 32000-2 Table 22): print (bit
/// 3), copy (5), accessibility (10) and print in high quality (12); not change it (4), add
/// notes (6), fill forms (9) or reassemble it (11). Bits 7, 8 and 13–32 are set as the
/// standard asks. Advisory only: they protect nothing (CRYPTO.md §3.10).
pub(super) const PERMISSIONS: i32 = -1324;

/// The longest password the standard reads (bytes, after SASLprep).
const MAX_PASSWORD: usize = 127;

/// The 8-byte salts of the U and O entries and the 4 bytes Perms ends with.
struct Salts {
    user_validation: [u8; 8],
    user_key: [u8; 8],
    owner_validation: [u8; 8],
    owner_key: [u8; 8],
    perms: [u8; 4],
}

/// The encrypt dictionary's five values (Algorithms 8, 9 and 10).
struct Entries {
    u: [u8; 48],
    ue: [u8; 32],
    o: [u8; 48],
    oe: [u8; 32],
    perms: [u8; 16],
}

/// One file's encryption: its random file key, the dictionary that unwraps it with the
/// password, and the file's `/ID`.
pub(super) struct Protection {
    file_key: Zeroizing<[u8; 32]>,
    entries: Entries,
    id: [u8; 16],
}

impl std::fmt::Debug for Protection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Protection(<redacted>)")
    }
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).map_err(|err| anyhow::anyhow!("no randomness: {err}"))?;
    Ok(bytes)
}

impl Protection {
    /// A new file key and dictionary for `password` as the person types it (its words with
    /// their spaces): the user password; the same characters without the spaces are the owner
    /// password, so either spelling opens the file.
    pub(super) fn new(password: &str) -> Result<Self> {
        let mut file_key = Zeroizing::new([0u8; 32]);
        getrandom::fill(file_key.as_mut())
            .map_err(|err| anyhow::anyhow!("no randomness: {err}"))?;
        let salts = Salts {
            user_validation: random()?,
            user_key: random()?,
            owner_validation: random()?,
            owner_key: random()?,
            perms: random()?,
        };
        let (user, owner) = spellings(password)?;
        let entries = entries(user.as_bytes(), owner.as_bytes(), &file_key, &salts)?;
        Ok(Self {
            file_key,
            entries,
            id: random()?,
        })
    }

    /// A string's or a stream's bytes as the file holds them (AESV3): a random IV, then
    /// AES-256-CBC with PKCS#7 padding.
    pub(super) fn encrypt(&self, data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        aes256_cbc(&self.file_key, &random()?, data)
    }

    /// The encrypt dictionary.
    pub(super) fn dictionary(&self) -> String {
        let e = &self.entries;
        format!(
            "<< /Filter /Standard /V 5 /R 6 /Length 256 \
             /CF << /StdCF << /Type /CryptFilter /CFM /AESV3 /AuthEvent /DocOpen /Length 32 >> >> \
             /StmF /StdCF /StrF /StdCF \
             /O <{}> /U <{}> /OE <{}> /UE <{}> /Perms <{}> /P {PERMISSIONS} >>",
            hex(&e.o),
            hex(&e.u),
            hex(&e.oe),
            hex(&e.ue),
            hex(&e.perms)
        )
    }

    /// The trailer's `/ID` (never encrypted): the same random bytes twice.
    pub(super) fn id(&self) -> String {
        let id = hex(&self.id);
        format!("[<{id}> <{id}>]")
    }
}

/// The user and owner passwords: as written, and without the spaces. Refused when longer
/// than the standard reads, not printable ASCII (which SASLprep leaves as it is), or with a
/// space at either end.
fn spellings(password: &str) -> Result<(&str, String)> {
    anyhow::ensure!(
        password.trim() == password
            && !password.is_empty()
            && password.len() <= MAX_PASSWORD
            && password.bytes().all(|b| b == b' ' || b.is_ascii_graphic()),
        "the file's password must be printable ASCII"
    );
    Ok((password, password.replace(' ', "")))
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn entries(user: &[u8], owner: &[u8], file_key: &[u8; 32], salts: &Salts) -> Result<Entries> {
    // Algorithm 8: U and UE.
    let mut u = [0u8; 48];
    u[..32].copy_from_slice(hash_2b(user, &salts.user_validation, b"").as_ref());
    u[32..40].copy_from_slice(&salts.user_validation);
    u[40..].copy_from_slice(&salts.user_key);
    let ue = wrap(&hash_2b(user, &salts.user_key, b""), file_key)?;
    // Algorithm 9: O and OE, over the whole U.
    let mut o = [0u8; 48];
    o[..32].copy_from_slice(hash_2b(owner, &salts.owner_validation, &u).as_ref());
    o[32..40].copy_from_slice(&salts.owner_validation);
    o[40..].copy_from_slice(&salts.owner_key);
    let oe = wrap(&hash_2b(owner, &salts.owner_key, &u), file_key)?;
    // Algorithm 10: Perms, one block under the file key.
    let mut block = [0u8; 16];
    block[..4].copy_from_slice(&PERMISSIONS.to_le_bytes());
    block[4..8].copy_from_slice(&[0xFF; 4]);
    block[8] = b'T';
    block[9..12].copy_from_slice(b"adb");
    block[12..].copy_from_slice(&salts.perms);
    let mut perms = aes::Block::from(block);
    aes::Aes256::new_from_slice(file_key)
        .context("AES-256 key")?
        .encrypt_block(&mut perms);
    Ok(Entries {
        u,
        ue,
        o,
        oe,
        perms: perms.into(),
    })
}

/// UE and OE: the file key under `key`, AES-256-CBC with a zero IV and no padding.
fn wrap(key: &[u8; 32], file_key: &[u8; 32]) -> Result<[u8; 32]> {
    let mut out = *file_key;
    cbc::Encryptor::<aes::Aes256>::new_from_slices(key, &[0u8; 16])
        .context("AES-256-CBC key")?
        .encrypt_padded::<NoPadding>(&mut out, 32)
        .map_err(|_| anyhow::anyhow!("AES-256-CBC block"))?;
    Ok(out)
}

/// AES-256-CBC with PKCS#7 padding, the IV first (how AESV3 keeps strings and streams).
fn aes256_cbc(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let padded = (data.len() / 16 + 1) * 16;
    let mut out = Zeroizing::new(vec![0u8; 16 + padded]);
    out[..16].copy_from_slice(iv);
    out[16..16 + data.len()].copy_from_slice(data);
    cbc::Encryptor::<aes::Aes256>::new_from_slices(key, iv)
        .context("AES-256-CBC key")?
        .encrypt_padded::<Pkcs7>(&mut out[16..], data.len())
        .map_err(|_| anyhow::anyhow!("AES-256-CBC padding"))?;
    Ok(out)
}

/// Algorithm 2.B: the revision 6 hash of `password` with an 8-byte `salt` and `udata` (empty
/// for the user password, the 48-byte U for the owner's).
fn hash_2b(password: &[u8], salt: &[u8], udata: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut k: Zeroizing<Vec<u8>> = Zeroizing::new(
        Sha256::new()
            .chain_update(password)
            .chain_update(salt)
            .chain_update(udata)
            .finalize()
            .to_vec(),
    );
    let mut rounds = 0usize;
    loop {
        // a) K1 = (password ‖ K ‖ udata) 64 times; a whole number of blocks, as 64 is.
        let piece = password.len() + k.len() + udata.len();
        let mut e = Zeroizing::new(Vec::with_capacity(64 * piece));
        for _ in 0..64 {
            e.extend_from_slice(password);
            e.extend_from_slice(&k);
            e.extend_from_slice(udata);
        }
        // b) E = AES-128-CBC(key = K[0..16], IV = K[16..32], K1), no padding.
        let len = e.len();
        cbc::Encryptor::<aes::Aes128>::new_from_slices(&k[..16], &k[16..32])
            .expect("16-byte key and IV")
            .encrypt_padded::<NoPadding>(&mut e, len)
            .expect("64 copies are a whole number of blocks");
        // c) E[0..16] as a big-endian number, mod 3: 256 ≡ 1 (mod 3), so the sum of its bytes.
        let pick = e[..16].iter().map(|&b| u32::from(b)).sum::<u32>() % 3;
        // d) The next K.
        *k = match pick {
            0 => Sha256::digest(&e[..]).to_vec(),
            1 => Sha384::digest(&e[..]).to_vec(),
            _ => Sha512::digest(&e[..]).to_vec(),
        };
        rounds += 1;
        // e) At least 64 rounds, then until E's last byte is at most the rounds done − 32.
        if rounds >= 64 && usize::from(e[len - 1]) <= rounds - 32 {
            break;
        }
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&k[..32]);
    out
}

/// Reads a protected kit back as a viewer would (Algorithms 2.A, 11, 12 and 13): `password`
/// in either spelling must open it, and then the content streams are decrypted. Gives the
/// file with each stream decrypted in place, or `None` when the password doesn't open it or
/// the file isn't one this module wrote. Used to check a saved file before it is called done,
/// and by the tests.
pub fn open(bytes: &[u8], password: &str) -> Option<Zeroizing<Vec<u8>>> {
    let text = String::from_utf8_lossy(bytes);
    let entry = |name: &str, len: usize| -> Option<Vec<u8>> {
        let start = text.find(&format!("/{name} <"))? + name.len() + 3;
        let hex = text.get(start..start + 2 * len)?;
        (0..len)
            .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok())
            .collect()
    };
    let (u, ue, o, oe, perms) = (
        entry("U", 48)?,
        entry("UE", 32)?,
        entry("O", 48)?,
        entry("OE", 32)?,
        entry("Perms", 16)?,
    );
    let password = password.as_bytes();
    // The owner password first, then the user's (Algorithm 2.A).
    let (key, wrapped) = if hash_2b(password, &o[32..40], &u)
        .as_ref()
        .ct_eq(&o[..32])
        .into()
    {
        (hash_2b(password, &o[40..48], &u), oe)
    } else if hash_2b(password, &u[32..40], b"")
        .as_ref()
        .ct_eq(&u[..32])
        .into()
    {
        (hash_2b(password, &u[40..48], b""), ue)
    } else {
        return None;
    };
    let mut file_key = Zeroizing::new([0u8; 32]);
    file_key.copy_from_slice(&wrapped);
    cbc::Decryptor::<aes::Aes256>::new_from_slices(key.as_ref(), &[0u8; 16])
        .ok()?
        .decrypt_padded::<NoPadding>(file_key.as_mut())
        .ok()?;
    // Algorithm 13: Perms opens under the file key and says what the dictionary says.
    let mut block = aes::Block::try_from(&perms[..]).ok()?;
    aes::Aes256::new_from_slice(file_key.as_ref())
        .ok()?
        .decrypt_block(&mut block);
    if block[9..12] != *b"adb" || block[..4] != PERMISSIONS.to_le_bytes()[..] {
        return None;
    }
    // Each stream: `/Length n >>\nstream\n`, n bytes, then `\nendstream`.
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let mut rest = bytes;
    while let Some(at) = find(rest, b">>\nstream\n") {
        let head = &rest[..at];
        let length_at = rfind(head, b"/Length ")? + b"/Length ".len();
        let length: usize = std::str::from_utf8(&head[length_at..])
            .ok()?
            .trim()
            .parse()
            .ok()?;
        let data_at = at + b">>\nstream\n".len();
        let data = rest.get(data_at..data_at + length)?;
        if data.len() < 32 {
            return None;
        }
        let mut plain = Zeroizing::new(data[16..].to_vec());
        let plain_len =
            cbc::Decryptor::<aes::Aes256>::new_from_slices(file_key.as_ref(), &data[..16])
                .ok()?
                .decrypt_padded::<Pkcs7>(&mut plain)
                .ok()?
                .len();
        out.extend_from_slice(&rest[..data_at]);
        out.extend_from_slice(&plain[..plain_len]);
        rest = &rest[data_at + length..];
    }
    out.extend_from_slice(rest);
    Some(out)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn rfind(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .rposition(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len() / 2)
            .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    const USER: &str = "cupped reverend native quaking";

    fn fixed_salts() -> Salts {
        Salts {
            user_validation: std::array::from_fn(|i| 0x40 + i as u8),
            user_key: std::array::from_fn(|i| 0x48 + i as u8),
            owner_validation: std::array::from_fn(|i| 0x50 + i as u8),
            owner_key: std::array::from_fn(|i| 0x58 + i as u8),
            perms: [0xE0, 0xE1, 0xE2, 0xE3],
        }
    }

    /// Known answers computed apart: pypdf 7.2's revision 6 code (a port of qpdf's, with the
    /// `cryptography` package's AES) for Algorithm 2.B and the five entries, `cryptography`'s
    /// AES-256-CBC for the string (scratch scripts outside the repository).
    #[test]
    fn known_answers() {
        assert_eq!(
            hash_2b(USER.as_bytes(), &fixed_salts().user_validation, b"").as_ref(),
            unhex("2e5a71096aba55f4df17bd57ea014964072774ea1da67f94d33298888df09096").as_slice()
        );
        let file_key: [u8; 32] = std::array::from_fn(|i| i as u8);
        let (user, owner) = spellings(USER).unwrap();
        assert_eq!(owner, "cuppedreverendnativequaking");
        let e = entries(user.as_bytes(), owner.as_bytes(), &file_key, &fixed_salts()).unwrap();
        assert_eq!(
            e.u.as_slice(),
            unhex(
                "2e5a71096aba55f4df17bd57ea014964072774ea1da67f94d33298888df09096\
                 404142434445464748494a4b4c4d4e4f"
            )
        );
        assert_eq!(
            e.ue.as_slice(),
            unhex("19c42cd0573947bebe028551474afda6a59a6ba11f197656bd066070885aa9b0")
        );
        assert_eq!(
            e.o.as_slice(),
            unhex(
                "36a248d40ffed5c5c988ff9b174a159c61bd2a4f85707434f98e4dadeb65e440\
                 505152535455565758595a5b5c5d5e5f"
            )
        );
        assert_eq!(
            e.oe.as_slice(),
            unhex("7bb94d43ddfc06b99f13252cfc19db0471f5068a8f07b103c6d003ef38adcfa9")
        );
        assert_eq!(
            e.perms.as_slice(),
            unhex("0669ad60435dad065d386561ba3acf21")
        );
        let iv: [u8; 16] = std::array::from_fn(|i| 0xF0 + i as u8);
        let sealed =
            aes256_cbc(&file_key, &iv, b"(S0-ABCDEFG-HJKMNPQ-RSTVWXY-Z012345) Tj").unwrap();
        assert_eq!(
            sealed.as_slice(),
            unhex(
                "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff20e42b266aca75b109ad10930528162a\
                 da19ef896d8dfa1059b1480216a8855077ce8b567cfda40fbc542ab4e302c47a"
            )
        );
    }

    #[test]
    fn only_plain_ascii_passwords() {
        assert!(spellings("").is_err());
        assert!(spellings("pässword").is_err());
        assert!(spellings(" leading space").is_err());
        assert!(spellings("tab\tinside").is_err());
        assert!(spellings("four words like this").is_ok());
        assert!(spellings(&"x".repeat(128)).is_err());
        assert!(spellings(&"x".repeat(127)).is_ok());
    }

    #[test]
    fn each_file_has_its_own_key_and_salts() {
        let a = Protection::new(USER).unwrap();
        let b = Protection::new(USER).unwrap();
        assert_ne!(*a.file_key, *b.file_key);
        assert_ne!(a.entries.u, b.entries.u);
        assert_ne!(a.id, b.id);
        // A new IV for each stream: the same text never encrypts the same twice.
        assert_ne!(*a.encrypt(b"same").unwrap(), *a.encrypt(b"same").unwrap());
        assert_eq!(
            a.encrypt(b"").unwrap().len(),
            32,
            "IV and one block of padding"
        );
        assert_eq!(a.encrypt(&[0; 16]).unwrap().len(), 48);
        assert_eq!(format!("{a:?}"), "Protection(<redacted>)");
        let dictionary = a.dictionary();
        assert!(dictionary.contains("/V 5 /R 6") && dictionary.contains("/CFM /AESV3"));
        assert!(dictionary.contains("/P -1324"));
    }
}
