//! Randomness from the operating system CSPRNG.

use zeroize::Zeroizing;

use crate::{Error, Result};

/// Fills `buf` with cryptographically secure random bytes.
pub(crate) fn fill(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|_| Error::Rng)
}

/// Returns a random byte array (for public values such as ids, salts and nonces).
pub(crate) fn array<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    fill(&mut out)?;
    Ok(out)
}

/// Returns a random byte array that is wiped on drop (for key material).
pub(crate) fn secret_array<const N: usize>() -> Result<Zeroizing<[u8; N]>> {
    let mut out = Zeroizing::new([0u8; N]);
    fill(out.as_mut())?;
    Ok(out)
}
