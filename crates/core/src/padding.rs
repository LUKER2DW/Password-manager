//! Length-hiding padding (spec: CRYPTO.md §7): `u32 LE length ‖ data ‖ zeros`.

use zeroize::Zeroizing;

use crate::{Error, Result};

const LEN_PREFIX: usize = 4;
const ITEM_BLOCK: usize = 256;
const BODY_MIN: usize = 4096;

/// Items: round up to a multiple of 256 bytes.
pub(crate) fn item_bucket(n: usize) -> usize {
    n.div_ceil(ITEM_BLOCK).max(1) * ITEM_BLOCK
}

/// Body: at least 4 KiB, then steps of max(4 KiB, next_pow2(n) / 8) — at most 12.5 % overhead.
pub(crate) fn body_bucket(n: usize) -> usize {
    if n <= BODY_MIN {
        return BODY_MIN;
    }
    let step = (n.next_power_of_two() / 8).max(BODY_MIN);
    n.div_ceil(step) * step
}

pub(crate) fn pad(data: &[u8], bucket: fn(usize) -> usize) -> Result<Zeroizing<Vec<u8>>> {
    let len = u32::try_from(data.len()).map_err(|_| Error::Malformed)?;
    let total = bucket(LEN_PREFIX + data.len());
    let mut out = Zeroizing::new(vec![0u8; total]);
    out[..LEN_PREFIX].copy_from_slice(&len.to_le_bytes());
    out[LEN_PREFIX..LEN_PREFIX + data.len()].copy_from_slice(data);
    Ok(out)
}

pub(crate) fn unpad(padded: &[u8]) -> Result<&[u8]> {
    let prefix: [u8; LEN_PREFIX] = padded
        .get(..LEN_PREFIX)
        .and_then(|p| p.try_into().ok())
        .ok_or(Error::Malformed)?;
    let len = u32::from_le_bytes(prefix) as usize;
    let end = LEN_PREFIX.checked_add(len).ok_or(Error::Malformed)?;
    let data = padded.get(LEN_PREFIX..end).ok_or(Error::Malformed)?;
    if padded[end..].iter().any(|&b| b != 0) {
        return Err(Error::Malformed);
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets() {
        assert_eq!(item_bucket(0), 256);
        assert_eq!(item_bucket(1), 256);
        assert_eq!(item_bucket(256), 256);
        assert_eq!(item_bucket(257), 512);

        assert_eq!(body_bucket(1), 4096);
        assert_eq!(body_bucket(4096), 4096);
        assert_eq!(body_bucket(4097), 8192);
        // next_pow2(100_000) = 131_072 → step 16_384 → 7 steps.
        assert_eq!(body_bucket(100_000), 114_688);
        for n in [5_000usize, 70_000, 1_000_000, 10_000_000] {
            let padded = body_bucket(n);
            assert!(padded >= n);
            assert!(padded - n <= n / 8 + BODY_MIN, "overhead too large for {n}");
        }
    }

    #[test]
    fn round_trip() {
        for len in [0usize, 1, 251, 252, 253, 1000] {
            let data = vec![0xAB; len];
            let padded = pad(&data, item_bucket).unwrap();
            assert_eq!(padded.len() % 256, 0);
            assert_eq!(unpad(&padded).unwrap(), &data[..]);
        }
    }

    #[test]
    fn rejects_bad_padding() {
        assert!(unpad(&[1, 0]).is_err());
        assert!(unpad(&[9, 0, 0, 0, 1, 2]).is_err(), "length beyond buffer");
        assert!(unpad(&[1, 0, 0, 0, 7, 0, 1]).is_err(), "non-zero padding");
    }
}
