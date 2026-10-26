use std::time::{SystemTime, UNIX_EPOCH};

use airlock_core::encoding::{b64e, hex, sha256};
use rand_core::{OsRng, RngCore};

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

pub fn sha256_hex(b: &[u8]) -> String {
    hex(&sha256(b))
}

/// 32 random bytes, base64url.
pub fn new_token() -> String {
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    b64e(&b)
}

pub fn random_suffix() -> String {
    let mut b = [0u8; 6];
    OsRng.fill_bytes(&mut b);
    hex(&b)
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
}
