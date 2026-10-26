//! Byte encodings and canonical JSON.
//!
//! Canonical JSON (used for everything that is signed or used as AEAD
//! associated data) is: UTF-8, no insignificant whitespace, object keys
//! sorted by byte order, keys restricted to ASCII, integers only (no floats)
//! within ±(2^53 − 1) so JavaScript reads them exactly, strings escaped as
//! `serde_json` does (only `"`, `\` and control characters).

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{Error, Result};

/// Largest integer allowed in canonical JSON (JavaScript's `Number.MAX_SAFE_INTEGER`).
pub const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// base64url without padding (RFC 4648 §5).
pub fn b64e(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn b64d(s: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s).map_err(|_| Error::Encoding("bad base64url".into()))
}

pub fn b64d_32(s: &str) -> Result<[u8; 32]> {
    b64d(s)?.try_into().map_err(|_| Error::Encoding("expected 32 bytes".into()))
}

pub fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// RFC 4648 base32, lowercase alphabet, no padding.
pub fn base32_lower(bytes: &[u8]) -> String {
    const ALPHA: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::new();
    let mut buf: u32 = 0;
    let mut bits = 0;
    for &b in bytes {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHA[((buf >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHA[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Serialize `value` to canonical JSON bytes.
pub fn canonical_json<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>> {
    let v = serde_json::to_value(value)?;
    let mut out = Vec::new();
    write_canonical(&v, &mut out)?;
    Ok(out)
}

/// Parse JSON that must already be canonical: the bytes received are exactly
/// the bytes that are signed. Rejects whitespace, key reordering, alternate
/// escapes, missing `null` fields and anything else that re-serializes
/// differently, so every verifier sees the same input.
pub fn parse_canonical<T: DeserializeOwned + Serialize>(s: &str, what: &'static str) -> Result<T> {
    let v: T = serde_json::from_str(s)?;
    if canonical_json(&v)? != s.as_bytes() {
        return Err(Error::invalid(what, "not canonical json"));
    }
    Ok(v)
}

fn write_canonical(v: &Value, out: &mut Vec<u8>) -> Result<()> {
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => {
            if n.is_f64() {
                return Err(Error::Encoding("floats are not allowed in canonical json".into()));
            }
            let in_range = n.as_u64().map(|u| u <= MAX_SAFE_INTEGER).unwrap_or(false)
                || n.as_i64().map(|i| i.unsigned_abs() <= MAX_SAFE_INTEGER).unwrap_or(false);
            if !in_range {
                return Err(Error::Encoding("integer outside ±(2^53-1) in canonical json".into()));
            }
            out.extend_from_slice(n.to_string().as_bytes());
        }
        Value::String(s) => out.extend_from_slice(serde_json::to_string(s)?.as_bytes()),
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            if let Some(k) = keys.iter().find(|k| !k.is_ascii()) {
                return Err(Error::Encoding(format!("non-ascii object key {k:?}")));
            }
            keys.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            out.push(b'{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                out.extend_from_slice(serde_json::to_string(k)?.as_bytes());
                out.push(b':');
                write_canonical(&map[k.as_str()], out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

/// serde helpers: `Vec<u8>` as base64url.
pub mod serde_b64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&super::b64e(bytes))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        super::b64d(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_sorts_and_compacts() {
        let v = json!({"b": 1, "a": [true, null, "x\"y"], "C": {"z": -3, "y": "é"}});
        let got = String::from_utf8(canonical_json(&v).unwrap()).unwrap();
        assert_eq!(got, r#"{"C":{"y":"é","z":-3},"a":[true,null,"x\"y"],"b":1}"#);
    }

    #[test]
    fn canonical_rejects_floats_and_non_ascii_keys() {
        assert!(canonical_json(&json!({"a": 1.5})).is_err());
        assert!(canonical_json(&json!({"é": 1})).is_err());
        assert!(canonical_json(&json!({"a": MAX_SAFE_INTEGER + 1})).is_err());
        assert!(canonical_json(&json!({"a": -(MAX_SAFE_INTEGER as i64) - 1})).is_err());
        assert!(canonical_json(&json!({"a": MAX_SAFE_INTEGER})).is_ok());
    }

    #[test]
    fn canonical_edge_strings() {
        // Non-ASCII stays raw, control characters use short or \u escapes,
        // U+2028 stays raw, "/" is not escaped.
        let v = json!({"s": "é\u{1}\n\u{2028}/\"\\"});
        let got = String::from_utf8(canonical_json(&v).unwrap()).unwrap();
        assert_eq!(got, "{\"s\":\"é\\u0001\\n\u{2028}/\\\"\\\\\"}");
    }

    #[test]
    fn parse_canonical_rejects_variants() {
        #[derive(serde::Serialize, serde::Deserialize)]
        struct S {
            a: u32,
            b: Option<u32>,
        }
        assert!(parse_canonical::<S>(r#"{"a":1,"b":null}"#, "s").is_ok());
        for bad in [r#"{"b":null,"a":1}"#, r#"{"a":1}"#, r#"{"a": 1,"b":null}"#, r#"{"a":1,"b":null} "#] {
            assert!(parse_canonical::<S>(bad, "s").is_err(), "{bad}");
        }
    }

    #[test]
    fn base32_matches_rfc4648() {
        assert_eq!(base32_lower(b""), "");
        assert_eq!(base32_lower(b"f"), "my");
        assert_eq!(base32_lower(b"foobar"), "mzxw6ytboi");
    }

    #[test]
    fn b64_roundtrip() {
        let b = [0u8, 255, 17, 42];
        assert_eq!(b64d(&b64e(&b)).unwrap(), b);
        assert!(b64d("not base64!").is_err());
    }
}
