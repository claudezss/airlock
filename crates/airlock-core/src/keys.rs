//! Ed25519 keys and domain-separated signatures.
//!
//! Every signature covers `b"airlock/v1/" || context || 0x00 || message`, so a
//! signature made for one purpose (say a role certificate) can never be
//! replayed as another (say an item).

use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::{CryptoRngCore, OsRng};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::encoding::{b64d, b64d_32, b64e, hex, sha256};
use crate::{Error, Result};

/// Signature contexts. Each signed structure has exactly one.
pub mod ctx {
    pub const MANIFEST: &str = "manifest";
    pub const CERT: &str = "cert";
    pub const JOIN: &str = "join";
    pub const ITEM: &str = "item";
}

fn domain(context: &str, msg: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(16 + context.len() + msg.len());
    m.extend_from_slice(b"airlock/v1/");
    m.extend_from_slice(context.as_bytes());
    m.push(0);
    m.extend_from_slice(msg);
    m
}

/// An Ed25519 signing key. Zeroized on drop.
pub struct Keypair {
    sk: SigningKey,
}

impl Keypair {
    pub fn generate() -> Self {
        Self::generate_with(&mut OsRng)
    }

    pub fn generate_with<R: CryptoRngCore + ?Sized>(rng: &mut R) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Self::from_seed(&seed)
    }

    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self { sk: SigningKey::from_bytes(seed) }
    }

    pub fn seed(&self) -> [u8; 32] {
        self.sk.to_bytes()
    }

    pub fn public(&self) -> PublicKey {
        PublicKey(self.sk.verifying_key())
    }

    pub fn sign(&self, context: &str, msg: &[u8]) -> Sig {
        Sig(self.sk.sign(&domain(context, msg)).to_bytes())
    }
}

impl fmt::Debug for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Keypair({})", self.public().fingerprint())
    }
}

/// An Ed25519 public key, serialized as base64url of its 32 bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey(VerifyingKey);

impl PublicKey {
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        VerifyingKey::from_bytes(bytes)
            .map(PublicKey)
            .map_err(|_| Error::Encoding("not a valid ed25519 public key".into()))
    }

    pub fn from_b64(s: &str) -> Result<Self> {
        Self::from_bytes(&b64d_32(s)?)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn to_b64(&self) -> String {
        b64e(&self.to_bytes())
    }

    /// First 8 bytes of SHA-256(public key), hex. Shown in UIs and logs.
    pub fn fingerprint(&self) -> String {
        hex(&sha256(&self.to_bytes())[..8])
    }

    /// Strict verification (rejects small-order keys and malleable signatures).
    pub fn verify(&self, context: &str, msg: &[u8], sig: &Sig) -> Result<()> {
        self.0
            .verify_strict(&domain(context, msg), &Signature::from_bytes(&sig.0))
            .map_err(|_| Error::Signature("bad signature"))
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.to_b64())
    }
}

impl Serialize for PublicKey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_b64())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        PublicKey::from_b64(&s).map_err(serde::de::Error::custom)
    }
}

/// A 64-byte Ed25519 signature, serialized as base64url.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Sig(pub [u8; 64]);

impl fmt::Debug for Sig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sig({})", b64e(&self.0))
    }
}

impl Serialize for Sig {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&b64e(&self.0))
    }
}

impl<'de> Deserialize<'de> for Sig {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let bytes: [u8; 64] = b64d(&s)
            .map_err(serde::de::Error::custom)?
            .try_into()
            .map_err(|_| serde::de::Error::custom("signature must be 64 bytes"))?;
        Ok(Sig(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_and_domain_separation() {
        let k = Keypair::from_seed(&[7u8; 32]);
        let sig = k.sign(ctx::CERT, b"hello");
        assert!(k.public().verify(ctx::CERT, b"hello", &sig).is_ok());
        assert!(k.public().verify(ctx::ITEM, b"hello", &sig).is_err());
        assert!(k.public().verify(ctx::CERT, b"hellp", &sig).is_err());
    }

    #[test]
    fn serde_roundtrip() {
        let k = Keypair::from_seed(&[1u8; 32]).public();
        let s = serde_json::to_string(&k).unwrap();
        let back: PublicKey = serde_json::from_str(&s).unwrap();
        assert_eq!(k, back);
        assert_eq!(k.fingerprint().len(), 16);
    }
}
