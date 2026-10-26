//! Items: the encrypted, signed unit of everything posted to a session.
//!
//! ```text
//! key   = HKDF-SHA256(ikm = session_key, salt = session_id,
//!                     info = "airlock/v1/item-key" || 0x00 || item_id)
//! blob  = nonce(12) || AES-256-GCM(key, nonce, payload, aad = canonical(header))
//! sig   = Ed25519(author, ctx "item", canonical(header) || SHA-256(blob))
//! ```
//!
//! The header is plaintext so the server can enforce policy; it carries no
//! names or content. The AAD binds header to ciphertext, so the server cannot
//! relabel a job as a message. The signature covers the blob hash, so the
//! server can check authorship without the key.

use aes_gcm::aead::{Aead, KeyInit, Payload as AeadPayload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use rand_core::{CryptoRngCore, OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::encoding::{b64e, canonical_json, sha256};
use crate::keys::{ctx, Keypair, PublicKey, Sig};
use crate::session::{is_session_id, ContentType};
use crate::{Error, Result, PROTOCOL_VERSION};

pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const BLOB_OVERHEAD: usize = NONCE_LEN + TAG_LEN;
pub const MAX_REFS: usize = 64;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum ItemKind {
    Text,
    File,
    Job,
    Result,
    Event,
}

impl ItemKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ItemKind::Text => "text",
            ItemKind::File => "file",
            ItemKind::Job => "job",
            ItemKind::Result => "result",
            ItemKind::Event => "event",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ItemHeader {
    pub v: u32,
    pub id: String,
    pub session_id: String,
    pub author: PublicKey,
    pub kind: ItemKind,
    pub subkind: Option<ContentType>,
    /// Plaintext payload length in bytes.
    pub size: u64,
    pub created_at_ms: u64,
    pub refs: Vec<String>,
}

/// Item ids are 16 random bytes, base64url (22 characters).
pub fn new_item_id() -> String {
    new_item_id_with(&mut OsRng)
}

pub fn new_item_id_with<R: CryptoRngCore + ?Sized>(rng: &mut R) -> String {
    let mut b = [0u8; 16];
    rng.fill_bytes(&mut b);
    b64e(&b)
}

pub fn is_item_id(s: &str) -> bool {
    s.len() == 22 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

impl ItemHeader {
    pub fn validate(&self) -> Result<()> {
        if self.v != PROTOCOL_VERSION {
            return Err(Error::invalid("item header", "unsupported version"));
        }
        if !is_item_id(&self.id) {
            return Err(Error::invalid("item header", "malformed id"));
        }
        if !is_session_id(&self.session_id) {
            return Err(Error::invalid("item header", "malformed session id"));
        }
        if self.refs.len() > MAX_REFS || !self.refs.iter().all(|r| is_item_id(r)) {
            return Err(Error::invalid("item header", "refs must be up to 64 item ids"));
        }
        use ContentType as C;
        let ok = matches!(
            (self.kind, self.subkind),
            (ItemKind::Text, None)
                | (ItemKind::File, Some(C::Py | C::Md | C::Zip | C::Image))
                | (ItemKind::Job, Some(C::Py))
                | (ItemKind::Result, None)
                | (ItemKind::Event, None)
        );
        if !ok {
            return Err(Error::invalid(
                "item header",
                format!("subkind {:?} not valid for kind {}", self.subkind, self.kind.as_str()),
            ));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        canonical_json(self)
    }
}

/// Header plus signature: the JSON half of an item on the wire. The blob
/// travels separately as raw bytes.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ItemEnvelope {
    pub header: ItemHeader,
    pub sig: Sig,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedItem {
    pub envelope: ItemEnvelope,
    pub blob: Vec<u8>,
}

/// Header fields chosen by the author. `size`, `v` and `author` are filled in.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct NewItem {
    pub id: String,
    pub session_id: String,
    pub kind: ItemKind,
    pub subkind: Option<ContentType>,
    pub created_at_ms: u64,
    #[serde(default)]
    pub refs: Vec<String>,
}

pub fn item_key(session_key: &[u8; 32], session_id: &str, item_id: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(session_id.as_bytes()), session_key);
    let mut info = b"airlock/v1/item-key\0".to_vec();
    info.extend_from_slice(item_id.as_bytes());
    let mut out = [0u8; 32];
    hk.expand(&info, &mut out).expect("32 bytes is a valid hkdf length");
    out
}

fn sig_message(header_bytes: &[u8], blob: &[u8]) -> Vec<u8> {
    let mut m = header_bytes.to_vec();
    m.extend_from_slice(&sha256(blob));
    m
}

pub fn seal(session_key: &[u8; 32], author: &Keypair, new: NewItem, payload: &[u8]) -> Result<SealedItem> {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    seal_with_nonce(session_key, author, new, payload, nonce)
}

/// Deterministic sealing for test vectors. Never reuse a nonce in production.
#[doc(hidden)]
pub fn seal_with_nonce(
    session_key: &[u8; 32],
    author: &Keypair,
    new: NewItem,
    payload: &[u8],
    nonce: [u8; NONCE_LEN],
) -> Result<SealedItem> {
    let header = ItemHeader {
        v: PROTOCOL_VERSION,
        id: new.id,
        session_id: new.session_id,
        author: author.public(),
        kind: new.kind,
        subkind: new.subkind,
        size: payload.len() as u64,
        created_at_ms: new.created_at_ms,
        refs: new.refs,
    };
    header.validate()?;
    let hb = header.canonical_bytes()?;
    let key = item_key(session_key, &header.session_id, &header.id);
    let ct = Aes256Gcm::new((&key).into())
        .encrypt(Nonce::from_slice(&nonce), AeadPayload { msg: payload, aad: &hb })
        .map_err(|_| Error::invalid("item", "encryption failed"))?;
    let mut blob = Vec::with_capacity(NONCE_LEN + ct.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ct);
    let sig = author.sign(ctx::ITEM, &sig_message(&hb, &blob));
    Ok(SealedItem { envelope: ItemEnvelope { header, sig }, blob })
}

impl SealedItem {
    pub fn header(&self) -> &ItemHeader {
        &self.envelope.header
    }

    /// Checks the server can run: header shape, blob length, author signature.
    pub fn verify(&self) -> Result<()> {
        let h = &self.envelope.header;
        h.validate()?;
        let expected = h
            .size
            .checked_add(BLOB_OVERHEAD as u64)
            .ok_or_else(|| Error::invalid("item", "size overflow"))?;
        if self.blob.len() as u64 != expected {
            return Err(Error::invalid("item", "blob length does not match header size"));
        }
        h.author
            .verify(ctx::ITEM, &sig_message(&h.canonical_bytes()?, &self.blob), &self.envelope.sig)
            .map_err(|_| Error::Signature("item not signed by its author"))
    }

    /// Verify, then decrypt. Returns the plaintext payload.
    pub fn open(&self, session_key: &[u8; 32]) -> Result<Vec<u8>> {
        self.verify()?;
        let h = &self.envelope.header;
        let hb = h.canonical_bytes()?;
        let key = item_key(session_key, &h.session_id, &h.id);
        let (nonce, ct) = self.blob.split_at(NONCE_LEN);
        let pt = Aes256Gcm::new((&key).into())
            .decrypt(Nonce::from_slice(nonce), AeadPayload { msg: ct, aad: &hb })
            .map_err(|_| Error::Decrypt)?;
        debug_assert_eq!(pt.len() as u64, h.size);
        Ok(pt)
    }

    pub fn blob_sha256(&self) -> [u8; 32] {
        sha256(&self.blob)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new(kind: ItemKind, subkind: Option<ContentType>) -> NewItem {
        NewItem {
            id: "AAAAAAAAAAAAAAAAAAAAAA".into(),
            session_id: "ak_aaaaaaaaaaaa".into(),
            kind,
            subkind,
            created_at_ms: 5,
            refs: vec![],
        }
    }

    #[test]
    fn seal_open_roundtrip() {
        let k = [1u8; 32];
        let a = Keypair::from_seed(&[2u8; 32]);
        let s = seal(&k, &a, new(ItemKind::Text, None), b"hello").unwrap();
        assert_eq!(s.blob.len(), 5 + BLOB_OVERHEAD);
        assert_eq!(s.open(&k).unwrap(), b"hello");
        assert_eq!(s.open(&[9u8; 32]), Err(Error::Decrypt));
    }

    #[test]
    fn relabel_and_tamper_are_detected() {
        let k = [1u8; 32];
        let a = Keypair::from_seed(&[2u8; 32]);
        let s = seal(&k, &a, new(ItemKind::File, Some(ContentType::Md)), b"# hi").unwrap();

        let mut relabeled = s.clone();
        relabeled.envelope.header.subkind = Some(ContentType::Zip);
        assert!(matches!(relabeled.verify(), Err(Error::Signature(_))));

        let mut flipped = s.clone();
        *flipped.blob.last_mut().unwrap() ^= 1;
        assert!(matches!(flipped.verify(), Err(Error::Signature(_))));

        // Re-signed by another key with a relabeled header: signature passes
        // for the forger, but AAD binding makes decryption fail.
        let forger = Keypair::from_seed(&[3u8; 32]);
        let mut h = s.envelope.header.clone();
        h.kind = ItemKind::Job;
        h.subkind = Some(ContentType::Py);
        h.author = forger.public();
        let sig = forger.sign(ctx::ITEM, &sig_message(&h.canonical_bytes().unwrap(), &s.blob));
        let forged = SealedItem { envelope: ItemEnvelope { header: h, sig }, blob: s.blob.clone() };
        forged.verify().unwrap();
        assert_eq!(forged.open(&k), Err(Error::Decrypt));
    }

    #[test]
    fn subkind_rules() {
        let k = [1u8; 32];
        let a = Keypair::from_seed(&[2u8; 32]);
        assert!(seal(&k, &a, new(ItemKind::Text, Some(ContentType::Md)), b"").is_err());
        assert!(seal(&k, &a, new(ItemKind::Job, Some(ContentType::Zip)), b"").is_err());
        assert!(seal(&k, &a, new(ItemKind::File, None), b"").is_err());
    }
}
