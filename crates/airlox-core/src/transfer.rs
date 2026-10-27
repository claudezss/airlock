//! One-time transfer codes: hand an invite link to another machine by
//! typing a short code such as `7-guitar-orbit` instead of the link.
//!
//! ```text
//! code   = {nameplate}-{word}-{word}
//! secret = "{word}-{word}"                     (16 bits, from WORDS)
//! key    = HKDF-SHA256(secret, info = "airlox transfer v1 key")
//! claim  = HKDF-SHA256(secret, info = "airlox transfer v1 claim")
//! box    = nonce(12) || AES-256-GCM(key, nonce, invite, aad = "airlox transfer v1")
//! ```
//!
//! The sender stores `box` and `sha256(claim)` on the relay, which picks the
//! nameplate. The receiver shows `claim` to get `box` back; the relay hands
//! it out once and burns the drop after a few wrong claims, so someone
//! guessing the words gets a handful of tries in 65,536. The relay itself
//! could try every secret against `sha256(claim)`: a transfer code trusts the
//! relay with the invite in a way the link's fragment does not.

use aes_gcm::aead::{Aead, KeyInit, Payload as AeadPayload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;

use crate::encoding::{b64d, b64e, hex, sha256};
use crate::{Error, Result};

const AAD: &[u8] = b"airlox transfer v1";
/// Largest sealed box a relay needs to accept: an invite link is well under this.
pub const MAX_BOX_BYTES: usize = 4096;

/// 256 short words, one byte each. Part of the protocol: changing them
/// breaks codes between versions.
pub const WORDS: [&str; 256] = [
    "acid", "acorn", "actor", "adobe", "alarm", "album", "alpha", "amber", "anchor", "angle", "apple",
    "apron", "arch", "arrow", "atlas", "attic", "badge", "bagel", "baker", "bamboo", "banjo", "barn",
    "basil", "beach", "beard", "bell", "bench", "berry", "bike", "bingo", "birch", "bison", "blade", "blank",
    "blimp", "bloom", "board", "bolt", "bonus", "boot", "brass", "bread", "brick", "brook", "brush",
    "bucket", "buddy", "bugle", "cabin", "cable", "cactus", "camel", "candy", "canoe", "canyon", "cargo",
    "carpet", "cedar", "chalk", "charm", "cherry", "chess", "chief", "cider", "circus", "civic", "clam",
    "cliff", "clock", "cloud", "clover", "coast", "cobra", "cocoa", "comet", "coral", "cotton", "crane",
    "creek", "crown", "cube", "cycle", "daisy", "dance", "delta", "denim", "desk", "diary", "dingo", "disco",
    "dock", "donut", "dragon", "drum", "dune", "eagle", "easel", "echo", "elbow", "elder", "ember", "engine",
    "epic", "fable", "falcon", "fancy", "farm", "feast", "fern", "ferry", "fiber", "field", "flag", "flute",
    "focus", "forest", "fossil", "fox", "frost", "fudge", "galaxy", "garden", "garlic", "gecko", "giant",
    "ginger", "glove", "goose", "grape", "gravel", "guitar", "habit", "hammer", "harbor", "hazel", "helmet",
    "heron", "hippo", "honey", "hotel", "husky", "igloo", "index", "ink", "iris", "island", "ivory",
    "jacket", "jaguar", "jelly", "jewel", "jungle", "kayak", "kettle", "kiosk", "kite", "koala", "label",
    "ladder", "lagoon", "lamp", "laser", "lemon", "lever", "lily", "lime", "linen", "lizard", "locket",
    "lotus", "lunar", "magnet", "mango", "maple", "marble", "meadow", "melon", "mint", "mirror", "mocha",
    "monkey", "motor", "muffin", "nectar", "needle", "nickel", "noodle", "nova", "oasis", "ocean", "olive",
    "omega", "onion", "opal", "orbit", "orchid", "otter", "oyster", "paddle", "panda", "paper", "parrot",
    "pasta", "peach", "pebble", "pepper", "piano", "pickle", "pilot", "pine", "pixel", "planet", "plum",
    "polar", "poppy", "prism", "pulse", "puzzle", "quail", "quartz", "quilt", "rabbit", "radar", "radio",
    "raft", "raven", "reef", "ribbon", "river", "robin", "rocket", "salmon", "scarf", "shadow", "silver",
    "sketch", "socket", "spark", "spice", "sponge", "spruce", "squid", "stamp", "sunset", "tango", "teapot",
    "tiger", "toast", "tulip", "tundra", "velvet", "violin", "walnut", "willow", "yacht", "zebra",
];

/// A parsed transfer code.
#[derive(Clone, PartialEq, Eq)]
pub struct Code {
    pub nameplate: u32,
    secret: String,
}

impl std::fmt::Debug for Code {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Code").field("nameplate", &self.nameplate).finish_non_exhaustive()
    }
}

impl Code {
    /// Accepts what people type: any case, spaces or underscores for dashes,
    /// stray whitespace around it.
    pub fn parse(s: &str) -> Result<Self> {
        let norm: String = s
            .trim()
            .chars()
            .map(|c| if c.is_whitespace() || c == '_' { '-' } else { c.to_ascii_lowercase() })
            .collect();
        let parts: Vec<&str> = norm.split('-').filter(|p| !p.is_empty()).collect();
        let [n, a, b] = parts[..] else {
            return Err(Error::invalid("code", "expected a number and two words, like 7-guitar-orbit"));
        };
        let nameplate: u32 = n
            .parse()
            .ok()
            .filter(|n| *n > 0)
            .ok_or_else(|| Error::invalid("code", "must start with a number, like 7-guitar-orbit"))?;
        for w in [a, b] {
            if !WORDS.contains(&w) {
                return Err(Error::invalid("code", format!("{w:?} is not one of the code words")));
            }
        }
        Ok(Code { nameplate, secret: format!("{a}-{b}") })
    }

    /// The code as the sender shows it.
    pub fn to_code_string(&self) -> String {
        format!("{}-{}", self.nameplate, self.secret)
    }

    /// What the receiver shows the relay to get the box: base64url.
    pub fn claim(&self) -> String {
        b64e(&derive(&self.secret, b"airlox transfer v1 claim"))
    }

    /// Decrypt a box fetched with this code.
    pub fn open(&self, sealed_box: &str) -> Result<String> {
        let b = b64d(sealed_box)?;
        if b.len() < 12 + 16 {
            return Err(Error::Decrypt);
        }
        let (nonce, ct) = b.split_at(12);
        let key = derive(&self.secret, b"airlox transfer v1 key");
        let pt = Aes256Gcm::new((&key).into())
            .decrypt(Nonce::from_slice(nonce), AeadPayload { msg: ct, aad: AAD })
            .map_err(|_| Error::Decrypt)?;
        String::from_utf8(pt).map_err(|_| Error::Decrypt)
    }
}

/// What the sender uploads, and the words it shows next to the nameplate
/// the relay assigns.
pub struct Sealed {
    /// `"{word}-{word}"`; the code is `{nameplate}-{secret}`.
    pub secret: String,
    /// `sha256(claim)`, hex: the relay's only check on a claim.
    pub claim_hash: String,
    /// base64url `nonce || ciphertext`.
    pub sealed_box: String,
}

impl std::fmt::Debug for Sealed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sealed").field("claim_hash", &self.claim_hash).finish_non_exhaustive()
    }
}

fn derive(secret: &str, info: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(None, secret.as_bytes()).expand(info, &mut out).expect("32 bytes is a valid length");
    out
}

/// `sha256` of a claim (base64url), as the relay stores and compares it.
pub fn claim_hash(claim: &str) -> Result<String> {
    Ok(hex(&sha256(&b64d(claim)?)))
}

/// Seal `invite` under two fresh random words.
pub fn seal(invite: &str) -> Result<Sealed> {
    let mut r = [0u8; 2];
    OsRng.fill_bytes(&mut r);
    seal_with(invite, WORDS[r[0] as usize], WORDS[r[1] as usize], &random_nonce())
}

fn random_nonce() -> [u8; 12] {
    let mut n = [0u8; 12];
    OsRng.fill_bytes(&mut n);
    n
}

fn seal_with(invite: &str, a: &str, b: &str, nonce: &[u8; 12]) -> Result<Sealed> {
    let secret = format!("{a}-{b}");
    let key = derive(&secret, b"airlox transfer v1 key");
    let ct = Aes256Gcm::new((&key).into())
        .encrypt(Nonce::from_slice(nonce), AeadPayload { msg: invite.as_bytes(), aad: AAD })
        .map_err(|_| Error::invalid("invite", "could not seal"))?;
    let mut b = nonce.to_vec();
    b.extend_from_slice(&ct);
    if b.len() > MAX_BOX_BYTES {
        return Err(Error::invalid("invite", "too long to send with a code"));
    }
    let claim = b64e(&derive(&secret, b"airlox transfer v1 claim"));
    Ok(Sealed { claim_hash: claim_hash(&claim)?, secret, sealed_box: b64e(&b) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn words_are_unique_and_plain() {
        let set: HashSet<&str> = WORDS.iter().copied().collect();
        assert_eq!(set.len(), 256);
        assert!(WORDS
            .iter()
            .all(|w| (3..=8).contains(&w.len()) && w.bytes().all(|c| c.is_ascii_lowercase())));
    }

    #[test]
    fn seal_claim_open_roundtrip() {
        let invite = "https://airlox.app/s/ax_abc#v=1&r=run&k=AAAA&rk=BBBB";
        let s = seal(invite).unwrap();
        let code = Code::parse(&format!("7-{}", s.secret)).unwrap();
        assert_eq!(code.nameplate, 7);
        assert_eq!(claim_hash(&code.claim()).unwrap(), s.claim_hash);
        assert_eq!(code.open(&s.sealed_box).unwrap(), invite);
    }

    #[test]
    fn wrong_words_do_not_open() {
        let s = seal_with("x", "tiger", "orbit", &[0; 12]).unwrap();
        let wrong = Code::parse("7-tiger-otter").unwrap();
        assert_ne!(claim_hash(&wrong.claim()).unwrap(), s.claim_hash);
        assert!(matches!(wrong.open(&s.sealed_box), Err(Error::Decrypt)));
    }

    #[test]
    fn parse_is_forgiving_about_typing() {
        for s in ["7-guitar-orbit", " 7 Guitar ORBIT ", "7_guitar_orbit", "7--guitar-orbit\n"] {
            assert_eq!(Code::parse(s).unwrap().to_code_string(), "7-guitar-orbit", "{s:?}");
        }
        for s in [
            "",
            "guitar-orbit",
            "0-guitar-orbit",
            "x-guitar-orbit",
            "7-guitar",
            "7-guitar-orbit-fox",
            "7-guitar-zzz",
        ] {
            assert!(Code::parse(s).is_err(), "{s:?}");
        }
    }

    #[test]
    fn fixed_vector() {
        // Pins the derivation: a change here breaks codes between versions.
        let s = seal_with("hello", "acid", "zebra", &[7; 12]).unwrap();
        assert_eq!(s.secret, "acid-zebra");
        let c = Code::parse("1-acid-zebra").unwrap();
        assert_eq!(c.open(&s.sealed_box).unwrap(), "hello");
        assert_eq!(s.sealed_box, "BwcHBwcHBwcHBwcHtA6hRR1LA0KievfZ7tIdxmvWfYnk");
        assert_eq!(s.claim_hash, "87dee4d6585e6bab44eb6d041f8fd54da1bdbda6a7364c9c81dfa13462d2c747");
    }
}
