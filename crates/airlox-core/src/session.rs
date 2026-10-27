//! Sessions: the owner seed, everything derived from it, and the signed manifest.
//!
//! The owner seed is the root secret. The session key and the three role
//! keypairs are derived from it with HKDF, so the owner link only needs to
//! carry the seed. Member invites carry the session key and their role seed,
//! neither of which reveals the owner seed or any other role seed.

use hkdf::Hkdf;
use rand_core::{CryptoRngCore, OsRng};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::encoding::{base32_lower, canonical_json, parse_canonical, sha256, MAX_SAFE_INTEGER};
use crate::keys::{ctx, Keypair, PublicKey, Sig};
use crate::{Error, Result, PROTOCOL_VERSION};

pub const DEFAULT_MAX_ITEM_BYTES: u64 = 25 * 1024 * 1024;
pub const MAX_ITEM_BYTES_CEILING: u64 = 1024 * 1024 * 1024;
pub const MAX_TTL_MS: u64 = 30 * 24 * 60 * 60 * 1000;
/// Longest job timeout a manifest may allow: a day, for long simulations.
pub const MAX_JOB_TIMEOUT_S: u32 = 24 * 60 * 60;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Owner,
    Sender,
    Runner,
    Observer,
}

impl Role {
    pub const MEMBERS: [Role; 3] = [Role::Sender, Role::Runner, Role::Observer];

    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Owner => "owner",
            Role::Sender => "sender",
            Role::Runner => "runner",
            Role::Observer => "observer",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "owner" => Ok(Role::Owner),
            "sender" => Ok(Role::Sender),
            "runner" => Ok(Role::Runner),
            "observer" => Ok(Role::Observer),
            _ => Err(Error::invalid("role", s)),
        }
    }

    /// Short name used in invite URL fragments.
    pub fn url_name(&self) -> &'static str {
        match self {
            Role::Owner => "owner",
            Role::Sender => "send",
            Role::Runner => "run",
            Role::Observer => "view",
        }
    }

    pub fn from_url_name(s: &str) -> Result<Self> {
        match s {
            "owner" => Ok(Role::Owner),
            "send" => Ok(Role::Sender),
            "run" => Ok(Role::Runner),
            "view" => Ok(Role::Observer),
            _ => Err(Error::invalid("invite role", s)),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Relay,
    Execute,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum ContentType {
    Text,
    Py,
    Md,
    Zip,
    Image,
}

impl ContentType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ContentType::Text => "text",
            ContentType::Py => "py",
            ContentType::Md => "md",
            ContentType::Zip => "zip",
            ContentType::Image => "image",
        }
    }
}

/// Ceilings every runner must enforce. Only present in Execute mode.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct JobLimits {
    /// e.g. "python3.12"
    pub runtime: String,
    pub timeout_s: u32,
    pub memory_mb: u32,
    pub network: bool,
    /// Normalized package names a job may require. Empty = stdlib only.
    pub packages: Vec<String>,
    pub return_out: bool,
    pub approve_runners: bool,
}

impl Default for JobLimits {
    fn default() -> Self {
        JobLimits {
            runtime: "python3.12".into(),
            timeout_s: 30,
            memory_mb: 512,
            network: false,
            packages: vec![],
            return_out: true,
            approve_runners: true,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RoleKeys {
    pub sender: PublicKey,
    pub runner: PublicKey,
    pub observer: PublicKey,
}

/// Session policy. Plaintext (the server enforces it), signed by the owner.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub v: u32,
    pub session_id: String,
    pub owner_pub: PublicKey,
    pub roles: RoleKeys,
    pub mode: Mode,
    pub created_at_ms: u64,
    /// `None`: the session never expires; it ends when the owner closes it.
    #[serde(deserialize_with = "required")]
    pub expires_at_ms: Option<u64>,
    pub allowed_types: Vec<ContentType>,
    pub max_item_bytes: u64,
    pub job_limits: Option<JobLimits>,
}

/// An `Option` field that must be present, as `null` when it is `None`.
fn required<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> std::result::Result<Option<T>, D::Error> {
    Option::deserialize(d)
}

impl Manifest {
    pub fn role_key(&self, role: Role) -> PublicKey {
        match role {
            Role::Owner => self.owner_pub,
            Role::Sender => self.roles.sender,
            Role::Runner => self.roles.runner,
            Role::Observer => self.roles.observer,
        }
    }

    pub fn allows(&self, t: ContentType) -> bool {
        self.allowed_types.contains(&t)
    }

    pub fn is_expired(&self, now_ms: u64) -> bool {
        self.expires_at_ms.is_some_and(|e| now_ms >= e)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        canonical_json(self)
    }

    /// Structural checks shared by creation and verification.
    pub fn validate(&self) -> Result<()> {
        if self.v != PROTOCOL_VERSION {
            return Err(Error::invalid("manifest", format!("unsupported version {}", self.v)));
        }
        if self.session_id != derive_session_id(&self.owner_pub) {
            return Err(Error::invalid("manifest", "session_id does not match owner_pub"));
        }
        if let Some(expires) = self.expires_at_ms {
            if expires > MAX_SAFE_INTEGER {
                return Err(Error::invalid("manifest", "timestamp out of range"));
            }
            if expires <= self.created_at_ms {
                return Err(Error::invalid("manifest", "expires_at_ms must be after created_at_ms"));
            }
            if expires - self.created_at_ms > MAX_TTL_MS {
                return Err(Error::invalid(
                    "manifest",
                    "ttl exceeds 30 days; leave it out for a session that never expires",
                ));
            }
        }
        if self.allowed_types.is_empty() {
            return Err(Error::invalid("manifest", "allowed_types is empty"));
        }
        let mut seen = self.allowed_types.clone();
        seen.sort_by_key(|t| t.as_str());
        seen.dedup();
        if seen.len() != self.allowed_types.len() {
            return Err(Error::invalid("manifest", "allowed_types has duplicates"));
        }
        if self.max_item_bytes == 0 || self.max_item_bytes > MAX_ITEM_BYTES_CEILING {
            return Err(Error::invalid("manifest", "max_item_bytes out of range"));
        }
        let keys = [self.owner_pub, self.roles.sender, self.roles.runner, self.roles.observer];
        for (i, a) in keys.iter().enumerate() {
            if keys[i + 1..].contains(a) {
                return Err(Error::invalid("manifest", "role keys must be distinct"));
            }
        }
        match (&self.mode, &self.job_limits) {
            (Mode::Relay, None) => {}
            (Mode::Relay, Some(_)) => {
                return Err(Error::invalid("manifest", "job_limits must be null in relay mode"))
            }
            (Mode::Execute, None) => {
                return Err(Error::invalid("manifest", "execute mode requires job_limits"))
            }
            (Mode::Execute, Some(l)) => {
                if !self.allows(ContentType::Py) {
                    return Err(Error::invalid("manifest", "execute mode requires py in allowed_types"));
                }
                validate_job_limits(l)?;
            }
        }
        Ok(())
    }
}

fn validate_job_limits(l: &JobLimits) -> Result<()> {
    let rt_ok = l
        .runtime
        .strip_prefix("python3.")
        .is_some_and(|minor| !minor.is_empty() && minor.chars().all(|c| c.is_ascii_digit()));
    if !rt_ok {
        return Err(Error::invalid("job_limits", format!("runtime {:?}", l.runtime)));
    }
    if l.timeout_s == 0 || l.timeout_s > MAX_JOB_TIMEOUT_S {
        return Err(Error::invalid("job_limits", format!("timeout_s must be 1..={MAX_JOB_TIMEOUT_S}")));
    }
    if l.memory_mb < 32 || l.memory_mb > 65536 {
        return Err(Error::invalid("job_limits", "memory_mb must be 32..=65536"));
    }
    for p in &l.packages {
        if crate::policy::normalize_package(p)? != *p {
            return Err(Error::invalid("job_limits", format!("package {p:?} is not normalized")));
        }
    }
    Ok(())
}

/// A manifest plus the owner's signature over its canonical bytes.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedManifest {
    pub manifest: Manifest,
    pub sig: Sig,
}

impl SignedManifest {
    pub fn verify(&self) -> Result<()> {
        self.manifest.validate()?;
        self.manifest
            .owner_pub
            .verify(ctx::MANIFEST, &self.manifest.canonical_bytes()?, &self.sig)
            .map_err(|_| Error::Signature("manifest not signed by owner"))
    }

    /// Parse canonical JSON and verify.
    pub fn from_json(s: &str) -> Result<Self> {
        let m: SignedManifest = parse_canonical(s, "signed manifest")?;
        m.verify()?;
        Ok(m)
    }
}

/// `ax_` + base32 of the first 16 bytes (128 bits) of SHA-256(owner public
/// key): 26 characters. A member link pins the manifest through this id, so it
/// must be infeasible to grind another owner key onto the same id.
pub fn derive_session_id(owner_pub: &PublicKey) -> String {
    let h = sha256(&owner_pub.to_bytes());
    format!("ax_{}", base32_lower(&h[..16]))
}

pub fn is_session_id(s: &str) -> bool {
    s.len() == 29
        && s.starts_with("ax_")
        && s[3..].bytes().all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
}

/// Inputs for a new session.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct SessionParams {
    pub mode: Mode,
    pub created_at_ms: u64,
    /// `None` (`null`): the session never expires. Required, so leaving it
    /// out by mistake does not make a session that never ends.
    #[serde(deserialize_with = "required")]
    pub ttl_ms: Option<u64>,
    pub allowed_types: Vec<ContentType>,
    #[serde(default = "default_max_item_bytes")]
    pub max_item_bytes: u64,
    #[serde(default)]
    pub job_limits: Option<JobLimits>,
}

fn default_max_item_bytes() -> u64 {
    DEFAULT_MAX_ITEM_BYTES
}

/// The owner's root secret. The seed is zeroized on drop; keep this struct
/// short-lived and avoid copying the seed out of it.
pub struct SessionSecrets {
    owner_seed: [u8; 32],
}

impl SessionSecrets {
    pub fn generate() -> Self {
        Self::generate_with(&mut OsRng)
    }

    pub fn generate_with<R: CryptoRngCore + ?Sized>(rng: &mut R) -> Self {
        let mut s = [0u8; 32];
        rng.fill_bytes(&mut s);
        Self { owner_seed: s }
    }

    pub fn from_owner_seed(seed: [u8; 32]) -> Self {
        Self { owner_seed: seed }
    }

    pub fn owner_seed(&self) -> [u8; 32] {
        self.owner_seed
    }

    pub fn owner(&self) -> Keypair {
        Keypair::from_seed(&self.owner_seed)
    }

    pub fn session_id(&self) -> String {
        derive_session_id(&self.owner().public())
    }

    pub fn session_key(&self) -> [u8; 32] {
        self.derive("session-key")
    }

    pub fn role_seed(&self, role: Role) -> [u8; 32] {
        match role {
            Role::Owner => self.owner_seed,
            r => self.derive(&format!("role:{}", r.as_str())),
        }
    }

    pub fn role_keypair(&self, role: Role) -> Keypair {
        Keypair::from_seed(&self.role_seed(role))
    }

    fn derive(&self, info: &str) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(Some(b"airlox/v1"), &self.owner_seed);
        let mut out = [0u8; 32];
        hk.expand(info.as_bytes(), &mut out).expect("32 bytes is a valid hkdf length");
        out
    }

    /// Build and sign the manifest. Deterministic for fixed inputs.
    pub fn manifest(&self, p: &SessionParams) -> Result<SignedManifest> {
        let owner = self.owner();
        let manifest = Manifest {
            v: PROTOCOL_VERSION,
            session_id: self.session_id(),
            owner_pub: owner.public(),
            roles: RoleKeys {
                sender: self.role_keypair(Role::Sender).public(),
                runner: self.role_keypair(Role::Runner).public(),
                observer: self.role_keypair(Role::Observer).public(),
            },
            mode: p.mode,
            created_at_ms: p.created_at_ms,
            expires_at_ms: p
                .ttl_ms
                .map(|t| {
                    p.created_at_ms
                        .checked_add(t)
                        .ok_or_else(|| Error::invalid("session params", "ttl overflow"))
                })
                .transpose()?,
            allowed_types: p.allowed_types.clone(),
            max_item_bytes: p.max_item_bytes,
            job_limits: p.job_limits.clone(),
        };
        manifest.validate()?;
        let sig = owner.sign(ctx::MANIFEST, &manifest.canonical_bytes()?);
        Ok(SignedManifest { manifest, sig })
    }
}

impl Drop for SessionSecrets {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.owner_seed.zeroize();
    }
}

impl std::fmt::Debug for SessionSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SessionSecrets({})", self.session_id())
    }
}

/// Create a new session with fresh randomness.
pub fn create_session(p: &SessionParams) -> Result<(SessionSecrets, SignedManifest)> {
    let s = SessionSecrets::generate();
    let m = s.manifest(p)?;
    Ok((s, m))
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn params(mode: Mode) -> SessionParams {
        SessionParams {
            mode,
            created_at_ms: 1_700_000_000_000,
            ttl_ms: Some(3_600_000),
            allowed_types: vec![ContentType::Text, ContentType::Py, ContentType::Md],
            max_item_bytes: DEFAULT_MAX_ITEM_BYTES,
            job_limits: (mode == Mode::Execute).then(JobLimits::default),
        }
    }

    #[test]
    fn manifest_signs_and_verifies() {
        let (s, m) = create_session(&params(Mode::Execute)).unwrap();
        m.verify().unwrap();
        assert!(is_session_id(&m.manifest.session_id));
        assert_eq!(m.manifest.session_id, s.session_id());
        let json = String::from_utf8(canonical_json(&m).unwrap()).unwrap();
        SignedManifest::from_json(&json).unwrap();
        assert!(SignedManifest::from_json(&serde_json::to_string_pretty(&m).unwrap()).is_err());
    }

    #[test]
    fn a_session_may_never_expire() {
        let mut p = params(Mode::Relay);
        p.ttl_ms = None;
        let (_, m) = create_session(&p).unwrap();
        let json = String::from_utf8(canonical_json(&m).unwrap()).unwrap();
        assert!(json.contains("\"expires_at_ms\":null"));
        let m = SignedManifest::from_json(&json).unwrap();
        assert!(!m.manifest.is_expired(u64::MAX));
        // The field must be there: leaving it out is not "never".
        let without = json.replace("\"expires_at_ms\":null,", "");
        assert!(SignedManifest::from_json(&without).is_err());
        let params = r#"{"mode":"relay","created_at_ms":1,"allowed_types":["text"]}"#;
        assert!(serde_json::from_str::<SessionParams>(params).is_err());
        let params = r#"{"mode":"relay","created_at_ms":1,"ttl_ms":null,"allowed_types":["text"]}"#;
        assert_eq!(serde_json::from_str::<SessionParams>(params).unwrap().ttl_ms, None);
        // A finite lifetime still has its 30-day ceiling.
        p.ttl_ms = Some(MAX_TTL_MS + 1);
        assert!(create_session(&p).is_err());
    }

    #[test]
    fn tampered_manifest_fails() {
        let (_, mut m) = create_session(&params(Mode::Execute)).unwrap();
        m.manifest.job_limits.as_mut().unwrap().network = true;
        assert!(matches!(m.verify(), Err(Error::Signature(_))));
    }

    #[test]
    fn mode_and_limits_must_agree() {
        let mut p = params(Mode::Relay);
        p.job_limits = Some(JobLimits::default());
        assert!(SessionSecrets::generate().manifest(&p).is_err());
        let mut p = params(Mode::Execute);
        p.allowed_types = vec![ContentType::Text];
        assert!(SessionSecrets::generate().manifest(&p).is_err());
    }

    #[test]
    fn derivation_is_deterministic_and_distinct() {
        let s = SessionSecrets::from_owner_seed([9u8; 32]);
        let t = SessionSecrets::from_owner_seed([9u8; 32]);
        assert_eq!(s.session_key(), t.session_key());
        assert_ne!(s.role_seed(Role::Sender), s.role_seed(Role::Runner));
        assert_ne!(s.session_key(), s.role_seed(Role::Observer));
    }
}
