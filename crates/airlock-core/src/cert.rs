//! Role certificates and join requests.
//!
//! A participant generates its own keypair and uses the role key from its
//! invite to certify "this public key holds role R in session S". Anyone with
//! the signed manifest can check that chain without trusting the server.

use serde::{Deserialize, Serialize};

use crate::encoding::canonical_json;
use crate::keys::{ctx, Keypair, PublicKey, Sig};
use crate::session::{Manifest, Role};
use crate::{Error, Result, PROTOCOL_VERSION};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RoleCert {
    pub v: u32,
    pub session_id: String,
    pub role: Role,
    pub participant_pub: PublicKey,
    pub issued_at_ms: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedRoleCert {
    pub cert: RoleCert,
    pub sig: Sig,
}

/// Issue a certificate with the role key (the owner key for `Role::Owner`).
pub fn issue_cert(
    role_key: &Keypair,
    session_id: &str,
    role: Role,
    participant_pub: PublicKey,
    issued_at_ms: u64,
) -> Result<SignedRoleCert> {
    let cert = RoleCert {
        v: PROTOCOL_VERSION,
        session_id: session_id.to_string(),
        role,
        participant_pub,
        issued_at_ms,
    };
    let sig = role_key.sign(ctx::CERT, &canonical_json(&cert)?);
    Ok(SignedRoleCert { cert, sig })
}

impl SignedRoleCert {
    /// Verify against an already verified manifest.
    pub fn verify(&self, m: &Manifest) -> Result<()> {
        if self.cert.v != PROTOCOL_VERSION {
            return Err(Error::invalid("cert", "unsupported version"));
        }
        if self.cert.session_id != m.session_id {
            return Err(Error::invalid("cert", "session id does not match manifest"));
        }
        m.role_key(self.cert.role)
            .verify(ctx::CERT, &canonical_json(&self.cert)?, &self.sig)
            .map_err(|_| Error::Signature("cert not signed by role key"))
    }

    pub fn role(&self) -> Role {
        self.cert.role
    }

    pub fn participant(&self) -> PublicKey {
        self.cert.participant_pub
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ClientKind {
    Sdk,
    Cli,
    Web,
    Runner,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SandboxKind {
    Local,
    Docker,
    Kubernetes,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RunnerInfo {
    pub name: String,
    pub labels: Vec<String>,
    pub host: String,
    pub sandbox: SandboxKind,
    /// True when the sandbox cannot block network access (local on macOS/Windows).
    pub network_unblocked: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct JoinRequest {
    pub v: u32,
    pub session_id: String,
    pub cert: SignedRoleCert,
    pub display_name: String,
    pub kind: ClientKind,
    pub runner: Option<RunnerInfo>,
    pub created_at_ms: u64,
}

/// A join request signed by the participant key named in its certificate.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedJoinRequest {
    pub join: JoinRequest,
    pub sig: Sig,
}

/// Runner names and labels: `[a-z0-9][a-z0-9._-]{0,62}`.
pub fn is_runner_token(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 63
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-'))
}

fn check_display_text(what: &'static str, s: &str, max_chars: usize) -> Result<()> {
    if s.is_empty() || s.chars().count() > max_chars || s.chars().any(char::is_control) {
        return Err(Error::invalid(what, format!("must be 1..={max_chars} printable characters")));
    }
    Ok(())
}

pub fn sign_join(participant: &Keypair, join: JoinRequest) -> Result<SignedJoinRequest> {
    if join.cert.participant() != participant.public() {
        return Err(Error::invalid("join", "certificate is for a different key"));
    }
    let sig = participant.sign(ctx::JOIN, &canonical_json(&join)?);
    Ok(SignedJoinRequest { join, sig })
}

impl SignedJoinRequest {
    pub fn verify(&self, m: &Manifest) -> Result<()> {
        let j = &self.join;
        if j.v != PROTOCOL_VERSION {
            return Err(Error::invalid("join", "unsupported version"));
        }
        if j.session_id != m.session_id {
            return Err(Error::invalid("join", "session id does not match manifest"));
        }
        j.cert.verify(m)?;
        j.cert
            .participant()
            .verify(ctx::JOIN, &canonical_json(j)?, &self.sig)
            .map_err(|_| Error::Signature("join not signed by participant"))?;
        check_display_text("display_name", &j.display_name, 64)?;
        let is_runner_role = j.cert.role() == Role::Runner;
        match (&j.kind, &j.runner, is_runner_role) {
            (ClientKind::Runner, Some(r), true) => {
                if !is_runner_token(&r.name) {
                    return Err(Error::invalid("runner name", r.name.clone()));
                }
                if r.labels.len() > 16 || !r.labels.iter().all(|l| is_runner_token(l)) {
                    return Err(Error::invalid("runner labels", "up to 16 labels of [a-z0-9._-]"));
                }
                check_display_text("runner host", &r.host, 128)?;
            }
            (ClientKind::Runner, _, _) | (_, Some(_), _) | (_, _, true) => {
                return Err(Error::invalid(
                    "join",
                    "runner role, runner kind and runner info must appear together",
                ));
            }
            _ => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{ContentType, JobLimits, Mode, SessionParams, SessionSecrets};

    fn setup() -> (SessionSecrets, Manifest) {
        let s = SessionSecrets::from_owner_seed([5u8; 32]);
        let m = s
            .manifest(&SessionParams {
                mode: Mode::Execute,
                created_at_ms: 1,
                ttl_ms: 1000,
                allowed_types: vec![ContentType::Py],
                max_item_bytes: 1024,
                job_limits: Some(JobLimits::default()),
            })
            .unwrap()
            .manifest;
        (s, m)
    }

    #[test]
    fn cert_chain() {
        let (s, m) = setup();
        let p = Keypair::from_seed(&[6u8; 32]);
        let c =
            issue_cert(&s.role_keypair(Role::Sender), &m.session_id, Role::Sender, p.public(), 2).unwrap();
        c.verify(&m).unwrap();
        // A sender key cannot mint a runner certificate.
        let forged =
            issue_cert(&s.role_keypair(Role::Sender), &m.session_id, Role::Runner, p.public(), 2).unwrap();
        assert!(forged.verify(&m).is_err());
    }

    #[test]
    fn runner_join() {
        let (s, m) = setup();
        let p = Keypair::from_seed(&[8u8; 32]);
        let cert =
            issue_cert(&s.role_keypair(Role::Runner), &m.session_id, Role::Runner, p.public(), 2).unwrap();
        let join = JoinRequest {
            v: 1,
            session_id: m.session_id.clone(),
            cert,
            display_name: "runner-01".into(),
            kind: ClientKind::Runner,
            runner: Some(RunnerInfo {
                name: "runner-01".into(),
                labels: vec!["cpu".into(), "py3.12".into()],
                host: "yan-mbp".into(),
                sandbox: SandboxKind::Docker,
                network_unblocked: false,
            }),
            created_at_ms: 3,
        };
        let signed = sign_join(&p, join.clone()).unwrap();
        signed.verify(&m).unwrap();
        let mut bad = signed.clone();
        bad.join.runner.as_mut().unwrap().labels.push("gpu".into());
        assert!(bad.verify(&m).is_err());
        let mut no_info = join;
        no_info.runner = None;
        assert!(sign_join(&p, no_info).unwrap().verify(&m).is_err());
    }
}
