//! A flat, JSON-in/JSON-out facade over the core.
//!
//! The Python and wasm bindings wrap these functions one-to-one, so both
//! bindings expose exactly the same surface and the same error messages.
//! Structured values cross the boundary as JSON strings; secrets and blobs
//! cross as raw bytes. Signed structures received from elsewhere (manifests,
//! certificates, joins, item envelopes) must be canonical JSON, exactly as
//! produced by these functions; anything else is rejected.

use serde::{Deserialize, Serialize};

use crate::cert::{issue_cert as issue, sign_join as sign, JoinRequest, SignedJoinRequest, SignedRoleCert};
use crate::encoding::{canonical_json, parse_canonical};
use crate::invite::Invite;
use crate::item::{seal, ItemEnvelope, ItemRef, NewItem, SealedItem};
use crate::keys::{Keypair, PublicKey};
use crate::payload::{Meta, Payload};
use crate::session::{Role, SessionParams, SessionSecrets, SignedManifest};
use crate::validate::zip::{inspect_zip as inspect, ZipLimits};
use crate::{Error, Result};

fn seed32(b: &[u8], what: &'static str) -> Result<[u8; 32]> {
    b.try_into().map_err(|_| Error::invalid(what, "must be 32 bytes"))
}

fn json<T: Serialize>(v: &T) -> Result<String> {
    Ok(String::from_utf8(canonical_json(v)?).expect("canonical json is utf-8"))
}

/// 32 random bytes from the OS. Used for owner and participant seeds.
pub fn generate_seed() -> [u8; 32] {
    use rand_core::{OsRng, RngCore};
    let mut s = [0u8; 32];
    OsRng.fill_bytes(&mut s);
    s
}

/// Returns `(owner_seed, signed_manifest_json)`.
pub fn create_session(params_json: &str, owner_seed: Option<&[u8]>) -> Result<([u8; 32], String)> {
    let params: SessionParams = serde_json::from_str(params_json)?;
    let secrets = match owner_seed {
        Some(s) => SessionSecrets::from_owner_seed(seed32(s, "owner seed")?),
        None => SessionSecrets::generate(),
    };
    let m = secrets.manifest(&params)?;
    Ok((secrets.owner_seed(), json(&m)?))
}

/// Verify a signed manifest; returns the canonical manifest JSON (without sig).
pub fn verify_manifest(signed_manifest_json: &str) -> Result<String> {
    let m = SignedManifest::from_json(signed_manifest_json)?;
    json(&m.manifest)
}

pub fn owner_invite(base_url: &str, owner_seed: &[u8]) -> Result<String> {
    let s = SessionSecrets::from_owner_seed(seed32(owner_seed, "owner seed")?);
    Ok(Invite::owner(base_url, &s)?.to_url())
}

pub fn member_invite(base_url: &str, owner_seed: &[u8], role: &str) -> Result<String> {
    let s = SessionSecrets::from_owner_seed(seed32(owner_seed, "owner seed")?);
    Ok(Invite::member(base_url, &s, Role::parse(role)?)?.to_url())
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ParsedInvite {
    pub base_url: String,
    pub session_id: String,
    pub role: Role,
}

/// Returns `(public fields, session_key, role_seed)`. For the owner link the
/// role seed is the owner seed.
pub fn parse_invite(url: &str) -> Result<(ParsedInvite, [u8; 32], [u8; 32])> {
    let i = Invite::parse(url)?;
    let info = ParsedInvite { base_url: i.base_url.clone(), session_id: i.session_id.clone(), role: i.role };
    Ok((info, i.session_key(), i.role_keypair().seed()))
}

pub fn check_invite(url: &str, signed_manifest_json: &str) -> Result<()> {
    let m = SignedManifest::from_json(signed_manifest_json)?;
    Invite::parse(url)?.check_against(&m.manifest)
}

pub fn public_key(seed: &[u8]) -> Result<String> {
    Ok(Keypair::from_seed(&seed32(seed, "seed")?).public().to_b64())
}

pub fn fingerprint(public_key_b64: &str) -> Result<String> {
    Ok(PublicKey::from_b64(public_key_b64)?.fingerprint())
}

pub fn issue_cert(
    role_seed: &[u8],
    session_id: &str,
    role: &str,
    participant_pub_b64: &str,
    issued_at_ms: u64,
) -> Result<String> {
    let c = issue(
        &Keypair::from_seed(&seed32(role_seed, "role seed")?),
        session_id,
        Role::parse(role)?,
        PublicKey::from_b64(participant_pub_b64)?,
        issued_at_ms,
    )?;
    json(&c)
}

/// Verify a certificate; returns its role.
pub fn verify_cert(cert_json: &str, signed_manifest_json: &str) -> Result<String> {
    let m = SignedManifest::from_json(signed_manifest_json)?;
    let c: SignedRoleCert = parse_canonical(cert_json, "certificate")?;
    c.verify(&m.manifest)?;
    Ok(c.role().as_str().to_string())
}

pub fn sign_join(participant_seed: &[u8], join_json: &str) -> Result<String> {
    let j: JoinRequest = serde_json::from_str(join_json)?;
    json(&sign(&Keypair::from_seed(&seed32(participant_seed, "participant seed")?), j)?)
}

pub fn verify_join(signed_join_json: &str, signed_manifest_json: &str) -> Result<()> {
    let m = SignedManifest::from_json(signed_manifest_json)?;
    let j: SignedJoinRequest = parse_canonical(signed_join_json, "join request")?;
    j.verify(&m.manifest)
}

/// The role certificate inside a signed join request, as canonical JSON.
/// Clients use it with [`check_header`] and [`open_checked`] after
/// [`verify_join`] has accepted the join.
pub fn join_cert(signed_join_json: &str) -> Result<String> {
    let j: SignedJoinRequest = parse_canonical(signed_join_json, "join request")?;
    json(&j.join.cert)
}

pub fn new_item_id() -> String {
    crate::item::new_item_id()
}

/// Returns `(envelope_json, blob)`.
pub fn seal_item(
    session_key: &[u8],
    author_seed: &[u8],
    new_item_json: &str,
    payload: &[u8],
) -> Result<(String, Vec<u8>)> {
    let new: NewItem = serde_json::from_str(new_item_json)?;
    let s = seal(
        &seed32(session_key, "session key")?,
        &Keypair::from_seed(&seed32(author_seed, "author seed")?),
        new,
        payload,
    )?;
    Ok((json(&s.envelope)?, s.blob))
}

fn sealed(envelope_json: &str, blob: &[u8]) -> Result<SealedItem> {
    let envelope: ItemEnvelope = parse_canonical(envelope_json, "item envelope")?;
    Ok(SealedItem { envelope, blob: blob.to_vec() })
}

/// The `{id, blob_sha256}` reference other items use to point at this one.
pub fn item_ref(envelope_json: &str, blob: &[u8]) -> Result<String> {
    let s = sealed(envelope_json, blob)?;
    s.verify()?;
    json(&ItemRef::to(&s))
}

pub fn verify_item(envelope_json: &str, blob: &[u8]) -> Result<()> {
    sealed(envelope_json, blob)?.verify()
}

pub fn open_item(session_key: &[u8], envelope_json: &str, blob: &[u8]) -> Result<Vec<u8>> {
    sealed(envelope_json, blob)?.open(&seed32(session_key, "session key")?)
}

pub fn encode_payload(meta_json: &str, body: &[u8]) -> Result<Vec<u8>> {
    let meta: Meta = serde_json::from_str(meta_json)?;
    Payload { meta, body: body.to_vec() }.encode()
}

/// Returns `(meta_json, body)`.
pub fn decode_payload(bytes: &[u8]) -> Result<(String, Vec<u8>)> {
    let p = Payload::decode(bytes)?;
    Ok((json(&p.meta)?, p.body))
}

/// Server-side check: verify the author's certificate, bind it to the item's
/// author key, verify the item signature, and apply header policy. Returns
/// the author's role.
pub fn check_header(
    signed_manifest_json: &str,
    author_cert_json: &str,
    envelope_json: &str,
    blob: &[u8],
) -> Result<String> {
    let m = SignedManifest::from_json(signed_manifest_json)?;
    let cert: SignedRoleCert = parse_canonical(author_cert_json, "certificate")?;
    let s = sealed(envelope_json, blob)?;
    s.verify()?;
    let role = crate::policy::author_role(&m.manifest, &cert, s.header())?;
    crate::policy::check_header(&m.manifest, role, s.header())?;
    Ok(role.as_str().to_string())
}

/// Client-side open: everything [`check_header`] does, then decrypt, decode
/// and apply payload policy. Returns `(author_role, meta_json, body)`.
pub fn open_checked(
    signed_manifest_json: &str,
    author_cert_json: &str,
    session_key: &[u8],
    envelope_json: &str,
    blob: &[u8],
) -> Result<(String, String, Vec<u8>)> {
    let m = SignedManifest::from_json(signed_manifest_json)?;
    let cert: SignedRoleCert = parse_canonical(author_cert_json, "certificate")?;
    let s = sealed(envelope_json, blob)?;
    let role = crate::policy::author_role(&m.manifest, &cert, s.header())?;
    let pt = s.open(&seed32(session_key, "session key")?)?;
    let p = Payload::decode(&pt)?;
    crate::policy::check_payload(&m.manifest, role, s.header(), &p)?;
    Ok((role.as_str().to_string(), json(&p.meta)?, p.body))
}

/// Bind a decrypted result to the job it answers: the result must reference
/// exactly this job item, and a job aimed at one runner only accepts that
/// runner's result. `job_ref_json` comes from [`item_ref`] on the fetched job;
/// both metas come from [`open_checked`].
pub fn check_result_for_job(
    job_ref_json: &str,
    job_meta_json: &str,
    result_author_b64: &str,
    result_meta_json: &str,
) -> Result<()> {
    let job_ref: ItemRef = serde_json::from_str(job_ref_json)?;
    let (Meta::Job(job), Meta::Result(r)) =
        (serde_json::from_str(job_meta_json)?, serde_json::from_str(result_meta_json)?)
    else {
        return Err(Error::invalid("result", "expected a job meta and a result meta"));
    };
    crate::policy::check_result_matches_job(&job_ref, &job, PublicKey::from_b64(result_author_b64)?, &r)
}

/// Returns a JSON array of entries.
pub fn inspect_zip(bytes: &[u8]) -> Result<String> {
    Ok(serde_json::to_string(&inspect(bytes, &ZipLimits::default())?)?)
}

#[cfg(feature = "fs")]
pub fn extract_zip(bytes: &[u8], dest: &str) -> Result<String> {
    let e = crate::validate::zip::extract_zip(bytes, std::path::Path::new(dest), &ZipLimits::default())?;
    Ok(serde_json::to_string(&e)?)
}

#[cfg(feature = "image")]
pub fn sanitize_image(bytes: &[u8]) -> Result<(String, Vec<u8>)> {
    let (mime, out) = crate::validate::image::sanitize_image(bytes)?;
    Ok((mime.to_string(), out))
}

pub fn shim_source() -> &'static str {
    crate::shim::SHIM_PY
}
