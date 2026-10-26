//! WebAssembly bindings: a one-to-one wrapper over `airlock_core::api`.
//!
//! Names are camelCase. Structured values are JSON strings, secrets and
//! blobs are `Uint8Array`. Multi-value results are plain objects. Errors
//! throw a JS `Error` whose message starts with the error class, e.g.
//! `"SignatureError: …"`.

use airlock_core::{api, Error};
use js_sys::{Object, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;

fn err(e: Error) -> JsError {
    let class = match e {
        Error::Signature(_) => "SignatureError",
        Error::Decrypt => "DecryptError",
        Error::Policy(_) => "PolicyError",
        Error::Io(_) => "AirlockError",
        _ => "ValidationError",
    };
    JsError::new(&format!("{class}: {e}"))
}

type R<T> = Result<T, JsError>;

fn obj(fields: &[(&str, JsValue)]) -> JsValue {
    let o = Object::new();
    for (k, v) in fields {
        Reflect::set(&o, &JsValue::from_str(k), v).expect("set on a fresh object");
    }
    o.into()
}

fn bytes(v: &[u8]) -> JsValue {
    Uint8Array::from(v).into()
}

#[wasm_bindgen(js_name = protocolVersion)]
pub fn protocol_version() -> u32 {
    airlock_core::PROTOCOL_VERSION
}

#[wasm_bindgen(js_name = generateSeed)]
pub fn generate_seed() -> Vec<u8> {
    api::generate_seed().to_vec()
}

/// Returns `{ ownerSeed: Uint8Array, signedManifest: string }`.
#[wasm_bindgen(js_name = createSession)]
pub fn create_session(params_json: &str, owner_seed: Option<Vec<u8>>) -> R<JsValue> {
    let (seed, m) = api::create_session(params_json, owner_seed.as_deref()).map_err(err)?;
    Ok(obj(&[("ownerSeed", bytes(&seed)), ("signedManifest", m.into())]))
}

#[wasm_bindgen(js_name = verifyManifest)]
pub fn verify_manifest(signed_manifest_json: &str) -> R<String> {
    api::verify_manifest(signed_manifest_json).map_err(err)
}

#[wasm_bindgen(js_name = ownerInvite)]
pub fn owner_invite(base_url: &str, owner_seed: &[u8]) -> R<String> {
    api::owner_invite(base_url, owner_seed).map_err(err)
}

#[wasm_bindgen(js_name = memberInvite)]
pub fn member_invite(base_url: &str, owner_seed: &[u8], role: &str) -> R<String> {
    api::member_invite(base_url, owner_seed, role).map_err(err)
}

/// Returns `{ baseUrl, sessionId, role, sessionKey: Uint8Array, roleSeed: Uint8Array }`.
#[wasm_bindgen(js_name = parseInvite)]
pub fn parse_invite(url: &str) -> R<JsValue> {
    let (info, k, rk) = api::parse_invite(url).map_err(err)?;
    Ok(obj(&[
        ("baseUrl", info.base_url.into()),
        ("sessionId", info.session_id.into()),
        ("role", info.role.as_str().into()),
        ("sessionKey", bytes(&k)),
        ("roleSeed", bytes(&rk)),
    ]))
}

#[wasm_bindgen(js_name = checkInvite)]
pub fn check_invite(url: &str, signed_manifest_json: &str) -> R<()> {
    api::check_invite(url, signed_manifest_json).map_err(err)
}

#[wasm_bindgen(js_name = publicKey)]
pub fn public_key(seed: &[u8]) -> R<String> {
    api::public_key(seed).map_err(err)
}

#[wasm_bindgen]
pub fn fingerprint(public_key_b64: &str) -> R<String> {
    api::fingerprint(public_key_b64).map_err(err)
}

#[wasm_bindgen(js_name = issueCert)]
pub fn issue_cert(
    role_seed: &[u8],
    session_id: &str,
    role: &str,
    participant_pub: &str,
    issued_at_ms: f64,
) -> R<String> {
    api::issue_cert(role_seed, session_id, role, participant_pub, ms(issued_at_ms)?).map_err(err)
}

fn ms(v: f64) -> R<u64> {
    if v.is_finite() && v >= 0.0 && v.fract() == 0.0 && v <= 9_007_199_254_740_991.0 {
        Ok(v as u64)
    } else {
        Err(JsError::new("ValidationError: timestamp must be a non-negative integer"))
    }
}

#[wasm_bindgen(js_name = verifyCert)]
pub fn verify_cert(cert_json: &str, signed_manifest_json: &str) -> R<String> {
    api::verify_cert(cert_json, signed_manifest_json).map_err(err)
}

#[wasm_bindgen(js_name = signJoin)]
pub fn sign_join(participant_seed: &[u8], join_json: &str) -> R<String> {
    api::sign_join(participant_seed, join_json).map_err(err)
}

#[wasm_bindgen(js_name = verifyJoin)]
pub fn verify_join(signed_join_json: &str, signed_manifest_json: &str) -> R<()> {
    api::verify_join(signed_join_json, signed_manifest_json).map_err(err)
}

#[wasm_bindgen(js_name = newItemId)]
pub fn new_item_id() -> String {
    api::new_item_id()
}

/// Returns `{ envelope: string, blob: Uint8Array }`.
#[wasm_bindgen(js_name = sealItem)]
pub fn seal_item(session_key: &[u8], author_seed: &[u8], new_item_json: &str, payload: &[u8]) -> R<JsValue> {
    let (env, blob) = api::seal_item(session_key, author_seed, new_item_json, payload).map_err(err)?;
    Ok(obj(&[("envelope", env.into()), ("blob", bytes(&blob))]))
}

#[wasm_bindgen(js_name = verifyItem)]
pub fn verify_item(envelope_json: &str, blob: &[u8]) -> R<()> {
    api::verify_item(envelope_json, blob).map_err(err)
}

#[wasm_bindgen(js_name = openItem)]
pub fn open_item(session_key: &[u8], envelope_json: &str, blob: &[u8]) -> R<Vec<u8>> {
    api::open_item(session_key, envelope_json, blob).map_err(err)
}

#[wasm_bindgen(js_name = encodePayload)]
pub fn encode_payload(meta_json: &str, body: &[u8]) -> R<Vec<u8>> {
    api::encode_payload(meta_json, body).map_err(err)
}

/// Returns `{ meta: string, body: Uint8Array }`.
#[wasm_bindgen(js_name = decodePayload)]
pub fn decode_payload(payload: &[u8]) -> R<JsValue> {
    let (meta, body) = api::decode_payload(payload).map_err(err)?;
    Ok(obj(&[("meta", meta.into()), ("body", bytes(&body))]))
}

#[wasm_bindgen(js_name = checkHeader)]
pub fn check_header(signed_manifest_json: &str, author_role: &str, envelope_json: &str) -> R<()> {
    api::check_header(signed_manifest_json, author_role, envelope_json).map_err(err)
}

#[wasm_bindgen(js_name = checkPayload)]
pub fn check_payload(
    signed_manifest_json: &str,
    author_role: &str,
    envelope_json: &str,
    payload: &[u8],
) -> R<()> {
    api::check_payload(signed_manifest_json, author_role, envelope_json, payload).map_err(err)
}

#[wasm_bindgen(js_name = inspectZip)]
pub fn inspect_zip(data: &[u8]) -> R<String> {
    api::inspect_zip(data).map_err(err)
}

/// Returns `{ mime: string, data: Uint8Array }`.
#[wasm_bindgen(js_name = sanitizeImage)]
pub fn sanitize_image(data: &[u8]) -> R<JsValue> {
    let (mime, out) = api::sanitize_image(data).map_err(err)?;
    Ok(obj(&[("mime", mime.into()), ("data", bytes(&out))]))
}
