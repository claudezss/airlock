//! Python bindings: a one-to-one wrapper over `airlock_core::api`.
//!
//! Structured values are JSON strings; secrets and blobs are `bytes`.
//! Errors raise `AirlockError` or one of its subclasses.

use ::airlock_core::{api, Error};
use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

create_exception!(airlock_core, AirlockError, PyException, "Any airlock-core failure.");
create_exception!(airlock_core, SignatureError, AirlockError, "A signature did not verify.");
create_exception!(
    airlock_core,
    DecryptError,
    AirlockError,
    "Decryption failed (wrong key or tampered data)."
);
create_exception!(airlock_core, PolicyError, AirlockError, "The session policy forbids this.");
create_exception!(airlock_core, ValidationError, AirlockError, "Malformed or unsafe input.");

fn err(e: Error) -> PyErr {
    let msg = e.to_string();
    match e {
        Error::Signature(_) => SignatureError::new_err(msg),
        Error::Decrypt => DecryptError::new_err(msg),
        Error::Policy(_) => PolicyError::new_err(msg),
        Error::Zip(_) | Error::Image(_) | Error::Invalid { .. } | Error::Encoding(_) | Error::Json(_) => {
            ValidationError::new_err(msg)
        }
        Error::Io(_) => AirlockError::new_err(msg),
    }
}

fn b<'py>(py: Python<'py>, v: &[u8]) -> Bound<'py, PyBytes> {
    PyBytes::new(py, v)
}

#[pyfunction]
fn generate_seed(py: Python<'_>) -> Bound<'_, PyBytes> {
    b(py, &api::generate_seed())
}

/// Returns (owner_seed: bytes, signed_manifest_json: str).
#[pyfunction]
#[pyo3(signature = (params_json, owner_seed=None))]
fn create_session<'py>(
    py: Python<'py>,
    params_json: &str,
    owner_seed: Option<&[u8]>,
) -> PyResult<(Bound<'py, PyBytes>, String)> {
    let (seed, m) = api::create_session(params_json, owner_seed).map_err(err)?;
    Ok((b(py, &seed), m))
}

#[pyfunction]
fn verify_manifest(signed_manifest_json: &str) -> PyResult<String> {
    api::verify_manifest(signed_manifest_json).map_err(err)
}

#[pyfunction]
fn owner_invite(base_url: &str, owner_seed: &[u8]) -> PyResult<String> {
    api::owner_invite(base_url, owner_seed).map_err(err)
}

#[pyfunction]
fn member_invite(base_url: &str, owner_seed: &[u8], role: &str) -> PyResult<String> {
    api::member_invite(base_url, owner_seed, role).map_err(err)
}

/// Returns (info_json: str, session_key: bytes, role_seed: bytes).
#[pyfunction]
fn parse_invite<'py>(
    py: Python<'py>,
    url: &str,
) -> PyResult<(String, Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let (info, k, rk) = api::parse_invite(url).map_err(err)?;
    let info = serde_json_string(&info)?;
    Ok((info, b(py, &k), b(py, &rk)))
}

fn serde_json_string<T: serde::Serialize>(v: &T) -> PyResult<String> {
    ::airlock_core::encoding::canonical_json(v).map(|b| String::from_utf8(b).expect("utf-8")).map_err(err)
}

#[pyfunction]
fn check_invite(url: &str, signed_manifest_json: &str) -> PyResult<()> {
    api::check_invite(url, signed_manifest_json).map_err(err)
}

#[pyfunction]
fn public_key(seed: &[u8]) -> PyResult<String> {
    api::public_key(seed).map_err(err)
}

#[pyfunction]
fn fingerprint(public_key_b64: &str) -> PyResult<String> {
    api::fingerprint(public_key_b64).map_err(err)
}

#[pyfunction]
fn issue_cert(
    role_seed: &[u8],
    session_id: &str,
    role: &str,
    participant_pub: &str,
    issued_at_ms: u64,
) -> PyResult<String> {
    api::issue_cert(role_seed, session_id, role, participant_pub, issued_at_ms).map_err(err)
}

/// Returns the certified role.
#[pyfunction]
fn verify_cert(cert_json: &str, signed_manifest_json: &str) -> PyResult<String> {
    api::verify_cert(cert_json, signed_manifest_json).map_err(err)
}

#[pyfunction]
fn sign_join(participant_seed: &[u8], join_json: &str) -> PyResult<String> {
    api::sign_join(participant_seed, join_json).map_err(err)
}

#[pyfunction]
fn verify_join(signed_join_json: &str, signed_manifest_json: &str) -> PyResult<()> {
    api::verify_join(signed_join_json, signed_manifest_json).map_err(err)
}

/// The role certificate inside a signed join request, as canonical JSON.
#[pyfunction]
fn join_cert(signed_join_json: &str) -> PyResult<String> {
    api::join_cert(signed_join_json).map_err(err)
}

#[pyfunction]
fn new_item_id() -> String {
    api::new_item_id()
}

/// Returns (envelope_json: str, blob: bytes).
#[pyfunction]
fn seal_item<'py>(
    py: Python<'py>,
    session_key: &[u8],
    author_seed: &[u8],
    new_item_json: &str,
    payload: &[u8],
) -> PyResult<(String, Bound<'py, PyBytes>)> {
    let (env, blob) =
        py.allow_threads(|| api::seal_item(session_key, author_seed, new_item_json, payload)).map_err(err)?;
    Ok((env, b(py, &blob)))
}

#[pyfunction]
fn verify_item(py: Python<'_>, envelope_json: &str, blob: &[u8]) -> PyResult<()> {
    py.allow_threads(|| api::verify_item(envelope_json, blob)).map_err(err)
}

#[pyfunction]
fn open_item<'py>(
    py: Python<'py>,
    session_key: &[u8],
    envelope_json: &str,
    blob: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let pt = py.allow_threads(|| api::open_item(session_key, envelope_json, blob)).map_err(err)?;
    Ok(b(py, &pt))
}

#[pyfunction]
#[pyo3(signature = (meta_json, body=b"".as_slice()))]
fn encode_payload<'py>(py: Python<'py>, meta_json: &str, body: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    Ok(b(py, &api::encode_payload(meta_json, body).map_err(err)?))
}

/// Returns (meta_json: str, body: bytes).
#[pyfunction]
fn decode_payload<'py>(py: Python<'py>, payload: &[u8]) -> PyResult<(String, Bound<'py, PyBytes>)> {
    let (meta, body) = api::decode_payload(payload).map_err(err)?;
    Ok((meta, b(py, &body)))
}

/// Verify the author's certificate, bind it to the item, verify the item
/// signature and apply header policy. Returns the author's role.
#[pyfunction]
fn check_header(
    py: Python<'_>,
    signed_manifest_json: &str,
    author_cert_json: &str,
    envelope_json: &str,
    blob: &[u8],
) -> PyResult<String> {
    py.allow_threads(|| api::check_header(signed_manifest_json, author_cert_json, envelope_json, blob))
        .map_err(err)
}

/// check_header, then decrypt, decode and apply payload policy.
/// Returns (author_role: str, meta_json: str, body: bytes).
#[pyfunction]
fn open_checked<'py>(
    py: Python<'py>,
    signed_manifest_json: &str,
    author_cert_json: &str,
    session_key: &[u8],
    envelope_json: &str,
    blob: &[u8],
) -> PyResult<(String, String, Bound<'py, PyBytes>)> {
    let (role, meta, body) = py
        .allow_threads(|| {
            api::open_checked(signed_manifest_json, author_cert_json, session_key, envelope_json, blob)
        })
        .map_err(err)?;
    Ok((role, meta, b(py, &body)))
}

/// The {id, blob_sha256} reference other items use to point at this one.
#[pyfunction]
fn item_ref(py: Python<'_>, envelope_json: &str, blob: &[u8]) -> PyResult<String> {
    py.allow_threads(|| api::item_ref(envelope_json, blob)).map_err(err)
}

/// Bind a result to its job: same job reference, for a job aimed at one
/// runner a result from that runner, and when approved_runners_json (a JSON
/// list of approved runner keys) is given, an author on that list.
#[pyfunction]
#[pyo3(signature = (job_ref_json, job_meta_json, result_author, result_meta_json, approved_runners_json=None))]
fn check_result_for_job(
    job_ref_json: &str,
    job_meta_json: &str,
    result_author: &str,
    result_meta_json: &str,
    approved_runners_json: Option<&str>,
) -> PyResult<()> {
    api::check_result_for_job(
        job_ref_json,
        job_meta_json,
        result_author,
        result_meta_json,
        approved_runners_json,
    )
    .map_err(err)
}

/// Returns a JSON array of {path, size, compressed_size, is_dir}.
#[pyfunction]
fn inspect_zip(py: Python<'_>, data: &[u8]) -> PyResult<String> {
    py.allow_threads(|| api::inspect_zip(data)).map_err(err)
}

#[pyfunction]
fn extract_zip(py: Python<'_>, data: &[u8], dest: &str) -> PyResult<String> {
    py.allow_threads(|| api::extract_zip(data, dest)).map_err(err)
}

/// Returns (mime: str, sanitized: bytes).
#[pyfunction]
fn sanitize_image<'py>(py: Python<'py>, data: &[u8]) -> PyResult<(String, Bound<'py, PyBytes>)> {
    let (mime, out) = py.allow_threads(|| api::sanitize_image(data)).map_err(err)?;
    Ok((mime, b(py, &out)))
}

#[pyfunction]
fn shim_source() -> &'static str {
    api::shim_source()
}

#[pymodule]
fn airlock_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();
    m.add("PROTOCOL_VERSION", ::airlock_core::PROTOCOL_VERSION)?;
    m.add("AirlockError", py.get_type::<AirlockError>())?;
    m.add("SignatureError", py.get_type::<SignatureError>())?;
    m.add("DecryptError", py.get_type::<DecryptError>())?;
    m.add("PolicyError", py.get_type::<PolicyError>())?;
    m.add("ValidationError", py.get_type::<ValidationError>())?;
    m.add_function(wrap_pyfunction!(generate_seed, m)?)?;
    m.add_function(wrap_pyfunction!(create_session, m)?)?;
    m.add_function(wrap_pyfunction!(verify_manifest, m)?)?;
    m.add_function(wrap_pyfunction!(owner_invite, m)?)?;
    m.add_function(wrap_pyfunction!(member_invite, m)?)?;
    m.add_function(wrap_pyfunction!(parse_invite, m)?)?;
    m.add_function(wrap_pyfunction!(check_invite, m)?)?;
    m.add_function(wrap_pyfunction!(public_key, m)?)?;
    m.add_function(wrap_pyfunction!(fingerprint, m)?)?;
    m.add_function(wrap_pyfunction!(issue_cert, m)?)?;
    m.add_function(wrap_pyfunction!(verify_cert, m)?)?;
    m.add_function(wrap_pyfunction!(sign_join, m)?)?;
    m.add_function(wrap_pyfunction!(verify_join, m)?)?;
    m.add_function(wrap_pyfunction!(join_cert, m)?)?;
    m.add_function(wrap_pyfunction!(new_item_id, m)?)?;
    m.add_function(wrap_pyfunction!(seal_item, m)?)?;
    m.add_function(wrap_pyfunction!(verify_item, m)?)?;
    m.add_function(wrap_pyfunction!(open_item, m)?)?;
    m.add_function(wrap_pyfunction!(encode_payload, m)?)?;
    m.add_function(wrap_pyfunction!(decode_payload, m)?)?;
    m.add_function(wrap_pyfunction!(check_header, m)?)?;
    m.add_function(wrap_pyfunction!(open_checked, m)?)?;
    m.add_function(wrap_pyfunction!(item_ref, m)?)?;
    m.add_function(wrap_pyfunction!(check_result_for_job, m)?)?;
    m.add_function(wrap_pyfunction!(inspect_zip, m)?)?;
    m.add_function(wrap_pyfunction!(extract_zip, m)?)?;
    m.add_function(wrap_pyfunction!(sanitize_image, m)?)?;
    m.add_function(wrap_pyfunction!(shim_source, m)?)?;
    Ok(())
}
