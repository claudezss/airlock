//! The web UI: static files embedded from `web/` at build time (read from
//! disk in debug builds).
//!
//! Text assets are gzipped once on first request and kept in memory; every
//! file carries an ETag from rust-embed's SHA-256, so `no-cache` costs a 304
//! instead of a download. The API is never compressed here: event streams
//! must reach clients unbuffered.

use std::borrow::Cow;
use std::collections::HashMap;
use std::io::Write;
use std::sync::{Arc, Mutex, OnceLock};

use axum::extract::Path;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use tokio::sync::OnceCell;

#[derive(rust_embed::RustEmbed)]
#[folder = "../../web/"]
struct Assets;

const CSP: &str = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; \
    img-src 'self' blob: data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/// Below this, gzip framing outweighs the saving.
const MIN_GZIP: usize = 1024;

fn compressible(mime: &str) -> bool {
    mime.starts_with("text/")
        || matches!(
            mime,
            "application/javascript" | "application/json" | "application/wasm" | "image/svg+xml"
        )
}

/// Whether the client accepts gzip: an explicit `gzip` entry decides, else
/// `*` does (RFC 9110 §12.5.3), so `gzip;q=0, *` refuses it.
fn accepts_gzip(headers: &HeaderMap) -> bool {
    let entries = headers
        .get_all(header::ACCEPT_ENCODING)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|part| {
            let mut it = part.split(';').map(str::trim);
            let name = it.next().unwrap_or("").to_ascii_lowercase();
            let q0 = it.any(|p| {
                p.split_once('=').is_some_and(|(k, q)| {
                    k.trim().eq_ignore_ascii_case("q") && q.trim().parse::<f32>().is_ok_and(|q| q == 0.0)
                })
            });
            (name, !q0)
        })
        .collect::<Vec<_>>();
    let pick =
        |want: &str| entries.iter().filter(|(n, _)| n == want).map(|(_, ok)| *ok).reduce(|a, b| a || b);
    pick("gzip").or_else(|| pick("*")).unwrap_or(false)
}

/// One gzip per (path, content hash), made once even when requests race;
/// the hash keys out stale entries when debug builds read changed files.
type Gzipped = ([u8; 32], Arc<OnceCell<Bytes>>);

async fn gzipped(path: &str, hash: [u8; 32], data: Cow<'static, [u8]>) -> Bytes {
    static CACHE: OnceLock<Mutex<HashMap<String, Gzipped>>> = OnceLock::new();
    let cell = {
        let mut cache = CACHE.get_or_init(Default::default).lock().unwrap();
        let entry = cache.entry(path.to_string()).or_insert_with(|| (hash, Arc::default()));
        if entry.0 != hash {
            *entry = (hash, Arc::default());
        }
        entry.1.clone()
    };
    cell.get_or_init(|| async move {
        // Compressing the 1.6 MB wasm at the best level takes a while: keep it off the async workers.
        tokio::task::spawn_blocking(move || {
            let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
            enc.write_all(&data).expect("gzip to memory");
            Bytes::from(enc.finish().expect("gzip to memory"))
        })
        .await
        .expect("gzip task")
    })
    .await
    .clone()
}

/// Gzip every compressible asset in the background at startup, so the first
/// visitors after a deploy do not wait for it.
pub async fn warm() {
    for path in Assets::iter() {
        if let Some(f) = Assets::get(&path) {
            let mime = mime_guess::from_path(path.as_ref()).first_or_octet_stream();
            if compressible(mime.as_ref()) && f.data.len() >= MIN_GZIP {
                gzipped(&path, f.metadata.sha256_hash(), f.data).await;
            }
        }
    }
}

fn etag_matches(headers: &HeaderMap, etag: &str) -> bool {
    headers
        .get_all(header::IF_NONE_MATCH)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|t| t.trim().trim_start_matches("W/"))
        .any(|t| t == "*" || t == etag)
}

async fn serve(path: &str, req: &HeaderMap) -> Response {
    let Some(f) = Assets::get(path) else {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    };
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    let hash = f.metadata.sha256_hash();
    let hex: String = hash[..16].iter().map(|b| format!("{b:02x}")).collect();
    let can_gzip = compressible(mime.as_ref()) && f.data.len() >= MIN_GZIP;
    let gzip = can_gzip && accepts_gzip(req);
    // Each encoding is a different representation, so a different tag.
    let etag = if gzip { format!("\"{hex}-gz\"") } else { format!("\"{hex}\"") };

    let mut h = HeaderMap::new();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    h.insert(header::ETAG, HeaderValue::from_str(&etag).expect("hex etag"));
    if can_gzip {
        h.insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));
    }
    if etag_matches(req, &etag) {
        return (StatusCode::NOT_MODIFIED, h).into_response();
    }
    h.insert(header::CONTENT_TYPE, HeaderValue::from_str(mime.as_ref()).expect("mime"));
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    if gzip {
        h.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        (h, gzipped(path, hash, f.data).await).into_response()
    } else {
        (h, f.data).into_response()
    }
}

pub async fn index(req: HeaderMap) -> Response {
    serve("index.html", &req).await
}

pub async fn new_page(req: HeaderMap) -> Response {
    serve("index.html", &req).await
}

pub async fn receive_page(req: HeaderMap) -> Response {
    serve("index.html", &req).await
}

pub async fn session_page(Path(_id): Path<String>, req: HeaderMap) -> Response {
    serve("index.html", &req).await
}

pub async fn asset(Path(path): Path<String>, req: HeaderMap) -> Response {
    if path.split('/').any(|p| p == ".." || p.is_empty()) {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    serve(&path, &req).await
}
