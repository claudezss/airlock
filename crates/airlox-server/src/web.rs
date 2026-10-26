//! The web UI: static files embedded from `web/` at build time (read from
//! disk in debug builds).

use axum::extract::Path;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};

#[derive(rust_embed::RustEmbed)]
#[folder = "../../web/"]
struct Assets;

const CSP: &str = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; \
    img-src 'self' blob: data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

fn serve(path: &str) -> Response {
    match Assets::get(path) {
        Some(f) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            (
                [
                    (header::CONTENT_TYPE, mime.as_ref().to_string()),
                    (header::CACHE_CONTROL, "no-cache".to_string()),
                    (header::CONTENT_SECURITY_POLICY, CSP.to_string()),
                    (header::REFERRER_POLICY, "no-referrer".to_string()),
                    (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
                ],
                f.data,
            )
                .into_response()
        }
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

pub async fn index() -> Response {
    serve("index.html")
}

pub async fn new_page() -> Response {
    serve("index.html")
}

pub async fn session_page(Path(_id): Path<String>) -> Response {
    serve("index.html")
}

pub async fn asset(Path(path): Path<String>) -> Response {
    if path.split('/').any(|p| p == ".." || p.is_empty()) {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    serve(&path)
}
