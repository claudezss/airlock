use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

/// An HTTP error with a stable machine-readable code.
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        ApiError { status, code, message: message.into() }
    }
    pub fn bad_request(code: &'static str, m: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, m)
    }
    pub fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized", "missing or unknown bearer token")
    }
    pub fn forbidden(m: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", m)
    }
    pub fn not_found(m: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", m)
    }
    pub fn conflict(m: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, "conflict", m)
    }
    pub fn no_runner(m: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, "no_runner_available", m)
    }
    pub fn gone(code: &'static str, m: impl Into<String>) -> Self {
        Self::new(StatusCode::GONE, code, m)
    }
    pub fn too_large(m: impl Into<String>) -> Self {
        Self::new(StatusCode::PAYLOAD_TOO_LARGE, "too_large", m)
    }
    pub fn limit(m: impl Into<String>) -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, "limit", m)
    }
    pub fn timeout() -> Self {
        Self::new(StatusCode::REQUEST_TIMEOUT, "timeout", "request body stalled")
    }
    pub fn storage_full() -> Self {
        Self::new(StatusCode::INSUFFICIENT_STORAGE, "storage_full", "relay storage is nearly full")
    }
    pub fn internal(e: impl std::fmt::Display) -> Self {
        tracing::error!("internal error: {e}");
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", "internal error")
    }
}

impl From<airlox_core::Error> for ApiError {
    fn from(e: airlox_core::Error) -> Self {
        use airlox_core::Error as E;
        match e {
            E::Policy(m) => ApiError::forbidden(m),
            E::Signature(_) => ApiError::bad_request("signature", e.to_string()),
            E::Io(m) => ApiError::internal(m),
            other => ApiError::bad_request("invalid", other.to_string()),
        }
    }
}

impl From<std::io::Error> for ApiError {
    fn from(e: std::io::Error) -> Self {
        ApiError::internal(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({"error": self.code, "message": self.message}))).into_response()
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
