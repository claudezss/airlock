//! HTTP client for the relay (protocol §12 and §13).

use std::time::Duration;

use anyhow::{Context, Result};
use serde_json::Value;

/// A refusal from the relay: `{"error", "message"}` with its status.
#[derive(Debug)]
pub struct RelayError {
    pub status: u16,
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "relay answered {} {}: {}", self.status, self.code, self.message)
    }
}

impl std::error::Error for RelayError {}

/// The relay status behind an error, if it was a relay refusal.
pub fn status_of(e: &anyhow::Error) -> Option<u16> {
    e.downcast_ref::<RelayError>().map(|r| r.status)
}

/// Worth retrying: network trouble, rate limits and server errors.
pub fn is_transient(e: &anyhow::Error) -> bool {
    match status_of(e) {
        Some(s) => s == 429 || s >= 500,
        None => e.downcast_ref::<reqwest::Error>().is_some(),
    }
}

async fn check(r: reqwest::Response) -> Result<reqwest::Response> {
    if r.status().is_success() {
        return Ok(r);
    }
    let status = r.status().as_u16();
    let body: Value = r.json().await.unwrap_or(Value::Null);
    Err(RelayError {
        status,
        code: body["error"].as_str().unwrap_or("error").to_string(),
        message: body["message"].as_str().unwrap_or("").to_string(),
    }
    .into())
}

pub fn http() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .user_agent(concat!("airlock/", env!("CARGO_PKG_VERSION")))
        .build()?)
}

/// `GET /v1/sessions/{id}`: the signed manifest.
pub async fn get_manifest(http: &reqwest::Client, base: &str, sid: &str) -> Result<String> {
    let r = check(http.get(format!("{base}/v1/sessions/{sid}")).send().await?).await?;
    let v: Value = r.json().await?;
    v["signed_manifest"].as_str().map(str::to_string).context("relay sent no manifest")
}

/// `POST /v1/sessions/{id}/participants`: returns the bearer token.
pub async fn join(http: &reqwest::Client, base: &str, sid: &str, signed_join: String) -> Result<String> {
    let r =
        check(http.post(format!("{base}/v1/sessions/{sid}/participants")).body(signed_join).send().await?)
            .await?;
    let v: Value = r.json().await?;
    v["token"].as_str().map(str::to_string).context("relay sent no token")
}

/// One participant's authenticated view of a session on the relay.
#[derive(Clone)]
pub struct Relay {
    pub http: reqwest::Client,
    pub base: String,
    pub sid: String,
    token: String,
}

impl Relay {
    pub fn new(http: reqwest::Client, base: &str, sid: &str, token: &str) -> Self {
        Relay { http, base: base.to_string(), sid: sid.to_string(), token: token.to_string() }
    }

    fn url(&self, path: &str) -> String {
        format!("{}/v1/sessions/{}{path}", self.base, self.sid)
    }

    fn get(&self, path: &str) -> reqwest::RequestBuilder {
        self.http.get(self.url(path)).bearer_auth(&self.token).timeout(Duration::from_secs(60))
    }

    fn post(&self, path: &str) -> reqwest::RequestBuilder {
        self.http.post(self.url(path)).bearer_auth(&self.token).timeout(Duration::from_secs(300))
    }

    /// Public events with `seq > after`.
    pub async fn events(&self, after: Option<u64>) -> Result<Vec<Value>> {
        let q = after.map(|a| format!("?after={a}")).unwrap_or_default();
        let v: Value = check(self.get(&format!("/events{q}")).send().await?).await?.json().await?;
        Ok(v["events"].as_array().cloned().unwrap_or_default())
    }

    /// The ciphertext blob, or `None` once it has left the relay.
    pub async fn blob(&self, item: &str) -> Result<Option<Vec<u8>>> {
        match check(self.get(&format!("/items/{item}/blob")).send().await?).await {
            Ok(r) => Ok(Some(r.bytes().await?.to_vec())),
            Err(e) if matches!(status_of(&e), Some(404 | 410)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub async fn ack(&self, item: &str) -> Result<()> {
        match check(self.post(&format!("/items/{item}/ack")).send().await?).await {
            Ok(_) => Ok(()),
            Err(e) if matches!(status_of(&e), Some(404 | 410)) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// `POST /items` with the upload frame `u32_be(len) || envelope || blob`.
    pub async fn post_item(&self, envelope_json: &str, blob: &[u8]) -> Result<()> {
        let mut frame = Vec::with_capacity(4 + envelope_json.len() + blob.len());
        frame.extend_from_slice(&(envelope_json.len() as u32).to_be_bytes());
        frame.extend_from_slice(envelope_json.as_bytes());
        frame.extend_from_slice(blob);
        check(self.post("/items").body(frame).send().await?).await?;
        Ok(())
    }

    /// Claim an assigned job. `false` when it is no longer ours.
    pub async fn claim(&self, job: &str) -> Result<bool> {
        match check(self.post(&format!("/jobs/{job}/claim")).send().await?).await {
            Ok(_) => Ok(true),
            Err(e) if matches!(status_of(&e), Some(404 | 409)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    pub async fn heartbeat(&self, job: Option<&str>) -> Result<Value> {
        let body = serde_json::json!({ "job": job }).to_string();
        let r = self.post("/runners/me/heartbeat").timeout(Duration::from_secs(20)).body(body).send().await?;
        Ok(check(r).await?.json().await?)
    }

    /// Open the runner's assignment stream (SSE).
    pub async fn runner_stream(&self) -> Result<reqwest::Response> {
        let r = self.http.get(self.url("/runners/me/stream")).bearer_auth(&self.token).send().await?;
        check(r).await
    }
}
