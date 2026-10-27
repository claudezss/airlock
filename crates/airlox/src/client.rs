//! HTTP client for the relay (protocol §12 and §13).

use std::time::Duration;

use anyhow::{bail, Context, Result};
use futures_util::StreamExt;
use serde_json::Value;

/// How long a plain request may take, and how long a stream may take to
/// start answering.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Largest JSON answer read from a relay (event pages, listings).
const MAX_JSON: usize = 32 << 20;

/// Read a response body, refusing one larger than `limit` bytes: a relay
/// cannot make a client buffer without bound.
/// The largest audit trail read: a session log is capped well below this.
pub const MAX_AUDIT: usize = 32 << 20;

pub async fn read_capped(r: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    if r.content_length().is_some_and(|n| n > limit as u64) {
        bail!("the relay's answer is larger than {limit} bytes");
    }
    let mut out = Vec::new();
    let mut body = r.bytes_stream();
    while let Some(chunk) = body.next().await {
        let chunk = chunk?;
        if out.len() + chunk.len() > limit {
            bail!("the relay's answer is larger than {limit} bytes");
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

async fn read_json(r: reqwest::Response) -> Result<Value> {
    Ok(serde_json::from_slice(&read_capped(r, MAX_JSON).await?)?)
}

/// Send a request whose answer is a stream: only the wait for its headers
/// is bounded.
async fn send_stream(req: reqwest::RequestBuilder) -> Result<reqwest::Response> {
    match tokio::time::timeout(REQUEST_TIMEOUT, req.send()).await {
        Ok(r) => Ok(r?),
        Err(_) => bail!("the relay did not answer within {} s", REQUEST_TIMEOUT.as_secs()),
    }
}

/// A refusal from the relay: `{"error", "message"}` with its status.
#[derive(Debug)]
pub struct RelayError {
    pub status: u16,
    pub code: String,
    pub message: String,
}

/// Text from the relay, made safe to print or hand to a model: control and
/// invisible characters escaped, and at most 300 characters.
pub fn relay_text(s: &str) -> String {
    let mut t = crate::files::clean_line(s);
    if t.chars().count() > 300 {
        t = t.chars().take(300).collect::<String>() + "…";
    }
    t
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "relay answered {} {}: {:?}",
            self.status,
            relay_text(&self.code),
            relay_text(&self.message)
        )
    }
}

impl std::error::Error for RelayError {}

/// The relay status behind an error, if it was a relay refusal.
pub fn status_of(e: &anyhow::Error) -> Option<u16> {
    e.downcast_ref::<RelayError>().map(|r| r.status)
}

/// Worth retrying: network trouble, rate limits, server errors, a session
/// short of storage until deliveries free some, and an upload of the same
/// item still in progress. Not a session at a limit that will not lift
/// (`session_full`; older relays say so only in the message).
pub fn is_transient(e: &anyhow::Error) -> bool {
    let Some(r) = e.downcast_ref::<RelayError>() else {
        return e.downcast_ref::<reqwest::Error>().is_some();
    };
    let older_full =
        r.code == "limit" && (r.message.contains("item limit") || r.message.contains("transfer limit"));
    let older_storage = r.code == "too_large" && r.message.contains("wait for deliveries");
    match (r.status, r.code.as_str()) {
        (_, "session_full") => false,
        (409, "uploading") | (413, "storage_wait") => true,
        (413, _) => older_storage,
        (s, _) => (s == 429 && !older_full) || s >= 500,
    }
}

/// The relay already has an item with this id: a `409 duplicate`, or the
/// generic `409 conflict` older relays send for it.
pub fn is_duplicate(e: &anyhow::Error) -> bool {
    e.downcast_ref::<RelayError>().is_some_and(|r| {
        r.status == 409
            && (r.code == "duplicate" || (r.code == "conflict" && r.message.contains("already exists")))
    })
}

async fn check(r: reqwest::Response) -> Result<reqwest::Response> {
    if r.status().is_success() {
        return Ok(r);
    }
    let status = r.status().as_u16();
    let body: Value = read_capped(r, 64 << 10)
        .await
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(Value::Null);
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
        .user_agent(concat!("airlox/", env!("CARGO_PKG_VERSION")))
        .build()?)
}

/// `GET /v1/sessions/{id}`: the signed manifest.
pub async fn get_manifest(http: &reqwest::Client, base: &str, sid: &str) -> Result<String> {
    let r =
        check(http.get(format!("{base}/v1/sessions/{sid}")).timeout(REQUEST_TIMEOUT).send().await?).await?;
    let v = read_json(r).await?;
    v["signed_manifest"].as_str().map(str::to_string).context("relay sent no manifest")
}

/// `POST /v1/sessions`: register a session from its signed manifest.
pub async fn create_session(http: &reqwest::Client, base: &str, signed_manifest: String) -> Result<()> {
    let req = http.post(format!("{base}/v1/sessions")).timeout(REQUEST_TIMEOUT).body(signed_manifest);
    check(req.send().await?).await?;
    Ok(())
}

/// `POST /v1/drops/{n}/claim`: trade a one-time transfer code for the
/// invite link it carries. A right code is used up; a wrong one spends one
/// of the few tries the code has.
pub async fn receive_code(http: &reqwest::Client, relay: &str, code: &str) -> Result<String> {
    let code = airlox_core::transfer::Code::parse(code)?;
    let relay = relay.trim_end_matches('/');
    let req = http
        .post(format!("{relay}/v1/drops/{}/claim", code.nameplate))
        .timeout(REQUEST_TIMEOUT)
        .json(&serde_json::json!({"claim": code.claim()}));
    let r = match check(req.send().await?).await {
        Ok(r) => r,
        Err(e) => match status_of(&e) {
            Some(404) => {
                bail!("no code {} on {}; it may have expired", code.to_code_string(), relay_text(relay))
            }
            Some(403) => bail!("wrong code: check the two words"),
            Some(410) => {
                let why = match e.downcast_ref::<RelayError>().map(|r| r.code.as_str()) {
                    Some("used") => "was already used",
                    Some("burned") => "was cancelled after too many wrong tries",
                    Some("cancelled") => "was cancelled by the sender",
                    Some("expired") => "expired",
                    _ => "no longer works",
                };
                bail!("code {} {why}; ask for a new one", code.to_code_string())
            }
            Some(429) => bail!("too many wrong codes from this address; wait a few minutes"),
            _ => return Err(e),
        },
    };
    let v = read_json(r).await?;
    let sealed = v["box"].as_str().context("relay sent no box")?;
    // Checks it is an invite link, so nothing else reaches the terminal.
    airlox_core::api::transfer_open(&code.to_code_string(), sealed)
        .context("the code's words do not open what the relay sent")
}

/// `POST /v1/sessions/{id}/participants`: returns the bearer token.
pub async fn join(http: &reqwest::Client, base: &str, sid: &str, signed_join: String) -> Result<String> {
    let req = http.post(format!("{base}/v1/sessions/{sid}/participants")).timeout(REQUEST_TIMEOUT);
    let r = check(req.body(signed_join).send().await?).await?;
    let v = read_json(r).await?;
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
        let v = read_json(check(self.get(&format!("/events{q}")).send().await?).await?).await?;
        Ok(v["events"].as_array().cloned().unwrap_or_default())
    }

    /// The ciphertext blob, or `None` once it has left the relay. Larger
    /// than `limit` bytes is an error.
    pub async fn blob(&self, item: &str, limit: usize) -> Result<Option<Vec<u8>>> {
        match check(self.get(&format!("/items/{item}/blob")).send().await?).await {
            Ok(r) => Ok(Some(read_capped(r, limit).await?)),
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

    /// Ask holders to upload an evicted blob again. `false` when it is back
    /// on the relay already.
    pub async fn want(&self, item: &str) -> Result<bool> {
        match check(self.post(&format!("/items/{item}/want")).send().await?).await {
            Ok(_) => Ok(true),
            Err(e) if e.downcast_ref::<RelayError>().is_some_and(|r| r.code == "present") => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Upload an evicted blob someone asked for (`PUT /items/:id/blob`).
    pub async fn reseed(&self, item: &str, blob: Vec<u8>) -> Result<()> {
        let req = self.http.put(self.url(&format!("/items/{item}/blob"))).bearer_auth(&self.token);
        check(req.timeout(Duration::from_secs(300)).body(blob).send().await?).await?;
        Ok(())
    }

    /// `POST /items` with the upload frame `u32_be(len) || envelope || blob`.
    pub async fn post_item(&self, envelope_json: &str, blob: &[u8]) -> Result<()> {
        let mut frame = Vec::with_capacity(4 + envelope_json.len() + blob.len());
        frame.extend_from_slice(&(envelope_json.len() as u32).to_be_bytes());
        frame.extend_from_slice(envelope_json.as_bytes());
        frame.extend_from_slice(blob);
        // Large items on a slow link: five minutes plus a second per 32 KiB.
        let timeout = Duration::from_secs(300 + blob.len() as u64 / (32 << 10));
        check(self.post("/items").timeout(timeout).body(frame).send().await?).await?;
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
        self.send_heartbeat(serde_json::json!({ "job": job })).await
    }

    /// A heartbeat that also reports the runner's setup (`preparing`,
    /// `ready`, `failed`), so the session sees a runner that cannot start.
    /// `job` is one it still owes an answer for (from before a restart), so
    /// the relay does not count that job lost while the answer is on its way.
    pub async fn report(&self, state: &str, detail: Option<&str>, job: Option<&str>) -> Result<Value> {
        self.send_heartbeat(serde_json::json!({ "job": job, "state": state, "detail": detail })).await
    }

    async fn send_heartbeat(&self, body: Value) -> Result<Value> {
        let r = self.post("/runners/me/heartbeat").timeout(Duration::from_secs(20)).body(body.to_string());
        read_json(check(r.send().await?).await?).await
    }

    /// Open the runner's assignment stream (SSE).
    pub async fn runner_stream(&self) -> Result<reqwest::Response> {
        check(send_stream(self.http.get(self.url("/runners/me/stream")).bearer_auth(&self.token)).await?)
            .await
    }

    /// An authenticated `GET` of a session path, as JSON.
    pub async fn get_json(&self, path: &str) -> Result<Value> {
        read_json(check(self.get(path).send().await?).await?).await
    }

    /// An authenticated `POST` with an optional body and extra headers.
    pub async fn post_raw(
        &self,
        path: &str,
        body: Vec<u8>,
        headers: &[(&str, String)],
    ) -> Result<reqwest::Response> {
        let mut req = self.post(path).body(body);
        for (k, v) in headers {
            req = req.header(*k, v);
        }
        check(req.send().await?).await
    }

    /// The session's audit trail as JSONL (owner or observer).
    pub async fn audit(&self) -> Result<Vec<u8>> {
        read_capped(check(self.get("/audit.jsonl").send().await?).await?, MAX_AUDIT).await
    }

    /// Open the session's event stream (SSE), resuming after `last_seq`.
    pub async fn session_stream(&self, last_seq: Option<u64>) -> Result<reqwest::Response> {
        let mut req = self.http.get(self.url("/stream")).bearer_auth(&self.token);
        if let Some(s) = last_seq {
            req = req.header("Last-Event-ID", s.to_string());
        }
        check(send_stream(req).await?).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_errors_print_safely() {
        let e = RelayError {
            status: 400,
            code: "bad".into(),
            message: format!("\u{1b}[2J\u{1b}]52;c;eA==\u{7}{}", "x".repeat(500)),
        };
        let s = e.to_string();
        assert!(!s.contains('\u{1b}') && !s.contains('\u{7}') && s.len() < 400, "{s}");
    }
}
