//! One-time transfer codes (`/v1/drops`): a sealed invite parked under a
//! small number until another machine claims it with the code's words.
//!
//! Drops live in memory only, for minutes; a restart forgets them. The relay
//! holds ciphertext and `sha256(claim)`, hands the box out once, and burns a
//! drop after [`MAX_WRONG_CLAIMS`] wrong claims so the words cannot be
//! guessed online.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;

use airlox_core::transfer::{claim_hash, MAX_BOX_BYTES};
use axum::body::Body;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::api::{bearer, client_bucket, read_json_body, AppState};
use crate::error::{ApiError, ApiResult};
use crate::util::{new_token, now_ms, sha256_hex};

/// Wrong claims a drop takes before it is burned.
pub const MAX_WRONG_CLAIMS: u8 = 3;

#[derive(Clone, Copy, PartialEq, Eq)]
enum DropState {
    Waiting,
    PickedUp { at_ms: u64 },
    Burned,
}

struct DropRec {
    claim_hash: String,
    /// Gone once claimed: the relay keeps only the state for the sender.
    sealed_box: Option<String>,
    token_hash: String,
    ip_hash: String,
    expires_at_ms: u64,
    wrong: u8,
    state: DropState,
}

#[derive(Default)]
pub struct Drops(Mutex<HashMap<u32, DropRec>>);

impl Drops {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u32, DropRec>> {
        let mut g = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let now = now_ms();
        g.retain(|_, d| d.expires_at_ms > now);
        g
    }
}

#[derive(Deserialize)]
struct NewDrop {
    claim_hash: String,
    #[serde(rename = "box")]
    sealed_box: String,
}

#[derive(Deserialize)]
struct Claim {
    claim: String,
}

fn nameplate(s: &str) -> ApiResult<u32> {
    s.parse().ok().filter(|n| *n > 0).ok_or_else(|| ApiError::not_found("no such code"))
}

/// `POST /v1/drops` — body: `{claim_hash, box}`. Returns the nameplate and
/// the sender's token for checking on and cancelling the drop.
pub async fn create(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Body,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let d: NewDrop = serde_json::from_str(&read_json_body(body).await?)
        .map_err(|e| ApiError::bad_request("invalid", e.to_string()))?;
    let hex_ok =
        d.claim_hash.len() == 64 && d.claim_hash.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'));
    if !hex_ok {
        return Err(ApiError::bad_request("invalid", "claim_hash must be 64 lowercase hex characters"));
    }
    match airlox_core::encoding::b64d(&d.sealed_box) {
        Ok(b) if (28..=MAX_BOX_BYTES).contains(&b.len()) => {}
        _ => return Err(ApiError::bad_request("invalid", "box must be base64url, at most 4096 bytes")),
    }
    let cfg = &st.store.cfg;
    let ip_hash = st.store.ip_hash(&client_bucket(&st, &headers, peer));
    let token = new_token();
    let expires_at_ms = now_ms() + cfg.drop_ttl_ms;
    let mut g = st.drops.lock();
    if g.len() >= cfg.max_drops {
        return Err(ApiError::limit("relay is at its transfer code limit; try again in a few minutes"));
    }
    if g.values().filter(|r| r.ip_hash == ip_hash).count() >= cfg.max_drops_per_ip {
        return Err(ApiError::limit("too many open transfer codes from this address"));
    }
    // The lowest free number, so codes stay short.
    let n = (1..).find(|n| !g.contains_key(n)).expect("fewer than u32::MAX drops");
    g.insert(
        n,
        DropRec {
            claim_hash: d.claim_hash,
            sealed_box: Some(d.sealed_box),
            token_hash: sha256_hex(token.as_bytes()),
            ip_hash,
            expires_at_ms,
            wrong: 0,
            state: DropState::Waiting,
        },
    );
    Ok((StatusCode::CREATED, Json(json!({"nameplate": n, "token": token, "expires_at_ms": expires_at_ms}))))
}

/// `POST /v1/drops/:n/claim` — body: `{claim}`. Returns `{box}` once.
pub async fn claim(State(st): State<AppState>, Path(n): Path<String>, body: Body) -> ApiResult<Json<Value>> {
    let n = nameplate(&n)?;
    let c: Claim = serde_json::from_str(&read_json_body(body).await?)
        .map_err(|e| ApiError::bad_request("invalid", e.to_string()))?;
    let hash =
        claim_hash(&c.claim).map_err(|_| ApiError::bad_request("invalid", "claim must be base64url"))?;
    let mut g = st.drops.lock();
    let d = g.get_mut(&n).ok_or_else(|| ApiError::not_found("no such code; it may have expired"))?;
    if d.state != DropState::Waiting {
        return Err(ApiError::gone("used", "this code was already used or cancelled"));
    }
    if hash != d.claim_hash {
        d.wrong += 1;
        if d.wrong >= MAX_WRONG_CLAIMS {
            d.state = DropState::Burned;
            d.sealed_box = None;
            return Err(ApiError::gone("burned", "too many wrong codes; ask for a new one"));
        }
        return Err(ApiError::forbidden("wrong code; check the words"));
    }
    d.state = DropState::PickedUp { at_ms: now_ms() };
    Ok(Json(json!({"box": d.sealed_box.take()})))
}

fn owned<'a>(g: &'a mut HashMap<u32, DropRec>, n: u32, headers: &HeaderMap) -> ApiResult<&'a mut DropRec> {
    let token = bearer(headers).ok_or_else(ApiError::unauthorized)?;
    let hash = sha256_hex(token.as_bytes());
    g.get_mut(&n).filter(|d| d.token_hash == hash).ok_or_else(|| ApiError::not_found("no such code"))
}

/// `GET /v1/drops/:n` — the sender's view: `waiting`, `picked_up`, `burned`.
pub async fn status(
    State(st): State<AppState>,
    Path(n): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let n = nameplate(&n)?;
    let mut g = st.drops.lock();
    let d = owned(&mut g, n, &headers)?;
    let (state, at) = match d.state {
        DropState::Waiting => ("waiting", None),
        DropState::PickedUp { at_ms } => ("picked_up", Some(at_ms)),
        DropState::Burned => ("burned", None),
    };
    Ok(Json(json!({"state": state, "picked_up_at_ms": at, "expires_at_ms": d.expires_at_ms})))
}

/// `DELETE /v1/drops/:n` — the sender cancels a code.
pub async fn cancel(
    State(st): State<AppState>,
    Path(n): Path<String>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    let n = nameplate(&n)?;
    let mut g = st.drops.lock();
    owned(&mut g, n, &headers)?;
    g.remove(&n);
    Ok(StatusCode::NO_CONTENT)
}
