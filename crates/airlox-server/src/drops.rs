//! One-time transfer codes (`/v1/drops`): a sealed invite parked under a
//! small number until another machine claims it with the code's words.
//!
//! Drops live in memory only, for minutes; a restart forgets them. The relay
//! holds ciphertext and `sha256(claim)`, hands the box out once, and burns a
//! drop after [`MAX_WRONG_CLAIMS`] wrong claims so the words cannot be
//! guessed online. One address gets [`MAX_WRONG_PER_ADDRESS`] wrong claims
//! (unknown numbers included) per TTL over all drops, so it can neither try
//! every open code nor burn them all. Nameplates are drawn at random, and a
//! finished drop keeps its number for another TTL, so a stale or mistyped
//! code does not land on someone else's.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;

use airlox_core::keys::PublicKey;
use airlox_core::transfer::{claim_hash, MAX_BOX_BYTES};
use axum::body::Body;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::api::{bearer, client_bucket, read_json_body, AppState};
use crate::error::{ApiError, ApiResult};
use crate::util::{new_token, now_ms, random_bytes, sha256_hex};

/// Wrong claims a drop takes before it is burned.
pub const MAX_WRONG_CLAIMS: u8 = 3;
/// Wrong claims one address may make per TTL, over all drops.
pub const MAX_WRONG_PER_ADDRESS: u32 = 10;
/// Finished drops kept (to reserve their numbers), as a multiple of `max_drops`.
const MAX_RECORDS_FACTOR: usize = 4;

#[derive(Clone, Copy, PartialEq, Eq)]
enum DropState {
    Waiting,
    PickedUp { at_ms: u64 },
    Burned,
    Cancelled,
}

struct DropRec {
    claim_hash: String,
    /// Gone once the drop is finished: the relay keeps only its state.
    sealed_box: Option<String>,
    token_hash: String,
    ip_hash: String,
    expires_at_ms: u64,
    wrong: u8,
    state: DropState,
    /// The key the claimant said it will join with, as given at pickup.
    participant_pub: Option<String>,
}

impl DropRec {
    fn open(&self, now: u64) -> bool {
        self.state == DropState::Waiting && now < self.expires_at_ms
    }
}

#[derive(Default)]
struct Inner {
    drops: HashMap<u32, DropRec>,
    /// Wrong claims per address bucket hash: `(count, window end)`.
    wrong: HashMap<String, (u32, u64)>,
}

#[derive(Default)]
pub struct Drops(Mutex<Inner>);

impl Drops {
    /// Lock, after forgetting what has outlived its reservation.
    fn lock(&self, ttl_ms: u64) -> std::sync::MutexGuard<'_, Inner> {
        let mut g = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let now = now_ms();
        g.drops.retain(|_, d| d.expires_at_ms.saturating_add(ttl_ms) > now);
        for d in g.drops.values_mut() {
            if now >= d.expires_at_ms {
                d.sealed_box = None;
            }
        }
        g.wrong.retain(|_, (_, end)| *end > now);
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
    /// The Ed25519 key the claimant will join the session with, which the
    /// creator learns from the drop's status. The claimant's own word.
    #[serde(default)]
    participant_pub: Option<String>,
}

fn nameplate(s: &str) -> ApiResult<u32> {
    s.parse().ok().filter(|n| *n > 0).ok_or_else(|| ApiError::not_found("no such code"))
}

/// A free number from `1..=max(100, 4 × records)`: short, but not the next one in line.
fn free_nameplate(drops: &HashMap<u32, DropRec>) -> u32 {
    let range = (drops.len() as u32).saturating_mul(4).max(100);
    loop {
        let n = u32::from_le_bytes(random_bytes()) % range + 1;
        if !drops.contains_key(&n) {
            return n;
        }
    }
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
    let now = now_ms();
    let expires_at_ms = now + cfg.drop_ttl_ms;
    let mut g = st.drops.lock(cfg.drop_ttl_ms);
    // Only open drops count toward the limits; finished ones just hold their
    // number, up to a bound on memory.
    let open = g.drops.values().filter(|r| r.open(now));
    if open.clone().count() >= cfg.max_drops || g.drops.len() >= cfg.max_drops * MAX_RECORDS_FACTOR {
        return Err(ApiError::limit("relay is at its transfer code limit; try again in a few minutes"));
    }
    if open.filter(|r| r.ip_hash == ip_hash).count() >= cfg.max_drops_per_ip {
        return Err(ApiError::limit("too many open transfer codes from this address"));
    }
    let n = free_nameplate(&g.drops);
    g.drops.insert(
        n,
        DropRec {
            claim_hash: d.claim_hash,
            sealed_box: Some(d.sealed_box),
            token_hash: sha256_hex(token.as_bytes()),
            ip_hash,
            expires_at_ms,
            wrong: 0,
            state: DropState::Waiting,
            participant_pub: None,
        },
    );
    Ok((
        StatusCode::CREATED,
        Json(
            json!({"nameplate": n, "token": token, "expires_at_ms": expires_at_ms, "ttl_ms": cfg.drop_ttl_ms}),
        ),
    ))
}

/// `POST /v1/drops/:n/claim` — body: `{claim, participant_pub?}`. Returns
/// `{box}` once.
pub async fn claim(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(n): Path<String>,
    body: Body,
) -> ApiResult<Json<Value>> {
    let n = nameplate(&n)?;
    let c: Claim = serde_json::from_str(&read_json_body(body).await?)
        .map_err(|e| ApiError::bad_request("invalid", e.to_string()))?;
    let hash =
        claim_hash(&c.claim).map_err(|_| ApiError::bad_request("invalid", "claim must be base64url"))?;
    // Checked before the drop is looked at, so a malformed key is neither a wrong claim nor a pickup.
    let participant_pub = c
        .participant_pub
        .as_deref()
        .map(|k| {
            PublicKey::from_b64(k).map(|k| k.to_b64()).map_err(|_| {
                ApiError::bad_request("invalid", "participant_pub must be a base64url Ed25519 public key")
            })
        })
        .transpose()?;
    let ttl = st.store.cfg.drop_ttl_ms;
    let ip_hash = st.store.ip_hash(&client_bucket(&st, &headers, peer));
    let now = now_ms();
    let mut g = st.drops.lock(ttl);
    if g.wrong.get(&ip_hash).is_some_and(|(count, _)| *count >= MAX_WRONG_PER_ADDRESS) {
        return Err(ApiError::limit("too many wrong codes from this address; try again in a few minutes"));
    }
    let miss = |g: &mut Inner| {
        let e = g.wrong.entry(ip_hash.clone()).or_insert((0, now + ttl));
        e.0 += 1;
    };
    let Some(d) = g.drops.get_mut(&n) else {
        miss(&mut g);
        return Err(ApiError::not_found("no such code; check the number"));
    };
    let gone = match d.state {
        DropState::PickedUp { .. } => Some(("used", "this code was already used")),
        DropState::Burned => Some(("burned", "too many wrong tries cancelled this code; ask for a new one")),
        DropState::Cancelled => Some(("cancelled", "the sender cancelled this code; ask for a new one")),
        DropState::Waiting if now >= d.expires_at_ms => {
            Some(("expired", "this code expired; ask for a new one"))
        }
        DropState::Waiting => None,
    };
    if let Some((code, message)) = gone {
        return Err(ApiError::gone(code, message));
    }
    if hash != d.claim_hash {
        d.wrong += 1;
        let burned = d.wrong >= MAX_WRONG_CLAIMS;
        if burned {
            d.state = DropState::Burned;
            d.sealed_box = None;
        }
        miss(&mut g);
        return Err(if burned {
            ApiError::gone("burned", "too many wrong tries cancelled this code; ask for a new one")
        } else {
            ApiError::forbidden("wrong code; check the words")
        });
    }
    d.state = DropState::PickedUp { at_ms: now };
    d.participant_pub = participant_pub;
    Ok(Json(json!({"box": d.sealed_box.take()})))
}

fn owned<'a>(g: &'a mut Inner, n: u32, headers: &HeaderMap) -> ApiResult<&'a mut DropRec> {
    let token = bearer(headers).ok_or_else(ApiError::unauthorized)?;
    let hash = sha256_hex(token.as_bytes());
    g.drops.get_mut(&n).filter(|d| d.token_hash == hash).ok_or_else(|| ApiError::not_found("no such code"))
}

/// `GET /v1/drops/:n` — the sender's view: `waiting`, `picked_up`, `burned`,
/// `cancelled` or `expired`, and for a pickup the `participant_pub` the
/// claimant named (`null` if it named none).
pub async fn status(
    State(st): State<AppState>,
    Path(n): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let n = nameplate(&n)?;
    let mut g = st.drops.lock(st.store.cfg.drop_ttl_ms);
    let d = owned(&mut g, n, &headers)?;
    let (state, at) = match d.state {
        DropState::Waiting if now_ms() >= d.expires_at_ms => ("expired", None),
        DropState::Waiting => ("waiting", None),
        DropState::PickedUp { at_ms } => ("picked_up", Some(at_ms)),
        DropState::Burned => ("burned", None),
        DropState::Cancelled => ("cancelled", None),
    };
    Ok(Json(json!({
        "state": state,
        "picked_up_at_ms": at,
        "expires_at_ms": d.expires_at_ms,
        "participant_pub": d.participant_pub,
    })))
}

/// `DELETE /v1/drops/:n` — the sender cancels a code. Its number stays
/// reserved, so the code reads as cancelled rather than as someone else's.
pub async fn cancel(
    State(st): State<AppState>,
    Path(n): Path<String>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    let n = nameplate(&n)?;
    let mut g = st.drops.lock(st.store.cfg.drop_ttl_ms);
    let d = owned(&mut g, n, &headers)?;
    if d.state == DropState::Waiting {
        d.state = DropState::Cancelled;
    }
    d.sealed_box = None;
    Ok(StatusCode::NO_CONTENT)
}
