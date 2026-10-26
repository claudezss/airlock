//! HTTP handlers. Every write is checked against the manifest and the
//! author's certificate; the relay never sees plaintext.

use std::collections::VecDeque;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use airlock_core::cert::SignedJoinRequest;
use airlock_core::encoding::parse_canonical;
use airlock_core::item::{is_item_id, ItemEnvelope};
use airlock_core::policy;
use airlock_core::session::{is_session_id, Mode, Role, SignedManifest};
use axum::body::Body;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures_util::{Stream, StreamExt};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::sync::{broadcast, watch};

use crate::error::{ApiError, ApiResult};
use crate::store::{Event, Rec, Session, Store, MAX_PARTICIPANTS};
use crate::util::{new_token, now_ms, random_suffix, sha256_hex};

/// Largest item envelope accepted (header + signature JSON).
pub const MAX_ENVELOPE_BYTES: usize = 64 * 1024;
/// Allowed clock skew for a new session's `created_at_ms`.
pub const MAX_CLOCK_SKEW_MS: u64 = 5 * 60 * 1000;

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Store>,
    pub shutdown: watch::Receiver<bool>,
}

fn session(st: &AppState, id: &str) -> ApiResult<Arc<Session>> {
    if !is_session_id(id) {
        return Err(ApiError::not_found("no such session"));
    }
    st.store.get(id).ok_or_else(|| ApiError::not_found("no such session"))
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers.get(header::AUTHORIZATION)?.to_str().ok()?.strip_prefix("Bearer ")
}

/// Resolve the bearer token to `(participant_pub, role)`.
fn auth(s: &Session, headers: &HeaderMap) -> ApiResult<(String, Role)> {
    let token = bearer(headers).ok_or_else(ApiError::unauthorized)?;
    let g = s.lock();
    if g.closed {
        return Err(ApiError::gone("closed", "session is closed"));
    }
    g.participant_by_token(&sha256_hex(token.as_bytes())).ok_or_else(ApiError::unauthorized)
}

fn client_ip(st: &AppState, headers: &HeaderMap, peer: SocketAddr) -> IpAddr {
    if st.store.cfg.trust_proxy {
        let forwarded = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .and_then(|v| v.trim().parse().ok());
        if let Some(ip) = forwarded {
            return ip;
        }
    }
    peer.ip()
}

pub async fn health() -> Json<Value> {
    Json(json!({"ok": true, "protocol": airlock_core::PROTOCOL_VERSION}))
}

/// `POST /v1/sessions` — body: canonical signed manifest.
pub async fn create_session(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: String,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let signed = SignedManifest::from_json(&body)?;
    let m = &signed.manifest;
    let cfg = &st.store.cfg;
    let now = now_ms();
    if m.created_at_ms > now + MAX_CLOCK_SKEW_MS || m.expires_at_ms <= now {
        return Err(ApiError::bad_request(
            "clock",
            "created_at_ms must be about now and expires_at_ms in the future",
        ));
    }
    if m.expires_at_ms - m.created_at_ms > cfg.max_ttl_ms || m.expires_at_ms > now + cfg.max_ttl_ms {
        return Err(ApiError::bad_request(
            "ttl",
            format!("this relay allows sessions of at most {} ms", cfg.max_ttl_ms),
        ));
    }
    if m.max_item_bytes > cfg.max_item_bytes {
        return Err(ApiError::bad_request(
            "item_size",
            format!("this relay allows max_item_bytes of at most {}", cfg.max_item_bytes),
        ));
    }
    if st.store.count() >= cfg.max_sessions {
        return Err(ApiError::limit("relay is at its session limit"));
    }
    let ip_hash = sha256_hex(client_ip(&st, &headers, peer).to_string().as_bytes());
    if st.store.count_for_ip(&ip_hash) >= cfg.max_sessions_per_ip {
        return Err(ApiError::limit("too many active sessions from this address"));
    }
    if !st.store.disk_ok() {
        return Err(ApiError::storage_full());
    }
    let expires = m.expires_at_ms;
    let s = st
        .store
        .create(signed, body, ip_hash)?
        .ok_or_else(|| ApiError::conflict("session already exists"))?;
    Ok((StatusCode::CREATED, Json(json!({"session_id": s.id, "expires_at_ms": expires}))))
}

/// `GET /v1/sessions/:id` — the signed manifest (public policy).
pub async fn get_session(State(st): State<AppState>, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    let s = session(&st, &id)?;
    Ok(Json(json!({"signed_manifest": s.manifest_json})))
}

/// `POST /v1/sessions/:id/close` — owner only.
pub async fn close_session(
    State(st): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    let s = session(&st, &id)?;
    let (_, role) = auth(&s, &headers)?;
    if role != Role::Owner {
        return Err(ApiError::forbidden("only the owner may close the session"));
    }
    st.store.purge(&id, "closed by owner");
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/sessions/:id/participants` — body: canonical signed join request.
pub async fn join(
    State(st): State<AppState>,
    Path(id): Path<String>,
    body: String,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let s = session(&st, &id)?;
    let j: SignedJoinRequest = parse_canonical(&body, "join request")?;
    j.verify(&s.signed.manifest)?;
    let role = j.join.cert.role();
    if role == Role::Runner && s.signed.manifest.mode == Mode::Relay {
        return Err(ApiError::forbidden("runners can only join execute sessions"));
    }
    let token = new_token();
    let mut g = s.lock();
    if g.closed {
        return Err(ApiError::gone("closed", "session is closed"));
    }
    let pk = j.join.cert.participant().to_b64();
    if !g.participants.contains_key(&pk) && g.participants.len() >= MAX_PARTICIPANTS {
        return Err(ApiError::limit("session is at its participant limit"));
    }
    let ev =
        s.append(&mut g, Rec::Join { signed_join: body, token_sha256: sha256_hex(token.as_bytes()) }, true)?;
    let seq = ev.map(|e| e.seq).unwrap_or_default();
    Ok((
        StatusCode::CREATED,
        Json(json!({"token": token, "participant_pub": pk, "role": role.as_str(), "seq": seq})),
    ))
}

/// `GET /v1/sessions/:id/participants`
pub async fn participants(
    State(st): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let s = session(&st, &id)?;
    auth(&s, &headers)?;
    let g = s.lock();
    let mut list: Vec<_> = g.participants.values().collect();
    list.sort_by_key(|p| p.seq);
    Ok(Json(json!({"participants": list.iter().map(|p| p.public.clone()).collect::<Vec<_>>()})))
}

#[derive(Deserialize)]
pub struct After {
    after: Option<u64>,
}

/// `GET /v1/sessions/:id/events?after=N` — public events with `seq > N`.
pub async fn events(
    State(st): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<After>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let s = session(&st, &id)?;
    auth(&s, &headers)?;
    let g = s.lock();
    let evs: Vec<&Event> =
        g.events.iter().filter(|e| q.after.is_none_or(|a| e.seq > a)).map(|e| e.as_ref()).collect();
    Ok(Json(json!({"events": evs})))
}

fn sse_event(e: &Event) -> SseEvent {
    SseEvent::default().id(e.seq.to_string()).event(e.kind).data(e.data.to_string())
}

/// `GET /v1/sessions/:id/stream` — SSE; resume with `Last-Event-ID`.
pub async fn stream(
    State(st): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Sse<impl Stream<Item = Result<SseEvent, Infallible>>>> {
    let s = session(&st, &id)?;
    auth(&s, &headers)?;
    let after: Option<u64> =
        headers.get("last-event-id").and_then(|v| v.to_str().ok()).and_then(|v| v.trim().parse().ok());
    // Snapshot and subscribe under the session lock: events are broadcast
    // under the same lock, so nothing falls between the two.
    let (backlog, rx) = {
        let g = s.lock();
        let backlog: VecDeque<Arc<Event>> =
            g.events.iter().filter(|e| after.is_none_or(|a| e.seq > a)).cloned().collect();
        (backlog, s.tx.subscribe())
    };
    struct St {
        backlog: VecDeque<Arc<Event>>,
        rx: broadcast::Receiver<Arc<Event>>,
        shutdown: watch::Receiver<bool>,
        done: bool,
    }
    let state = St { backlog, rx, shutdown: st.shutdown.clone(), done: false };
    let out = futures_util::stream::unfold(state, |mut st| async move {
        if st.done {
            return None;
        }
        let ev = if let Some(e) = st.backlog.pop_front() {
            e
        } else {
            tokio::select! {
                r = st.rx.recv() => match r {
                    Ok(e) => e,
                    // Lagged or closed: end the stream; the client resumes from its last id.
                    Err(_) => return None,
                },
                _ = st.shutdown.changed() => return None,
            }
        };
        if ev.kind == "closed" {
            st.done = true;
        }
        Some((Ok(sse_event(&ev)), st))
    });
    Ok(Sse::new(out).keep_alive(KeepAlive::default()))
}

/// Releases an upload's reserved quota unless committed.
struct Reservation {
    session: Arc<Session>,
    id: String,
    bytes: u64,
    committed: bool,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if !self.committed {
            let mut g = self.session.lock();
            g.pending.remove(&self.id);
            g.pending_bytes -= self.bytes;
        }
    }
}

/// `POST /v1/sessions/:id/items` — body: `u32_be(len) || envelope || blob`.
pub async fn post_item(
    State(st): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let s = session(&st, &id)?;
    let (who, role) = auth(&s, &headers)?;
    let cfg = st.store.cfg.clone();
    let mut chunks = body.into_data_stream();
    let mut buf: Vec<u8> = Vec::new();
    let read_err = |e: axum::Error| ApiError::bad_request("body", format!("could not read body: {e}"));

    while buf.len() < 4 {
        match chunks.next().await {
            Some(c) => buf.extend_from_slice(&c.map_err(read_err)?),
            None => return Err(ApiError::bad_request("body", "truncated body")),
        }
    }
    let n = u32::from_be_bytes(buf[..4].try_into().expect("4 bytes")) as usize;
    if n > MAX_ENVELOPE_BYTES {
        return Err(ApiError::too_large("envelope too large"));
    }
    while buf.len() < 4 + n {
        match chunks.next().await {
            Some(c) => buf.extend_from_slice(&c.map_err(read_err)?),
            None => return Err(ApiError::bad_request("body", "truncated envelope")),
        }
    }
    let env_json = std::str::from_utf8(&buf[4..4 + n])
        .map_err(|_| ApiError::bad_request("invalid", "envelope is not utf-8"))?
        .to_string();
    let env: ItemEnvelope = parse_canonical(&env_json, "item envelope")?;
    let h = &env.header;
    if h.author.to_b64() != who {
        return Err(ApiError::forbidden("item author does not match the authenticated participant"));
    }
    policy::check_header(&s.signed.manifest, role, h)?;
    let item_id = h.id.clone();
    let blob_len = h.blob_len()?;

    let mut reservation = {
        let mut g = s.lock();
        if g.items.contains_key(&item_id) || g.pending.contains(&item_id) {
            return Err(ApiError::conflict("an item with this id already exists"));
        }
        if g.items.len() + g.pending.len() >= cfg.max_items {
            return Err(ApiError::limit("session is at its item limit"));
        }
        if g.held_bytes + g.pending_bytes + blob_len > cfg.max_session_bytes {
            return Err(ApiError::too_large("session would exceed its storage limit; wait for deliveries"));
        }
        if g.transfer_bytes + blob_len > cfg.max_session_transfer {
            return Err(ApiError::limit("session transfer limit reached"));
        }
        g.pending.insert(item_id.clone());
        g.pending_bytes += blob_len;
        Reservation { session: s.clone(), id: item_id.clone(), bytes: blob_len, committed: false }
    };
    if !st.store.disk_ok() {
        return Err(ApiError::storage_full());
    }

    let final_path = s.blob_path(&item_id);
    let tmp_path = s.dir.join("blobs").join(format!(".{item_id}.{}.tmp", random_suffix()));
    let result: ApiResult<[u8; 32]> = async {
        let mut file = tokio::fs::OpenOptions::new().write(true).create_new(true).open(&tmp_path).await?;
        let mut hasher = Sha256::new();
        let mut written: u64 = 0;
        let mut feed = |data: &[u8], written: &mut u64| -> ApiResult<()> {
            *written += data.len() as u64;
            if *written > blob_len {
                return Err(ApiError::bad_request("body", "blob is longer than the header size allows"));
            }
            hasher.update(data);
            Ok(())
        };
        let rest = &buf[4 + n..];
        feed(rest, &mut written)?;
        file.write_all(rest).await?;
        while let Some(c) = chunks.next().await {
            let c = c.map_err(read_err)?;
            feed(&c, &mut written)?;
            file.write_all(&c).await?;
        }
        if written != blob_len {
            return Err(ApiError::bad_request("body", "blob is shorter than the header size requires"));
        }
        file.sync_all().await?;
        Ok(hasher.finalize().into())
    }
    .await;
    let digest = match result {
        Ok(d) => d,
        Err(e) => {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(e);
        }
    };
    if let Err(e) = env.verify_blob_digest(blob_len, &digest) {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return Err(e.into());
    }
    tokio::fs::rename(&tmp_path, &final_path).await?;

    let mut g = s.lock();
    if g.closed {
        drop(g);
        let _ = std::fs::remove_file(&final_path);
        return Err(ApiError::gone("closed", "session is closed"));
    }
    let recipients: Vec<String> = g.participants.keys().filter(|k| **k != who).cloned().collect();
    g.pending.remove(&item_id);
    g.pending_bytes -= blob_len;
    reservation.committed = true;
    let ev = s.append(&mut g, Rec::Item { envelope: env_json, recipients, blob_len }, true)?;
    let seq = ev.map(|e| e.seq).unwrap_or_default();
    Ok((StatusCode::CREATED, Json(json!({"id": item_id, "seq": seq}))))
}

fn item_path_ok(item: &str) -> ApiResult<()> {
    if is_item_id(item) {
        Ok(())
    } else {
        Err(ApiError::not_found("no such item"))
    }
}

/// `GET /v1/sessions/:id/items/:item/blob`
pub async fn get_blob(
    State(st): State<AppState>,
    Path((id, item)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    item_path_ok(&item)?;
    let s = session(&st, &id)?;
    auth(&s, &headers)?;
    let len = {
        let mut g = s.lock();
        let r = g.items.get(&item).ok_or_else(|| ApiError::not_found("no such item"))?;
        if !r.blob_present {
            return Err(ApiError::gone("evicted", "delivered and removed from the relay"));
        }
        let len = r.blob_len;
        if g.transfer_bytes + len > st.store.cfg.max_session_transfer {
            return Err(ApiError::limit("session transfer limit reached"));
        }
        g.transfer_bytes += len;
        len
    };
    let file = match tokio::fs::File::open(s.blob_path(&item)).await {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(ApiError::gone("evicted", "delivered and removed from the relay"))
        }
        Err(e) => return Err(e.into()),
    };
    let body = Body::from_stream(tokio_util::io::ReaderStream::new(file));
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (header::CONTENT_LENGTH, len.to_string()),
        ],
        body,
    )
        .into_response())
}

/// `POST /v1/sessions/:id/items/:item/ack` — the caller stored the blob locally.
pub async fn ack(
    State(st): State<AppState>,
    Path((id, item)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    item_path_ok(&item)?;
    let s = session(&st, &id)?;
    let (who, _) = auth(&s, &headers)?;
    let mut g = s.lock();
    let r = g.items.get(&item).ok_or_else(|| ApiError::not_found("no such item"))?;
    if r.recipients.contains(&who) && !r.acked.contains(&who) {
        s.append(&mut g, Rec::Ack { item, by: who }, false)?;
    }
    Ok(StatusCode::NO_CONTENT)
}
