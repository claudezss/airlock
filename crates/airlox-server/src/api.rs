//! HTTP handlers. Every write is checked against the manifest and the
//! author's certificate; the relay never sees plaintext. Log writes fsync,
//! so they run on the blocking pool, never on the async workers.

use std::collections::{HashSet, VecDeque};
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use airlox_core::cert::SignedJoinRequest;
use airlox_core::encoding::parse_canonical;
use airlox_core::item::{is_item_id, ItemEnvelope, ItemHeader, ItemKind};
use airlox_core::policy;
use airlox_core::session::{is_session_id, Mode, Role, SignedManifest};
use axum::body::{Body, BodyDataStream};
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::Json;
use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::sync::{broadcast, watch};

use crate::error::{ApiError, ApiResult};
use crate::store::{
    sync_dir, CreateError, Event, Inner, JobState, Rec, Session, Store, MAX_OPEN_WANTS, MAX_PARTICIPANTS,
    MAX_STREAMS_PER_PARTICIPANT, MAX_WANTS, WANT_REFRESH_MS,
};
use crate::util::{new_token, now_ms, random_suffix, sha256_hex};

/// Largest item envelope accepted (header + signature JSON).
pub const MAX_ENVELOPE_BYTES: usize = 64 * 1024;
/// Largest JSON body (signed manifest or join request).
pub const MAX_JSON_BYTES: usize = 256 * 1024;
/// Allowed clock skew for a new session's `created_at_ms`.
pub const MAX_CLOCK_SKEW_MS: u64 = 5 * 60 * 1000;
/// A request body that sends nothing for this long is dropped.
pub const BODY_IDLE: Duration = Duration::from_secs(30);
/// Log space reserved per line beyond its payload (seq, timestamps, token hash).
const LOG_LINE_OVERHEAD: u64 = 512;
/// Re-seed uploads one participant may have in flight.
const MAX_RESEEDS_IN_FLIGHT: usize = 4;
/// Audit exports built at once, relay-wide: each holds about twice its log
/// in memory.
static AUDITS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Store>,
    pub shutdown: watch::Receiver<bool>,
}

/// Run disk-bound work on the blocking pool.
pub(crate) async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> ApiResult<T> + Send + 'static,
) -> ApiResult<T> {
    tokio::task::spawn_blocking(f).await.map_err(ApiError::internal)?
}

pub(crate) fn session(st: &AppState, id: &str) -> ApiResult<Arc<Session>> {
    if !is_session_id(id) {
        return Err(ApiError::not_found("no such session"));
    }
    st.store.get(id).ok_or_else(|| ApiError::not_found("no such session"))
}

pub(crate) fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers.get(header::AUTHORIZATION)?.to_str().ok()?.strip_prefix("Bearer ")
}

/// Resolve the bearer token to `(participant_pub, role)`.
pub(crate) fn auth(s: &Session, headers: &HeaderMap) -> ApiResult<(String, Role)> {
    let token = bearer(headers).ok_or_else(ApiError::unauthorized)?;
    let g = s.lock();
    if g.closed {
        return Err(ApiError::gone("closed", "session is closed"));
    }
    g.participant_by_token(&sha256_hex(token.as_bytes())).ok_or_else(ApiError::unauthorized)
}

/// The address bucket that per-address limits count: the peer, or with
/// `--trust-proxy` the last `X-Forwarded-For` hop (the one the proxy added).
/// IPv6 addresses are grouped by /64, since one host usually owns a /64.
fn client_bucket(st: &AppState, headers: &HeaderMap, peer: SocketAddr) -> String {
    let mut ip = peer.ip();
    if st.store.cfg.trust_proxy {
        let last = headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .next_back()
            .and_then(|v| v.trim().parse::<IpAddr>().ok());
        if let Some(fwd) = last {
            ip = fwd;
        }
    }
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let s = v6.segments();
                format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
            }
        },
    }
}

async fn next_chunk(chunks: &mut BodyDataStream) -> ApiResult<Option<Bytes>> {
    match tokio::time::timeout(BODY_IDLE, chunks.next()).await {
        Err(_) => Err(ApiError::timeout()),
        Ok(None) => Ok(None),
        Ok(Some(c)) => {
            c.map(Some).map_err(|e| ApiError::bad_request("body", format!("could not read body: {e}")))
        }
    }
}

/// Read a small UTF-8 body with a size cap and an idle timeout.
pub(crate) async fn read_json_body(body: Body) -> ApiResult<String> {
    let mut chunks = body.into_data_stream();
    let mut buf = Vec::new();
    while let Some(c) = next_chunk(&mut chunks).await? {
        if buf.len() + c.len() > MAX_JSON_BYTES {
            return Err(ApiError::too_large("request body too large"));
        }
        buf.extend_from_slice(&c);
    }
    String::from_utf8(buf).map_err(|_| ApiError::bad_request("invalid", "body is not utf-8"))
}

pub async fn health() -> Json<Value> {
    Json(json!({"ok": true, "protocol": airlox_core::PROTOCOL_VERSION}))
}

/// `POST /v1/sessions` — body: canonical signed manifest.
pub async fn create_session(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Body,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let body = read_json_body(body).await?;
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
    let ip_hash = st.store.ip_hash(&client_bucket(&st, &headers, peer));
    if st.store.count_for_ip(&ip_hash) >= cfg.max_sessions_per_ip {
        return Err(ApiError::limit("too many active sessions from this address"));
    }
    if !st.store.disk_ok() {
        return Err(ApiError::storage_full());
    }
    let expires = m.expires_at_ms;
    let store = st.store.clone();
    let s = blocking(move || match store.create(signed, body, ip_hash) {
        Ok(s) => Ok(s),
        Err(CreateError::Exists) => Err(ApiError::conflict("session already exists")),
        Err(CreateError::Closed) => {
            Err(ApiError::gone("closed", "this session was closed and cannot be re-created"))
        }
        Err(CreateError::Io(e)) => Err(e.into()),
    })
    .await?;
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
    let store = st.store.clone();
    blocking(move || {
        store.purge(&id, "closed by owner");
        Ok(())
    })
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/sessions/:id/participants` — body: canonical signed join request.
///
/// Each key joins once. A signed join is public (every participant sees it),
/// so accepting it twice would hand its token to whoever replays it.
pub async fn join(
    State(st): State<AppState>,
    Path(id): Path<String>,
    body: Body,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let s = session(&st, &id)?;
    let body = read_json_body(body).await?;
    let j: SignedJoinRequest = parse_canonical(&body, "join request")?;
    j.verify(&s.signed.manifest)?;
    let role = j.join.cert.role();
    if role == Role::Runner && s.signed.manifest.mode == Mode::Relay {
        return Err(ApiError::forbidden("runners can only join execute sessions"));
    }
    if !st.store.disk_ok() {
        return Err(ApiError::storage_full());
    }
    let pk = j.join.cert.participant().to_b64();
    let max_log = st.store.cfg.max_log_bytes;
    let token = new_token();
    let token_sha256 = sha256_hex(token.as_bytes());
    let pk2 = pk.clone();
    let seq = blocking(move || {
        let mut g = s.lock();
        if g.closed {
            return Err(ApiError::gone("closed", "session is closed"));
        }
        if g.revoked.contains(&role) {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "revoked",
                "the owner revoked this invite's role",
            ));
        }
        if g.participants.contains_key(&pk2) {
            return Err(ApiError::conflict(
                "this key has already joined; a client that lost its token joins again with a new key",
            ));
        }
        if g.participants.len() >= MAX_PARTICIPANTS {
            return Err(ApiError::limit("session is at its participant limit"));
        }
        if g.log_len() + body.len() as u64 + LOG_LINE_OVERHEAD > max_log {
            return Err(ApiError::too_large("session history limit reached"));
        }
        let ev = s.append(&mut g, Rec::Join { signed_join: body, token_sha256 })?;
        Ok(ev.map(|e| e.seq).unwrap_or_default())
    })
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({"token": token, "participant_pub": pk, "role": role.as_str(), "seq": seq})),
    ))
}

/// `POST /v1/sessions/:id/leave` — stop receiving; the token stops working.
pub async fn leave(
    State(st): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    let s = session(&st, &id)?;
    let (who, _) = auth(&s, &headers)?;
    blocking(move || {
        let mut g = s.lock();
        if !g.closed {
            s.fail_runner_job(&mut g, &who, "runner_left")?;
            s.append(&mut g, Rec::Leave { who })?;
        }
        Ok(())
    })
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /v1/sessions/:id/participants` — current (not departed) participants.
pub async fn participants(
    State(st): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let s = session(&st, &id)?;
    auth(&s, &headers)?;
    let g = s.lock();
    let mut list: Vec<_> = g.participants.values().filter(|p| !p.left).collect();
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

pub(crate) fn sse_event(e: &Event) -> SseEvent {
    SseEvent::default().id(e.seq.to_string()).event(e.kind).data(e.data.to_string())
}

/// Counts a participant's open streams.
struct StreamSlot {
    session: Arc<Session>,
    who: String,
}

impl Drop for StreamSlot {
    fn drop(&mut self) {
        let mut g = self.session.lock();
        if let Some(n) = g.streams.get_mut(&self.who) {
            *n -= 1;
            if *n == 0 {
                g.streams.remove(&self.who);
            }
        }
    }
}

/// `GET /v1/sessions/:id/stream` — SSE; resume with `Last-Event-ID`.
pub async fn stream(
    State(st): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Sse<impl Stream<Item = Result<SseEvent, Infallible>>>> {
    let s = session(&st, &id)?;
    let (who, _) = auth(&s, &headers)?;
    let after: Option<u64> =
        headers.get("last-event-id").and_then(|v| v.to_str().ok()).and_then(|v| v.trim().parse().ok());
    // Snapshot and subscribe under the session lock: events are broadcast
    // under the same lock, so nothing falls between the two.
    let (backlog, rx, slot) = {
        let mut g = s.lock();
        let n = g.streams.entry(who.clone()).or_default();
        if *n >= MAX_STREAMS_PER_PARTICIPANT {
            return Err(ApiError::limit("too many open streams for this participant"));
        }
        *n += 1;
        let backlog: VecDeque<Arc<Event>> =
            g.events.iter().filter(|e| after.is_none_or(|a| e.seq > a)).cloned().collect();
        (backlog, s.tx.subscribe(), StreamSlot { session: s.clone(), who })
    };
    struct St {
        backlog: VecDeque<Arc<Event>>,
        rx: broadcast::Receiver<Arc<Event>>,
        shutdown: watch::Receiver<bool>,
        done: bool,
        _slot: StreamSlot,
    }
    let state = St { backlog, rx, shutdown: st.shutdown.clone(), done: false, _slot: slot };
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
        // The last event a participant gets: the session closed, or it left
        // or was revoked (its token no longer works).
        let me = &st._slot.who;
        st.done = match ev.kind {
            "closed" => true,
            "left" => ev.data["participant_pub"] == me.as_str(),
            "revoked" => {
                ev.data["participants"].as_array().is_some_and(|a| a.iter().any(|p| p == me.as_str()))
            }
            _ => false,
        };
        Some((Ok(sse_event(&ev)), st))
    });
    Ok(Sse::new(out).keep_alive(KeepAlive::default()))
}

/// An upload's claim on the session's quotas. The transfer charge for
/// bytes actually received stays even if the upload fails.
struct Reservation {
    session: Arc<Session>,
    id: String,
    bytes: u64,
    received: u64,
    committed: bool,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if !self.committed {
            let mut g = self.session.lock();
            g.pending.remove(&self.id);
            g.pending_bytes -= self.bytes;
            g.transfer_bytes -= self.bytes - self.received.min(self.bytes);
        }
    }
}

fn closed_if_missing(e: std::io::Error) -> ApiError {
    if e.kind() == std::io::ErrorKind::NotFound {
        ApiError::gone("closed", "session is closed")
    } else {
        e.into()
    }
}

/// A verified upload whose blob sits in a temp file, not yet in the log.
pub(crate) struct Upload {
    env_json: String,
    pub(crate) env: ItemEnvelope,
    blob_len: u64,
    blob_sha256: String,
    tmp_path: std::path::PathBuf,
    reservation: Reservation,
}

/// Read an upload frame (`u32_be(len) || envelope || blob`), check the
/// envelope against the author and header policy, and stream the blob to a
/// temp file while hashing it. `header_ok` decides which items this endpoint
/// takes, from the verified header.
pub(crate) async fn receive_upload(
    st: &AppState,
    s: &Arc<Session>,
    who: &str,
    role: Role,
    body: Body,
    header_ok: impl FnOnce(&ItemHeader) -> ApiResult<()>,
) -> ApiResult<Upload> {
    let cfg = st.store.cfg.clone();
    let mut chunks = body.into_data_stream();
    let mut buf: Vec<u8> = Vec::new();

    while buf.len() < 4 {
        match next_chunk(&mut chunks).await? {
            Some(c) => buf.extend_from_slice(&c),
            None => return Err(ApiError::bad_request("body", "truncated body")),
        }
    }
    let n = u32::from_be_bytes(buf[..4].try_into().expect("4 bytes")) as usize;
    if n > MAX_ENVELOPE_BYTES {
        return Err(ApiError::too_large("envelope too large"));
    }
    while buf.len() < 4 + n {
        match next_chunk(&mut chunks).await? {
            Some(c) => buf.extend_from_slice(&c),
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
    if h.size > s.signed.manifest.max_item_bytes {
        return Err(ApiError::too_large(format!(
            "item exceeds this session's limit of {} bytes",
            s.signed.manifest.max_item_bytes
        )));
    }
    policy::check_header(&s.signed.manifest, role, h)?;
    header_ok(h)?;
    let item_id = h.id.clone();
    let blob_len = h.blob_len()?;

    if !st.store.disk_ok() {
        return Err(ApiError::storage_full());
    }
    let mut reservation = {
        let mut g = s.lock();
        if g.items.contains_key(&item_id) || g.pending.contains(&item_id) {
            return Err(ApiError::conflict("an item with this id already exists"));
        }
        if g.items.len() + g.pending.len() >= cfg.max_items {
            return Err(ApiError::limit("session is at its item limit"));
        }
        if g.log_len() + env_json.len() as u64 + LOG_LINE_OVERHEAD > cfg.max_log_bytes {
            return Err(ApiError::too_large("session history limit reached"));
        }
        if g.held_bytes + g.pending_bytes + blob_len > cfg.max_session_bytes {
            return Err(ApiError::too_large("session would exceed its storage limit; wait for deliveries"));
        }
        // Pending uploads are already charged, so concurrent uploads cannot overshoot.
        if g.transfer_bytes + blob_len > cfg.max_session_transfer {
            return Err(ApiError::limit("session transfer limit reached"));
        }
        g.pending.insert(item_id.clone());
        g.pending_bytes += blob_len;
        g.transfer_bytes += blob_len;
        Reservation {
            session: s.clone(),
            id: item_id.clone(),
            bytes: blob_len,
            received: 0,
            committed: false,
        }
    };

    let first = Bytes::copy_from_slice(&buf[4 + n..]);
    let (tmp_path, digest) = receive_blob(s, &env, blob_len, first, chunks, &mut reservation).await?;
    let blob_sha256 = airlox_core::encoding::b64e(&digest);
    Ok(Upload { env_json, env, blob_len, blob_sha256, tmp_path, reservation })
}

/// Stream a blob (`first`, then the rest of the body) to a temp file in the
/// session's blob directory, checking its length and its SHA-256 against
/// the signed envelope. Returns the temp file's path and the SHA-256.
async fn receive_blob(
    s: &Session,
    env: &ItemEnvelope,
    blob_len: u64,
    first: Bytes,
    mut chunks: BodyDataStream,
    reservation: &mut Reservation,
) -> ApiResult<(std::path::PathBuf, [u8; 32])> {
    let tmp_path = s.dir.join("blobs").join(format!(".{}.{}.tmp", env.header.id, random_suffix()));
    // A steady trickle still has to finish: allow two minutes plus 16 KiB/s.
    let deadline = Duration::from_secs(120 + blob_len / (16 * 1024));
    let mut written: u64 = 0;
    let upload = async {
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .await
            .map_err(closed_if_missing)?;
        let mut hasher = Sha256::new();
        let mut chunk = first;
        loop {
            written += chunk.len() as u64;
            if written > blob_len {
                return Err(ApiError::bad_request("body", "blob is longer than the header size allows"));
            }
            hasher.update(&chunk);
            file.write_all(&chunk).await?;
            match next_chunk(&mut chunks).await? {
                Some(c) => chunk = c,
                None => break,
            }
        }
        if written != blob_len {
            return Err(ApiError::bad_request("body", "blob is shorter than the header size requires"));
        }
        file.sync_all().await?;
        Ok::<[u8; 32], ApiError>(hasher.finalize().into())
    };
    let result = match tokio::time::timeout(deadline, upload).await {
        Ok(r) => r,
        Err(_) => Err(ApiError::timeout()),
    };
    reservation.received = written;
    match result.and_then(|d| env.verify_blob_digest(blob_len, &d).map(|()| d).map_err(ApiError::from)) {
        Ok(d) => Ok((tmp_path, d)),
        Err(e) => {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            Err(e)
        }
    }
}

/// Move the blob into place and append the item to the log. `then` runs
/// under the same session lock right after the item is recorded, so routing
/// decisions and job state changes are atomic with it. Blocks on disk.
pub(crate) fn commit_upload<T>(
    s: &Arc<Session>,
    who: &str,
    up: Upload,
    then: impl FnOnce(&Session, &mut Inner, u64) -> ApiResult<T>,
) -> ApiResult<(u64, T)> {
    let Upload { env_json, env, blob_len, blob_sha256, tmp_path, mut reservation } = up;
    let final_path = s.blob_path(&env.header.id);
    let commit = || -> ApiResult<(u64, T)> {
        std::fs::rename(&tmp_path, &final_path).map_err(closed_if_missing)?;
        sync_dir(final_path.parent().expect("blob has a parent")).map_err(closed_if_missing)?;
        let mut g = s.lock();
        if g.closed {
            return Err(ApiError::gone("closed", "session is closed"));
        }
        // The author may have left, been rejected or revoked while uploading.
        if !g.is_live(who) {
            return Err(ApiError::unauthorized());
        }
        let recipients: Vec<String> = g.active_participants().filter(|k| *k != who).cloned().collect();
        g.pending.remove(&reservation.id);
        g.pending_bytes -= blob_len;
        // Applying the Item record charges the transfer for real.
        g.transfer_bytes -= blob_len;
        reservation.committed = true;
        let rec = Rec::Item { envelope: env_json, recipients, blob_len, blob_sha256: Some(blob_sha256) };
        let seq = match s.append(&mut g, rec) {
            Ok(ev) => ev.map(|e| e.seq).unwrap_or_default(),
            Err(e) => {
                g.transfer_bytes += blob_len;
                reservation.committed = false;
                // Reservation::drop releases pending; it re-locks, so drop the guard first.
                g.pending.insert(reservation.id.clone());
                g.pending_bytes += blob_len;
                reservation.received = blob_len;
                return Err(e.into());
            }
        };
        let out = then(s, &mut g, seq)?;
        Ok((seq, out))
    };
    let r = commit();
    if r.is_err() && !reservation.committed {
        let _ = std::fs::remove_file(&tmp_path);
        let _ = std::fs::remove_file(&final_path);
    }
    drop(reservation);
    r
}

/// `POST /v1/sessions/:id/items` — body: `u32_be(len) || envelope || blob`.
/// Jobs go through `POST /jobs` instead, so every job gets routed.
pub async fn post_item(
    State(st): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let s = session(&st, &id)?;
    let (who, role) = auth(&s, &headers)?;
    let s2 = s.clone();
    let who2 = who.clone();
    let up = receive_upload(&st, &s, &who, role, body, |h| {
        if h.kind == ItemKind::Job {
            return Err(ApiError::forbidden("submit jobs with POST /jobs"));
        }
        if role == Role::Runner {
            // A runner posts only as an eligible runner, and a result only
            // for a job the relay gave it.
            let g = s2.lock();
            if !g.runner_eligible(&who2) {
                return Err(ApiError::forbidden("this runner is not approved"));
            }
            let assigned =
                h.refs.iter().any(|r| g.jobs.get(&r.id).is_some_and(|j| j.runner.as_deref() == Some(&who2)));
            if h.kind == ItemKind::Result && !assigned {
                return Err(ApiError::forbidden("results must reference a job assigned to this runner"));
            }
        }
        Ok(())
    })
    .await?;
    let item_id = up.env.header.id.clone();
    let is_result = up.env.header.kind == ItemKind::Result;
    let refs: Vec<String> = up.env.header.refs.iter().map(|r| r.id.clone()).collect();
    let (seq, ()) = blocking(move || {
        commit_upload(&s, &who.clone(), up, |s, g, _| {
            // A result from the runner a job is assigned to finishes that job.
            if is_result {
                let done: Vec<String> = refs
                    .iter()
                    .filter(|j| {
                        g.jobs.get(*j).is_some_and(|r| r.state.active() && r.runner.as_deref() == Some(&who))
                    })
                    .cloned()
                    .collect();
                for j in done {
                    s.set_job(g, &j, JobState::Done, Some(who.clone()), None)?;
                }
            }
            Ok(())
        })
    })
    .await?;
    Ok((StatusCode::CREATED, Json(json!({"id": item_id, "seq": seq}))))
}

pub(crate) fn item_path_ok(item: &str) -> ApiResult<()> {
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
        g.last_activity_ms = now_ms();
        len
    };
    let file = match tokio::fs::File::open(s.blob_path(&item)).await {
        Ok(f) => f,
        Err(e) => {
            s.lock().transfer_bytes -= len;
            if e.kind() == std::io::ErrorKind::NotFound {
                return Err(ApiError::gone("evicted", "delivered and removed from the relay"));
            }
            return Err(e.into());
        }
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
    blocking(move || {
        let mut g = s.lock();
        let r = g.items.get(&item).ok_or_else(|| ApiError::not_found("no such item"))?;
        if r.recipients.contains(&who) && !r.acked.contains(&who) && !g.closed {
            s.append(&mut g, Rec::Ack { item, by: who })?;
        }
        Ok(())
    })
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/sessions/:id/items/:item/want` — ask the participants still
/// holding an evicted blob to upload it again. Only for a participant that
/// never received it; rate-limited per participant. Asking again while the
/// want is open refreshes it once `WANT_REFRESH_MS` has passed, and is a
/// no-op before that. A re-seed upload in progress does not answer a want:
/// it may fail, and the wanter must stay a recipient if it succeeds.
pub async fn want(
    State(st): State<AppState>,
    Path((id, item)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<(StatusCode, Json<Value>)> {
    item_path_ok(&item)?;
    let s = session(&st, &id)?;
    let (who, _) = auth(&s, &headers)?;
    let max_log = st.store.cfg.max_log_bytes;
    blocking(move || {
        let mut g = s.lock();
        if g.closed {
            return Err(ApiError::gone("closed", "session is closed"));
        }
        let r = g.items.get(&item).ok_or_else(|| ApiError::not_found("no such item"))?;
        if r.blob_present {
            return Err(ApiError::conflict_code("present", "the blob is on the relay; download it"));
        }
        if r.acked.contains(&who) {
            return Err(ApiError::forbidden("you have already received this item"));
        }
        let now = now_ms();
        g.prune_wants(now);
        match g.wants.get(&item).and_then(|w| w.get(&who)) {
            Some(t) if now.saturating_sub(*t) < WANT_REFRESH_MS => {
                return Ok((StatusCode::ACCEPTED, Json(json!({"open": true}))));
            }
            Some(_) => {}
            None => {
                if g.open_wants(&who) >= MAX_OPEN_WANTS {
                    return Err(ApiError::limit("too many open wants; wait for some to be answered"));
                }
                let asked = g.wanted_items.get(&who);
                if asked.is_some_and(|a| a.len() >= MAX_WANTS && !a.contains(&item)) {
                    return Err(ApiError::limit("this participant has asked for too many blobs"));
                }
            }
        }
        if g.log_len() + LOG_LINE_OVERHEAD > max_log {
            return Err(ApiError::too_large("session history limit reached"));
        }
        s.append(&mut g, Rec::Want { item, by: who })?;
        Ok((StatusCode::ACCEPTED, Json(json!({"open": true}))))
    })
    .await
}

/// `PUT /v1/sessions/:id/items/:item/blob` — re-seed an evicted blob: the
/// raw ciphertext, accepted only while a want for it is open and it is
/// absent, and only if its SHA-256 matches the author-signed envelope.
/// Holders may upload at once and the first to finish wins, so one slow or
/// stalled uploader cannot hold the others off.
pub async fn reseed(
    State(st): State<AppState>,
    Path((id, item)): Path<(String, String)>,
    headers: HeaderMap,
    body: Body,
) -> ApiResult<StatusCode> {
    item_path_ok(&item)?;
    let s = session(&st, &id)?;
    let (who, _) = auth(&s, &headers)?;
    if !st.store.disk_ok() {
        return Err(ApiError::storage_full());
    }
    let cfg = st.store.cfg.clone();
    // Pending under its own key, apart from the item id and from other
    // holders' uploads of the same blob.
    let key = format!("{item}/reseed/{who}");
    let (env, mut reservation) = {
        let mut g = s.lock();
        let r = g.items.get(&item).ok_or_else(|| ApiError::not_found("no such item"))?;
        if r.blob_present {
            return Err(ApiError::conflict_code("present", "the blob is on the relay"));
        }
        if g.pending.contains(&key) {
            return Err(ApiError::conflict_code("uploading", "you are already uploading this blob"));
        }
        let suffix = format!("/reseed/{who}");
        if g.pending.iter().filter(|k| k.ends_with(&suffix)).count() >= MAX_RESEEDS_IN_FLIGHT {
            return Err(ApiError::limit("too many re-seed uploads at once"));
        }
        let blob_len = r.blob_len;
        g.prune_wants(now_ms());
        if !g.wants.get(&item).is_some_and(|w| w.keys().any(|k| *k != who)) {
            return Err(ApiError::conflict_code("not_wanted", "no one is waiting for this blob"));
        }
        let env_json = g
            .item_event(&item)
            .and_then(|e| e.data["envelope"].as_str().map(str::to_string))
            .ok_or_else(|| ApiError::internal("item without its envelope"))?;
        let env: ItemEnvelope = parse_canonical(&env_json, "item envelope")?;
        if g.held_bytes + g.pending_bytes + blob_len > cfg.max_session_bytes {
            return Err(ApiError::too_large("session would exceed its storage limit; wait for deliveries"));
        }
        if g.transfer_bytes + blob_len > cfg.max_session_transfer {
            return Err(ApiError::limit("session transfer limit reached"));
        }
        g.pending.insert(key.clone());
        g.pending_bytes += blob_len;
        g.transfer_bytes += blob_len;
        let res = Reservation {
            session: s.clone(),
            id: key.clone(),
            bytes: blob_len,
            received: 0,
            committed: false,
        };
        (env, res)
    };
    let blob_len = reservation.bytes;
    let (tmp_path, _) =
        receive_blob(&s, &env, blob_len, Bytes::new(), body.into_data_stream(), &mut reservation).await?;
    blocking(move || {
        let final_path = s.blob_path(&item);
        // Checked and moved into place under the lock: another holder's
        // upload may have won meanwhile, and its file must not be touched.
        let mut placed = false;
        let mut commit = || -> ApiResult<()> {
            let mut g = s.lock();
            if g.closed {
                return Err(ApiError::gone("closed", "session is closed"));
            }
            if !g.is_live(&who) {
                return Err(ApiError::unauthorized());
            }
            if g.items.get(&item).is_some_and(|r| r.blob_present) {
                return Err(ApiError::conflict_code("present", "another holder re-seeded it first"));
            }
            // The wanters may have left, been revoked or stopped asking
            // during the upload; then nobody would fetch it.
            g.prune_wants(now_ms());
            if !g.wants.get(&item).is_some_and(|w| w.keys().any(|k| *k != who)) {
                return Err(ApiError::conflict_code(
                    "not_wanted",
                    "no one is waiting for this blob any more",
                ));
            }
            std::fs::rename(&tmp_path, &final_path).map_err(closed_if_missing)?;
            placed = true;
            sync_dir(final_path.parent().expect("blob has a parent")).map_err(closed_if_missing)?;
            g.pending.remove(&key);
            g.pending_bytes -= blob_len;
            // Applying the Reseed record charges the transfer for real.
            g.transfer_bytes -= blob_len;
            reservation.committed = true;
            if let Err(e) = s.append(&mut g, Rec::Reseed { item: item.clone(), by: who.clone() }) {
                g.transfer_bytes += blob_len;
                g.pending.insert(key.clone());
                g.pending_bytes += blob_len;
                reservation.committed = false;
                reservation.received = blob_len;
                return Err(e.into());
            }
            Ok(())
        };
        let r = commit();
        if r.is_err() && !reservation.committed {
            let _ = std::fs::remove_file(&tmp_path);
            if placed {
                let _ = std::fs::remove_file(&final_path);
            }
        }
        drop(reservation);
        r
    })
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/sessions/:id/roles/:role/revoke` — owner only. The role's
/// participants are cut off (their tokens stop working, a runner's active
/// job fails) and its invite admits no one from then on. Anyone who kept the
/// invite still holds the session key and can decrypt what they copied;
/// only closing the session ends access to the rest.
pub async fn revoke_role(
    State(st): State<AppState>,
    Path((id, role)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    let s = session(&st, &id)?;
    let (_, by) = auth(&s, &headers)?;
    if by != Role::Owner {
        return Err(ApiError::forbidden("only the owner may revoke a role"));
    }
    let role = Role::parse(&role)
        .ok()
        .filter(|r| *r != Role::Owner)
        .ok_or_else(|| ApiError::not_found("no such role; revoke sender, observer or runner"))?;
    blocking(move || {
        let mut g = s.lock();
        if g.closed {
            return Err(ApiError::gone("closed", "session is closed"));
        }
        if g.revoked.contains(&role) {
            return Ok(());
        }
        let cut: HashSet<String> = g
            .participants
            .iter()
            .filter(|(_, p)| p.role == role && !p.left && !p.rejected)
            .map(|(k, _)| k.clone())
            .collect();
        // A cut-off runner's job fails, and so does any job a cut-off
        // sender still has queued or running.
        for r in cut.iter().filter(|_| role == Role::Runner) {
            s.fail_runner_job(&mut g, r, "runner_revoked")?;
        }
        let mut authored: Vec<(String, Option<String>)> = g
            .jobs
            .iter()
            .filter(|(_, j)| j.state.active() && cut.contains(&j.author))
            .map(|(id, j)| (id.clone(), j.runner.clone()))
            .collect();
        authored.sort();
        for (job, runner) in authored {
            s.set_job(&mut g, &job, JobState::Failed, runner.clone(), Some("author_revoked"))?;
            if let Some(r) = &runner {
                s.tell_runner(r, "job_cancel", json!({"job": job}));
            }
        }
        s.append(&mut g, Rec::Revoke { role })?;
        Ok(())
    })
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /v1/sessions/:id/audit.jsonl` — owner or observer. The session's
/// history as JSONL, derived from its log (envelopes, hashes and events,
/// never ciphertext). It is purged with the session, so export it first.
pub async fn audit(
    State(st): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let s = session(&st, &id)?;
    let (_, role) = auth(&s, &headers)?;
    if !matches!(role, Role::Owner | Role::Observer) {
        return Err(ApiError::forbidden("only the owner and observers may export the audit trail"));
    }
    let name = format!("attachment; filename=\"{}-audit.jsonl\"", s.id);
    let _permit =
        AUDITS.try_acquire().map_err(|_| ApiError::limit("the relay is busy exporting; try again"))?;
    let body = blocking(move || Ok(s.audit()?)).await?;
    Ok((
        [(header::CONTENT_TYPE, "application/x-ndjson".to_string()), (header::CONTENT_DISPOSITION, name)],
        body,
    )
        .into_response())
}
