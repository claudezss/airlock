//! Execute mode: runner approval, job routing, claims, heartbeats, cancels
//! and the per-runner assignment stream.
//!
//! The relay cannot read a job, so the sender names its target in the
//! `Airlox-Target` header next to the sealed job item. The relay routes on
//! that copy; the runner refuses a job whose signed target does not match
//! it. Routing is "no queue": a job either goes to a runner with a free slot
//! at once or fails with `runner_busy` (a matching runner is online but all
//! its slots are taken) or `no_runner_available`. A runner declares its slots
//! (how many jobs it runs at once) in its signed join.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use airlox_core::cert::is_runner_token;
use airlox_core::item::ItemKind;
use airlox_core::keys::PublicKey;
use airlox_core::payload::Target;
use airlox_core::policy::target_matches;
use airlox_core::session::{ContentType, JobKind, Mode, Role};
use axum::body::Body;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::Json;
use futures_util::Stream;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::{broadcast, watch};

use crate::api::{
    auth, blocking, commit_upload, item_path_ok, read_json_body, receive_upload, session, uploader, AppState,
};
use crate::error::{ApiError, ApiResult};
use crate::store::{Event, Inner, JobState, Participant, Rec, RunnerMsg, Session};
use crate::util::now_ms;

/// Header carrying a job's routing target (the `target` JSON of protocol §7).
pub const TARGET_HEADER: &str = "airlox-target";
/// Concurrent assignment streams per runner.
pub const MAX_RUNNER_STREAMS: usize = 2;

fn require_execute(s: &Session) -> ApiResult<()> {
    if s.signed.manifest.mode == Mode::Execute {
        Ok(())
    } else {
        Err(ApiError::forbidden("session is in relay mode"))
    }
}

fn parse_target(headers: &HeaderMap) -> ApiResult<Target> {
    let raw = headers
        .get(TARGET_HEADER)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::bad_request("invalid", "missing Airlox-Target header"))?;
    let t: Target = serde_json::from_str(raw)
        .map_err(|e| ApiError::bad_request("invalid", format!("bad Airlox-Target: {e}")))?;
    let ok = match &t {
        Target::Runner { name, .. } => is_runner_token(name),
        Target::Labels { labels } => {
            !labels.is_empty() && labels.len() <= 16 && labels.iter().all(|l| is_runner_token(l))
        }
        Target::Any => true,
    };
    if !ok {
        return Err(ApiError::bad_request("invalid", "bad Airlox-Target"));
    }
    Ok(t)
}

fn job_json(id: &str, g: &Inner) -> Option<Value> {
    let j = g.jobs.get(id)?;
    Some(json!({"job": id, "state": j.state, "runner": j.runner, "reason": j.reason}))
}

/// Eligible, online runners that match the target, earliest joined first.
fn matching_runners<'a>(
    g: &'a Inner,
    target: &Target,
    kind: JobKind,
    now: u64,
    timeout_ms: u64,
) -> Vec<(&'a String, &'a Participant)> {
    let mut found: Vec<_> = g
        .participants
        .iter()
        .filter(|(pk, _)| g.runner_eligible(pk) && g.runner_online(pk, now, timeout_ms))
        // The kinds a runner signed in its join: one that would only
        // refuse the job is no match.
        .filter(|(_, p)| p.runner.as_ref().is_some_and(|r| r.kinds.contains(&kind)))
        .filter(|(pk, p)| {
            let labels = p.runner.as_ref().map(|r| r.labels.as_slice()).unwrap_or_default();
            PublicKey::from_b64(pk).is_ok_and(|key| target_matches(target, key, labels))
        })
        .collect();
    found.sort_by_key(|(_, p)| p.seq);
    found
}

/// Pick the runner for a job: eligible, online, matching the target and with
/// a free slot. The least loaded (active jobs per slot) wins, so jobs spread
/// over runners; ties go to the earliest joined.
fn pick_runner(g: &Inner, target: &Target, kind: JobKind, now: u64, timeout_ms: u64) -> Option<String> {
    // jobs/slots compared as a cross product, without division.
    let fuller = |a: &(&String, &Participant), b: &(&String, &Participant)| {
        (a.1.jobs.len() * g.runner_slots(b.0)).cmp(&(b.1.jobs.len() * g.runner_slots(a.0)))
    };
    matching_runners(g, target, kind, now, timeout_ms)
        .into_iter()
        .filter(|(pk, _)| g.runner_has_room(pk))
        .min_by(fuller)
        .map(|(pk, _)| pk.clone())
}

/// The name of a runner that would take the job if it had a free slot:
/// eligible, online, matching, and with every slot taken.
fn busy_runner(g: &Inner, target: &Target, kind: JobKind, now: u64, timeout_ms: u64) -> Option<String> {
    matching_runners(g, target, kind, now, timeout_ms)
        .into_iter()
        .find(|(pk, _)| !g.runner_has_room(pk))
        .map(|(_, p)| p.runner.as_ref().map(|r| r.name.clone()).unwrap_or_default())
}

/// `POST /v1/sessions/:id/jobs` — header `Airlox-Target`, body an upload
/// frame holding a `job` item. `201` once a runner has it; otherwise the
/// job is stored as failed (so the timeline shows it) and the answer is
/// `409 runner_busy` when a matching runner is online but has no free slot, otherwise
/// `409 no_runner_available`. Jobs are never queued.
pub async fn post_job(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let s = session(&st, &id)?;
    let (who, role) = auth(&s, &headers)?;
    require_execute(&s)?;
    let target = parse_target(&headers)?;
    let ip_hash = uploader(&st, &headers, peer);
    let up = receive_upload(&st, &s, &who, role, ip_hash, body, |h| match h.kind {
        ItemKind::Job => Ok(()),
        _ => Err(ApiError::forbidden("POST /jobs takes job items only")),
    })
    .await?;
    let job = up.env.header.id.clone();
    // The header's subkind is the job's kind (protocol §6).
    let kind = if up.env.header.subkind == Some(ContentType::Sh) { JobKind::Shell } else { JobKind::Python };
    let timeout_ms = st.store.cfg.runner_timeout_ms;
    let job2 = job.clone();
    let (seq, routed) = blocking(move || {
        commit_upload(&s, &who, up, |s, g, _| {
            let now = now_ms();
            match pick_runner(g, &target, kind, now, timeout_ms) {
                Some(r) => {
                    s.set_job(g, &job2, JobState::Assigned, Some(r.clone()), None)?;
                    let envelope = g.item_event(&job2).map(|e| e.data["envelope"].clone());
                    s.tell_runner(&r, "job_assigned", json!({"job": job2, "envelope": envelope}));
                    Ok(Ok(r))
                }
                None => {
                    let busy = busy_runner(g, &target, kind, now, timeout_ms);
                    let reason = if busy.is_some() { "runner_busy" } else { "not_available" };
                    s.set_job(g, &job2, JobState::Failed, None, Some(reason))?;
                    Ok(Err(busy))
                }
            }
        })
    })
    .await?;
    match routed {
        Ok(r) => Ok((
            StatusCode::CREATED,
            Json(json!({"id": job, "seq": seq, "state": JobState::Assigned, "runner": r})),
        )),
        Err(Some(name)) => Err(ApiError::conflict_code(
            "runner_busy",
            format!("runner {name} matches job {job} but has no free slot; it was not queued"),
        )),
        Err(None) => Err(ApiError::no_runner(format!(
            "no approved, online runner that runs {} jobs and has a free slot matches job {job}; it was not \
             queued",
            kind.as_str()
        ))),
    }
}

/// `GET /v1/sessions/:id/jobs/:job` — the relay's routing view of a job.
pub async fn get_job(
    State(st): State<AppState>,
    Path((id, job)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    item_path_ok(&job)?;
    let s = session(&st, &id)?;
    auth(&s, &headers)?;
    let g = s.lock();
    job_json(&job, &g).map(Json).ok_or_else(|| ApiError::not_found("no such job"))
}

/// `POST /v1/sessions/:id/jobs/:job/claim` — the assigned runner takes the job.
pub async fn claim_job(
    State(st): State<AppState>,
    Path((id, job)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    item_path_ok(&job)?;
    let s = session(&st, &id)?;
    let (who, role) = auth(&s, &headers)?;
    if role != Role::Runner {
        return Err(ApiError::forbidden("only runners claim jobs"));
    }
    blocking(move || {
        let mut g = s.lock();
        g.presence.entry(who.clone()).or_default().last_seen_ms = now_ms();
        let j = g.jobs.get(&job).ok_or_else(|| ApiError::not_found("no such job"))?;
        if j.runner.as_deref() != Some(who.as_str()) {
            return Err(ApiError::conflict("this job is not assigned to you"));
        }
        match j.state {
            JobState::Assigned => s.set_job(&mut g, &job, JobState::Running, Some(who), None)?,
            JobState::Running => {}
            _ => return Err(ApiError::conflict("this job is no longer assigned to you")),
        }
        Ok(StatusCode::NO_CONTENT)
    })
    .await
}

/// `POST /v1/sessions/:id/jobs/:job/cancel` — the owner or the job's author.
/// An unclaimed job fails at once; a running one is cancelled by its runner,
/// which then posts a `cancelled` result.
pub async fn cancel_job(
    State(st): State<AppState>,
    Path((id, job)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<(StatusCode, Json<Value>)> {
    item_path_ok(&job)?;
    let s = session(&st, &id)?;
    let (who, role) = auth(&s, &headers)?;
    blocking(move || {
        let mut g = s.lock();
        let j = g.jobs.get(&job).ok_or_else(|| ApiError::not_found("no such job"))?;
        if !(role == Role::Owner || (role == Role::Sender && j.author == who)) {
            return Err(ApiError::forbidden("only the owner or the job's sender may cancel it"));
        }
        let runner = j.runner.clone();
        match j.state {
            JobState::Assigned => {
                s.set_job(&mut g, &job, JobState::Failed, runner.clone(), Some("cancelled"))?;
            }
            JobState::Running => {
                // Remembered so a runner that reconnects still gets it.
                if let Some(j) = g.jobs.get_mut(&job) {
                    j.cancel_requested = true;
                }
            }
            _ => return Err(ApiError::conflict("the job has already finished")),
        }
        if let Some(r) = &runner {
            s.tell_runner(r, "job_cancel", json!({"job": job}));
        }
        let out = job_json(&job, &g).unwrap_or_default();
        Ok((StatusCode::ACCEPTED, Json(out)))
    })
    .await
}

/// `GET /v1/sessions/:id/runners` — runners that have not left, with the
/// relay's view of approval, presence and load (`jobs`, `slots`, `busy`: no
/// free slot). Clients verify approvals
/// themselves from the owner's signed `runner_approve` events.
pub async fn runners(
    State(st): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let s = session(&st, &id)?;
    auth(&s, &headers)?;
    let now = now_ms();
    let timeout_ms = st.store.cfg.runner_timeout_ms;
    let g = s.lock();
    let mut list: Vec<_> = g.participants.iter().filter(|(_, p)| p.role == Role::Runner && !p.left).collect();
    list.sort_by_key(|(_, p)| p.seq);
    let out: Vec<Value> = list
        .into_iter()
        .map(|(pk, p)| {
            let busy = !g.runner_has_room(pk);
            json!({
                "participant_pub": pk,
                "runner": p.runner,
                "approved": p.approved,
                "rejected": p.rejected,
                "online": g.runner_online(pk, now, timeout_ms),
                "jobs": p.jobs,
                "slots": g.runner_slots(pk),
                // No free slot. `job` (an active job, only when busy) is what
                // clients from before slots read as "busy".
                "busy": busy,
                "job": p.jobs.iter().next().filter(|_| busy),
                "state": g.presence.get(pk).and_then(|x| x.state.clone()),
                "detail": g.presence.get(pk).and_then(|x| x.detail.clone()),
                "signed_join": p.public["signed_join"],
            })
        })
        .collect();
    Ok(Json(json!({"runners": out, "approval_required": g.approve_runners()})))
}

fn owner_only(role: Role) -> ApiResult<()> {
    if role == Role::Owner {
        Ok(())
    } else {
        Err(ApiError::forbidden("only the owner may approve or reject runners"))
    }
}

fn runner_target<'a>(g: &'a Inner, pk: &str) -> ApiResult<&'a crate::store::Participant> {
    g.participants
        .get(pk)
        .filter(|p| p.role == Role::Runner && !p.left)
        .ok_or_else(|| ApiError::not_found("no such runner"))
}

/// `POST /v1/sessions/:id/runners/:participant/approve` — owner. The owner
/// also posts a signed `runner_approve` event; this is the relay's copy.
pub async fn approve_runner(
    State(st): State<AppState>,
    Path((id, pk)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    let s = session(&st, &id)?;
    let (_, role) = auth(&s, &headers)?;
    owner_only(role)?;
    require_execute(&s)?;
    blocking(move || {
        let mut g = s.lock();
        let p = runner_target(&g, &pk)?;
        if p.rejected {
            return Err(ApiError::conflict("this runner was rejected"));
        }
        if !p.approved {
            s.append(&mut g, Rec::Approve { who: pk })?;
        }
        Ok(StatusCode::NO_CONTENT)
    })
    .await
}

/// `POST /v1/sessions/:id/runners/:participant/reject` — owner. Revokes the
/// runner's token, fails its job and ends its streams.
pub async fn reject_runner(
    State(st): State<AppState>,
    Path((id, pk)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    let s = session(&st, &id)?;
    let (_, role) = auth(&s, &headers)?;
    owner_only(role)?;
    require_execute(&s)?;
    blocking(move || {
        let mut g = s.lock();
        if runner_target(&g, &pk)?.rejected {
            return Ok(StatusCode::NO_CONTENT);
        }
        s.fail_runner_jobs(&mut g, &pk, "runner_rejected")?;
        s.append(&mut g, Rec::Reject { who: pk.clone() })?;
        s.tell_runner(&pk, "rejected", json!({}));
        Ok(StatusCode::NO_CONTENT)
    })
    .await
}

#[derive(Deserialize, Default)]
struct Heartbeat {
    /// The jobs the runner is working on.
    #[serde(default)]
    jobs: Vec<String>,
    /// The runner's setup: `preparing`, `ready` or `failed`. Kept until the
    /// next heartbeat that carries one.
    #[serde(default)]
    state: Option<String>,
    /// Why, for `failed`; at most `MAX_DETAIL_CHARS`.
    #[serde(default)]
    detail: Option<String>,
}

pub const MAX_DETAIL_CHARS: usize = 300;
/// Most job ids one heartbeat may name (a runner's slots, plus the jobs it
/// still owes an answer for after a restart).
pub const MAX_HEARTBEAT_JOBS: usize = 64;

/// `POST /v1/sessions/:id/runners/me/heartbeat` — body `{"jobs": [id…],
/// "state": "preparing"|"ready"|"failed", "detail": text}` (all optional).
/// A running job the runner leaves out of `jobs` is lost: it fails. A job the
/// relay failed as `runner_lost` (the runner was cut off, not gone) that the
/// runner names again comes back, while the runner has a free slot for it.
pub async fn heartbeat(
    State(st): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> ApiResult<Json<Value>> {
    let s = session(&st, &id)?;
    let (who, role) = auth(&s, &headers)?;
    if role != Role::Runner {
        return Err(ApiError::forbidden("only runners send heartbeats"));
    }
    let raw = read_json_body(body).await?;
    let hb: Heartbeat = if raw.trim().is_empty() {
        Heartbeat::default()
    } else {
        serde_json::from_str(&raw).map_err(|e| ApiError::bad_request("invalid", e.to_string()))?
    };
    if hb.state.as_deref().is_some_and(|st| !matches!(st, "preparing" | "ready" | "failed")) {
        return Err(ApiError::bad_request("invalid", "state must be preparing, ready or failed"));
    }
    if hb.detail.as_ref().is_some_and(|d| d.chars().count() > MAX_DETAIL_CHARS) {
        return Err(ApiError::bad_request(
            "invalid",
            format!("detail is over {MAX_DETAIL_CHARS} characters"),
        ));
    }
    if hb.jobs.len() > MAX_HEARTBEAT_JOBS {
        return Err(ApiError::bad_request(
            "invalid",
            format!("a heartbeat names at most {MAX_HEARTBEAT_JOBS} jobs"),
        ));
    }
    blocking(move || {
        let mut g = s.lock();
        let presence = g.presence.entry(who.clone()).or_default();
        presence.last_seen_ms = now_ms();
        if hb.state.is_some() {
            presence.state = hb.state;
            presence.detail = hb.detail;
        }
        for job in &hb.jobs {
            if g.lost_by(job, &who) && g.runner_has_room(&who) {
                tracing::info!(session = %s.id, job, "runner reconnected; its job is running again");
                s.set_job(&mut g, job, JobState::Running, Some(who.clone()), None)?;
            }
        }
        let current: Vec<String> =
            g.participants.get(&who).map(|p| p.jobs.iter().cloned().collect()).unwrap_or_default();
        for job in current {
            let running = g.jobs.get(&job).is_some_and(|j| j.state == JobState::Running);
            if running && !hb.jobs.contains(&job) {
                s.set_job(&mut g, &job, JobState::Failed, Some(who.clone()), Some("runner_lost"))?;
            }
        }
        let p = g.participants.get(&who);
        Ok(Json(json!({
            "approved": p.is_some_and(|p| p.approved) || !g.approve_runners(),
            "jobs": p.map(|p| p.jobs.clone()).unwrap_or_default(),
        })))
    })
    .await
}

/// Counts a runner's open assignment streams.
struct RunnerSlot {
    session: Arc<Session>,
    who: String,
}

impl Drop for RunnerSlot {
    fn drop(&mut self) {
        let mut g = self.session.lock();
        if let Some(p) = g.presence.get_mut(&self.who) {
            p.streams = p.streams.saturating_sub(1);
        }
        // A machine idle between jobs counts as idle from when it drops off.
        g.last_activity_ms = g.last_activity_ms.max(now_ms());
    }
}

fn runner_event(m: &RunnerMsg) -> SseEvent {
    SseEvent::default().event(m.kind).data(m.data.to_string())
}

/// `GET /v1/sessions/:id/runners/me/stream` — SSE for one runner:
/// `job_assigned {job, envelope}`, `job_cancel {job}` and `rejected {}`.
/// On connect it repeats each of the runner's active assignments (and the
/// pending cancel of each), oldest first, so a runner that reconnects loses
/// none. Holding this stream (plus heartbeats) is what makes a runner online.
pub async fn runner_stream(
    State(st): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Sse<impl Stream<Item = Result<SseEvent, Infallible>>>> {
    let s = session(&st, &id)?;
    let (who, role) = auth(&s, &headers)?;
    if role != Role::Runner {
        return Err(ApiError::forbidden("only runners open an assignment stream"));
    }
    let (backlog, rx, closed_rx, slot) = {
        let mut g = s.lock();
        let p = g.presence.entry(who.clone()).or_default();
        if p.streams >= MAX_RUNNER_STREAMS {
            return Err(ApiError::limit("too many open streams for this runner"));
        }
        p.streams += 1;
        p.last_seen_ms = now_ms();
        let mut active: Vec<(u64, String)> = g
            .participants
            .get(&who)
            .into_iter()
            .flat_map(|p| p.jobs.iter())
            .map(|j| (g.jobs.get(j).map_or(0, |r| r.since_ms), j.clone()))
            .collect();
        active.sort();
        let mut backlog = std::collections::VecDeque::new();
        for (_, job) in active {
            let envelope = g.item_event(&job).map(|e| e.data["envelope"].clone());
            let msg = |kind, data| Arc::new(RunnerMsg { runner: who.clone(), kind, data });
            backlog.push_back(msg("job_assigned", json!({"job": job, "envelope": envelope})));
            if g.jobs.get(&job).is_some_and(|j| j.cancel_requested) {
                backlog.push_back(msg("job_cancel", json!({"job": job})));
            }
        }
        (
            backlog,
            s.runner_tx.subscribe(),
            s.tx.subscribe(),
            RunnerSlot { session: s.clone(), who: who.clone() },
        )
    };
    struct St {
        who: String,
        backlog: std::collections::VecDeque<Arc<RunnerMsg>>,
        rx: broadcast::Receiver<Arc<RunnerMsg>>,
        closed_rx: broadcast::Receiver<Arc<Event>>,
        shutdown: watch::Receiver<bool>,
        done: bool,
        _slot: RunnerSlot,
    }
    let state = St { who, backlog, rx, closed_rx, shutdown: st.shutdown.clone(), done: false, _slot: slot };
    let out = futures_util::stream::unfold(state, |mut st| async move {
        if st.done {
            return None;
        }
        let msg = loop {
            if let Some(m) = st.backlog.pop_front() {
                break m;
            }
            tokio::select! {
                r = st.rx.recv() => match r {
                    Ok(m) if m.runner == st.who => break m,
                    Ok(_) => continue,
                    // Lagged or closed: end; the runner reconnects and gets its assignment again.
                    Err(_) => return None,
                },
                r = st.closed_rx.recv() => match r {
                    Ok(e) if e.kind == "closed" => return None,
                    Ok(e) if e.kind == "revoked"
                        && e.data["participants"].as_array().is_some_and(|a| a.iter().any(|p| p == st.who.as_str())) =>
                    {
                        return None
                    }
                    Ok(_) => continue,
                    // Lagged: it may have missed its own revocation; end, and
                    // a reconnect re-checks its token.
                    Err(_) => return None,
                },
                _ = st.shutdown.changed() => return None,
            }
        };
        if msg.kind == "rejected" {
            st.done = true;
        }
        Some((Ok(runner_event(&msg)), st))
    });
    Ok(Sse::new(out).keep_alive(KeepAlive::default()))
}
