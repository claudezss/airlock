//! File-backed storage: one directory per session, no database.
//!
//! ```text
//! $DATA/LOCK                       exclusive flock while a server runs
//! $DATA/ip.key                     secret for hashing client addresses
//! $DATA/sessions/<id>/manifest.json
//! $DATA/sessions/<id>/log.jsonl    append-only, replayed at startup
//! $DATA/sessions/<id>/blobs/<item> ciphertext until evicted (or re-seeded)
//! $DATA/tombstones/<id>            closed sessions that must not be re-created
//! $DATA/trash/                     purged sessions awaiting deletion
//! ```
//!
//! Every state change is a log line, fsynced before it is applied or
//! broadcast, so the in-memory index can always be rebuilt from the log and
//! no client ever sees an event id that a crash could reuse. Runner presence
//! (open streams, heartbeats) lives in memory only.
//!
//! `progress` items are the exception: output chunks arrive by the hundred
//! and are display only, so they are never logged. They take event ids from
//! a block the log reserved first ([`Rec::Reserve`]), live in memory until
//! delivered or held out, and then vanish without a trace: no envelope, no
//! event. A restart forgets the ones in flight.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};

use airlox_core::cert::{RunnerInfo, SignedJoinRequest};
use airlox_core::encoding::{parse_canonical, sha256};
use airlox_core::item::{ItemEnvelope, ItemKind};
use airlox_core::session::{is_session_id, Mode, Role, SignedManifest};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::broadcast;

use crate::config::Config;
use crate::util::{now_ms, random_bytes, random_suffix};

pub const MAX_PARTICIPANTS: usize = 64;
/// Concurrent SSE streams per participant.
pub const MAX_STREAMS_PER_PARTICIPANT: usize = 4;
/// How long a `want` stays open for holders to answer. Clients ask again
/// while they still lack the blob.
pub const WANT_TTL_MS: u64 = 10 * 60 * 1000;
/// Open wants per participant, and distinct items a participant may ask
/// for over the session.
pub const MAX_OPEN_WANTS: usize = 16;
pub const MAX_WANTS: usize = 1024;
/// `want` log lines per participant and per session (about 140 bytes
/// each), so asking cannot fill the session log.
pub const MAX_WANT_LINES: u32 = 256;
pub const MAX_WANT_LINES_SESSION: u32 = 2048;
/// The longest a re-seeded blob stays (capped by the blob hold).
pub const RESEED_HOLD_MS: u64 = 10 * 60 * 1000;
/// The owner's signed events (runner approvals and rejections, close) up to
/// this size stay on the relay for the session's life, so a late joiner can
/// always check who the owner approved.
pub const KEEP_EVENT_BYTES: u64 = 16 * 1024;
const EVENT_BUFFER: usize = 1024;
/// Event ids reserved in the log at a time for progress items, which are not
/// logged themselves: after a crash no id handed out in the block is reused.
const SEQ_RESERVE: u64 = 1024;

/// One state change. Serialized as a line of `log.jsonl`.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Rec {
    Create {
        ip_hash: String,
    },
    Join {
        signed_join: String,
        token_sha256: String,
    },
    Item {
        envelope: String,
        recipients: Vec<String>,
        blob_len: u64,
        /// base64url SHA-256 of the blob, which the author's signature
        /// covers; absent in logs written before it was recorded.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        blob_sha256: Option<String>,
        /// The uploader's address hash, whose per-address storage the blob
        /// counts against while it is held. Never exported.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ip_hash: Option<String>,
    },
    Ack {
        item: String,
        by: String,
    },
    Leave {
        who: String,
    },
    Evict {
        item: String,
    },
    /// A participant that never got an evicted blob asked holders for it.
    Want {
        item: String,
        by: String,
    },
    /// A holder uploaded an evicted blob again, for the open wants.
    Reseed {
        item: String,
        by: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ip_hash: Option<String>,
    },
    /// The owner revoked a role: its participants are cut off and its
    /// invite admits no one.
    Revoke {
        role: Role,
    },
    Close {
        reason: String,
    },
    /// The next `count` event ids may go to progress items, which are not
    /// logged: replay skips them instead of reusing them.
    Reserve {
        count: u64,
    },
    /// The owner let a runner take jobs.
    Approve {
        who: String,
    },
    /// The owner turned a runner away; like `Leave`, its token stops working.
    Reject {
        who: String,
    },
    /// A job's relay-side state. The signed result is the source of truth;
    /// this only tracks routing.
    Job {
        job: String,
        state: JobState,
        runner: Option<String>,
        reason: Option<String>,
    },
    /// A record from a newer relay, read by an older one after a rollback:
    /// skipped, so the session survives instead of being purged.
    #[serde(other)]
    Unknown,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    /// Sent to a runner, which has not claimed it yet.
    Assigned,
    /// Claimed by its runner.
    Running,
    /// Its runner posted a result referencing it.
    Done,
    /// Never ran or was abandoned; see the reason.
    Failed,
}

impl JobState {
    pub fn active(self) -> bool {
        matches!(self, JobState::Assigned | JobState::Running)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LogLine {
    pub seq: u64,
    pub ts_ms: u64,
    #[serde(flatten)]
    pub rec: Rec,
}

/// A public event: what `/events` returns and SSE streams.
#[derive(Serialize, Debug, Clone)]
pub struct Event {
    pub seq: u64,
    pub kind: &'static str,
    pub data: Value,
}

pub struct Participant {
    pub role: Role,
    pub seq: u64,
    pub public: Value,
    pub left: bool,
    pub runner: Option<RunnerInfo>,
    pub approved: bool,
    pub rejected: bool,
    /// The runner's active jobs (assigned or running), at most its slots.
    pub jobs: BTreeSet<String>,
}

pub struct JobRec {
    pub author: String,
    pub runner: Option<String>,
    pub state: JobState,
    pub reason: Option<String>,
    /// When it entered its current state.
    pub since_ms: u64,
    /// A cancel was requested while it ran (in memory only).
    pub cancel_requested: bool,
}

/// A runner's liveness. In memory only: after a restart runners reconnect.
#[derive(Default)]
pub struct Presence {
    pub streams: usize,
    pub last_seen_ms: u64,
    /// What the runner last said about its setup (`preparing`, `ready`,
    /// `failed`) and why: its own unsigned word, shown so a runner that
    /// cannot start is not just missing.
    pub state: Option<String>,
    pub detail: Option<String>,
}

/// A message on one runner's private stream.
#[derive(Debug, Clone)]
pub struct RunnerMsg {
    pub runner: String,
    pub kind: &'static str,
    pub data: Value,
}

/// Bytes held or being uploaded per uploader address hash, over every
/// session, for `max_bytes_per_ip`. Sessions add and remove their blobs as
/// they apply records, and give everything back when they are dropped.
#[derive(Default)]
pub struct IpUsage(std::sync::Mutex<HashMap<String, u64>>);

impl IpUsage {
    fn map(&self) -> std::sync::MutexGuard<'_, HashMap<String, u64>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn get(&self, ip: &str) -> u64 {
        self.map().get(ip).copied().unwrap_or(0)
    }

    /// Add `n` bytes for `ip` unless that would pass `cap`.
    pub fn try_add(&self, ip: &str, n: u64, cap: u64) -> bool {
        let mut m = self.map();
        let used = m.entry(ip.to_string()).or_default();
        if used.saturating_add(n) > cap {
            return false;
        }
        *used += n;
        true
    }

    pub fn add(&self, ip: Option<&str>, n: u64) {
        if let Some(ip) = ip {
            *self.map().entry(ip.to_string()).or_default() += n;
        }
    }

    pub fn sub(&self, ip: Option<&str>, n: u64) {
        let Some(ip) = ip else { return };
        let mut m = self.map();
        if let Some(used) = m.get_mut(ip) {
            *used = used.saturating_sub(n);
            if *used == 0 {
                m.remove(ip);
            }
        }
    }
}

impl Drop for Inner {
    /// A purged or unloaded session no longer holds its blobs.
    fn drop(&mut self) {
        for r in self.items.values().filter(|r| r.blob_present) {
            self.usage.sub(r.ip_hash.as_deref(), r.blob_len);
        }
    }
}

pub struct ItemRec {
    pub seq: u64,
    /// The address hash whose storage the held blob counts against.
    pub ip_hash: Option<String>,
    pub author: String,
    pub recipients: HashSet<String>,
    pub acked: HashSet<String>,
    pub blob_len: u64,
    pub blob_present: bool,
    pub evict_at: u64,
    /// Never evicted: a small signed event from the owner.
    pub keep: bool,
    /// A `progress` item: not logged, not counted toward the session's
    /// history, and forgotten entirely once its blob goes.
    pub progress: bool,
}

pub struct Inner {
    log: File,
    log_len: u64,
    /// Set when a failed write could not be rolled back; the session then
    /// refuses further writes rather than corrupt its log.
    broken: bool,
    next_seq: u64,
    pub participants: HashMap<String, Participant>,
    tokens: HashMap<String, String>,
    pub items: HashMap<String, ItemRec>,
    pub events: Vec<Arc<Event>>,
    /// Items in `items` that are progress reports.
    pub progress_items: usize,
    /// Event ids up to this one may have been given to progress items.
    reserved_to: u64,
    pub held_bytes: u64,
    pub pending_bytes: u64,
    pub pending: HashSet<String>,
    pub transfer_bytes: u64,
    pub last_activity_ms: u64,
    pub closed: bool,
    pub ip_hash: Option<String>,
    pub streams: HashMap<String, usize>,
    pub jobs: HashMap<String, JobRec>,
    pub presence: HashMap<String, Presence>,
    evictions: BTreeMap<u64, Vec<String>>,
    /// Open wants: item → (participant → when asked).
    pub wants: HashMap<String, HashMap<String, u64>>,
    /// The items each participant has asked for.
    pub wanted_items: HashMap<String, HashSet<String>>,
    /// `want` log lines per participant.
    pub want_lines: HashMap<String, u32>,
    /// When each open want was last logged (and so announced to holders):
    /// item → (participant → when).
    pub want_announced: HashMap<String, HashMap<String, u64>>,
    /// Roles the owner revoked.
    pub revoked: HashSet<Role>,
    /// Held bytes per uploader address, shared by every session.
    pub usage: Arc<IpUsage>,
    hold_ms: u64,
    grace_ms: u64,
    /// Whether runners need the owner's approval before they get jobs.
    approve_runners: bool,
}

impl Inner {
    fn push_event(&mut self, seq: u64, kind: &'static str, data: Value) -> Option<Arc<Event>> {
        let e = Arc::new(Event { seq, kind, data });
        self.events.push(e.clone());
        Some(e)
    }

    pub fn log_len(&self) -> u64 {
        self.log_len
    }

    /// Items that count toward the session's item limit: everything but
    /// progress reports.
    pub fn history_items(&self) -> usize {
        self.items.len() - self.progress_items
    }

    /// Whether `rec` is about a progress item, and so is applied without
    /// being logged.
    fn is_progress_rec(&self, rec: &Rec) -> bool {
        match rec {
            Rec::Ack { item, .. } | Rec::Evict { item } => self.items.get(item).is_some_and(|r| r.progress),
            _ => false,
        }
    }

    /// Drop a progress item: its blob accounting, its envelope in the event
    /// log, everything. Clients that have not fetched it find it gone (the
    /// blob answers 404) and the live ones are told `evicted` once.
    fn forget_progress(&mut self, seq: u64, item: &str) -> Option<Arc<Event>> {
        let r = self.items.remove(item)?;
        self.progress_items -= 1;
        if r.blob_present {
            self.held_bytes -= r.blob_len;
            self.usage.sub(r.ip_hash.as_deref(), r.blob_len);
        }
        if let Ok(i) = self.events.binary_search_by_key(&r.seq, |e| e.seq) {
            self.events.remove(i);
        }
        // Not kept in `events`: a client that replays the log never saw the item.
        Some(Arc::new(Event { seq, kind: "evicted", data: json!({"item": item}) }))
    }

    /// Schedule eviction once every remaining recipient has acked. A
    /// progress item goes at once; the grace period is for blobs a client
    /// may still need to fetch again.
    fn check_delivered(&mut self, item: &str, ts: u64) {
        let grace = self.grace_ms;
        if let Some(r) = self.items.get_mut(item) {
            let grace = if r.progress { 0 } else { grace };
            if r.blob_present && !r.keep && !r.recipients.is_empty() && r.recipients.is_subset(&r.acked) {
                let t = ts.saturating_add(grace);
                if t < r.evict_at {
                    r.evict_at = t;
                    self.evictions.entry(t).or_default().push(item.to_string());
                }
            }
        }
    }

    /// Stop counting `who` as a recipient and revoke its token.
    fn depart(&mut self, who: &str, ts: u64) {
        self.tokens.retain(|_, pk| pk != who);
        for w in self.wants.values_mut().chain(self.want_announced.values_mut()) {
            w.remove(who);
        }
        self.wants.retain(|_, w| !w.is_empty());
        self.want_announced.retain(|_, w| !w.is_empty());
        // Stop waiting for this participant on blobs still held.
        let waiting: Vec<String> = self
            .items
            .iter_mut()
            .filter(|(_, r)| r.blob_present && !r.acked.contains(who))
            .filter_map(|(id, r)| r.recipients.remove(who).then(|| id.clone()))
            .collect();
        for id in waiting {
            self.check_delivered(&id, ts);
        }
    }

    /// Apply a log line to the index. Log lines are only written from
    /// validated input, so a failure here means a corrupt log.
    fn apply(&mut self, line: &LogLine) -> Result<Option<Arc<Event>>, String> {
        let ts = line.ts_ms;
        match &line.rec {
            Rec::Create { ip_hash } => {
                self.ip_hash = Some(ip_hash.clone());
                Ok(None)
            }
            Rec::Join { signed_join, token_sha256 } => {
                let j: SignedJoinRequest = parse_canonical(signed_join, "join").map_err(|e| e.to_string())?;
                let pk = j.join.cert.participant().to_b64();
                let role = j.join.cert.role();
                if self.participants.contains_key(&pk) {
                    // Only logs written before re-joins were refused contain this.
                    self.tokens.insert(token_sha256.clone(), pk);
                    return Ok(None);
                }
                let public = json!({
                    "participant_pub": pk,
                    "role": role.as_str(),
                    "display_name": j.join.display_name,
                    "kind": j.join.kind,
                    "runner": j.join.runner,
                    "signed_join": signed_join,
                });
                self.participants.insert(
                    pk.clone(),
                    Participant {
                        role,
                        seq: line.seq,
                        public: public.clone(),
                        left: false,
                        runner: j.join.runner.clone(),
                        approved: false,
                        rejected: false,
                        jobs: BTreeSet::new(),
                    },
                );
                self.tokens.insert(token_sha256.clone(), pk);
                self.last_activity_ms = self.last_activity_ms.max(ts);
                Ok(self.push_event(line.seq, "participant", public))
            }
            Rec::Item { envelope, recipients, blob_len, ip_hash, .. } => {
                let env: ItemEnvelope =
                    parse_canonical(envelope, "item envelope").map_err(|e| e.to_string())?;
                let id = env.header.id.clone();
                let author = env.header.author.to_b64();
                let keep = env.header.kind == ItemKind::Event
                    && *blob_len <= KEEP_EVENT_BYTES
                    && self.participants.get(&author).is_some_and(|p| p.role == Role::Owner);
                let evict_at = if keep { u64::MAX } else { ts.saturating_add(self.hold_ms) };
                let progress = env.header.kind == ItemKind::Progress;
                self.progress_items += usize::from(progress);
                self.items.insert(
                    id.clone(),
                    ItemRec {
                        seq: line.seq,
                        ip_hash: ip_hash.clone(),
                        author,
                        recipients: recipients.iter().cloned().collect(),
                        acked: HashSet::new(),
                        blob_len: *blob_len,
                        blob_present: true,
                        evict_at,
                        keep,
                        progress,
                    },
                );
                if !keep {
                    self.evictions.entry(evict_at).or_default().push(id);
                }
                self.held_bytes += blob_len;
                self.transfer_bytes += blob_len;
                self.usage.add(ip_hash.as_deref(), *blob_len);
                self.last_activity_ms = self.last_activity_ms.max(ts);
                Ok(self.push_event(
                    line.seq,
                    "item",
                    json!({"envelope": envelope, "blob_len": blob_len, "blob_present": true}),
                ))
            }
            Rec::Ack { item, by } => {
                if let Some(r) = self.items.get_mut(item) {
                    r.acked.insert(by.clone());
                }
                self.check_delivered(item, ts);
                self.last_activity_ms = self.last_activity_ms.max(ts);
                Ok(None)
            }
            Rec::Leave { who } => {
                if let Some(p) = self.participants.get_mut(who) {
                    p.left = true;
                }
                self.depart(who, ts);
                Ok(self.push_event(line.seq, "left", json!({"participant_pub": who})))
            }
            Rec::Approve { who } => {
                if let Some(p) = self.participants.get_mut(who) {
                    p.approved = true;
                }
                Ok(self.push_event(line.seq, "runner", json!({"participant_pub": who, "status": "approved"})))
            }
            Rec::Reject { who } => {
                if let Some(p) = self.participants.get_mut(who) {
                    p.rejected = true;
                    p.approved = false;
                }
                self.depart(who, ts);
                Ok(self.push_event(line.seq, "runner", json!({"participant_pub": who, "status": "rejected"})))
            }
            Rec::Job { job, state, runner, reason } => {
                let author = self.items.get(job).map(|r| r.author.clone()).unwrap_or_default();
                let prev = self.jobs.get(job).and_then(|j| j.runner.clone());
                // Free the previous runner's slot; occupy the new one's while active.
                if let Some(p) = prev.as_ref().and_then(|r| self.participants.get_mut(r)) {
                    p.jobs.remove(job);
                }
                if state.active() {
                    if let Some(p) = runner.as_ref().and_then(|r| self.participants.get_mut(r)) {
                        p.jobs.insert(job.clone());
                    }
                }
                self.jobs.insert(
                    job.clone(),
                    JobRec {
                        author,
                        runner: runner.clone(),
                        state: *state,
                        reason: reason.clone(),
                        since_ms: ts,
                        cancel_requested: false,
                    },
                );
                Ok(self.push_event(
                    line.seq,
                    "job",
                    json!({"job": job, "state": state, "runner": runner, "reason": reason}),
                ))
            }
            Rec::Evict { item } if self.items.get(item).is_some_and(|r| r.progress) => {
                Ok(self.forget_progress(line.seq, item))
            }
            Rec::Evict { item } => {
                if let Some(r) = self.items.get_mut(item) {
                    if r.blob_present {
                        r.blob_present = false;
                        self.held_bytes -= r.blob_len;
                        self.usage.sub(r.ip_hash.as_deref(), r.blob_len);
                    }
                }
                Ok(self.push_event(line.seq, "evicted", json!({"item": item})))
            }
            Rec::Want { item, by } => {
                self.wants.entry(item.clone()).or_default().insert(by.clone(), ts);
                self.want_announced.entry(item.clone()).or_default().insert(by.clone(), ts);
                self.wanted_items.entry(by.clone()).or_default().insert(item.clone());
                *self.want_lines.entry(by.clone()).or_default() += 1;
                // Not activity: asking alone must not keep a session alive.
                Ok(self.push_event(line.seq, "want", json!({"item": item, "by": by})))
            }
            Rec::Reseed { item, by, ip_hash } => {
                // The wanters become the blob's recipients: it goes once they
                // have all acked, or when its short hold ends. Expired wants
                // are dropped here too, so a replay matches what happened live.
                self.want_announced.remove(item);
                let wanters: HashSet<String> = self
                    .wants
                    .remove(item)
                    .map(|w| {
                        w.into_iter()
                            .filter(|(_, t)| ts.saturating_sub(*t) < WANT_TTL_MS)
                            .map(|(k, _)| k)
                            .collect()
                    })
                    .unwrap_or_default();
                let hold = self.hold_ms.min(RESEED_HOLD_MS);
                if let Some(r) = self.items.get_mut(item) {
                    if !r.blob_present {
                        r.blob_present = true;
                        self.held_bytes += r.blob_len;
                        self.transfer_bytes += r.blob_len;
                        r.ip_hash = ip_hash.clone();
                        self.usage.add(ip_hash.as_deref(), r.blob_len);
                    }
                    r.recipients = wanters;
                    r.evict_at = ts.saturating_add(hold);
                    self.evictions.entry(r.evict_at).or_default().push(item.clone());
                }
                self.check_delivered(item, ts);
                self.last_activity_ms = self.last_activity_ms.max(ts);
                Ok(self.push_event(line.seq, "reseeded", json!({"item": item, "by": by})))
            }
            Rec::Revoke { role } => {
                self.revoked.insert(*role);
                let mut cut: Vec<String> = self
                    .participants
                    .iter()
                    .filter(|(_, p)| p.role == *role && !p.left && !p.rejected)
                    .map(|(k, _)| k.clone())
                    .collect();
                cut.sort();
                for who in &cut {
                    if let Some(p) = self.participants.get_mut(who) {
                        p.left = true;
                    }
                    self.depart(who, ts);
                }
                self.last_activity_ms = self.last_activity_ms.max(ts);
                Ok(self.push_event(line.seq, "revoked", json!({"role": role, "participants": cut})))
            }
            Rec::Close { reason } => {
                self.closed = true;
                Ok(self.push_event(line.seq, "closed", json!({"reason": reason})))
            }
            Rec::Reserve { count } => {
                self.reserved_to = self.reserved_to.max(line.seq.saturating_add(*count));
                Ok(None)
            }
            Rec::Unknown => Ok(None),
        }
    }

    /// Whether `who` is still in the session: not left, rejected or revoked.
    pub fn is_live(&self, who: &str) -> bool {
        self.participants.get(who).is_some_and(|p| !p.left && !p.rejected)
    }

    /// `(participant_pub, role)` for a live token.
    pub fn participant_by_token(&self, token_sha256: &str) -> Option<(String, Role)> {
        let pk = self.tokens.get(token_sha256)?;
        let p = self.participants.get(pk)?;
        (!p.left).then(|| (pk.clone(), p.role))
    }

    /// Participants who still receive new items. A runner awaiting approval
    /// is not a recipient, so it cannot pin blobs on the relay.
    pub fn active_participants(&self) -> impl Iterator<Item = &String> {
        let need_approval = self.approve_runners;
        self.participants
            .iter()
            .filter(move |(_, p)| {
                !p.left && !p.rejected && (p.role != Role::Runner || p.approved || !need_approval)
            })
            .map(|(k, _)| k)
    }

    /// Whether a runner may be given jobs: joined, approved (when the
    /// session requires it) and neither left nor rejected.
    pub fn runner_eligible(&self, pk: &str) -> bool {
        self.participants.get(pk).is_some_and(|p| {
            p.role == Role::Runner && !p.left && !p.rejected && (p.approved || !self.approve_runners)
        })
    }

    /// Online: an open runner stream and a heartbeat within `timeout_ms`.
    pub fn runner_online(&self, pk: &str, now: u64, timeout_ms: u64) -> bool {
        self.presence
            .get(pk)
            .is_some_and(|p| p.streams > 0 && now.saturating_sub(p.last_seen_ms) <= timeout_ms)
    }

    /// Whether a participant or runner holds a stream to the session.
    pub fn has_open_stream(&self) -> bool {
        !self.streams.is_empty() || self.presence.values().any(|p| p.streams > 0)
    }

    /// How many jobs a runner runs at once (its signed `slots`).
    pub fn runner_slots(&self, pk: &str) -> usize {
        self.participants.get(pk).and_then(|p| p.runner.as_ref()).map_or(1, |r| r.slots as usize)
    }

    /// Whether an eligible runner has a slot for another job.
    pub fn runner_has_room(&self, pk: &str) -> bool {
        self.participants.get(pk).is_some_and(|p| p.jobs.len() < self.runner_slots(pk))
    }

    /// A job its runner `who` lost (the relay failed it as `runner_lost`)
    /// that the runner may still finish: it reconnected, or posted the result.
    pub fn lost_by(&self, job: &str, who: &str) -> bool {
        self.jobs.get(job).is_some_and(|j| {
            j.state == JobState::Failed
                && j.reason.as_deref() == Some("runner_lost")
                && j.runner.as_deref() == Some(who)
        })
    }

    pub fn approve_runners(&self) -> bool {
        self.approve_runners
    }

    /// Drop wants older than `WANT_TTL_MS`.
    pub fn prune_wants(&mut self, now: u64) {
        for w in self.wants.values_mut() {
            w.retain(|_, ts| now.saturating_sub(*ts) < WANT_TTL_MS);
        }
        self.wants.retain(|_, w| !w.is_empty());
    }

    /// How many wants `who` has open.
    pub fn open_wants(&self, who: &str) -> usize {
        self.wants.values().filter(|w| w.contains_key(who)).count()
    }

    /// The `item` event carrying this item's envelope.
    pub fn item_event(&self, id: &str) -> Option<&Arc<Event>> {
        let seq = self.items.get(id)?.seq;
        self.events.binary_search_by_key(&seq, |e| e.seq).ok().map(|i| &self.events[i])
    }
}

pub struct Session {
    pub id: String,
    pub dir: PathBuf,
    pub signed: SignedManifest,
    pub manifest_json: String,
    inner: Mutex<Inner>,
    pub tx: broadcast::Sender<Arc<Event>>,
    /// Private messages to runners (assignments, cancels); each runner
    /// stream keeps only its own.
    pub runner_tx: broadcast::Sender<Arc<RunnerMsg>>,
}

pub fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    File::open(dir)?.sync_all()?;
    let _ = dir;
    Ok(())
}

fn invalid(e: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

impl Session {
    fn new_inner(
        log: File,
        log_len: u64,
        cfg: &Config,
        signed: &SignedManifest,
        usage: Arc<IpUsage>,
    ) -> Inner {
        let m = &signed.manifest;
        let approve_runners =
            m.mode == Mode::Execute && m.job_limits.as_ref().is_none_or(|l| l.approve_runners);
        Inner {
            log,
            log_len,
            broken: false,
            next_seq: 0,
            participants: HashMap::new(),
            tokens: HashMap::new(),
            items: HashMap::new(),
            events: Vec::new(),
            progress_items: 0,
            reserved_to: 0,
            held_bytes: 0,
            pending_bytes: 0,
            pending: HashSet::new(),
            transfer_bytes: 0,
            last_activity_ms: 0,
            closed: false,
            ip_hash: None,
            streams: HashMap::new(),
            jobs: HashMap::new(),
            presence: HashMap::new(),
            evictions: BTreeMap::new(),
            wants: HashMap::new(),
            wanted_items: HashMap::new(),
            want_lines: HashMap::new(),
            want_announced: HashMap::new(),
            revoked: HashSet::new(),
            usage,
            hold_ms: cfg.blob_hold_ms,
            grace_ms: cfg.blob_grace_ms,
            approve_runners,
        }
    }

    /// Set up a session in `dir`, which the caller has just created.
    fn create(
        dir: PathBuf,
        signed: SignedManifest,
        manifest_json: String,
        ip_hash: String,
        cfg: &Config,
        usage: Arc<IpUsage>,
    ) -> io::Result<Session> {
        fs::create_dir(dir.join("blobs"))?;
        let tmp = dir.join(".manifest.json.tmp");
        {
            let mut f = File::create(&tmp)?;
            f.write_all(manifest_json.as_bytes())?;
            f.sync_all()?;
        }
        fs::rename(&tmp, dir.join("manifest.json"))?;
        let log = OpenOptions::new().create_new(true).append(true).open(dir.join("log.jsonl"))?;
        sync_dir(&dir)?;
        if let Some(parent) = dir.parent() {
            sync_dir(parent)?;
        }
        let mut inner = Self::new_inner(log, 0, cfg, &signed, usage);
        inner.last_activity_ms = now_ms();
        let (tx, _) = broadcast::channel(EVENT_BUFFER);
        let (runner_tx, _) = broadcast::channel(EVENT_BUFFER);
        let s = Session {
            id: signed.manifest.session_id.clone(),
            dir,
            signed,
            manifest_json,
            inner: Mutex::new(inner),
            tx,
            runner_tx,
        };
        {
            let mut g = s.lock();
            s.append(&mut g, Rec::Create { ip_hash })?;
        }
        Ok(s)
    }

    fn load(dir: PathBuf, cfg: &Config, usage: Arc<IpUsage>) -> io::Result<Session> {
        let manifest_json = fs::read_to_string(dir.join("manifest.json"))?;
        let signed = SignedManifest::from_json(&manifest_json).map_err(invalid)?;
        let id = signed.manifest.session_id.clone();
        if dir.file_name().and_then(|n| n.to_str()) != Some(id.as_str()) {
            return Err(invalid("directory name does not match session id"));
        }
        let mut log = OpenOptions::new().read(true).append(true).open(dir.join("log.jsonl"))?;
        let mut raw = Vec::new();
        log.read_to_end(&mut raw)?;
        // A crash can leave a partial last line; drop it so appends stay aligned.
        let valid = raw.iter().rposition(|&b| b == b'\n').map(|i| i + 1).unwrap_or(0);
        if valid < raw.len() {
            tracing::warn!(session = %id, "dropping partial trailing log line");
            log.set_len(valid as u64)?;
            log.seek(SeekFrom::End(0))?;
        }
        let mut inner = Self::new_inner(log, valid as u64, cfg, &signed, usage);
        for line in raw[..valid].split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
            let line: LogLine = serde_json::from_slice(line).map_err(invalid)?;
            // Only ids reserved for progress items, which are not logged, may be missing.
            if line.seq != inner.next_seq && !(inner.next_seq..=inner.reserved_to + 1).contains(&line.seq) {
                return Err(invalid(format!("log sequence gap at {}", line.seq)));
            }
            inner.apply(&line).map_err(invalid)?;
            inner.next_seq = line.seq + 1;
        }
        inner.next_seq = inner.next_seq.max(inner.reserved_to + 1);
        if inner.last_activity_ms == 0 {
            inner.last_activity_ms = signed.manifest.created_at_ms;
        }
        let now = now_ms();
        // Streams are not logged, so a session a runner held open before the
        // restart looks idle since its last logged activity. Its streams get
        // the reconnect grace before it can go idle.
        let idle_ttl = cfg.idle_ttl_for(signed.manifest.expires_at_ms);
        let grace = cfg.job_reconnect_grace_ms.min(idle_ttl);
        inner.last_activity_ms = inner.last_activity_ms.max(now.saturating_sub(idle_ttl) + grace);
        // Runners with an active job get one timeout from now to reconnect.
        let busy: Vec<String> =
            inner.jobs.values().filter(|j| j.state.active()).filter_map(|j| j.runner.clone()).collect();
        for r in busy {
            inner.presence.entry(r).or_default().last_seen_ms = now;
        }
        for j in inner.jobs.values_mut().filter(|j| j.state == JobState::Assigned) {
            j.since_ms = j.since_ms.max(now);
        }
        let (tx, _) = broadcast::channel(EVENT_BUFFER);
        let (runner_tx, _) = broadcast::channel(EVENT_BUFFER);
        let s = Session { id, dir, signed, manifest_json, inner: Mutex::new(inner), tx, runner_tx };
        s.reconcile_blobs()?;
        Ok(s)
    }

    /// Remove temp and orphaned blob files; record evictions for blobs that
    /// the log says are present but are missing on disk.
    fn reconcile_blobs(&self) -> io::Result<()> {
        let blobs = self.dir.join("blobs");
        fs::create_dir_all(&blobs)?;
        let mut g = self.lock();
        let mut on_disk = HashSet::new();
        for entry in fs::read_dir(&blobs)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let keep = g.items.get(&name).is_some_and(|r| r.blob_present);
            if name.starts_with('.') || !keep {
                let _ = fs::remove_file(entry.path());
            } else {
                on_disk.insert(name);
            }
        }
        let missing: Vec<String> = g
            .items
            .iter()
            .filter(|(id, r)| r.blob_present && !on_disk.contains(*id))
            .map(|(id, _)| id.clone())
            .collect();
        for id in missing {
            tracing::warn!(session = %self.id, item = %id, "blob missing on disk; marking evicted");
            self.append(&mut g, Rec::Evict { item: id })?;
        }
        Ok(())
    }

    pub fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Write and fsync a log line, then apply and broadcast it. On a failed
    /// write the file is truncated back so the log stays replayable. This
    /// blocks on disk: call it from a blocking context.
    pub fn append(&self, inner: &mut Inner, rec: Rec) -> io::Result<Option<Arc<Event>>> {
        if inner.broken {
            return Err(io::Error::other("session log is unwritable"));
        }
        if inner.is_progress_rec(&rec) {
            return self.append_progress(inner, rec);
        }
        let line = LogLine { seq: inner.next_seq, ts_ms: now_ms(), rec };
        let mut bytes = serde_json::to_vec(&line).map_err(invalid)?;
        bytes.push(b'\n');
        let before = inner.log_len;
        let written = inner.log.write_all(&bytes).and_then(|()| inner.log.sync_data());
        if let Err(e) = written {
            if inner.log.set_len(before).and_then(|()| inner.log.sync_data()).is_err() {
                inner.broken = true;
                tracing::error!(session = %self.id, "log write failed and could not be rolled back: {e}");
            }
            return Err(e);
        }
        inner.log_len += bytes.len() as u64;
        inner.next_seq += 1;
        let ev = inner.apply(&line).map_err(invalid)?;
        if let Some(e) = &ev {
            let _ = self.tx.send(e.clone());
        }
        Ok(ev)
    }

    /// Apply and broadcast a record about a progress item without logging
    /// it. Its event id comes from a block the log reserved, which costs a
    /// log line (and an fsync) only once per [`SEQ_RESERVE`] records.
    pub fn append_progress(&self, inner: &mut Inner, rec: Rec) -> io::Result<Option<Arc<Event>>> {
        if inner.broken {
            return Err(io::Error::other("session log is unwritable"));
        }
        if inner.next_seq > inner.reserved_to {
            self.append(inner, Rec::Reserve { count: SEQ_RESERVE })?;
        }
        let line = LogLine { seq: inner.next_seq, ts_ms: now_ms(), rec };
        inner.next_seq += 1;
        let ev = inner.apply(&line).map_err(invalid)?;
        if let Some(e) = &ev {
            let _ = self.tx.send(e.clone());
        }
        Ok(ev)
    }

    /// Send a message on one runner's private stream.
    pub fn tell_runner(&self, runner: &str, kind: &'static str, data: Value) {
        let _ = self.runner_tx.send(Arc::new(RunnerMsg { runner: runner.to_string(), kind, data }));
    }

    /// Record a job state change. Blocks on disk.
    pub fn set_job(
        &self,
        inner: &mut Inner,
        job: &str,
        state: JobState,
        runner: Option<String>,
        reason: Option<&str>,
    ) -> io::Result<()> {
        let rec = Rec::Job { job: job.to_string(), state, runner, reason: reason.map(str::to_string) };
        self.append(inner, rec).map(|_| ())
    }

    /// Fail the active jobs of a runner that left or was rejected or revoked.
    pub fn fail_runner_jobs(&self, inner: &mut Inner, runner: &str, reason: &str) -> io::Result<()> {
        let jobs: Vec<String> =
            inner.participants.get(runner).map(|p| p.jobs.iter().cloned().collect()).unwrap_or_default();
        for job in jobs {
            self.set_job(inner, &job, JobState::Failed, Some(runner.to_string()), Some(reason))?;
            self.tell_runner(runner, "job_cancel", json!({"job": job}));
        }
        Ok(())
    }

    /// Fail jobs that were not claimed in time or whose runner stopped
    /// sending heartbeats: an assigned job after `runner_ms`, a running one
    /// after `grace_ms` (its runner may only have lost its connection).
    fn sweep_jobs(&self, now: u64, claim_ms: u64, runner_ms: u64, grace_ms: u64) -> io::Result<()> {
        let mut g = self.lock();
        let mut due = Vec::new();
        for (id, j) in g.jobs.iter().filter(|(_, j)| j.state.active()) {
            let Some(runner) = j.runner.clone() else { continue };
            let seen = g.presence.get(&runner).map(|p| p.last_seen_ms).unwrap_or(0);
            if j.state == JobState::Assigned && now.saturating_sub(j.since_ms) > claim_ms {
                due.push((id.clone(), runner, "runner_unresponsive"));
            } else if now.saturating_sub(seen.max(j.since_ms))
                > if j.state == JobState::Running { grace_ms.max(runner_ms) } else { runner_ms }
            {
                due.push((id.clone(), runner, "runner_lost"));
            }
        }
        for (job, runner, reason) in due {
            self.set_job(&mut g, &job, JobState::Failed, Some(runner.clone()), Some(reason))?;
            self.tell_runner(&runner, "job_cancel", json!({"job": job}));
            // Unresponsive: offline until its next heartbeat.
            if let Some(p) = g.presence.get_mut(&runner) {
                p.last_seen_ms = 0;
            }
        }
        Ok(())
    }

    /// The audit trail as JSONL: one line per log record, with who did
    /// what to which item and the signed material to check it, but without
    /// token hashes or the creator's address hash. Blocks on disk.
    pub fn audit(&self) -> io::Result<Vec<u8>> {
        let len = self.lock().log_len;
        let mut raw = vec![0; len as usize];
        File::open(self.dir.join("log.jsonl"))?.read_exact(&mut raw)?;
        let owner = self.signed.manifest.owner_pub.to_b64();
        // Who holds each role at this point in the log, for `revoke` lines.
        let mut live: HashMap<String, Role> = HashMap::new();
        let mut out = Vec::with_capacity(raw.len());
        for line in raw.split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
            let line: LogLine = serde_json::from_slice(line).map_err(invalid)?;
            let mut a = json!({"seq": line.seq, "ts_ms": line.ts_ms});
            let mut set = |k: &str, v: Value| {
                a[k] = v;
            };
            match line.rec {
                Rec::Create { .. } => {
                    set("action", json!("create"));
                    set("actor", json!(owner));
                    set("signed_manifest", json!(self.manifest_json));
                }
                Rec::Join { signed_join, .. } => {
                    let j: SignedJoinRequest = parse_canonical(&signed_join, "join").map_err(invalid)?;
                    let pk = j.join.cert.participant().to_b64();
                    live.insert(pk.clone(), j.join.cert.role());
                    set("action", json!("join"));
                    set("actor", json!(pk));
                    set("role", json!(j.join.cert.role()));
                    set("signed_join", json!(signed_join));
                }
                Rec::Item { envelope, blob_len, blob_sha256, .. } => {
                    let env: ItemEnvelope = parse_canonical(&envelope, "item envelope").map_err(invalid)?;
                    set("action", json!("item"));
                    set("actor", json!(env.header.author.to_b64()));
                    set("item", json!(env.header.id));
                    set("kind", json!(env.header.kind));
                    set("blob_len", json!(blob_len));
                    set("blob_sha256", json!(blob_sha256));
                    set("envelope", json!(envelope));
                }
                Rec::Ack { item, by } => {
                    set("action", json!("ack"));
                    set("actor", json!(by));
                    set("item", json!(item));
                }
                Rec::Leave { who } => {
                    live.remove(&who);
                    set("action", json!("leave"));
                    set("actor", json!(who));
                }
                Rec::Evict { item } => {
                    set("action", json!("evict"));
                    set("item", json!(item));
                }
                Rec::Want { item, by } => {
                    set("action", json!("want"));
                    set("actor", json!(by));
                    set("item", json!(item));
                }
                Rec::Reseed { item, by, .. } => {
                    set("action", json!("reseed"));
                    set("actor", json!(by));
                    set("item", json!(item));
                }
                Rec::Approve { who } => {
                    set("action", json!("runner_approve"));
                    set("actor", json!(owner));
                    set("runner", json!(who));
                }
                Rec::Reject { who } => {
                    live.remove(&who);
                    set("action", json!("runner_reject"));
                    set("actor", json!(owner));
                    set("runner", json!(who));
                }
                Rec::Job { job, state, runner, reason } => {
                    set("action", json!("job"));
                    set("item", json!(job));
                    set("state", json!(state));
                    set("runner", json!(runner));
                    set("reason", json!(reason));
                }
                Rec::Revoke { role } => {
                    let mut cut: Vec<String> =
                        live.iter().filter(|(_, r)| **r == role).map(|(k, _)| k.clone()).collect();
                    cut.sort();
                    live.retain(|_, r| *r != role);
                    set("action", json!("revoke"));
                    set("actor", json!(owner));
                    set("role", json!(role));
                    set("participants", json!(cut));
                }
                Rec::Close { reason } => {
                    set("action", json!("close"));
                    set("reason", json!(reason));
                }
                // Bookkeeping for the ids of progress items, which are not in the trail.
                Rec::Reserve { .. } => continue,
                Rec::Unknown => set("action", json!("unknown")),
            }
            serde_json::to_writer(&mut out, &a).map_err(invalid)?;
            out.push(b'\n');
        }
        Ok(out)
    }

    pub fn blob_path(&self, item: &str) -> PathBuf {
        self.dir.join("blobs").join(item)
    }

    /// Evict blobs whose time has come.
    fn sweep_evictions(&self, now: u64) -> io::Result<()> {
        let mut g = self.lock();
        let mut due = Vec::new();
        while let Some((&t, _)) = g.evictions.first_key_value() {
            if t > now {
                break;
            }
            due.extend(g.evictions.pop_first().map(|(_, v)| v).unwrap_or_default());
        }
        for id in due {
            let evict = g.items.get(&id).is_some_and(|r| r.blob_present && r.evict_at <= now);
            if evict {
                match fs::remove_file(self.blob_path(&id)) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e),
                }
                self.append(&mut g, Rec::Evict { item: id })?;
            }
        }
        Ok(())
    }
}

/// Why a create was refused.
pub enum CreateError {
    Exists,
    Closed,
    Io(io::Error),
}

impl From<io::Error> for CreateError {
    fn from(e: io::Error) -> Self {
        CreateError::Io(e)
    }
}

/// All sessions on this relay.
pub struct Store {
    pub cfg: Arc<Config>,
    sessions_dir: PathBuf,
    tombstones_dir: PathBuf,
    trash_dir: PathBuf,
    sessions: RwLock<HashMap<String, Arc<Session>>>,
    /// Closed sessions and their manifest expiry: refused if re-created.
    tombstones: Mutex<HashMap<String, u64>>,
    /// Held and in-flight bytes per uploader address, over all sessions.
    pub usage: Arc<IpUsage>,
    /// Active sessions as of the last sweep, so `/v1/health` locks none.
    active: AtomicUsize,
    ip_key: [u8; 32],
    #[cfg(unix)]
    _lock: nix::fcntl::Flock<File>,
}

fn load_or_create_key(path: &Path) -> io::Result<[u8; 32]> {
    if let Ok(b) = fs::read(path) {
        if let Ok(k) = <[u8; 32]>::try_from(b.as_slice()) {
            return Ok(k);
        }
    }
    let k: [u8; 32] = random_bytes();
    let tmp = path.with_extension("tmp");
    {
        let mut o = OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
        let mut f = o.open(&tmp)?;
        f.write_all(&k)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(k)
}

impl Store {
    pub fn open(cfg: Arc<Config>) -> io::Result<Arc<Store>> {
        fs::create_dir_all(&cfg.data)?;
        let lock_file =
            OpenOptions::new().create(true).truncate(false).write(true).open(cfg.data.join("LOCK"))?;
        #[cfg(unix)]
        let lock = nix::fcntl::Flock::lock(lock_file, nix::fcntl::FlockArg::LockExclusiveNonblock).map_err(
            |(_, e)| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    format!("data directory is in use by another server ({e})"),
                )
            },
        )?;
        #[cfg(not(unix))]
        drop(lock_file);

        let sessions_dir = cfg.data.join("sessions");
        let tombstones_dir = cfg.data.join("tombstones");
        let trash_dir = cfg.data.join("trash");
        if cfg.ephemeral {
            let _ = fs::remove_dir_all(&sessions_dir);
            let _ = fs::remove_dir_all(&tombstones_dir);
            let _ = fs::remove_dir_all(&trash_dir);
            let _ = fs::remove_file(cfg.data.join("ip.key"));
        }
        fs::create_dir_all(&sessions_dir)?;
        fs::create_dir_all(&tombstones_dir)?;
        let _ = fs::remove_dir_all(&trash_dir);
        fs::create_dir_all(&trash_dir)?;
        let ip_key = load_or_create_key(&cfg.data.join("ip.key"))?;

        let store = Store {
            cfg: cfg.clone(),
            sessions_dir,
            tombstones_dir,
            trash_dir,
            sessions: RwLock::new(HashMap::new()),
            tombstones: Mutex::new(HashMap::new()),
            usage: Arc::default(),
            active: AtomicUsize::new(0),
            ip_key,
            #[cfg(unix)]
            _lock: lock,
        };
        let now = now_ms();
        for entry in fs::read_dir(&store.tombstones_dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let until = fs::read_to_string(entry.path()).ok().and_then(|s| s.trim().parse::<u64>().ok());
            match until {
                Some(t) if t > now && is_session_id(&name) => {
                    store.tombstones.lock().unwrap_or_else(|e| e.into_inner()).insert(name, t);
                }
                _ => {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
        for entry in fs::read_dir(&store.sessions_dir)? {
            let path = entry?.path();
            if !path.is_dir() {
                continue;
            }
            match Session::load(path.clone(), &cfg, store.usage.clone()) {
                Ok(s) if s.signed.manifest.is_expired(now) || s.lock().closed => store.trash(&path),
                Ok(s) => {
                    store
                        .sessions
                        .write()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(s.id.clone(), Arc::new(s));
                }
                Err(e) => {
                    tracing::warn!(dir = %path.display(), "unreadable session moved to trash: {e}");
                    store.trash(&path);
                }
            }
        }
        tracing::info!(sessions = store.count(), data = %cfg.data.display(), "store opened");
        Ok(Arc::new(store))
    }

    /// A keyed hash of a client address bucket, so the log never holds a
    /// value that can be reversed by enumerating addresses.
    pub fn ip_hash(&self, bucket: &str) -> String {
        let mut b = self.ip_key.to_vec();
        b.extend_from_slice(bucket.as_bytes());
        airlox_core::encoding::hex(&sha256(&b))
    }

    pub fn get(&self, id: &str) -> Option<Arc<Session>> {
        self.sessions.read().unwrap_or_else(|e| e.into_inner()).get(id).cloned()
    }

    pub fn count(&self) -> usize {
        self.sessions.read().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Sessions someone is in, as of the last sweep: a participant or runner
    /// holds a stream, or something happened within `--active-window`. A
    /// session merely held until it expires or goes idle is not active.
    pub fn count_active(&self) -> usize {
        self.active.load(Ordering::Relaxed)
    }

    pub fn count_for_ip(&self, ip_hash: &str) -> usize {
        self.all().iter().filter(|s| s.lock().ip_hash.as_deref() == Some(ip_hash)).count()
    }

    pub fn all(&self) -> Vec<Arc<Session>> {
        self.sessions.read().unwrap_or_else(|e| e.into_inner()).values().cloned().collect()
    }

    /// Percent of the data volume in use, if it can be measured.
    pub fn disk_used_pct(&self) -> Option<u8> {
        #[cfg(unix)]
        {
            let st = nix::sys::statvfs::statvfs(&self.cfg.data).ok()?;
            let total = st.blocks() as u128;
            let avail = st.blocks_available() as u128;
            if total == 0 {
                return None;
            }
            Some((100 - (avail * 100 / total)) as u8)
        }
        #[cfg(not(unix))]
        None
    }

    pub fn disk_ok(&self) -> bool {
        self.disk_used_pct().is_none_or(|p| p < self.cfg.disk_high_watermark)
    }

    /// Create a session directory. The caller has already applied policy.
    /// Blocks on disk; the global map is only locked to insert.
    pub fn create(
        &self,
        signed: SignedManifest,
        manifest_json: String,
        ip_hash: String,
    ) -> Result<Arc<Session>, CreateError> {
        let id = signed.manifest.session_id.clone();
        if self.tombstones.lock().unwrap_or_else(|e| e.into_inner()).contains_key(&id) {
            return Err(CreateError::Closed);
        }
        if self.get(&id).is_some() {
            return Err(CreateError::Exists);
        }
        let dir = self.sessions_dir.join(&id);
        // create_dir is the atomic claim: a concurrent create of the same id fails here.
        match fs::create_dir(&dir) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => return Err(CreateError::Exists),
            Err(e) => return Err(e.into()),
        }
        let s =
            match Session::create(dir.clone(), signed, manifest_json, ip_hash, &self.cfg, self.usage.clone())
            {
                Ok(s) => Arc::new(s),
                Err(e) => {
                    let _ = fs::remove_dir_all(&dir);
                    return Err(e.into());
                }
            };
        self.sessions.write().unwrap_or_else(|e| e.into_inner()).insert(id, s.clone());
        Ok(s)
    }

    fn trash(&self, dir: &Path) {
        let name = dir.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let target = self.trash_dir.join(format!("{name}-{}", random_suffix()));
        if fs::rename(dir, &target).is_ok() {
            std::thread::spawn(move || {
                let _ = fs::remove_dir_all(target);
            });
        } else {
            let _ = fs::remove_dir_all(dir);
        }
    }

    fn tombstone(&self, s: &Session) {
        // Anyone holding the signed manifest could re-create the session, so
        // one that never expires keeps its tombstone for good.
        let until = s.signed.manifest.expires_at_ms.unwrap_or(u64::MAX);
        if until <= now_ms() {
            return;
        }
        let path = self.tombstones_dir.join(&s.id);
        if let Err(e) = fs::write(&path, until.to_string()).and_then(|()| sync_dir(&self.tombstones_dir)) {
            tracing::warn!(session = %s.id, "could not write tombstone: {e}");
        }
        self.tombstones.lock().unwrap_or_else(|e| e.into_inner()).insert(s.id.clone(), until);
    }

    /// End a session: record `closed`, keep a tombstone until it would have
    /// expired, then delete its directory. Blocks on disk.
    pub fn purge(&self, id: &str, reason: &str) {
        let removed = self.sessions.write().unwrap_or_else(|e| e.into_inner()).remove(id);
        if let Some(s) = removed {
            self.tombstone(&s);
            {
                let mut g = s.lock();
                if !g.closed {
                    if let Err(e) = s.append(&mut g, Rec::Close { reason: reason.to_string() }) {
                        tracing::warn!(session = %id, "close record failed: {e}");
                        // Still end live streams and refuse further requests.
                        g.closed = true;
                        let seq = g.next_seq;
                        let _ = s.tx.send(Arc::new(Event {
                            seq,
                            kind: "closed",
                            data: json!({"reason": reason}),
                        }));
                    }
                }
            }
            self.trash(&s.dir);
            tracing::info!(session = %id, reason, "session purged");
        }
    }

    /// Expire, idle-close, evict, and count the active sessions. Called
    /// periodically from a blocking thread.
    pub fn sweep(&self, now: u64) {
        let mut active = 0;
        for s in self.all() {
            if s.signed.manifest.is_expired(now) {
                self.purge(&s.id, "expired");
                continue;
            }
            let idle_ttl = self.cfg.idle_ttl_for(s.signed.manifest.expires_at_ms);
            // Idle: no upload in progress, nobody holding a stream (a paired
            // machine's runner waits on one between jobs), and nothing done
            // for the idle limit.
            let (idle, is_active) = {
                let g = s.lock();
                let quiet = now.saturating_sub(g.last_activity_ms);
                let open = g.has_open_stream();
                (
                    g.pending.is_empty() && !open && quiet >= idle_ttl,
                    !g.closed && (open || quiet <= self.cfg.active_window_ms),
                )
            };
            if idle {
                self.purge(&s.id, "idle");
                continue;
            }
            active += usize::from(is_active);
            if let Err(e) = s.sweep_evictions(now) {
                tracing::error!(session = %s.id, "eviction failed: {e}");
            }
            let (claim, runner, grace) =
                (self.cfg.claim_timeout_ms, self.cfg.runner_timeout_ms, self.cfg.job_reconnect_grace_ms);
            if let Err(e) = s.sweep_jobs(now, claim, runner, grace) {
                tracing::error!(session = %s.id, "job sweep failed: {e}");
            }
        }
        self.active.store(active, Ordering::Relaxed);
        self.tombstones.lock().unwrap_or_else(|e| e.into_inner()).retain(|id, until| {
            let keep = *until > now;
            if !keep {
                let _ = fs::remove_file(self.tombstones_dir.join(id));
            }
            keep
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_records_are_skipped() {
        let line: LogLine =
            serde_json::from_str(r#"{"seq":3,"ts_ms":1,"type":"from_the_future","x":[1,2]}"#).unwrap();
        assert!(matches!(line.rec, Rec::Unknown));
        let line: LogLine = serde_json::from_str(r#"{"seq":4,"ts_ms":1,"type":"evict","item":"a"}"#).unwrap();
        assert!(matches!(line.rec, Rec::Evict { .. }));
    }
}
