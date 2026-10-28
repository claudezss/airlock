//! A participant's view of one session, for the CLI and the MCP server.
//!
//! The Rust counterpart of the Python SDK's `Session`
//! (python/airlox/src/airlox/session.py): the same joins, item handling and
//! job results, and the same local cache layout, so the SDK, the CLI and the
//! MCP server reuse one identity per session and role. Every signature,
//! certificate and payload check goes through `airlox_core::api`; what counts
//! is what verifies, never the relay's unsigned fields.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use airlox_core::api;
use airlox_core::session::{JobLimits, Manifest, Mode, Role, SessionParams, SignedManifest};
use anyhow::{anyhow, bail, Context, Result};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::client::{self, is_transient, status_of, Relay, RelayError};
use crate::sse::SseParser;
use crate::view::write_atomic;

/// Largest believable gap between consecutive event sequence numbers a
/// participant sees (gaps are only events meant for others, such as job
/// routing). Small, so one forged event cannot hide the session's future.
const MAX_SEQ_JUMP: u64 = 10_000;
/// Ask again for an evicted blob nobody re-seeded after this long; the
/// relay drops a want after ten minutes.
const REASK: Duration = Duration::from_secs(5 * 60);

/// Content types a new session allows unless told otherwise.
pub const DEFAULT_TYPES: &[&str] = &["text", "py", "md", "zip", "image"];

/// `(subkind, mime)` for a file name the protocol can carry.
pub fn file_type(name: &str) -> Option<(&'static str, &'static str)> {
    let ext = Path::new(name).extension()?.to_str()?.to_ascii_lowercase();
    Some(match ext.as_str() {
        "py" => ("py", "text/x-python"),
        "md" | "markdown" => ("md", "text/markdown"),
        "zip" => ("zip", "application/zip"),
        "png" => ("image", "image/png"),
        "jpg" | "jpeg" => ("image", "image/jpeg"),
        "webp" => ("image", "image/webp"),
        _ => return None,
    })
}

pub const FILE_TYPES_HELP: &str = ".py, .md, .zip, .png, .jpg, .webp";

/// A job id goes into relay URLs: it must be a well-formed item id.
fn check_job_id(job: &str) -> Result<()> {
    if !airlox_core::item::is_item_id(job) {
        bail!("{} is not a job id", client::relay_text(job));
    }
    Ok(())
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex32(s: &str) -> Result<[u8; 32]> {
    let b: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2).unwrap_or("zz"), 16))
        .collect::<Result<_, _>>()
        .context("bad identity seed")?;
    b.try_into().map_err(|_| anyhow!("bad identity seed length"))
}

pub fn default_cache_root() -> PathBuf {
    crate::runner::default_cache_root()
}

// ---------------------------------------------------------------- cache --

/// `<root>/<session_id>/`: `manifest.json`, `events.jsonl` as received,
/// `identity-<role>.json` (participant seed, token and the relay it is for,
/// 0600) and `blobs/` (ciphertext). The session key and invite links are
/// never written.
struct Cache {
    dir: PathBuf,
}

#[derive(Serialize, Deserialize)]
struct Identity {
    participant_seed: String,
    token: String,
    #[serde(default)]
    role: Option<String>,
    /// The relay that issued `token`. An invite with the same session and
    /// keys but another relay must not get it (it would hand the token to
    /// whoever runs that host).
    #[serde(default)]
    base_url: Option<String>,
}

impl Cache {
    fn open(root: &Path, sid: &str) -> Result<Cache> {
        let dir = root.join(sid);
        // A new cache root is private too: its entries name the sessions.
        #[cfg(unix)]
        if !root.exists() {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new().recursive(true).mode(0o700).create(root)?;
        }
        fs::create_dir_all(dir.join("blobs"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        }
        Ok(Cache { dir })
    }

    /// The cached identity for `role`. A damaged file is an error rather than
    /// a reason to join again as someone new.
    fn load_identity(&self, role: &str) -> Result<Option<Identity>> {
        let path = self.dir.join(format!("identity-{role}.json"));
        let Ok(b) = fs::read(&path) else { return Ok(None) };
        let id = serde_json::from_slice(&b).with_context(|| format!("{} is damaged", path.display()))?;
        Ok(Some(id))
    }

    fn save_identity(&self, role: &str, id: &Identity) -> Result<()> {
        write_atomic(&self.dir.join(format!("identity-{role}.json")), &serde_json::to_vec(id)?, 0o600)
    }

    /// How far this role's listener has handled the session (`airlox
    /// listen`, `mark_handled`): a local cursor, never sent to the relay.
    fn handled(&self, role: &str) -> Option<u64> {
        let b = fs::read(self.dir.join(format!("handled-{role}.json"))).ok()?;
        serde_json::from_slice::<Value>(&b).ok()?["seq"].as_u64()
    }

    fn save_handled(&self, role: &str, seq: u64) -> Result<()> {
        write_atomic(
            &self.dir.join(format!("handled-{role}.json")),
            json!({"seq": seq}).to_string().as_bytes(),
            0o600,
        )
    }

    fn load_manifest(&self) -> Option<String> {
        fs::read_to_string(self.dir.join("manifest.json")).ok()
    }

    fn save_manifest(&self, signed: &str) -> Result<()> {
        write_atomic(&self.dir.join("manifest.json"), signed.as_bytes(), 0o644)
    }

    fn events(&self) -> Vec<Value> {
        let Ok(text) = fs::read_to_string(self.dir.join("events.jsonl")) else { return vec![] };
        let mut out = Vec::new();
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            match serde_json::from_str(line) {
                Ok(v) => out.push(v),
                Err(_) => break, // a partial last line after a crash
            }
        }
        out
    }

    fn append_event(&self, ev: &Value) -> Result<()> {
        let mut f = fs::OpenOptions::new().create(true).append(true).open(self.dir.join("events.jsonl"))?;
        writeln!(f, "{}", serde_json::to_string(ev)?)?;
        Ok(())
    }

    /// Blob files are named by item id only; ids come from the relay, and
    /// anything else could name another file.
    fn read_blob(&self, id: &str) -> Option<Vec<u8>> {
        if !airlox_core::item::is_item_id(id) {
            return None;
        }
        fs::read(self.dir.join("blobs").join(id)).ok()
    }

    fn write_blob(&self, id: &str, blob: &[u8]) -> Result<()> {
        if !airlox_core::item::is_item_id(id) {
            bail!("not an item id: {id:?}");
        }
        write_atomic(&self.dir.join("blobs").join(id), blob, 0o600)
    }

    /// Delete caches of sessions whose manifest has expired.
    fn sweep_expired(root: &Path) {
        let now = now_ms();
        let Ok(entries) = fs::read_dir(root) else { return };
        for e in entries.flatten() {
            // Only session caches: never another directory that happens to
            // hold a manifest.json.
            if !e.file_name().to_str().is_some_and(airlox_core::session::is_session_id) {
                continue;
            }
            let Ok(text) = fs::read_to_string(e.path().join("manifest.json")) else { continue };
            let expires = serde_json::from_str::<Value>(&text)
                .ok()
                .and_then(|v| v["manifest"]["expires_at_ms"].as_u64());
            if expires.is_some_and(|x| x <= now) {
                let _ = fs::remove_dir_all(e.path());
            }
        }
    }
}

/// Keeps a listener's cursor from stalling behind an item that never
/// arrives (its blob evicted, no holder online): an item pending longer than
/// the limit is skipped, with a warning on stderr. One that arrives after
/// all is reported once by [`PendingWatch::arrived_late`], since the cursor
/// has gone past it.
pub struct PendingWatch {
    limit: Duration,
    since: HashMap<u64, Instant>,
    skipped: HashSet<u64>,
}

impl PendingWatch {
    pub fn new(limit: Duration) -> PendingWatch {
        PendingWatch { limit, since: HashMap::new(), skipped: HashSet::new() }
    }

    /// Like [`Session::settled_seq`], but not held back by items pending
    /// longer than the limit as of `now`.
    pub fn settled_seq(&mut self, items: &[Item], now: Instant) -> Option<u64> {
        let pending: Vec<u64> = items.iter().filter(|i| i.status == Status::Pending).map(|i| i.seq).collect();
        self.since.retain(|seq, _| pending.contains(seq));
        let mut lowest = None;
        for seq in pending {
            let since = *self.since.entry(seq).or_insert(now);
            if now.saturating_duration_since(since) >= self.limit {
                if self.skipped.insert(seq) {
                    eprintln!(
                        "skipping #{seq}: still not fetched after {}s; waking for later items",
                        self.limit.as_secs()
                    );
                }
            } else {
                lowest = Some(lowest.map_or(seq, |l: u64| l.min(seq)));
            }
        }
        match lowest {
            Some(p) => p.checked_sub(1),
            None => items.iter().map(|i| i.seq).max(),
        }
    }

    /// The sequence numbers of skipped items that have arrived since, once
    /// each, for the caller to wake for although its cursor is past them.
    pub fn arrived_late(&mut self, items: &[Item]) -> Vec<u64> {
        let arrived: Vec<u64> = items
            .iter()
            .filter(|i| i.status != Status::Pending && self.skipped.contains(&i.seq))
            .map(|i| i.seq)
            .collect();
        for seq in &arrived {
            self.skipped.remove(seq);
        }
        arrived
    }

    /// How long until the next pending item is given up on.
    pub fn next_check(&self, now: Instant) -> Option<Duration> {
        self.since
            .iter()
            .filter(|(seq, _)| !self.skipped.contains(seq))
            .map(|(_, since)| self.limit.saturating_sub(now.saturating_duration_since(*since)))
            .min()
    }
}

/// Whether `spec` names participant `p`: `owner`, `role:<role>`, a key or a
/// display name (`@` optional).
fn names(p: &Participant, spec: &str) -> bool {
    let spec = spec.trim();
    match spec {
        "owner" => p.role == "owner",
        _ => match spec.strip_prefix("role:") {
            Some(role) => p.role == role,
            None => p.participant_pub == spec || p.display_name == spec.strip_prefix('@').unwrap_or(spec),
        },
    }
}

/// See [`Session::agent_hops`].
fn hops(items: &[Item], index: &HashMap<String, usize>, web: &dyn Fn(&str) -> bool, item: &Item) -> usize {
    let parent = |i: &Item| index.get(i.reply_to()?).map(|&n| &items[n]);
    let mut chain = 0;
    let mut cur = Some(item);
    while let Some(i) = cur {
        if web(&i.author) || chain > 1000 {
            break;
        }
        chain += 1;
        cur = parent(i);
    }
    // Two agents addressing each other without replying never form a chain:
    // count the text just before it, up to the last thing a person posted.
    let mut run = 0;
    if item.to().is_some() && item.reply_to().is_none() {
        run = 1;
        for i in items.iter().rev().filter(|i| i.seq < item.seq) {
            if web(&i.author) || run > 1000 {
                break;
            }
            if i.kind == "text" {
                run += 1;
            }
        }
    }
    chain.max(run)
}

/// Why the relay stopped answering: the session is gone, or (401) this
/// participant left or its role was revoked.
fn gone_reason(e: &anyhow::Error) -> String {
    if status_of(e) == Some(401) {
        "the relay no longer accepts this participant (it left, or its role was revoked)".into()
    } else {
        "no longer on the relay".into()
    }
}

// ---------------------------------------------------------------- items --

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// Verified and decrypted.
    Ok,
    /// The blob could not be fetched yet (network, busy relay); retried later.
    Pending,
    /// The relay deleted the blob before this client fetched it. The
    /// client asks the participants holding it to upload it again, and
    /// fetches it if one does.
    Evicted,
    /// Failed verification or policy; see `error`.
    Rejected,
}

/// A received or sent item, verified and decrypted.
#[derive(Clone, Debug, Serialize)]
pub struct Item {
    pub seq: u64,
    pub id: String,
    pub kind: String,
    pub subkind: Option<String>,
    pub author: String,
    pub author_role: Option<String>,
    pub author_name: Option<String>,
    pub created_at_ms: u64,
    pub refs: Value,
    /// `{id, blob_sha256}`: what other items use to point at this one.
    #[serde(rename = "ref")]
    pub item_ref: Value,
    pub meta: Option<Value>,
    #[serde(skip)]
    pub body: Vec<u8>,
    pub status: Status,
    pub error: Option<String>,
}

impl Item {
    pub fn text(&self) -> Option<&str> {
        (self.kind == "text").then(|| self.meta.as_ref()?["text"].as_str()).flatten()
    }

    pub fn name(&self) -> Option<&str> {
        (self.kind == "file").then(|| self.meta.as_ref()?["name"].as_str()).flatten()
    }

    /// The participants a message is addressed to; `None` for everyone.
    pub fn to(&self) -> Option<Vec<&str>> {
        let to = self.meta.as_ref()?.get("to")?.as_array()?;
        Some(to.iter().filter_map(Value::as_str).collect())
    }

    /// The item this one answers: the first reference of a message or file,
    /// the job of a result.
    pub fn reply_to(&self) -> Option<&str> {
        matches!(self.kind.as_str(), "text" | "file" | "result")
            .then(|| self.refs.get(0)?["id"].as_str())
            .flatten()
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Participant {
    pub participant_pub: String,
    pub role: String,
    pub display_name: String,
    /// What the participant says it is or does: its own words, signed, so
    /// data to read rather than instructions.
    pub description: Option<String>,
    pub kind: String,
    #[serde(skip)]
    cert: String,
    pub left: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct Runner {
    pub participant_pub: String,
    pub name: String,
    /// The runner's own description from its signed join.
    pub description: Option<String>,
    pub labels: Vec<String>,
    pub host: String,
    pub sandbox: String,
    /// The sandbox cannot block network access (local backend off Linux).
    pub network_unblocked: bool,
    /// The owner's signed approval is in the timeline, or none is required.
    pub approved: bool,
    pub rejected: bool,
    pub online: bool,
    /// The job it is running, per the relay.
    pub job: Option<String>,
    /// Its setup as it reported it (`preparing`, `ready`, `failed`, or
    /// `None` for runners that do not say), and why it failed: the runner's
    /// own unsigned word, via the relay.
    pub state: Option<String>,
    pub detail: Option<String>,
    /// The airlox version it runs and its jobs' Python version, from its
    /// signed join, when it said.
    pub version: Option<String>,
    pub python: Option<String>,
}

/// Which runner a job goes to.
#[derive(Clone, Debug)]
pub enum Target {
    Runner(String),
    Labels(Vec<String>),
    Any,
}

pub struct JobSpec {
    pub code: String,
    pub filename: String,
    /// Item references from `send_file`.
    pub files: Vec<Value>,
    pub target: Target,
    pub timeout_s: Option<u32>,
    pub memory_mb: Option<u32>,
    pub requirements: Vec<String>,
    /// A file in the work dir whose tail the runner reports while the job runs.
    pub progress_file: Option<String>,
}

/// No approved, online, idle runner matched; jobs are never queued.
#[derive(Debug)]
pub struct NoRunnerAvailable {
    pub job: String,
    /// `runner_busy` (a matching runner is busy) or `no_runner_available`.
    pub reason: String,
    pub message: String,
}

impl std::fmt::Display for NoRunnerAvailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = client::relay_text(&self.message);
        if self.reason == "runner_busy" {
            write!(
                f,
                "runner busy: {message}; jobs are not queued. Retry when 'airlox runner list' shows it idle."
            )
        } else {
            write!(f, "no runner available: {message:?}")
        }
    }
}

impl std::error::Error for NoRunnerAvailable {}

#[derive(Clone, Debug, Serialize)]
pub struct OutFile {
    pub name: String,
    pub size: u64,
    #[serde(rename = "ref")]
    pub item_ref: Value,
    /// The bytes, verified against `ref`; `None` if they left the relay first.
    #[serde(skip)]
    pub data: Option<Vec<u8>>,
}

/// A small text file from a job's `out.zip`, shown inline so it can be read
/// without saving and unpacking the archive.
#[derive(Clone, Debug, Serialize)]
pub struct OutText {
    pub name: String,
    pub text: String,
}

/// The longest runner `detail` (its setup failure) kept, as the relay allows.
const MAX_DETAIL_CHARS: usize = 300;

/// Inline only files this small, at most this many bytes and files in all:
/// the runner chooses what is in out.zip, and this goes to a model.
const OUT_TEXT_MAX: u64 = 16 * 1024;
const OUT_TEXT_TOTAL: u64 = 64 * 1024;
const OUT_TEXT_FILES: usize = 20;

/// The small UTF-8 text files in `out.zip`, by path. Anything else in the
/// archive (binary, larger, or past the total) is left to `--out-dir`.
pub fn out_text(outs: &[OutFile]) -> Vec<OutText> {
    use airlox_core::validate::zip::{inspect_zip, ZipLimits};
    use std::io::Read;
    let Some(data) = outs.iter().find(|f| f.name == "out.zip").and_then(|f| f.data.as_deref()) else {
        return vec![];
    };
    let Ok(entries) = inspect_zip(data, &ZipLimits::default()) else { return vec![] };
    let Ok(mut ar) = zip::ZipArchive::new(std::io::Cursor::new(data)) else { return vec![] };
    let mut out = Vec::new();
    let mut budget = OUT_TEXT_TOTAL;
    for e in &entries {
        if out.len() == OUT_TEXT_FILES {
            break;
        }
        if e.is_dir || e.size == 0 || e.size > OUT_TEXT_MAX.min(budget) {
            continue;
        }
        let Ok(f) = ar.by_name(&e.path) else { continue };
        let mut buf = Vec::new();
        if f.take(OUT_TEXT_MAX + 1).read_to_end(&mut buf).is_err() || buf.len() as u64 > OUT_TEXT_MAX {
            continue;
        }
        let Ok(text) = String::from_utf8(buf) else { continue };
        if text.contains('\0') {
            continue;
        }
        budget -= text.len() as u64;
        out.push(OutText { name: e.path.clone(), text });
    }
    out
}

/// A job's outcome. `signed` outcomes come from the runner; unsigned ones
/// describe a job that never produced one (the relay's reason).
#[derive(Clone, Debug, Serialize)]
pub struct Outcome {
    pub job: String,
    pub status: String,
    pub exit_code: Option<i64>,
    pub reason: Option<String>,
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub wall_ms: u64,
    pub peak_mem_mb: u64,
    pub out_files: Vec<OutFile>,
    /// Small text files from `out.zip`, inline.
    pub out_text: Vec<OutText>,
    /// Where the job ran, as its runner measured and signed it (interpreter
    /// version, installed versions of the allowlisted packages, sandbox, where
    /// the interpreter came from). `None` for unsigned outcomes and for
    /// runners that do not report it.
    pub env: Option<airlox_core::payload::JobEnv>,
    /// The runner's key, and the name it joined with.
    pub runner: Option<String>,
    pub runner_name: Option<String>,
    pub signed: bool,
}

impl Outcome {
    fn unsigned(
        job: &str,
        status: &str,
        reason: Option<String>,
        runner: Option<String>,
        runner_name: Option<String>,
    ) -> Outcome {
        Outcome {
            job: job.into(),
            status: status.into(),
            exit_code: None,
            reason,
            stdout: String::new(),
            stderr: String::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            wall_ms: 0,
            peak_mem_mb: 0,
            out_files: vec![],
            out_text: vec![],
            env: None,
            runner,
            runner_name,
            signed: false,
        }
    }

    /// The relay lost contact with the job's runner and no signed result
    /// has come. Not final: the runner may still be running the job and
    /// post its result when it is back, so check again later.
    pub fn runner_lost(&self) -> bool {
        !self.signed && self.reason.as_deref() == Some("runner_lost")
    }
}

// -------------------------------------------------------------- session --

/// How this client presents itself when it joins: a display name and an
/// optional description (what it is or does), both shown to the others.
#[derive(Clone, Debug, Default)]
pub struct Profile {
    pub display_name: String,
    pub description: Option<String>,
}

impl Profile {
    /// An empty or blank description (an empty `AIRLOX_DESCRIPTION=`) means none.
    pub fn new(display_name: &str, description: Option<&str>) -> Profile {
        Profile {
            display_name: display_name.trim().to_string(),
            description: description.map(str::trim).filter(|d| !d.is_empty()).map(String::from),
        }
    }
}

/// What a new session allows.
pub struct NewSession {
    pub mode: Mode,
    /// `None`: the session never expires.
    pub ttl_ms: Option<u64>,
    pub allowed_types: Vec<String>,
    pub max_item_bytes: u64,
    pub job_limits: Option<JobLimits>,
    /// The relay host participants may reach over plain `http://`.
    pub insecure_http_host: Option<String>,
}

pub struct Session {
    relay: Relay,
    pub base_url: String,
    pub session_id: String,
    pub signed_manifest: String,
    pub manifest: Manifest,
    pub role: Role,
    /// This participant's public key.
    pub me: String,
    key: [u8; 32],
    seed: [u8; 32],
    owner_seed: Option<[u8; 32]>,
    cache: Cache,
    participants: HashMap<String, Participant>,
    items: Vec<Item>,
    index: HashMap<String, usize>,
    envelopes: HashMap<String, String>,
    evicted: HashSet<String>,
    /// Evicted items this client asked holders for, and when it last asked.
    wanted: HashMap<String, Instant>,
    /// Evicted items others asked for, which this client may hold.
    asked: HashSet<String>,
    /// Evicted items back on the relay, to fetch.
    reseeded: HashSet<String>,
    unacked: HashSet<String>,
    last_seq: Option<u64>,
    /// When this client last heard from the relay: a sync that went through,
    /// or data on the event stream.
    pub synced_at_ms: Option<u64>,
    /// Why the session is over, once it is.
    pub closed: Option<String>,
    /// This process joined as a new participant (no cached identity), so
    /// the name and description it gave are the ones others see.
    pub joined_now: bool,
}

impl Session {
    /// Create a session on `relay` and join it as the owner.
    pub async fn create(
        http: &reqwest::Client,
        relay: &str,
        new: NewSession,
        me: &Profile,
        cache_root: &Path,
    ) -> Result<Session> {
        let relay = relay.trim_end_matches('/');
        let params = SessionParams {
            mode: new.mode,
            created_at_ms: now_ms(),
            ttl_ms: new.ttl_ms,
            allowed_types: serde_json::from_value(json!(new.allowed_types))
                .context("unknown content type")?,
            max_item_bytes: new.max_item_bytes,
            job_limits: new.job_limits,
            insecure_http_host: new.insecure_http_host,
        };
        let (owner_seed, signed) = api::create_session(&serde_json::to_string(&params)?, None)?;
        // Refuse a relay URL the session's own links could not use before
        // the session exists (plain http to a host it does not name).
        let url = api::owner_invite(relay, &owner_seed)?;
        api::check_invite(&url, &signed).with_context(|| format!("relay {relay}"))?;
        client::create_session(http, relay, signed).await?;
        Session::join(http, &url, me, cache_root).await
    }

    /// Join with an invite link, as the participant this cache already holds
    /// for the session and role if there is one (its name and description
    /// were fixed when it first joined). If the relay no longer has the
    /// session but the cache does, it opens read-only with `closed` set.
    pub async fn join(
        http: &reqwest::Client,
        invite: &str,
        me: &Profile,
        cache_root: &Path,
    ) -> Result<Session> {
        let (info, key, role_seed) = api::parse_invite(invite).context("not a valid invite link")?;
        let base = info.base_url.trim_end_matches('/').to_string();
        let sid = info.session_id.clone();
        let role = info.role;
        Cache::sweep_expired(cache_root);
        let cache = Cache::open(cache_root, &sid)?;
        let identity = cache.load_identity(role.as_str())?;
        if let Some(bound) = identity.as_ref().and_then(|i| i.base_url.as_deref()) {
            if bound != base {
                bail!(
                    "this invite names relay {} but you joined session {sid} on {}; refusing to send your \
                     token to another relay (the link may have been altered)",
                    client::relay_text(&base),
                    client::relay_text(bound)
                );
            }
        }
        let (signed, offline) = match client::get_manifest(http, &base, &sid).await {
            Ok(s) => (s, false),
            Err(e) if matches!(status_of(&e), Some(404 | 410)) => match (cache.load_manifest(), &identity) {
                (Some(m), Some(_)) => (m, true),
                _ => return Err(e.context(format!("session {sid} is not on {base}"))),
            },
            Err(e) => return Err(e),
        };
        api::check_invite(invite, &signed)?;
        if !offline {
            cache.save_manifest(&signed)?;
        }
        let joined_now = identity.is_none();
        let identity = match identity {
            Some(i) => i,
            None => {
                let seed = api::generate_seed();
                let cert =
                    api::issue_cert(&role_seed, &sid, role.as_str(), &api::public_key(&seed)?, now_ms())?;
                let join = json!({
                    "v": 1,
                    "session_id": sid,
                    "cert": serde_json::from_str::<Value>(&cert)?,
                    "display_name": me.display_name,
                    "description": me.description,
                    "kind": "cli",
                    "runner": null,
                    "created_at_ms": now_ms(),
                });
                let signed_join = api::sign_join(&seed, &join.to_string())?;
                let token = client::join(http, &base, &sid, signed_join).await?;
                let id = Identity {
                    participant_seed: hex(&seed),
                    token,
                    role: Some(role.as_str().into()),
                    base_url: Some(base.clone()),
                };
                cache.save_identity(role.as_str(), &id)?;
                id
            }
        };
        // Identities cached before the relay was recorded are bound now.
        let identity = match identity.base_url {
            Some(_) => identity,
            None => {
                let id = Identity { base_url: Some(base.clone()), ..identity };
                cache.save_identity(role.as_str(), &id)?;
                id
            }
        };
        let seed = unhex32(&identity.participant_seed)?;
        let manifest = SignedManifest::from_json(&signed)?.manifest;
        let mut s = Session {
            relay: Relay::new(http.clone(), &base, &sid, &identity.token),
            base_url: base,
            session_id: sid,
            signed_manifest: signed,
            manifest,
            role,
            me: api::public_key(&seed)?,
            key,
            seed,
            owner_seed: (role == Role::Owner).then_some(role_seed),
            cache,
            participants: HashMap::new(),
            items: Vec::new(),
            index: HashMap::new(),
            envelopes: HashMap::new(),
            evicted: HashSet::new(),
            wanted: HashMap::new(),
            asked: HashSet::new(),
            reseeded: HashSet::new(),
            unacked: HashSet::new(),
            last_seq: None,
            synced_at_ms: None,
            closed: None,
            joined_now,
        };
        // Which blobs the relay lacks now, so replayed items without a
        // cached blob come out evicted rather than pending.
        let cached = s.cache.events();
        for e in &cached {
            let Some(id) = e["data"]["item"].as_str() else { continue };
            match e["kind"].as_str() {
                Some("evicted") => s.evicted.insert(id.to_string()),
                Some("reseeded") => s.evicted.remove(id),
                _ => false,
            };
        }
        for ev in &cached {
            s.apply(ev, false, false).await?;
        }
        if offline && s.closed.is_none() {
            s.closed = Some("no longer on the relay".into());
        }
        Ok(s)
    }

    // ------------------------------------------------------------ owner --

    /// Invite links per role (owner only).
    pub fn invites(&self) -> Result<BTreeMap<String, String>> {
        let seed = self.owner_seed.as_ref().context("only the owner can mint invites")?;
        let mut out = BTreeMap::new();
        let mut roles = vec!["sender", "observer"];
        if self.manifest.mode == Mode::Execute {
            roles.push("runner");
        }
        for r in roles {
            out.insert(r.to_string(), api::member_invite(&self.base_url, seed, r)?);
        }
        out.insert("owner".into(), api::owner_invite(&self.base_url, seed)?);
        Ok(out)
    }

    /// Revoke a role (owner only): its participants are cut off and its
    /// invite admits no one. Whoever kept that invite still holds the session
    /// key, so what they already copied stays readable to them.
    pub async fn revoke(&mut self, role: &str) -> Result<()> {
        if self.role != Role::Owner {
            bail!("only the owner can revoke a role");
        }
        let role = Role::parse(role)
            .ok()
            .filter(|r| *r != Role::Owner)
            .context("revoke one of sender, observer or runner")?;
        self.relay.post_raw(&format!("/roles/{}/revoke", role.as_str()), vec![], &[]).await?;
        Ok(())
    }

    /// The session's audit trail as JSONL (owner or observer): who joined,
    /// posted, acked, approved and revoked, with the signed joins and item
    /// envelopes to check it against. It is purged with the session. Each
    /// line is parsed and re-serialized: JSON from the relay, never raw bytes.
    pub async fn audit(&self) -> Result<String> {
        let raw = self.relay.audit().await?;
        let mut out = String::new();
        for line in raw.split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
            let v: Value =
                serde_json::from_slice(line).context("the relay sent an audit line that is not JSON")?;
            out.push_str(&v.to_string());
            out.push('\n');
        }
        Ok(out)
    }

    /// Close and purge the session on the relay (owner only).
    pub async fn close(&mut self) -> Result<()> {
        self.relay.post_raw("/close", vec![], &[]).await?;
        self.closed = Some("closed by owner".into());
        Ok(())
    }

    /// The description this participant joined with (fixed at its first
    /// join), as the others see it.
    /// `None` until this participant's own join has been seen (before the
    /// first sync).
    pub fn my_description(&self) -> Option<Option<&str>> {
        self.participants.get(&self.me).map(|p| p.description.as_deref())
    }

    /// The name a participant joined with, from its verified join.
    pub fn participant_name(&self, key: &str) -> Option<String> {
        self.participants.get(key).map(|p| p.display_name.clone())
    }

    pub fn participants(&self) -> Vec<Participant> {
        let mut v: Vec<_> = self.participants.values().cloned().collect();
        v.sort_by(|a, b| a.display_name.cmp(&b.display_name));
        v
    }

    // ---------------------------------------------------------- sending --

    /// Send a message addressed to `to` (participant keys, from
    /// [`Session::resolve_recipients`]; empty for everyone), as a reply to
    /// item `reply_to` if given. Returns the item reference.
    pub async fn send_message(&mut self, text: &str, to: &[String], reply_to: Option<&str>) -> Result<Value> {
        let mut meta = json!({"type": "text", "text": text});
        if !to.is_empty() {
            meta["to"] = json!(to);
        }
        let refs = self.reply_refs(reply_to).await?;
        self.send("text", None, meta, vec![], refs).await
    }

    /// The reference list for a reply: the parent item, pinned by blob hash.
    pub async fn reply_refs(&mut self, reply_to: Option<&str>) -> Result<Vec<Value>> {
        let Some(id) = reply_to else { return Ok(vec![]) };
        if self.get(id).is_none() {
            self.sync().await?;
        }
        let item = self.get(id).with_context(|| format!("no item {id} in this session to reply to"))?;
        Ok(vec![item.item_ref.clone()])
    }

    /// Participant keys for `specs`: a key, a display name (`@` optional),
    /// or `role:<owner|sender|observer|runner>`. A name that several
    /// participants share addresses all of them. Never yourself.
    pub fn resolve_recipients(&self, specs: &[String]) -> Result<Vec<String>> {
        let live: Vec<&Participant> = self.participants.values().filter(|p| !p.left).collect();
        let mut out: Vec<String> = Vec::new();
        for spec in specs {
            let spec = spec.trim();
            let found: Vec<&&Participant> = if let Some(role) = spec.strip_prefix("role:") {
                live.iter().filter(|p| p.role == role).collect()
            } else {
                let name = spec.strip_prefix('@').unwrap_or(spec);
                let by_key: Vec<_> = live.iter().filter(|p| p.participant_pub == spec).collect();
                if by_key.is_empty() {
                    live.iter().filter(|p| p.display_name == name).collect()
                } else {
                    by_key
                }
            };
            let found: Vec<_> = found.into_iter().filter(|p| p.participant_pub != self.me).collect();
            if found.is_empty() {
                let mut names: Vec<_> = live
                    .iter()
                    .filter(|p| p.participant_pub != self.me)
                    .map(|p| p.display_name.as_str())
                    .collect();
                names.sort();
                names.dedup();
                bail!("no other participant matches {spec:?}; participants: {}", names.join(", "));
            }
            for p in found {
                if !out.contains(&p.participant_pub) {
                    out.push(p.participant_pub.clone());
                }
            }
        }
        if out.len() > 64 {
            bail!("a message can be addressed to at most 64 participants");
        }
        Ok(out)
    }

    /// For this participant's own items, who has stored each one
    /// (`delivered`) and who the relay still holds it for (`waiting`), keyed
    /// by item id. Delivered means fetched, not read.
    pub async fn delivery(&self) -> Result<Value> {
        Ok(self.relay.get_json("/delivery").await?["items"].take())
    }

    /// Send a file the protocol can carry, as a reply to item `reply_to` if
    /// given. Images are re-encoded first to strip metadata; ZIPs are
    /// checked. Returns the item reference.
    pub async fn send_file_reply(
        &mut self,
        data: Vec<u8>,
        name: &str,
        reply_to: Option<&str>,
    ) -> Result<Value> {
        let refs = self.reply_refs(reply_to).await?;
        let (subkind, mime) = file_type(name)
            .with_context(|| format!("unsupported file type for {name:?}; use {FILE_TYPES_HELP}"))?;
        let (mime, data) = match subkind {
            "image" => {
                let (m, d) = api::sanitize_image(&data).context("not a valid image")?;
                (m, d)
            }
            "zip" => {
                api::inspect_zip(&data).context("not an acceptable ZIP")?;
                (mime.to_string(), data)
            }
            _ => (mime.to_string(), data),
        };
        self.send("file", Some(subkind), json!({"type": "file", "name": name, "mime": mime}), data, refs)
            .await
    }

    /// Returns `(item_id, envelope_json, blob, upload_frame)`.
    fn seal(
        &self,
        kind: &str,
        subkind: Option<&str>,
        meta: &Value,
        body: &[u8],
        refs: Vec<Value>,
    ) -> Result<(String, String, Vec<u8>, Vec<u8>)> {
        let needed = match kind {
            "text" => Some("text"),
            "file" => subkind,
            "job" => Some("py"),
            _ => None,
        };
        let allowed: Vec<String> = serde_json::from_value(json!(self.manifest.allowed_types))?;
        if let Some(n) = needed {
            if !allowed.iter().any(|a| a == n) {
                bail!("{n} is not allowed in this session (allowed: {})", allowed.join(", "));
            }
        }
        let payload = api::encode_payload(&meta.to_string(), body)?;
        if payload.len() as u64 > self.manifest.max_item_bytes {
            bail!(
                "the item is {} bytes; this session's limit is {}",
                payload.len(),
                self.manifest.max_item_bytes
            );
        }
        let id = api::new_item_id();
        let new = json!({
            "id": id,
            "session_id": self.session_id,
            "kind": kind,
            "subkind": subkind,
            "created_at_ms": now_ms(),
            "refs": refs,
        });
        let (env, blob) = api::seal_item(&self.key, &self.seed, &new.to_string(), &payload)?;
        let mut frame = Vec::with_capacity(4 + env.len() + blob.len());
        frame.extend_from_slice(&(env.len() as u32).to_be_bytes());
        frame.extend_from_slice(env.as_bytes());
        frame.extend_from_slice(&blob);
        self.cache.write_blob(&id, &blob)?;
        Ok((id, env, blob, frame))
    }

    async fn send(
        &mut self,
        kind: &str,
        subkind: Option<&str>,
        meta: Value,
        body: Vec<u8>,
        refs: Vec<Value>,
    ) -> Result<Value> {
        let (_, env, blob, frame) = self.seal(kind, subkind, &meta, &body, refs)?;
        self.relay.post_raw("/items", frame, &[]).await?;
        Ok(serde_json::from_str(&api::item_ref(&env, &blob)?)?)
    }

    // ------------------------------------------------------ execute mode --

    fn limits(&self) -> Result<&JobLimits> {
        if self.manifest.mode != Mode::Execute {
            bail!("this session is in relay mode; it has no runners");
        }
        self.manifest.job_limits.as_ref().context("execute session without job limits")
    }

    /// Runners in the session: names and labels from each verified join,
    /// approval from the owner's signed events and manifest. The relay's
    /// listing only says who is online, busy or turned away.
    pub async fn runners(&mut self) -> Result<Vec<Runner>> {
        let required = self.limits()?.approve_runners;
        self.sync().await?;
        let listing = self.relay.get_json("/runners").await?;
        let approvals = self.signed_approvals();
        let mut out = Vec::new();
        for r in listing["runners"].as_array().cloned().unwrap_or_default() {
            let Some(raw) = r["signed_join"].as_str() else { continue };
            if api::verify_join(raw, &self.signed_manifest).is_err() {
                continue;
            }
            let join: Value = serde_json::from_str(raw)?;
            let join = &join["join"];
            let info = &join["runner"];
            let public = join["cert"]["cert"]["participant_pub"].as_str().unwrap_or_default().to_string();
            let rejected_relay = r["rejected"].as_bool().unwrap_or(false);
            let approved = if required { approvals.get(&public) == Some(&true) } else { !rejected_relay };
            out.push(Runner {
                name: info["name"].as_str().unwrap_or_default().into(),
                labels: serde_json::from_value(info["labels"].clone()).unwrap_or_default(),
                description: join["description"].as_str().map(String::from),
                host: info["host"].as_str().unwrap_or_default().into(),
                sandbox: info["sandbox"].as_str().unwrap_or_default().into(),
                network_unblocked: info["network_unblocked"].as_bool().unwrap_or(false),
                approved: approved && !rejected_relay,
                rejected: rejected_relay || approvals.get(&public) == Some(&false),
                online: r["online"].as_bool().unwrap_or(false),
                job: r["job"].as_str().map(String::from),
                state: r["state"].as_str().map(String::from),
                // The relay caps it, but the relay is not trusted either.
                detail: r["detail"].as_str().map(|d| match d.char_indices().nth(MAX_DETAIL_CHARS) {
                    Some((cut, _)) => format!("{}…", &d[..cut]),
                    None => d.to_string(),
                }),
                version: info["version"].as_str().map(String::from),
                python: info["python"].as_str().map(String::from),
                participant_pub: public,
            });
        }
        Ok(out)
    }

    async fn runner(&mut self, which: &str) -> Result<Runner> {
        let matches: Vec<Runner> = self
            .runners()
            .await?
            .into_iter()
            .filter(|r| r.name == which || r.participant_pub == which)
            .collect();
        match matches.len() {
            1 => Ok(matches.into_iter().next().unwrap()),
            0 => bail!("no runner matches {which:?}"),
            _ => bail!("more than one runner matches {which:?}; use its key"),
        }
    }

    /// Let a runner take jobs (owner only): the relay's approval, then a
    /// signed `runner_approve` event for runners and senders to verify. In
    /// that order: a runner awaiting approval is not a recipient, so the relay
    /// would not keep the event for it, and a runner that fetched it late
    /// would never see its own approval.
    pub async fn approve_runner(&mut self, which: &str) -> Result<Runner> {
        let r = self.runner(which).await?;
        self.relay.post_raw(&format!("/runners/{}/approve", r.participant_pub), vec![], &[]).await?;
        let meta = json!({"type": "event", "event": "runner_approve", "participant_pub": r.participant_pub});
        self.send("event", None, meta, vec![], vec![]).await?;
        Ok(r)
    }

    /// Turn a runner away (owner only); its token stops working.
    pub async fn reject_runner(&mut self, which: &str, reason: Option<&str>) -> Result<Runner> {
        let r = self.runner(which).await?;
        let meta = json!({"type": "event", "event": "runner_reject", "participant_pub": r.participant_pub, "reason": reason});
        self.send("event", None, meta, vec![], vec![]).await?;
        self.relay.post_raw(&format!("/runners/{}/reject", r.participant_pub), vec![], &[]).await?;
        Ok(r)
    }

    /// Submit Python to a runner. Returns the job's item id and the runner
    /// the relay assigned, or `NoRunnerAvailable` at once if none matched.
    pub async fn run_python(&mut self, spec: JobSpec) -> Result<(String, Option<String>)> {
        let limits = self.limits()?.clone();
        let target = match &spec.target {
            Target::Runner(which) => {
                let r = self.runner(which).await?;
                // The relay may route to a runner the owner has not signed an
                // approval for (if posting it failed); it would get the code
                // and inputs only to refuse them.
                if !r.approved {
                    bail!(
                        "runner {} has no signed approval from the owner yet; ask the owner to approve it \
                         (again)",
                        client::relay_text(&r.name)
                    );
                }
                json!({"type": "runner", "participant_pub": r.participant_pub, "name": r.name})
            }
            Target::Labels(l) => json!({"type": "labels", "labels": l}),
            Target::Any => json!({"type": "any"}),
        };
        let mut meta = json!({
            "type": "job",
            "filename": spec.filename,
            "code": spec.code,
            "runtime": limits.runtime,
            "timeout_s": spec.timeout_s.unwrap_or(limits.timeout_s),
            "memory_mb": spec.memory_mb,
            "files": spec.files,
            "requirements": spec.requirements,
            "target": target,
        });
        // Absent rather than null: the canonical form leaves it out.
        if let Some(p) = &spec.progress_file {
            meta["progress_file"] = json!(p);
        }
        let (id, _, _, frame) = self.seal("job", Some("py"), &meta, b"", vec![])?;
        match self.relay.post_raw("/jobs", frame, &[("Airlox-Target", target.to_string())]).await {
            Ok(resp) => {
                let v: Value = client::read_capped(resp, 64 << 10)
                    .await
                    .ok()
                    .and_then(|b| serde_json::from_slice(&b).ok())
                    .unwrap_or(Value::Null);
                Ok((id, v["runner"].as_str().map(String::from)))
            }
            Err(e) => match e.downcast_ref::<RelayError>() {
                Some(r) if r.code == "no_runner_available" || r.code == "runner_busy" => {
                    Err(NoRunnerAvailable { job: id, reason: r.code.clone(), message: r.message.clone() }
                        .into())
                }
                _ => Err(e),
            },
        }
    }

    /// Ask a job's runner to stop it (owner or the job's sender), with a
    /// signed `job_cancel` event recording who asked.
    pub async fn cancel_job(&mut self, job: &str) -> Result<()> {
        check_job_id(job)?;
        self.sync().await?;
        let job_ref =
            self.get(job).filter(|i| i.kind == "job").map(|i| i.item_ref.clone()).context("no such job")?;
        let meta = json!({"type": "event", "event": "job_cancel", "job": job_ref});
        self.send("event", None, meta, vec![], vec![job_ref]).await?;
        self.relay.post_raw(&format!("/jobs/{job}/cancel"), vec![], &[]).await?;
        Ok(())
    }

    /// The relay's routing view of a job: `{job, state, runner, reason}`.
    pub async fn job_state(&self, job: &str) -> Result<Value> {
        check_job_id(job)?;
        self.relay.get_json(&format!("/jobs/{job}")).await
    }

    /// Whether a result item is a valid answer to the job it names: posted by
    /// a runner the job could go to (approved, when the manifest requires it)
    /// and bound to that job.
    pub fn result_is_valid(&self, item: &Item) -> bool {
        let Some(m) = item.meta.as_ref() else { return false };
        if item.kind != "result" || item.status != Status::Ok || item.author_role.as_deref() != Some("runner")
        {
            return false;
        }
        let Some(job_item) = m["job"]["id"]
            .as_str()
            .and_then(|j| self.get(j))
            .filter(|i| i.kind == "job" && i.status == Status::Ok)
        else {
            return false;
        };
        let Some(job_meta) = job_item.meta.as_ref() else { return false };
        let approved = match self.manifest.job_limits.as_ref() {
            Some(l) if l.approve_runners => {
                let mut v: Vec<String> =
                    self.signed_approvals().into_iter().filter(|(_, ok)| *ok).map(|(k, _)| k).collect();
                v.sort();
                Some(json!(v).to_string())
            }
            _ => None,
        };
        api::check_result_for_job(
            &job_item.item_ref.to_string(),
            &job_meta.to_string(),
            &item.author,
            &m.to_string(),
            approved.as_deref(),
        )
        .is_ok()
    }

    /// The job's signed outcome, once it and its out files have arrived.
    pub fn result(&self, job: &str) -> Option<Outcome> {
        for item in &self.items {
            let Some(m) = item.meta.as_ref() else { continue };
            if item.kind != "result" || m["job"]["id"] != job || !self.result_is_valid(item) {
                continue;
            }
            let mut outs = Vec::new();
            for o in m["out_files"].as_array().cloned().unwrap_or_default() {
                let got = o["item"]["id"].as_str().and_then(|id| self.get(id));
                let got = got?;
                if got.status == Status::Pending {
                    return None; // not here yet; the next sync fetches it
                }
                let data = (got.status == Status::Ok && got.item_ref == o["item"]).then(|| got.body.clone());
                outs.push(OutFile {
                    name: o["name"].as_str().unwrap_or_default().into(),
                    size: o["size"].as_u64().unwrap_or(0),
                    item_ref: o["item"].clone(),
                    data,
                });
            }
            return Some(Outcome {
                job: job.into(),
                status: m["status"].as_str().unwrap_or_default().into(),
                exit_code: m["exit_code"].as_i64(),
                reason: m["reason"].as_str().map(String::from),
                stdout: m["stdout"].as_str().unwrap_or_default().into(),
                stderr: m["stderr"].as_str().unwrap_or_default().into(),
                stdout_truncated: m["stdout_truncated"].as_bool().unwrap_or(false),
                stderr_truncated: m["stderr_truncated"].as_bool().unwrap_or(false),
                wall_ms: m["wall_ms"].as_u64().unwrap_or(0),
                peak_mem_mb: m["peak_mem_mb"].as_u64().unwrap_or(0),
                out_text: out_text(&outs),
                out_files: outs,
                // Shaped like a `JobEnv` already: the result passed the core's
                // checks, which refuse unknown fields.
                env: serde_json::from_value(m["env"].clone()).ok(),
                runner: Some(item.author.clone()),
                runner_name: item.author_name.clone(),
                signed: true,
            });
        }
        None
    }

    /// Wait for a job's outcome. A job that failed on the relay (no runner,
    /// runner lost, cancelled before it started) gives an unsigned outcome
    /// with the relay's reason. `None` if `timeout` passes first. A
    /// `runner_lost` outcome ([`Outcome::runner_lost`]) is not final: a
    /// late signed result still completes the job.
    pub async fn wait(&mut self, job: &str, timeout: Option<Duration>) -> Result<Option<Outcome>> {
        let deadline = timeout.map(|t| Instant::now() + t);
        loop {
            if let Some(r) = self.poll_job(job).await? {
                return Ok(Some(r));
            }
            if deadline.is_some_and(|d| Instant::now() >= d) {
                return Ok(None);
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    }

    /// One look at a job: its outcome if it has one. Network trouble and a
    /// busy relay count as "not yet", so long waits survive them.
    pub async fn poll_job(&mut self, job: &str) -> Result<Option<Outcome>> {
        check_job_id(job)?;
        match self.sync().await {
            Err(e) if is_transient(&e) => return Ok(None),
            r => r?,
        };
        if let Some(r) = self.result(job) {
            return Ok(Some(r));
        }
        if self.closed.is_some() {
            bail!("the session ended before job {job} finished");
        }
        let st = match self.job_state(job).await {
            Err(e) if is_transient(&e) => return Ok(None),
            r => r?,
        };
        if st["state"] != "failed" {
            return Ok(None);
        }
        // A runner that ran the job may still post its result.
        tokio::time::sleep(Duration::from_millis(500)).await;
        let _ = self.sync().await;
        if let Some(r) = self.result(job) {
            return Ok(Some(r));
        }
        let reason = st["reason"].as_str().map(String::from);
        let status = if reason.as_deref() == Some("cancelled") { "cancelled" } else { "failed" };
        let runner = st["runner"].as_str().map(String::from);
        let runner_name = runner.as_deref().and_then(|k| self.participant_name(k));
        Ok(Some(Outcome::unsigned(job, status, reason, runner, runner_name)))
    }

    /// `participant_pub -> approved?` from the owner's signed events. A
    /// rejection is final: a later (or replayed) approval does not undo it.
    fn signed_approvals(&self) -> HashMap<String, bool> {
        let mut out = HashMap::new();
        for it in &self.items {
            let Some(m) = it.meta.as_ref() else { continue };
            if it.kind != "event" || it.status != Status::Ok || it.author_role.as_deref() != Some("owner") {
                continue;
            }
            let public = m["participant_pub"].as_str().unwrap_or_default().to_string();
            match m["event"].as_str() {
                Some("runner_approve") if out.get(&public) != Some(&false) => {
                    out.insert(public, true);
                }
                Some("runner_reject") => {
                    out.insert(public, false);
                }
                _ => {}
            }
        }
        out
    }

    // -------------------------------------------------------- receiving --

    pub fn items(&self) -> &[Item] {
        &self.items
    }

    /// The cursor `mark_handled` keeps for this participant: items up to
    /// this sequence number were handled.
    pub fn handled_seq(&self) -> Option<u64> {
        self.cache.handled(&self.role_name())
    }

    /// Record that items up to `seq` were handled. The cursor only moves
    /// forward.
    pub fn mark_handled(&self, seq: u64) -> Result<()> {
        if self.handled_seq().is_some_and(|h| h >= seq) {
            return Ok(());
        }
        self.cache.save_handled(&self.role_name(), seq)
    }

    /// The highest sequence number below every item still being fetched:
    /// a cursor that never skips an item that arrives late.
    pub fn settled_seq(&self) -> Option<u64> {
        let pending = self.items.iter().filter(|i| i.status == Status::Pending).map(|i| i.seq).min();
        match pending {
            Some(p) => p.checked_sub(1),
            None => self.items.iter().map(|i| i.seq).max(),
        }
    }

    fn role_name(&self) -> String {
        serde_json::to_value(self.role).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default()
    }

    /// The highest event sequence number this client has seen.
    pub fn last_seq(&self) -> Option<u64> {
        self.last_seq
    }

    /// Why `item` should wake this participant's listener, if it should:
    /// `addressed` (its `to` names you), `reply` (it answers one of your
    /// items, a job result included, whoever else it is addressed to), or
    /// `owner` (the owner posted it to everyone). Your own items, progress reports, items addressed only to
    /// others and other participants' broadcasts wake no one.
    pub fn wake_reason(&self, item: &Item) -> Option<&'static str> {
        if item.author == self.me || item.status != Status::Ok || item.kind == "progress" {
            return None;
        }
        let to = item.to();
        if to.as_ref().is_some_and(|to| to.contains(&self.me.as_str())) {
            return Some("addressed");
        }
        // A reply reaches the author of what it answers, whoever else it names.
        if self.parent(item).is_some_and(|p| p.author == self.me) {
            return Some("reply");
        }
        if to.is_some() {
            return None;
        }
        if item.author_role.as_deref() == Some("owner") && matches!(item.kind.as_str(), "text" | "file") {
            return Some("owner");
        }
        None
    }

    /// The item `item` replies to (its first reference), if this client has it.
    pub fn parent(&self, item: &Item) -> Option<&Item> {
        self.get(item.reply_to()?)
    }

    /// How many items in a row were posted by programs (anything but the web
    /// client) rather than a person, which listeners use to stop waking
    /// agents for long agent-only exchanges: the items up `item`'s reply
    /// chain, or for an addressed item that replies to nothing, the text
    /// items just before it since a web participant last spoke, whichever
    /// is more. Participant kind is self-declared, so this is a safety net
    /// against accidental loops, not a security boundary.
    pub fn agent_hops(&self, item: &Item) -> usize {
        let web = |author: &str| self.participants.get(author).is_some_and(|p| p.kind == "web");
        hops(&self.items, &self.index, &web, item)
    }

    /// Whether `item`'s author is one of `specs` (any author if empty): the
    /// owner (`owner`, or `role:<role>`), a display name (`@` optional) or a
    /// key.
    pub fn author_in(&self, item: &Item, specs: &[String]) -> bool {
        specs.is_empty()
            || self.participants.get(&item.author).is_some_and(|p| specs.iter().any(|s| names(p, s)))
    }

    /// Whether `spec` (see [`Session::author_in`]) names a participant other than you.
    pub fn knows_participant(&self, spec: &str) -> bool {
        self.participants.values().any(|p| !p.left && p.participant_pub != self.me && names(p, spec))
    }

    pub fn get(&self, id: &str) -> Option<&Item> {
        self.index.get(id).map(|&i| &self.items[i])
    }

    /// Fetch new events, and retry pending downloads and acks. Returns the
    /// indexes of items that became available.
    pub async fn sync(&mut self) -> Result<Vec<usize>> {
        if self.closed.is_some() {
            return Ok(vec![]);
        }
        let mut out = self.retry().await?;
        let evs = match self.relay.events(self.last_seq).await {
            Ok(e) => e,
            Err(e) if matches!(status_of(&e), Some(401 | 404 | 410)) => {
                self.closed.get_or_insert_with(|| gone_reason(&e));
                return Ok(out);
            }
            Err(e) => return Err(e),
        };
        self.synced_at_ms = Some(now_ms());
        for ev in &evs {
            if let Some(i) = self.apply(ev, true, true).await? {
                if self.items[i].status != Status::Pending {
                    out.push(i);
                }
            }
        }
        self.trade_blobs().await;
        out.extend(self.fetch_reseeded().await?);
        Ok(out)
    }

    /// Fetch the items whose blobs were re-seeded; other pending downloads
    /// wait for the next retry.
    async fn fetch_reseeded(&mut self) -> Result<Vec<usize>> {
        let mut out = Vec::new();
        for id in std::mem::take(&mut self.reseeded) {
            let Some(&i) = self.index.get(&id) else { continue };
            if self.items[i].status != Status::Pending {
                continue;
            }
            let (seq, env) = (self.items[i].seq, self.envelopes.get(&id).cloned().unwrap_or_default());
            if let Some(i) = self.receive(seq, env, true).await? {
                if self.items[i].status != Status::Pending {
                    out.push(i);
                }
            }
        }
        Ok(out)
    }

    /// Re-seeding: ask holders for evicted items this participant never
    /// got, and upload the blobs others asked for that this cache holds.
    /// The relay takes an upload only if it matches the author's signed
    /// hash, so a cached blob is safe to offer.
    async fn trade_blobs(&mut self) {
        if self.closed.is_some() {
            return;
        }
        // Every holder sees the same want: wait a moment at random, so the
        // first upload usually lands before the others start.
        if !self.asked.is_empty() {
            let jitter =
                SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.subsec_nanos() % 2000).unwrap_or(0);
            tokio::time::sleep(Duration::from_millis(u64::from(jitter))).await;
        }
        for id in self.asked.clone() {
            let Some(blob) = self.cache.read_blob(&id) else {
                self.asked.remove(&id);
                continue;
            };
            match self.relay.reseed(&id, blob).await {
                Err(e) if is_transient(&e) => {}
                r => {
                    if let Err(e) = r {
                        tracing::debug!(item = %id, "re-seed refused: {e:#}");
                    }
                    self.asked.remove(&id);
                }
            }
        }
        // Never asked first, then the longest ago; a want lapses on the
        // relay, so one still unanswered is asked for again.
        let mut evicted: Vec<(Option<Instant>, String)> = self
            .items
            .iter()
            .filter(|i| i.status == Status::Evicted && i.author != self.me)
            .map(|i| (self.wanted.get(&i.id).copied(), i.id.clone()))
            .filter(|(at, _)| at.is_none_or(|t| t.elapsed() >= REASK))
            .collect();
        evicted.sort();
        for (_, id) in evicted {
            match self.relay.want(&id).await {
                Ok(true) => {}
                // Already back: fetch it. It stays wanted, so a relay that
                // says present but then serves 410 gets asked again later.
                Ok(false) => self.reappeared(&id),
                // Too many open, or a busy relay: ask again on a later sync.
                Err(e) if is_transient(&e) => break,
                Err(e) => tracing::debug!(item = %id, "want refused: {e:#}"),
            }
            self.wanted.insert(id, Instant::now());
        }
    }

    /// Whether an unanswered want is due to be asked again.
    fn reask_due(&self) -> bool {
        self.closed.is_none()
            && self.wanted.iter().any(|(id, t)| {
                t.elapsed() >= REASK && self.get(id).is_some_and(|i| i.status == Status::Evicted)
            })
    }

    /// An evicted blob is on the relay again: fetch it on the next retry.
    fn reappeared(&mut self, id: &str) {
        self.evicted.remove(id);
        self.wanted.remove(id);
        self.asked.remove(id);
        if let Some(&i) = self.index.get(id) {
            if self.items[i].status == Status::Evicted {
                self.items[i].status = Status::Pending;
                self.reseeded.insert(id.to_string());
            }
        }
    }

    /// Call `on_item` for each item as it arrives over the event stream,
    /// reconnecting as needed, until it returns `false`, the session ends,
    /// or `timeout` passes.
    pub async fn stream(
        &mut self,
        timeout: Option<Duration>,
        on_item: &mut (dyn FnMut(&Session, &Item) -> Result<bool> + Send),
    ) -> Result<()> {
        let deadline = timeout.map(|t| Instant::now() + t);
        let left = |d: Option<Instant>| d.map(|d| d.saturating_duration_since(Instant::now()));
        while self.closed.is_none() {
            if left(deadline) == Some(Duration::ZERO) {
                return Ok(());
            }
            self.trade_blobs().await;
            for i in self.retry().await? {
                if !on_item(self, &self.items[i])? {
                    return Ok(());
                }
            }
            let resp = match self.relay.session_stream(self.last_seq).await {
                Ok(r) => r,
                Err(e) if matches!(status_of(&e), Some(401 | 404 | 410)) => {
                    self.closed.get_or_insert_with(|| gone_reason(&e));
                    return Ok(());
                }
                Err(e) if is_transient(&e) => {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    continue;
                }
                Err(e) => return Err(e),
            };
            let mut body = resp.bytes_stream();
            let mut parser = SseParser::default();
            loop {
                let wait = left(deadline).unwrap_or(Duration::from_secs(60)).min(Duration::from_secs(60));
                let chunk = match tokio::time::timeout(wait, body.next()).await {
                    Err(_) => break, // quiet: reconnect, or stop at the deadline
                    Ok(None) | Ok(Some(Err(_))) => {
                        // Dropped: pause before reconnecting, so a relay that
                        // keeps hanging up does not get a tight loop.
                        let pause = left(deadline).unwrap_or(Duration::MAX).min(Duration::from_secs(1));
                        tokio::time::sleep(pause).await;
                        break;
                    }
                    Ok(Some(Ok(c))) => c,
                };
                self.synced_at_ms = Some(now_ms());
                let mut trade = false;
                for ev in parser.push(&chunk) {
                    trade |= matches!(ev.event.as_str(), "want" | "reseeded" | "evicted");
                    let seq = ev.id.as_deref().and_then(|s| s.parse::<u64>().ok());
                    let ev = json!({
                        "seq": seq,
                        "kind": ev.event,
                        "data": serde_json::from_str::<Value>(&ev.data).unwrap_or(Value::Null),
                    });
                    if let Some(i) = self.apply(&ev, true, true).await? {
                        if self.items[i].status != Status::Pending && !on_item(self, &self.items[i])? {
                            return Ok(());
                        }
                    }
                    if self.closed.is_some() || left(deadline) == Some(Duration::ZERO) {
                        return Ok(());
                    }
                }
                if trade || self.reask_due() {
                    self.trade_blobs().await;
                    for i in self.fetch_reseeded().await? {
                        if !on_item(self, &self.items[i])? {
                            return Ok(());
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Apply one event; returns the index of the item it carried, if any.
    async fn apply(&mut self, ev: &Value, fetch: bool, record: bool) -> Result<Option<usize>> {
        let Some(seq) = ev["seq"].as_u64() else { return Ok(None) };
        if record && self.last_seq.is_some_and(|l| seq <= l) {
            return Ok(None);
        }
        // Sequence numbers count up from 1, with gaps only for events this
        // participant does not see. A wild jump would make every later
        // event look old, and the cache would keep it: drop it unrecorded.
        if seq > self.last_seq.unwrap_or(0).saturating_add(MAX_SEQ_JUMP) {
            tracing::warn!(seq, "ignoring an event with an implausible sequence number");
            return Ok(None);
        }
        let data = &ev["data"];
        let mut out = None;
        match ev["kind"].as_str().unwrap_or_default() {
            "participant" => {
                // Only fields from the verified signed join count; the
                // relay's copies of role and name are unsigned.
                if let Some(raw) = data["signed_join"].as_str() {
                    if api::verify_join(raw, &self.signed_manifest).is_ok() {
                        if let (Ok(j), Ok(cert)) = (serde_json::from_str::<Value>(raw), api::join_cert(raw)) {
                            let j = &j["join"];
                            let public =
                                j["cert"]["cert"]["participant_pub"].as_str().unwrap_or_default().to_string();
                            self.participants.insert(
                                public.clone(),
                                Participant {
                                    participant_pub: public,
                                    role: j["cert"]["cert"]["role"].as_str().unwrap_or_default().into(),
                                    display_name: j["display_name"].as_str().unwrap_or_default().into(),
                                    description: j["description"].as_str().map(String::from),
                                    kind: j["kind"].as_str().unwrap_or_default().into(),
                                    cert,
                                    left: false,
                                },
                            );
                        }
                    }
                }
            }
            "item" => {
                if let Some(env) = data["envelope"].as_str() {
                    out = self.receive(seq, env.to_string(), fetch).await?;
                }
            }
            "evicted" => {
                if let Some(id) = data["item"].as_str() {
                    self.evicted.insert(id.to_string());
                    if let Some(&i) = self.index.get(id) {
                        if self.items[i].status == Status::Pending {
                            self.items[i].status = Status::Evicted;
                        }
                    }
                }
            }
            "want" => {
                // Only live wants: replayed ones were answered or expired.
                // Only for an item this client verified, never a name the relay made up.
                if let (true, Some(id), Some(by)) = (fetch, data["item"].as_str(), data["by"].as_str()) {
                    if by != self.me && self.get(id).is_some_and(|i| i.status == Status::Ok) {
                        self.asked.insert(id.to_string());
                    }
                }
            }
            "reseeded" => {
                if let Some(id) = data["item"].as_str() {
                    self.reappeared(id);
                }
            }
            "left" => {
                if let Some(p) = data["participant_pub"].as_str().and_then(|k| self.participants.get_mut(k)) {
                    p.left = true;
                }
            }
            "revoked" => {
                let cut: Vec<&str> =
                    data["participants"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
                for k in &cut {
                    if let Some(p) = self.participants.get_mut(*k) {
                        p.left = true;
                    }
                }
                if cut.contains(&self.me.as_str()) {
                    let role = data["role"].as_str().unwrap_or("this");
                    self.closed = Some(format!("the owner revoked the {role} role"));
                }
            }
            "closed" => {
                self.closed = Some(data["reason"].as_str().unwrap_or("closed").to_string());
            }
            _ => {}
        }
        if record {
            self.cache.append_event(ev)?;
        }
        self.last_seq = Some(self.last_seq.map_or(seq, |l| l.max(seq)));
        Ok(out)
    }

    /// Retry pending downloads and unsent acks.
    async fn retry(&mut self) -> Result<Vec<usize>> {
        let mut out = Vec::new();
        let pending: Vec<(u64, String)> = self
            .items
            .iter()
            .filter(|i| i.status == Status::Pending)
            .map(|i| (i.seq, i.id.clone()))
            .collect();
        for (seq, id) in pending {
            let env = self.envelopes.get(&id).cloned().unwrap_or_default();
            if let Some(i) = self.receive(seq, env, true).await? {
                if self.items[i].status != Status::Pending {
                    out.push(i);
                }
            }
        }
        for id in self.unacked.clone() {
            self.ack(&id).await;
        }
        Ok(out)
    }

    async fn ack(&mut self, id: &str) {
        match self.relay.ack(id).await {
            Ok(()) => {
                self.unacked.remove(id);
            }
            Err(e) if is_transient(&e) => {
                self.unacked.insert(id.to_string());
            }
            Err(e) => {
                self.unacked.remove(id);
                tracing::debug!(item = id, "ack refused: {e:#}");
            }
        }
    }

    /// The largest blob an item in this session can have.
    fn blob_limit(&self) -> usize {
        (self.manifest.max_item_bytes as usize).saturating_add(airlox_core::item::BLOB_OVERHEAD)
    }

    async fn receive(&mut self, seq: u64, envelope: String, fetch: bool) -> Result<Option<usize>> {
        let parsed: Value = serde_json::from_str(&envelope).context("item envelope is not JSON")?;
        let h = &parsed["header"];
        let id = h["id"].as_str().unwrap_or_default().to_string();
        // The id names a cache file; anything but a well-formed id is the
        // relay's invention and is dropped before it touches the disk.
        if !airlox_core::item::is_item_id(&id) {
            tracing::debug!("dropped an item with a malformed id");
            return Ok(None);
        }
        if self.get(&id).is_some_and(|i| i.status != Status::Pending) {
            return Ok(None);
        }
        self.envelopes.insert(id.clone(), envelope.clone());
        let author_pub = h["author"].as_str().unwrap_or_default().to_string();
        let author = self.participants.get(&author_pub).cloned();
        let mut item = Item {
            seq,
            id: id.clone(),
            kind: h["kind"].as_str().unwrap_or_default().into(),
            subkind: h["subkind"].as_str().map(String::from),
            author: author_pub.clone(),
            author_role: author.as_ref().map(|a| a.role.clone()),
            author_name: author.as_ref().map(|a| a.display_name.clone()),
            created_at_ms: h["created_at_ms"].as_u64().unwrap_or(0),
            refs: h["refs"].clone(),
            item_ref: json!({"id": id, "blob_sha256": ""}),
            meta: None,
            body: vec![],
            status: Status::Ok,
            error: None,
        };
        let finish = |s: &mut Session, item: Item| -> usize {
            match s.index.get(&item.id) {
                Some(&i) => {
                    s.items[i] = item;
                    i
                }
                None => {
                    s.index.insert(item.id.clone(), s.items.len());
                    s.items.push(item);
                    s.items.len() - 1
                }
            }
        };
        let Some(author) = author else {
            item.status = Status::Rejected;
            item.error = Some("the author is not a verified participant".into());
            return Ok(Some(finish(self, item)));
        };
        let mut fresh = false;
        let blob = match self.cache.read_blob(&id) {
            Some(b) => b,
            None if self.evicted.contains(&id) => {
                item.status = Status::Evicted;
                return Ok(Some(finish(self, item)));
            }
            None if !fetch => {
                item.status = Status::Pending;
                return Ok(Some(finish(self, item)));
            }
            None => match self.relay.blob(&id, self.blob_limit()).await {
                Ok(Some(b)) => {
                    fresh = true;
                    b
                }
                Ok(None) => {
                    item.status = Status::Evicted;
                    return Ok(Some(finish(self, item)));
                }
                Err(e) if is_transient(&e) => {
                    item.status = Status::Pending;
                    return Ok(Some(finish(self, item)));
                }
                Err(e) if status_of(&e).is_some() => return Err(e),
                Err(e) => {
                    // Not a refusal but a bad answer (too large): the item is unusable.
                    item.status = Status::Rejected;
                    item.error = Some(format!("{e:#}"));
                    return Ok(Some(finish(self, item)));
                }
            },
        };
        match api::open_checked(&self.signed_manifest, &author.cert, &self.key, &envelope, &blob) {
            Ok((role, meta, body)) => {
                item.author_role = Some(role);
                item.meta = Some(serde_json::from_str(&meta)?);
                item.body = body;
                item.item_ref = serde_json::from_str(&api::item_ref(&envelope, &blob)?)?;
            }
            Err(e) => {
                item.status = Status::Rejected;
                item.error = Some(e.to_string());
                return Ok(Some(finish(self, item)));
            }
        }
        let i = finish(self, item);
        if fresh {
            self.cache.write_blob(&id, &blob)?;
            if author_pub != self.me {
                self.ack(&id).await;
            }
        }
        Ok(Some(i))
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    fn out_zip(files: &[(&str, &[u8])]) -> Vec<OutFile> {
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (name, data) in files {
            w.start_file(*name, zip::write::SimpleFileOptions::default()).unwrap();
            w.write_all(data).unwrap();
        }
        let data = w.finish().unwrap().into_inner();
        vec![OutFile {
            name: "out.zip".into(),
            size: data.len() as u64,
            item_ref: json!({}),
            data: Some(data),
        }]
    }

    fn item(seq: u64, author: &str, to: Option<&[&str]>, reply_to: Option<u64>) -> Item {
        Item {
            seq,
            id: format!("i{seq}"),
            kind: "text".into(),
            subkind: None,
            author: author.into(),
            author_role: None,
            author_name: None,
            created_at_ms: 0,
            refs: reply_to.map(|n| json!([{"id": format!("i{n}")}])).unwrap_or(json!([])),
            item_ref: json!({}),
            meta: Some(match to {
                Some(to) => json!({"text": "x", "to": to}),
                None => json!({"text": "x"}),
            }),
            body: vec![],
            status: Status::Ok,
            error: None,
        }
    }

    fn hops_of(items: &[Item], seq: u64) -> usize {
        let index = items.iter().enumerate().map(|(n, i)| (i.id.clone(), n)).collect();
        let web = |a: &str| a == "person";
        hops(items, &index, &web, items.iter().find(|i| i.seq == seq).unwrap())
    }

    #[test]
    fn hops_follow_a_reply_chain_up_to_a_person() {
        let items = [
            item(1, "person", None, None),
            item(2, "a", Some(&["b"]), Some(1)),
            item(3, "b", Some(&["a"]), Some(2)),
            item(4, "a", Some(&["b"]), Some(3)),
        ];
        assert_eq!([2, 3, 4].map(|n| hops_of(&items, n)), [1, 2, 3]);
    }

    #[test]
    fn agents_addressing_each_other_without_replying_still_count() {
        let mut items = vec![item(1, "person", None, None)];
        for n in 2..=7u64 {
            let (from, to) = if n % 2 == 0 { ("a", "b") } else { ("b", "a") };
            items.push(item(n, from, Some(&[to]), None));
        }
        // Each message names no parent, but the run of agent text grows.
        assert_eq!([2, 3, 7].map(|n| hops_of(&items, n)), [1, 2, 6]);
        // A person speaking resets the count.
        items.push(item(8, "person", None, None));
        items.push(item(9, "a", Some(&["b"]), None));
        assert_eq!(hops_of(&items, 9), 1);
        // Non-text items neither count nor break the run; the reply chain
        // still wins when it is longer; a broadcast is not an addressed item.
        let mut progress = item(10, "runner", None, None);
        progress.kind = "progress".into();
        items.push(progress);
        items.push(item(11, "b", Some(&["a"]), None));
        assert_eq!(hops_of(&items, 11), 2);
        items.push(item(12, "a", None, None));
        assert_eq!(hops_of(&items, 12), 1);
    }

    fn pending(seq: u64) -> Item {
        let mut i = item(seq, "a", None, None);
        i.status = Status::Pending;
        i
    }

    #[test]
    fn a_pending_item_holds_the_cursor_only_for_the_limit() {
        let mut watch = PendingWatch::new(Duration::from_secs(60));
        let t0 = Instant::now();
        let items = [item(1, "a", None, None), pending(2), item(3, "a", None, None)];
        assert_eq!(watch.settled_seq(&items, t0), Some(1));
        assert_eq!(watch.next_check(t0 + Duration::from_secs(20)), Some(Duration::from_secs(40)));
        assert_eq!(watch.settled_seq(&items, t0 + Duration::from_secs(59)), Some(1));
        // Given up on: later items settle, and #2 is not waited for again.
        assert_eq!(watch.settled_seq(&items, t0 + Duration::from_secs(60)), Some(3));
        assert_eq!(watch.next_check(t0 + Duration::from_secs(60)), None);
        // A later one pending is held on its own clock.
        let items = [item(1, "a", None, None), pending(2), item(3, "a", None, None), pending(4)];
        assert_eq!(watch.settled_seq(&items, t0 + Duration::from_secs(61)), Some(3));
        assert_eq!(watch.settled_seq(&items, t0 + Duration::from_secs(130)), Some(4));
        // Nothing pending: everything settles.
        let items = [item(1, "a", None, None), item(2, "a", None, None)];
        assert_eq!(watch.settled_seq(&items, t0), Some(2));
    }

    #[test]
    fn an_item_given_up_on_is_reported_once_when_it_arrives() {
        let mut watch = PendingWatch::new(Duration::from_secs(60));
        let t0 = Instant::now();
        let held = [item(1, "a", None, None), pending(2), item(3, "a", None, None)];
        assert_eq!(watch.settled_seq(&held, t0), Some(1));
        assert_eq!(watch.settled_seq(&held, t0 + Duration::from_secs(60)), Some(3));
        // Still not here.
        assert!(watch.arrived_late(&held).is_empty());
        let here = [item(1, "a", None, None), item(2, "a", None, None), item(3, "a", None, None)];
        assert_eq!(watch.arrived_late(&here), [2]);
        assert!(watch.arrived_late(&here).is_empty());
        // One that arrives before it is given up on is just settled.
        let mut watch = PendingWatch::new(Duration::from_secs(60));
        assert_eq!(watch.settled_seq(&held, t0), Some(1));
        assert_eq!(watch.settled_seq(&here, t0), Some(3));
        assert!(watch.arrived_late(&here).is_empty());
    }

    fn participant(key: &str, name: &str, role: &str) -> Participant {
        Participant {
            participant_pub: key.into(),
            role: role.into(),
            display_name: name.into(),
            description: None,
            kind: "cli".into(),
            cert: String::new(),
            left: false,
        }
    }

    #[test]
    fn participants_are_named_by_role_display_name_or_key() {
        let owner = participant("K1", "lead", "owner");
        let coder = participant("K2", "coder", "sender");
        for spec in ["owner", "role:owner", "lead", "@lead", "K1"] {
            assert!(names(&owner, spec), "{spec}");
        }
        for spec in ["owner", "role:owner", "lead", "K1", "role:runner", "coder2"] {
            assert!(!names(&coder, spec), "{spec}");
        }
        assert!(names(&coder, "role:sender") && names(&coder, " @coder ") && names(&coder, "K2"));
    }

    #[test]
    fn out_text_inlines_only_small_text_files() {
        let big = vec![b'a'; OUT_TEXT_MAX as usize + 1];
        let outs = out_zip(&[
            ("report.json", b"{\"ok\": true}"),
            ("chart.bin", b"\x89PNG\x00\x01"),
            ("big.log", &big),
            ("dir/notes.md", b"# hi"),
        ]);
        let got: Vec<_> = out_text(&outs).into_iter().map(|t| (t.name, t.text)).collect();
        assert_eq!(
            got,
            [("report.json".into(), "{\"ok\": true}".into()), ("dir/notes.md".into(), "# hi".into())]
        );
    }

    #[test]
    fn out_text_stops_at_the_total() {
        let chunk = vec![b'a'; OUT_TEXT_MAX as usize];
        let names: Vec<String> = (0..6).map(|i| format!("f{i}.txt")).collect();
        let files: Vec<(&str, &[u8])> = names.iter().map(|n| (n.as_str(), chunk.as_slice())).collect();
        assert_eq!(out_text(&out_zip(&files)).len(), (OUT_TEXT_TOTAL / OUT_TEXT_MAX) as usize);
    }

    #[test]
    fn out_text_skips_empty_files_and_stops_at_a_count() {
        let names: Vec<String> = (0..40).map(|i| format!("f{i}.txt")).collect();
        let mut files: Vec<(&str, &[u8])> = names.iter().map(|n| (n.as_str(), b"x".as_slice())).collect();
        files.insert(0, ("empty.txt", b""));
        let got = out_text(&out_zip(&files));
        assert_eq!(got.len(), OUT_TEXT_FILES);
        assert_eq!(got[0].name, "f0.txt");
    }
}
