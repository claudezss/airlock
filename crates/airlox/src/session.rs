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
/// `identity-<role>.json` (participant seed and token, 0600) and `blobs/`
/// (ciphertext). The session key is never written.
struct Cache {
    dir: PathBuf,
}

#[derive(Serialize, Deserialize)]
struct Identity {
    participant_seed: String,
    token: String,
    #[serde(default)]
    role: Option<String>,
}

impl Cache {
    fn open(root: &Path, sid: &str) -> Result<Cache> {
        let dir = root.join(sid);
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

    fn read_blob(&self, id: &str) -> Option<Vec<u8>> {
        fs::read(self.dir.join("blobs").join(id)).ok()
    }

    fn write_blob(&self, id: &str, blob: &[u8]) -> Result<()> {
        write_atomic(&self.dir.join("blobs").join(id), blob, 0o600)
    }

    /// Delete caches of sessions whose manifest has expired.
    fn sweep_expired(root: &Path) {
        let now = now_ms();
        let Ok(entries) = fs::read_dir(root) else { return };
        for e in entries.flatten() {
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

// ---------------------------------------------------------------- items --

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// Verified and decrypted.
    Ok,
    /// The blob could not be fetched yet (network, busy relay); retried later.
    Pending,
    /// The relay deleted the blob before this client fetched it.
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
}

/// No approved, online, idle runner matched; jobs are never queued.
#[derive(Debug)]
pub struct NoRunnerAvailable {
    pub job: String,
    pub message: String,
}

impl std::fmt::Display for NoRunnerAvailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "no runner available: {}", self.message)
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
    pub runner: Option<String>,
    pub signed: bool,
}

impl Outcome {
    fn unsigned(job: &str, status: &str, reason: Option<String>, runner: Option<String>) -> Outcome {
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
            runner,
            signed: false,
        }
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

/// What a new session allows.
pub struct NewSession {
    pub mode: Mode,
    pub ttl_ms: u64,
    pub allowed_types: Vec<String>,
    pub max_item_bytes: u64,
    pub job_limits: Option<JobLimits>,
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
    unacked: HashSet<String>,
    last_seq: Option<u64>,
    /// Why the session is over, once it is.
    pub closed: Option<String>,
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
        };
        let (owner_seed, signed) = api::create_session(&serde_json::to_string(&params)?, None)?;
        client::create_session(http, relay, signed).await?;
        let url = api::owner_invite(relay, &owner_seed)?;
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
                let id = Identity { participant_seed: hex(&seed), token, role: Some(role.as_str().into()) };
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
            unacked: HashSet::new(),
            last_seq: None,
            closed: None,
        };
        let cached = s.cache.events();
        s.evicted = cached
            .iter()
            .filter(|e| e["kind"] == "evicted")
            .filter_map(|e| e["data"]["item"].as_str().map(String::from))
            .collect();
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

    /// Close and purge the session on the relay (owner only).
    pub async fn close(&mut self) -> Result<()> {
        self.relay.post_raw("/close", vec![], &[]).await?;
        self.closed = Some("closed by owner".into());
        Ok(())
    }

    pub fn participants(&self) -> Vec<Participant> {
        let mut v: Vec<_> = self.participants.values().cloned().collect();
        v.sort_by(|a, b| a.display_name.cmp(&b.display_name));
        v
    }

    // ---------------------------------------------------------- sending --

    pub async fn send_text(&mut self, text: &str) -> Result<Value> {
        self.send("text", None, json!({"type": "text", "text": text}), vec![], vec![]).await
    }

    /// Send a file the protocol can carry. Images are re-encoded first to
    /// strip metadata; ZIPs are checked. Returns the item reference.
    pub async fn send_file(&mut self, data: Vec<u8>, name: &str) -> Result<Value> {
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
        self.send("file", Some(subkind), json!({"type": "file", "name": name, "mime": mime}), data, vec![])
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
                json!({"type": "runner", "participant_pub": r.participant_pub, "name": r.name})
            }
            Target::Labels(l) => json!({"type": "labels", "labels": l}),
            Target::Any => json!({"type": "any"}),
        };
        let meta = json!({
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
                Some(r) if r.code == "no_runner_available" => {
                    Err(NoRunnerAvailable { job: id, message: r.message.clone() }.into())
                }
                _ => Err(e),
            },
        }
    }

    /// Ask a job's runner to stop it (owner or the job's sender), with a
    /// signed `job_cancel` event recording who asked.
    pub async fn cancel_job(&mut self, job: &str) -> Result<()> {
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
                out_files: outs,
                runner: Some(item.author.clone()),
                signed: true,
            });
        }
        None
    }

    /// Wait for a job's outcome. A job that failed on the relay (no runner,
    /// runner lost, cancelled before it started) gives an unsigned outcome
    /// with the relay's reason. `None` if `timeout` passes first.
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
        Ok(Some(Outcome::unsigned(job, status, reason, st["runner"].as_str().map(String::from))))
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
            Err(e) if matches!(status_of(&e), Some(404 | 410)) => {
                self.closed.get_or_insert_with(|| "no longer on the relay".into());
                return Ok(out);
            }
            Err(e) => return Err(e),
        };
        for ev in &evs {
            if let Some(i) = self.apply(ev, true, true).await? {
                if self.items[i].status != Status::Pending {
                    out.push(i);
                }
            }
        }
        Ok(out)
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
            for i in self.retry().await? {
                if !on_item(self, &self.items[i])? {
                    return Ok(());
                }
            }
            let resp = match self.relay.session_stream(self.last_seq).await {
                Ok(r) => r,
                Err(e) if matches!(status_of(&e), Some(404 | 410)) => {
                    self.closed.get_or_insert_with(|| "no longer on the relay".into());
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
                for ev in parser.push(&chunk) {
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
            "left" => {
                if let Some(p) = data["participant_pub"].as_str().and_then(|k| self.participants.get_mut(k)) {
                    p.left = true;
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
