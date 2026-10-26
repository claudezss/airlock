//! File-backed storage: one directory per session, no database.
//!
//! ```text
//! $DATA/LOCK                       exclusive flock while a server runs
//! $DATA/sessions/<id>/manifest.json
//! $DATA/sessions/<id>/log.jsonl    append-only, replayed at startup
//! $DATA/sessions/<id>/blobs/<item> ciphertext until evicted
//! $DATA/trash/                     purged sessions awaiting deletion
//! ```
//!
//! Every state change is a log line written before it is applied, so the
//! in-memory index can always be rebuilt from the log.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};

use airlock_core::cert::SignedJoinRequest;
use airlock_core::encoding::parse_canonical;
use airlock_core::item::ItemEnvelope;
use airlock_core::session::{Role, SignedManifest};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::broadcast;

use crate::config::Config;
use crate::util::{now_ms, random_suffix};

pub const MAX_PARTICIPANTS: usize = 64;
const EVENT_BUFFER: usize = 1024;

/// One state change. Serialized as a line of `log.jsonl`.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Rec {
    Create { ip_hash: String },
    Join { signed_join: String, token_sha256: String },
    Item { envelope: String, recipients: Vec<String>, blob_len: u64 },
    Ack { item: String, by: String },
    Evict { item: String },
    Close { reason: String },
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
}

pub struct ItemRec {
    pub seq: u64,
    pub author: String,
    pub recipients: HashSet<String>,
    pub acked: HashSet<String>,
    pub blob_len: u64,
    pub blob_present: bool,
    pub evict_at: u64,
}

pub struct Inner {
    log: File,
    next_seq: u64,
    pub participants: HashMap<String, Participant>,
    tokens: HashMap<String, String>,
    pub items: HashMap<String, ItemRec>,
    pub events: Vec<Arc<Event>>,
    pub held_bytes: u64,
    pub pending_bytes: u64,
    pub pending: HashSet<String>,
    pub transfer_bytes: u64,
    pub last_activity_ms: u64,
    pub closed: bool,
    pub ip_hash: Option<String>,
    evictions: BTreeMap<u64, Vec<String>>,
    hold_ms: u64,
    grace_ms: u64,
}

impl Inner {
    fn push_event(&mut self, seq: u64, kind: &'static str, data: Value) -> Option<Arc<Event>> {
        let e = Arc::new(Event { seq, kind, data });
        self.events.push(e.clone());
        Some(e)
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
                let public = json!({
                    "participant_pub": pk,
                    "role": role.as_str(),
                    "display_name": j.join.display_name,
                    "kind": j.join.kind,
                    "runner": j.join.runner,
                    "signed_join": signed_join,
                });
                self.participants
                    .insert(pk.clone(), Participant { role, seq: line.seq, public: public.clone() });
                self.tokens.insert(token_sha256.clone(), pk);
                self.last_activity_ms = self.last_activity_ms.max(ts);
                Ok(self.push_event(line.seq, "participant", public))
            }
            Rec::Item { envelope, recipients, blob_len } => {
                let env: ItemEnvelope =
                    parse_canonical(envelope, "item envelope").map_err(|e| e.to_string())?;
                let id = env.header.id.clone();
                let evict_at = ts.saturating_add(self.hold_ms);
                self.items.insert(
                    id.clone(),
                    ItemRec {
                        seq: line.seq,
                        author: env.header.author.to_b64(),
                        recipients: recipients.iter().cloned().collect(),
                        acked: HashSet::new(),
                        blob_len: *blob_len,
                        blob_present: true,
                        evict_at,
                    },
                );
                self.evictions.entry(evict_at).or_default().push(id);
                self.held_bytes += blob_len;
                self.transfer_bytes += blob_len;
                self.last_activity_ms = self.last_activity_ms.max(ts);
                Ok(self.push_event(
                    line.seq,
                    "item",
                    json!({"envelope": envelope, "blob_len": blob_len, "blob_present": true}),
                ))
            }
            Rec::Ack { item, by } => {
                let grace = self.grace_ms;
                if let Some(r) = self.items.get_mut(item) {
                    r.acked.insert(by.clone());
                    if r.blob_present && !r.recipients.is_empty() && r.recipients.is_subset(&r.acked) {
                        let t = ts.saturating_add(grace);
                        if t < r.evict_at {
                            r.evict_at = t;
                            self.evictions.entry(t).or_default().push(item.clone());
                        }
                    }
                }
                Ok(None)
            }
            Rec::Evict { item } => {
                if let Some(r) = self.items.get_mut(item) {
                    if r.blob_present {
                        r.blob_present = false;
                        self.held_bytes -= r.blob_len;
                    }
                }
                Ok(self.push_event(line.seq, "evicted", json!({"item": item})))
            }
            Rec::Close { reason } => {
                self.closed = true;
                Ok(self.push_event(line.seq, "closed", json!({"reason": reason})))
            }
        }
    }

    pub fn participant_by_token(&self, token_sha256: &str) -> Option<(String, Role)> {
        let pk = self.tokens.get(token_sha256)?;
        Some((pk.clone(), self.participants.get(pk)?.role))
    }
}

pub struct Session {
    pub id: String,
    pub dir: PathBuf,
    pub signed: SignedManifest,
    pub manifest_json: String,
    inner: Mutex<Inner>,
    pub tx: broadcast::Sender<Arc<Event>>,
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    File::open(dir)?.sync_all()?;
    let _ = dir;
    Ok(())
}

fn invalid(e: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

impl Session {
    fn new_inner(log: File, cfg: &Config) -> Inner {
        Inner {
            log,
            next_seq: 0,
            participants: HashMap::new(),
            tokens: HashMap::new(),
            items: HashMap::new(),
            events: Vec::new(),
            held_bytes: 0,
            pending_bytes: 0,
            pending: HashSet::new(),
            transfer_bytes: 0,
            last_activity_ms: 0,
            closed: false,
            ip_hash: None,
            evictions: BTreeMap::new(),
            hold_ms: cfg.blob_hold_ms,
            grace_ms: cfg.blob_grace_ms,
        }
    }

    fn create(
        dir: PathBuf,
        signed: SignedManifest,
        manifest_json: String,
        ip_hash: String,
        cfg: &Config,
    ) -> io::Result<Session> {
        fs::create_dir_all(dir.join("blobs"))?;
        let tmp = dir.join(".manifest.json.tmp");
        {
            let mut f = File::create(&tmp)?;
            f.write_all(manifest_json.as_bytes())?;
            f.sync_all()?;
        }
        fs::rename(&tmp, dir.join("manifest.json"))?;
        let log = OpenOptions::new().create_new(true).append(true).open(dir.join("log.jsonl"))?;
        sync_dir(&dir)?;
        let mut inner = Self::new_inner(log, cfg);
        inner.last_activity_ms = now_ms();
        let (tx, _) = broadcast::channel(EVENT_BUFFER);
        let s = Session {
            id: signed.manifest.session_id.clone(),
            dir,
            signed,
            manifest_json,
            inner: Mutex::new(inner),
            tx,
        };
        {
            let mut g = s.lock();
            s.append(&mut g, Rec::Create { ip_hash }, true)?;
        }
        Ok(s)
    }

    fn load(dir: PathBuf, cfg: &Config) -> io::Result<Session> {
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
        let mut inner = Self::new_inner(log, cfg);
        for line in raw[..valid].split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
            let line: LogLine = serde_json::from_slice(line).map_err(invalid)?;
            if line.seq != inner.next_seq {
                return Err(invalid(format!("log sequence gap at {}", line.seq)));
            }
            inner.apply(&line).map_err(invalid)?;
            inner.next_seq = line.seq + 1;
        }
        if inner.last_activity_ms == 0 {
            inner.last_activity_ms = signed.manifest.created_at_ms;
        }
        let (tx, _) = broadcast::channel(EVENT_BUFFER);
        let s = Session { id, dir, signed, manifest_json, inner: Mutex::new(inner), tx };
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
            self.append(&mut g, Rec::Evict { item: id }, false)?;
        }
        Ok(())
    }

    pub fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Write a log line, apply it, broadcast its event.
    pub fn append(&self, inner: &mut Inner, rec: Rec, fsync: bool) -> io::Result<Option<Arc<Event>>> {
        let line = LogLine { seq: inner.next_seq, ts_ms: now_ms(), rec };
        let mut bytes = serde_json::to_vec(&line).map_err(invalid)?;
        bytes.push(b'\n');
        inner.log.write_all(&bytes)?;
        if fsync {
            inner.log.sync_data()?;
        }
        inner.next_seq += 1;
        let ev = inner.apply(&line).map_err(invalid)?;
        if let Some(e) = &ev {
            let _ = self.tx.send(e.clone());
        }
        Ok(ev)
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
                self.append(&mut g, Rec::Evict { item: id }, false)?;
            }
        }
        Ok(())
    }
}

/// All sessions on this relay.
pub struct Store {
    pub cfg: Arc<Config>,
    sessions_dir: PathBuf,
    trash_dir: PathBuf,
    sessions: RwLock<HashMap<String, Arc<Session>>>,
    #[cfg(unix)]
    _lock: nix::fcntl::Flock<File>,
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
        let trash_dir = cfg.data.join("trash");
        if cfg.ephemeral {
            let _ = fs::remove_dir_all(&sessions_dir);
            let _ = fs::remove_dir_all(&trash_dir);
        }
        fs::create_dir_all(&sessions_dir)?;
        let _ = fs::remove_dir_all(&trash_dir);
        fs::create_dir_all(&trash_dir)?;

        let store = Store {
            cfg: cfg.clone(),
            sessions_dir,
            trash_dir,
            sessions: RwLock::new(HashMap::new()),
            #[cfg(unix)]
            _lock: lock,
        };
        let now = now_ms();
        for entry in fs::read_dir(&store.sessions_dir)? {
            let path = entry?.path();
            if !path.is_dir() {
                continue;
            }
            match Session::load(path.clone(), &cfg) {
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

    pub fn get(&self, id: &str) -> Option<Arc<Session>> {
        self.sessions.read().unwrap_or_else(|e| e.into_inner()).get(id).cloned()
    }

    pub fn count(&self) -> usize {
        self.sessions.read().unwrap_or_else(|e| e.into_inner()).len()
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
    pub fn create(
        &self,
        signed: SignedManifest,
        manifest_json: String,
        ip_hash: String,
    ) -> io::Result<Option<Arc<Session>>> {
        let id = signed.manifest.session_id.clone();
        let dir = self.sessions_dir.join(&id);
        let mut map = self.sessions.write().unwrap_or_else(|e| e.into_inner());
        if map.contains_key(&id) || dir.exists() {
            return Ok(None);
        }
        let s = Arc::new(Session::create(dir, signed, manifest_json, ip_hash, &self.cfg)?);
        map.insert(id, s.clone());
        Ok(Some(s))
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

    /// End a session: emit `closed`, then delete its directory.
    pub fn purge(&self, id: &str, reason: &str) {
        let removed = self.sessions.write().unwrap_or_else(|e| e.into_inner()).remove(id);
        if let Some(s) = removed {
            {
                let mut g = s.lock();
                if !g.closed {
                    if let Err(e) = s.append(&mut g, Rec::Close { reason: reason.to_string() }, false) {
                        tracing::warn!(session = %id, "close record failed: {e}");
                    }
                }
            }
            self.trash(&s.dir);
            tracing::info!(session = %id, reason, "session purged");
        }
    }

    /// Expire, idle-close and evict. Called periodically.
    pub fn sweep(&self, now: u64) {
        for s in self.all() {
            if s.signed.manifest.is_expired(now) {
                self.purge(&s.id, "expired");
                continue;
            }
            let idle = now.saturating_sub(s.lock().last_activity_ms) >= self.cfg.idle_ttl_ms;
            if idle {
                self.purge(&s.id, "idle");
                continue;
            }
            if let Err(e) = s.sweep_evictions(now) {
                tracing::error!(session = %s.id, "eviction failed: {e}");
            }
        }
    }
}
