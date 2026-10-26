//! The runner's view of a session: verified participants, item envelopes,
//! the owner's signed approval, and a local ciphertext cache.
//!
//! Everything that decides whether a job may run comes from signed data
//! verified here, never from the relay's unsigned fields. Participants come
//! from verified joins; approval comes from a `runner_approve` event signed
//! by an owner-role participant.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use airlox_core::api;
use airlox_core::cert::SignedJoinRequest;
use airlox_core::encoding::{canonical_json, parse_canonical};
use airlox_core::item::{ItemEnvelope, ItemKind};
use airlox_core::keys::PublicKey;
use airlox_core::payload::{Event, Meta};
use airlox_core::session::{Manifest, Role, SignedManifest};
use anyhow::{bail, Context, Result};
use serde_json::Value;

use crate::client::Relay;

pub struct Participant {
    pub role: Role,
    /// Canonical certificate JSON, for `open_checked`.
    pub cert: String,
}

/// A verified, decrypted item.
pub struct Opened {
    pub role: Role,
    pub meta: Meta,
    pub body: Vec<u8>,
    pub blob: Vec<u8>,
}

pub struct View {
    pub relay: Relay,
    pub signed_manifest: String,
    pub manifest: Manifest,
    key: [u8; 32],
    pub me: PublicKey,
    pub dir: PathBuf,
    participants: HashMap<String, Participant>,
    envelopes: HashMap<String, String>,
    acked: HashSet<String>,
    last_seq: Option<u64>,
    /// The owner approved this runner (signed), or approval is not required.
    pub approved: bool,
    pub rejected: bool,
    pub closed: bool,
}

pub fn write_atomic(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    let dir = path.parent().context("path has no parent")?;
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    tmp.write_all(data)?;
    tmp.as_file().sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    let _ = mode;
    tmp.persist(path)?;
    Ok(())
}

impl View {
    pub fn new(
        relay: Relay,
        signed_manifest: String,
        key: [u8; 32],
        me: PublicKey,
        dir: PathBuf,
    ) -> Result<View> {
        let manifest = SignedManifest::from_json(&signed_manifest)?.manifest;
        fs::create_dir_all(dir.join("blobs"))?;
        let approved = !manifest.job_limits.as_ref().is_some_and(|l| l.approve_runners);
        Ok(View {
            relay,
            signed_manifest,
            manifest,
            key,
            me,
            dir,
            participants: HashMap::new(),
            envelopes: HashMap::new(),
            acked: HashSet::new(),
            last_seq: None,
            approved,
            rejected: false,
            closed: false,
        })
    }

    fn blob_path(&self, id: &str) -> PathBuf {
        self.dir.join("blobs").join(id)
    }

    pub fn envelope(&self, id: &str) -> Option<&String> {
        self.envelopes.get(id)
    }

    /// Fetch new events from the relay and act on them.
    pub async fn sync(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        let evs = match self.relay.events(self.last_seq).await {
            Ok(e) => e,
            Err(e) if matches!(crate::client::status_of(&e), Some(404 | 410)) => {
                self.closed = true;
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        for ev in evs {
            let seq = ev["seq"].as_u64().context("event without seq")?;
            if let Err(e) = self.apply(&ev).await {
                // A network hiccup must not lose an event (say, the owner's
                // approval): stop here and pick it up again on the next sync.
                if crate::client::is_transient(&e) {
                    return Err(e.context(format!("event {seq}")));
                }
                tracing::warn!(seq, "ignoring event: {e:#}");
            }
            self.last_seq = Some(seq);
        }
        Ok(())
    }

    async fn apply(&mut self, ev: &Value) -> Result<()> {
        let data = &ev["data"];
        match ev["kind"].as_str().unwrap_or_default() {
            "participant" => {
                let raw = data["signed_join"].as_str().context("participant without signed_join")?;
                let j: SignedJoinRequest = parse_canonical(raw, "join request")?;
                j.verify(&self.manifest)?;
                let cert = String::from_utf8(canonical_json(&j.join.cert)?)?;
                self.participants.insert(
                    j.join.cert.participant().to_b64(),
                    Participant { role: j.join.cert.role(), cert },
                );
            }
            "item" => {
                let env_json = data["envelope"].as_str().context("item without envelope")?.to_string();
                let env: ItemEnvelope = parse_canonical(&env_json, "item envelope")?;
                let h = env.header.clone();
                // The id names a cache file and goes into URLs: only a
                // well-formed one, before anything touches the disk.
                if !airlox_core::item::is_item_id(&h.id) {
                    bail!("item with a malformed id");
                }
                self.envelopes.insert(h.id.clone(), env_json);
                if h.author == self.me {
                    return Ok(());
                }
                let author_role = self.participants.get(&h.author.to_b64()).map(|p| p.role);
                match h.kind {
                    // The owner's events decide approval; keep and act on them.
                    ItemKind::Event if author_role == Some(Role::Owner) => {
                        let o = self.open(&h.id).await?;
                        self.ack(&h.id).await;
                        self.on_owner_event(&o.meta);
                    }
                    // Inputs a later job may reference: cache them now, while
                    // the relay still has them.
                    ItemKind::File => {
                        if self.cached_blob(&h.id).await?.is_some() {
                            self.ack(&h.id).await;
                        }
                    }
                    // Jobs wait for their routing decision (below).
                    ItemKind::Job => {}
                    // Nothing a runner needs: tell the relay not to wait for us.
                    _ => self.ack(&h.id).await,
                }
            }
            "job" => {
                // Unless it is ours to run, we will not need the job's blob.
                let job = data["job"].as_str().unwrap_or_default().to_string();
                if !airlox_core::item::is_item_id(&job) {
                    bail!("job event with a malformed id");
                }
                let ours = data["runner"].as_str() == Some(self.me.to_b64().as_str());
                let active = matches!(data["state"].as_str(), Some("assigned" | "running"));
                if !(ours && active) {
                    self.ack(&job).await;
                }
            }
            "closed" => self.closed = true,
            _ => {}
        }
        Ok(())
    }

    fn on_owner_event(&mut self, meta: &Meta) {
        match meta {
            // A rejection is final: a replayed approval does not undo it.
            Meta::Event(Event::RunnerApprove { participant_pub })
                if *participant_pub == self.me && !self.rejected =>
            {
                tracing::info!("approved by the owner");
                self.approved = true;
            }
            Meta::Event(Event::RunnerReject { participant_pub, .. }) if *participant_pub == self.me => {
                self.rejected = true;
                self.approved = false;
            }
            _ => {}
        }
    }

    pub async fn ack(&mut self, id: &str) {
        if self.acked.contains(id) {
            return;
        }
        match self.relay.ack(id).await {
            Ok(()) => {
                self.acked.insert(id.to_string());
            }
            Err(e) => tracing::debug!(item = id, "ack failed, will retry on next use: {e:#}"),
        }
    }

    /// The item's ciphertext: from the cache, else from the relay (and then
    /// cached). `None` if it left the relay before we fetched it.
    pub async fn cached_blob(&mut self, id: &str) -> Result<Option<Vec<u8>>> {
        if !airlox_core::item::is_item_id(id) {
            bail!("malformed item id");
        }
        let path = self.blob_path(id);
        if let Ok(b) = fs::read(&path) {
            return Ok(Some(b));
        }
        let Some(env) = self.envelopes.get(id) else { bail!("unknown item {id}") };
        let limit = (self.manifest.max_item_bytes as usize).saturating_add(airlox_core::item::BLOB_OVERHEAD);
        let Some(blob) = self.relay.blob(id, limit).await? else { return Ok(None) };
        // Only keep bytes that match the author's signature.
        api::verify_item(env, &blob)?;
        write_atomic(&path, &blob, 0o600)?;
        Ok(Some(blob))
    }

    /// Fetch, verify and decrypt an item: author certificate, signature and
    /// payload policy, all through the core.
    pub async fn open(&mut self, id: &str) -> Result<Opened> {
        let env = self.envelopes.get(id).cloned().with_context(|| format!("unknown item {id}"))?;
        let header = parse_canonical::<ItemEnvelope>(&env, "item envelope")?.header;
        let author = self
            .participants
            .get(&header.author.to_b64())
            .with_context(|| "the author is not a verified participant".to_string())?;
        let cert = author.cert.clone();
        let blob = self.cached_blob(id).await?.context("the item left the relay before it was fetched")?;
        let (role, meta, body) = api::open_checked(&self.signed_manifest, &cert, &self.key, &env, &blob)?;
        Ok(Opened { role: Role::parse(&role)?, meta: serde_json::from_str(&meta)?, body, blob })
    }

    pub fn session_key(&self) -> &[u8; 32] {
        &self.key
    }
}
