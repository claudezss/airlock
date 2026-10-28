//! One job, from assignment to signed result.
//!
//! The runner checks everything itself before running (protocol §8): the
//! job and its inputs verify against the author's certificate, the author
//! holds the sender or owner role, the job fits the manifest limits, its
//! signed target names this runner, the owner's signed approval exists, and
//! the job has not run here before. Any failure becomes a `refused` result;
//! nothing runs.
//!
//! While a job runs the runner posts signed `progress` items: elapsed time
//! and the tail of the job's `progress_file`, and its output as it comes
//! ([`stream`]). Inputs are staged in a fresh work dir, or, for a runner with
//! workspaces, in the one it keeps for the job's sender ([`workspace`]),
//! where a working tree is synced rather than unpacked. Its answer (out files and
//! result) is sealed and kept on disk ([`outbox`]) before any of it is
//! posted, then posted with retries for as long as the relay is unreachable,
//! so a job that outlives a dropped connection, or a runner restart, still
//! reports, exactly once.

mod outbox;
mod redact;
mod stream;
mod tree;
mod workspace;

pub use workspace::Workspaces;

use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use airlox_core::encoding::{b64e, canonical_json, hex, sha256};
use airlox_core::item::{new_item_id, seal, ItemKind, ItemRef, NewItem};
use airlox_core::keys::Keypair;
use airlox_core::keys::PublicKey;
use airlox_core::payload::{
    JobEnv, JobKind, JobProgress, JobResult, JobSpec, JobStatus, Meta, OutFile, Payload,
    MAX_PROGRESS_TAIL_BYTES, MAX_STDIO_BYTES,
};
use airlox_core::policy::{check_file_name, target_matches};
use airlox_core::session::{ContentType, JobLimits, Role};
use airlox_core::validate::zip::{check_entry_path, extract_zip, ZipLimits};
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use tokio::sync::{watch, Mutex};

use crate::client::{is_duplicate, is_transient, Relay};
use crate::sandbox::{Backend, PreparedJob, RawResult, SCRIPT_FILE};
use crate::view::View;
use tree::Tree;
use workspace::Workspace;

/// How long a job that arrives just ahead of the owner's signed approval
/// waits for it before being refused.
const APPROVAL_WAIT: Duration = Duration::from_secs(5);

/// How long a finished job's result keeps being offered to an unreachable
/// relay before the runner gives up on it.
pub(crate) const RESULT_PATIENCE: Duration = Duration::from_secs(24 * 60 * 60);

/// What stays fixed for a runner across jobs.
pub struct Ctx {
    pub keypair: Keypair,
    pub labels: Vec<String>,
    pub backend: Backend,
    /// Parent of per-job directories.
    pub jobs_dir: PathBuf,
    /// Job ids this runner has started (`<id>`) and answered (`<id> posted`),
    /// so a relayed duplicate never runs twice, even across restarts.
    pub done_file: PathBuf,
    /// Upper bound on job memory from `--memory`, below the manifest's.
    pub memory_cap_mb: Option<u32>,
    pub network: bool,
    /// How often a running job's progress is posted; zero for never.
    pub progress_interval: Duration,
    /// Most bytes of a job's `progress_file` sent with each progress item.
    pub progress_tail: usize,
    /// Most output chunks posted per minute while a job runs (`--progress-rate`);
    /// zero for no streaming.
    pub progress_rate: u32,
    /// Most bytes of a job's output, both streams together, streamed
    /// (`--stream-max-mb`).
    pub stream_max_bytes: u64,
    /// Kept work dirs, one per sender (`--workspace`); `None` for a fresh
    /// work dir every job.
    pub workspaces: Option<Workspaces>,
    /// The workspaces running jobs hold, by work dir: a runner that runs
    /// several jobs at once lets a sender's workspace serve one at a time.
    pub workspaces_in_use: Arc<std::sync::Mutex<HashSet<PathBuf>>>,
    /// Where finished jobs' answers wait until the relay has them.
    pub outbox: PathBuf,
    /// Tests: exit once an answer is saved, before posting any of it.
    pub exit_before_posting: bool,
    /// Where jobs run, measured once when the runtime was prepared; every
    /// result of a job that ran carries it.
    pub env: Option<JobEnv>,
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// What this runner did with a job before: `None` never saw it,
/// `Some(false)` started it without posting a result (it restarted
/// mid-job), `Some(true)` posted its result.
fn run_record(ctx: &Ctx, id: &str) -> Option<bool> {
    let text = records(&ctx.done_file);
    let (mut started, mut posted) = (false, false);
    for line in text.lines() {
        match line.split_once(' ') {
            Some((j, "posted")) if j == id => posted = true,
            None if line == id => started = true,
            _ => {}
        }
    }
    (started || posted).then_some(posted)
}

/// The complete lines of a run-record file: a line cut short by a power
/// loss (no newline yet) never counts.
fn records(done_file: &Path) -> String {
    let mut text = fs::read_to_string(done_file).unwrap_or_default();
    text.truncate(text.rfind('\n').map_or(0, |i| i + 1));
    text
}

/// The jobs `done_file` records as started but not answered, oldest first.
pub(crate) fn unanswered(done_file: &Path) -> Vec<String> {
    let text = records(done_file);
    let mut started: Vec<&str> = text.lines().filter(|l| !l.contains(' ')).collect();
    started.retain(|id| !text.lines().any(|l| l.strip_suffix(" posted") == Some(*id)));
    started.dedup();
    started.into_iter().map(String::from).collect()
}

/// How long a runner that just started keeps offering saved answers to a
/// relay that will not take them before it gets on with its work (they stay
/// saved for the next start).
const STARTUP_PATIENCE: Duration = Duration::from_secs(10 * 60);

/// After a restart, post the saved answer of each job that finished before
/// the runner stopped. Needs no sandbox, so it runs before the sandbox is
/// prepared: a runner whose setup now fails still delivers them.
pub async fn deliver_saved(kp: &Keypair, done_file: &Path, outbox_root: &Path, view: &Arc<Mutex<View>>) {
    // Answers delivered just before a stop, whose folder outlived it.
    let posted: Vec<String> =
        records(done_file).lines().filter_map(|l| l.strip_suffix(" posted")).map(String::from).collect();
    for e in fs::read_dir(outbox_root).into_iter().flatten().flatten() {
        if e.file_name().to_str().is_some_and(|id| posted.iter().any(|p| p == id)) {
            let _ = fs::remove_dir_all(e.path());
        }
    }
    for id in unanswered(done_file) {
        let saved = outbox_root.join(&id);
        if !outbox::is_complete(&saved) {
            continue;
        }
        let poster = Poster::of(&*view.lock().await);
        match outbox::deliver(kp, done_file, &poster, &saved, STARTUP_PATIENCE).await {
            Ok(()) => {
                tracing::info!(job = %id, "posted the saved result of a job that finished before a restart")
            }
            Err(e) => tracing::warn!(job = %id, "could not post a saved result yet: {e:#}"),
        }
    }
}

/// After a restart, answer each job that was still running when the runner
/// stopped with a signed `failed` result (it is never run again), so its
/// sender learns why instead of only that the relay lost the runner. Jobs
/// with a saved answer are [`deliver_saved`]'s.
pub async fn report_interrupted(ctx: &Arc<Ctx>, view: &Arc<Mutex<View>>) {
    for id in unanswered(&ctx.done_file) {
        if outbox::is_complete(&ctx.outbox.join(&id)) {
            continue;
        }
        let (_, never) = watch::channel(false);
        if let Err(e) = handle(ctx.clone(), view.clone(), id.clone(), never).await {
            tracing::warn!(job = %id, "could not report the interrupted job: {e:#}");
            // Do not try again on every start.
            let _ = record(ctx, &format!("{id} posted"));
        }
    }
}

fn record(ctx: &Ctx, line: &str) -> Result<()> {
    record_to(&ctx.done_file, line)
}

fn record_to(done_file: &Path, line: &str) -> Result<()> {
    let mut f = fs::OpenOptions::new().create(true).append(true).open(done_file)?;
    writeln!(f, "{line}")?;
    f.sync_data()?;
    Ok(())
}

/// A sender's workspace, held by a job until the lease is dropped.
struct WorkspaceLease {
    in_use: Arc<std::sync::Mutex<HashSet<PathBuf>>>,
    dir: PathBuf,
}

impl WorkspaceLease {
    /// `None` while another job holds the workspace.
    fn take(in_use: &Arc<std::sync::Mutex<HashSet<PathBuf>>>, ws: &Workspace) -> Option<Self> {
        let dir = ws.work();
        let fresh = in_use.lock().unwrap_or_else(|e| e.into_inner()).insert(dir.clone());
        fresh.then(|| WorkspaceLease { in_use: in_use.clone(), dir })
    }
}

impl Drop for WorkspaceLease {
    fn drop(&mut self) {
        self.in_use.lock().unwrap_or_else(|e| e.into_inner()).remove(&self.dir);
    }
}

/// A job that passed every check, with its inputs.
struct Accepted {
    spec: JobSpec,
    /// The sender's workspace on this runner, when the job gets one, and
    /// the hold on it that lasts until the job is done with it.
    workspace: Option<Workspace>,
    _lease: Option<WorkspaceLease>,
    /// (item ref, file name, subkind, plaintext) per input.
    inputs: Vec<(ItemRef, String, ContentType, Vec<u8>)>,
    input_sha256: String,
}

enum Verdict {
    Run(Box<Accepted>),
    Refuse(String),
    /// It started here before the runner restarted; it does not run again.
    Interrupted,
}

/// Why a job that did not open is refused. The core's policy check is what
/// says the session does not allow its kind.
fn open_failure(e: &anyhow::Error) -> String {
    let why = format!("{e:#}");
    if why.contains("jobs are not allowed in this session") {
        format!("kind_not_supported: {why}")
    } else {
        format!("job did not verify: {why}")
    }
}

/// Why this runner will not run a job of `kind`, if it will not: the session
/// does not allow it, or this runner does not offer it.
fn kind_refusal(kind: JobKind, limits: &JobLimits, backend: &Backend) -> Option<String> {
    if !limits.allows_kind(kind) {
        return Some(format!("kind_not_supported: this session does not allow {} jobs", kind.as_str()));
    }
    (!backend.kinds().contains(&kind)).then(|| {
        format!(
            "kind_not_supported: this runner does not run {} jobs{}",
            kind.as_str(),
            backend.no_shell_hint()
        )
    })
}

/// Fetch, verify and check a job and its inputs.
async fn verify(ctx: &Ctx, view: &mut View, job_id: &str) -> Result<(ItemRef, Verdict)> {
    let job = view.open(job_id).await;
    // Without the blob there is no reference to answer with.
    let blob = match &job {
        Ok(o) => o.blob.clone(),
        Err(e) => match view.cached_blob(job_id).await {
            Ok(Some(b)) => b,
            _ => return Err(anyhow::anyhow!("cannot fetch job {job_id}: {e:#}")),
        },
    };
    let job_ref = ItemRef { id: job_id.to_string(), blob_sha256: b64e(&sha256(&blob)) };
    let refuse = |why: String| Ok((job_ref.clone(), Verdict::Refuse(why)));
    let job = match job {
        Ok(j) => j,
        Err(e) => return refuse(open_failure(&e)),
    };
    let Meta::Job(spec) = job.meta else { return refuse("not a job".into()) };
    if !matches!(job.role, Role::Sender | Role::Owner) {
        return refuse("jobs must come from the sender or owner role".into());
    }
    let limits = view.manifest.job_limits.clone().context("execute session without job limits")?;
    if let Some(why) = kind_refusal(spec.kind(), &limits, &ctx.backend) {
        return refuse(why);
    }
    match run_record(ctx, job_id) {
        Some(true) => bail!("job {job_id} already ran here; ignoring the duplicate"),
        Some(false) => return Ok((job_ref, Verdict::Interrupted)),
        None => {}
    }
    if !target_matches(&spec.target, ctx.keypair.public(), &ctx.labels) {
        return refuse("the job's signed target does not match this runner".into());
    }
    if !view.approved {
        // The owner approves on the relay just before posting the signed
        // event, so a job can arrive a moment ahead of it: wait for it briefly.
        let until = tokio::time::Instant::now() + APPROVAL_WAIT;
        while !view.approved && !view.rejected && !view.closed && tokio::time::Instant::now() < until {
            tokio::time::sleep_until(until.min(tokio::time::Instant::now() + Duration::from_millis(250)))
                .await;
            // Bounded by the same deadline, so a slow relay cannot stretch it.
            if let Ok(Err(e)) = tokio::time::timeout_at(until, view.sync()).await {
                tracing::debug!("sync while waiting for approval: {e:#}");
            }
        }
    }
    if !view.approved {
        return refuse("this runner has no signed approval from the session owner".into());
    }
    // The workspace is the author's: a sender's, or an owner's own jobs'.
    let author = view
        .envelope(job_id)
        .and_then(|e| serde_json::from_str::<serde_json::Value>(e).ok())
        .and_then(|e| PublicKey::from_b64(e["header"]["author"].as_str()?).ok())
        .context("the job's author")?;
    let workspace = ctx
        .workspaces
        .as_ref()
        .filter(|_| limits.workspace)
        .map(|w| (w.of(&view.manifest.session_id, &author), w.max_bytes));
    // One job at a time uses a workspace; the sender's next one is refused,
    // as a busy runner would refuse it, and may be sent again once this one
    // has finished.
    let lease = match &workspace {
        Some((ws, _)) => match WorkspaceLease::take(&ctx.workspaces_in_use, ws) {
            Some(lease) => Some(lease),
            None => {
                return refuse(
                    "runner_busy: another job of yours is using your workspace on this runner, and a \
                     workspace serves one job at a time; send this one again when that job has finished"
                        .into(),
                )
            }
        },
        None => None,
    };
    if let Some((ws, max)) = &workspace {
        let used = ws.size_bytes();
        if used > *max && !spec.fresh {
            return refuse(format!(
                "workspace_full: your workspace on this runner holds {} MB, over its {} MB limit; run the \
                 job with fresh (airlox run --fresh) to empty it",
                used.div_ceil(1 << 20),
                max >> 20
            ));
        }
    }
    let workspace = workspace.map(|(ws, _)| ws);
    let mut inputs = Vec::new();
    let mut hasher = Sha256::new();
    for r in &spec.files {
        let opened = match view.open(&r.id).await {
            Ok(o) => o,
            Err(e) => return refuse(format!("input {} is unavailable: {e:#}", r.id)),
        };
        if b64e(&sha256(&opened.blob)) != r.blob_sha256 {
            return refuse(format!("input {} does not match its reference", r.id));
        }
        let Meta::File { name, .. } = opened.meta else {
            return refuse(format!("input {} is not a file", r.id));
        };
        let env = view.envelope(&r.id).context("input envelope")?;
        let subkind = serde_json::from_str::<serde_json::Value>(env)?["header"]["subkind"].clone();
        let subkind: ContentType = serde_json::from_value(subkind)?;
        hasher.update(&opened.blob);
        inputs.push((r.clone(), name, subkind, opened.body));
    }
    let input_sha256 = hex(&hasher.finalize());
    Ok((job_ref, Verdict::Run(Box::new(Accepted { spec, workspace, _lease: lease, inputs, input_sha256 }))))
}

fn create_new(path: &Path, data: &[u8]) -> Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("{} already exists in the work dir", path.display()))?;
    f.write_all(data)?;
    Ok(())
}

/// Charge an archive's expanded size to the job's budget: one archive may
/// expand to the limit, not every one of a job's inputs.
fn charge(budget: &mut u64, body: &[u8], limits: &ZipLimits) -> Result<()> {
    let expands: u64 = airlox_core::validate::zip::inspect_zip(body, limits)?.iter().map(|e| e.size).sum();
    *budget = budget.checked_sub(expands).with_context(|| {
        format!("the job's archives expand beyond {} MiB in total", limits.max_total_bytes >> 20)
    })?;
    Ok(())
}

/// The tree input of a job, read and checked.
fn load_tree(a: &Accepted, tree: &ItemRef) -> Result<Tree> {
    let (_, _, subkind, body) =
        a.inputs.iter().find(|(r, ..)| r == tree).context("the job's tree is not one of its inputs")?;
    if *subkind != ContentType::Zip {
        bail!("the job's tree is not a zip");
    }
    Tree::load(body, &ZipLimits::default())
}

/// Place inputs and the entry file in `work`. ZIPs are unpacked (each into a
/// fresh directory first, as extraction requires, then moved over); no two
/// inputs may claim the same name.
fn stage_inputs(root: &Path, work: &Path, a: &Accepted) -> Result<()> {
    let limits = ZipLimits::default();
    let mut budget = limits.max_total_bytes;
    for (i, (_, name, subkind, body)) in a.inputs.iter().enumerate() {
        if *subkind == ContentType::Zip {
            charge(&mut budget, body, &limits)?;
            let staging = root.join(format!("unzip-{i}"));
            fs::create_dir(&staging)?;
            extract_zip(body, &staging, &limits)?;
            for entry in fs::read_dir(&staging)? {
                let entry = entry?;
                let dest = work.join(entry.file_name());
                if fs::symlink_metadata(&dest).is_ok() {
                    bail!("inputs collide on {:?}", entry.file_name());
                }
                fs::rename(entry.path(), dest)?;
            }
            fs::remove_dir(&staging)?;
        } else {
            create_new(&work.join(name), body)?;
        }
    }
    if a.spec.kind() == JobKind::Python {
        create_new(&work.join(&a.spec.filename), a.spec.code.as_bytes())?;
    }
    Ok(())
}

/// Place inputs and the entry file in a sender's workspace. The tree is
/// synced first; the other inputs and the entry file then replace what is
/// there, but not each other.
fn stage_workspace(ws: &Workspace, a: &Accepted, tree: Option<&Tree>) -> Result<()> {
    let limits = ZipLimits::default();
    let mut budget = limits.max_total_bytes;
    let mut claimed = std::collections::HashSet::new();
    if let (Some(tree), Some(tree_ref)) = (tree, &a.spec.tree) {
        if let Some((_, _, _, body)) = a.inputs.iter().find(|(r, ..)| r == tree_ref) {
            charge(&mut budget, body, &limits)?;
            ws.sync_tree(tree, body)?;
        }
    }
    for (r, name, subkind, body) in &a.inputs {
        if a.spec.tree.as_ref() == Some(r) {
            continue;
        }
        let zipped = *subkind == ContentType::Zip;
        if zipped {
            charge(&mut budget, body, &limits)?;
        }
        ws.put(name, body, zipped, &limits, &mut claimed)?;
    }
    if a.spec.kind() == JobKind::Python {
        ws.put(&a.spec.filename, a.spec.code.as_bytes(), false, &limits, &mut claimed)?;
    }
    Ok(())
}

/// Everything a job needs on disk: its inputs and entry file in the work
/// dir (a workspace is made ready first), a shell job's script in the meta
/// dir.
fn stage(job: &PreparedJob, a: &Accepted, tree: Option<&Tree>) -> Result<()> {
    match &a.workspace {
        Some(ws) => {
            ws.prepare(a.spec.fresh)?;
            stage_workspace(ws, a, tree)?;
        }
        None => stage_inputs(&job.root, &job.work_dir(), a)?,
    }
    if a.spec.kind() == JobKind::Shell {
        create_new(&job.meta_dir().join(SCRIPT_FILE), a.spec.code.as_bytes())?;
    }
    Ok(())
}

/// Give a tree to the user containers run as (root runners run them as
/// nobody), without following links.
#[cfg(unix)]
fn chown_for_container(path: &Path) {
    use nix::fcntl::AtFlags;
    let nobody = Some(nix::unistd::Uid::from_raw(65534));
    let group = Some(nix::unistd::Gid::from_raw(65534));
    let mut stack = vec![path.to_path_buf()];
    while let Some(p) = stack.pop() {
        let _ = nix::unistd::fchownat(None, &p, nobody, group, AtFlags::AT_SYMLINK_NOFOLLOW);
        if fs::symlink_metadata(&p).is_ok_and(|m| m.is_dir()) {
            stack.extend(fs::read_dir(&p).into_iter().flatten().flatten().map(|e| e.path()));
        }
    }
}

fn read_capped(path: &Path, max: u64) -> Result<(Vec<u8>, bool)> {
    crate::sandbox::read_sandbox_file(path, max)
}

/// stdout/stderr as UTF-8 within the 1 MiB result limit.
fn stdio(path: &Path) -> (String, bool) {
    let Ok((bytes, mut truncated)) = read_capped(path, MAX_STDIO_BYTES as u64) else {
        return (String::new(), false);
    };
    let mut s = String::from_utf8_lossy(&bytes).into_owned();
    if s.len() > MAX_STDIO_BYTES {
        let mut cut = MAX_STDIO_BYTES;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
        truncated = true;
    }
    (s, truncated)
}

const IMAGE_EXTS: &[(&str, &str)] =
    &[("png", "image/png"), ("jpg", "image/jpeg"), ("jpeg", "image/jpeg"), ("webp", "image/webp")];

/// A file from `/out` to send back.
pub struct OutItem {
    pub name: String,
    pub subkind: ContentType,
    pub mime: String,
    pub body: Vec<u8>,
}

/// Turn `/out` into items: top-level images become image items
/// (re-encoded, which strips metadata); everything else goes into one
/// `out.zip`. Links, special files and unportable names are skipped with a
/// note. Each item must fit the session's item size.
pub fn collect_out(out: &Path, max_item_bytes: u64, notes: &mut Vec<String>) -> Result<Vec<OutItem>> {
    let mut items = Vec::new();
    let mut zipped: Vec<(String, PathBuf)> = Vec::new();
    let mut stack = vec![(out.to_path_buf(), String::new())];
    while let Some((dir, prefix)) = stack.pop() {
        let mut entries: Vec<_> = fs::read_dir(&dir)?.collect::<std::io::Result<_>>()?;
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let name = e.file_name().to_string_lossy().into_owned();
            let rel = if prefix.is_empty() { name.clone() } else { format!("{prefix}/{name}") };
            let ft = fs::symlink_metadata(e.path())?.file_type();
            if ft.is_dir() {
                stack.push((e.path(), rel));
                continue;
            }
            if !ft.is_file() {
                notes.push(format!("skipped out/{rel}: not a regular file"));
                continue;
            }
            if check_entry_path(&rel, &ZipLimits::default()).is_err() {
                notes.push(format!("skipped out/{rel}: name is not portable"));
                continue;
            }
            let ext = name.rsplit_once('.').map(|(_, x)| x.to_ascii_lowercase()).unwrap_or_default();
            let image = IMAGE_EXTS.iter().find(|(x, _)| *x == ext);
            if prefix.is_empty() && image.is_some() && check_file_name(&name).is_ok() && items.len() < 63 {
                let (bytes, truncated) = match read_capped(&e.path(), max_item_bytes) {
                    Ok(r) => r,
                    Err(err) => {
                        notes.push(format!("skipped out/{rel}: {err:#}"));
                        continue;
                    }
                };
                if truncated {
                    notes.push(format!("skipped out/{rel}: larger than the session's item limit"));
                    continue;
                }
                match airlox_core::validate::image::sanitize_image(&bytes) {
                    Ok((mime, clean)) if Some(mime) == image.map(|(_, m)| *m) => items.push(OutItem {
                        name,
                        subkind: ContentType::Image,
                        mime: mime.into(),
                        body: clean,
                    }),
                    // Not really that image type: ship it inside the zip instead.
                    _ => zipped.push((rel, e.path())),
                }
            } else {
                zipped.push((rel, e.path()));
            }
        }
    }
    if !zipped.is_empty() {
        zipped.sort();
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .large_file(false);
        let mut total = 0u64;
        for (rel, path) in zipped {
            let (bytes, truncated) = match read_capped(&path, max_item_bytes) {
                Ok(r) => r,
                Err(e) => {
                    notes.push(format!("skipped out/{rel}: {e:#}"));
                    continue;
                }
            };
            total += bytes.len() as u64;
            if truncated || total > max_item_bytes {
                notes.push(format!(
                    "skipped out/{rel}: the output archive would exceed the session's item limit"
                ));
                total -= bytes.len() as u64;
                continue;
            }
            w.start_file(&rel, opts)?;
            w.write_all(&bytes)?;
        }
        let body = w.finish()?.into_inner();
        if body.len() as u64 + 1024 > max_item_bytes {
            notes.push("skipped out.zip: compressed output exceeds the session's item limit".into());
        } else if let Err(e) = airlox_core::validate::zip::inspect_zip(&body, &ZipLimits::default()) {
            notes.push(format!("skipped out.zip: {e}"));
        } else {
            items.push(OutItem {
                name: "out.zip".into(),
                subkind: ContentType::Zip,
                mime: "application/zip".into(),
                body,
            });
        }
    }
    Ok(items)
}

/// Map a sandbox run onto the protocol's status rules (§8).
fn outcome(raw: &RawResult, timeout_s: u32, memory_mb: u32) -> (JobStatus, Option<i32>, Option<String>) {
    let s = raw.shim.as_ref();
    if let Some(e) = &raw.error {
        return (JobStatus::Failed, None, Some(e.clone()));
    }
    if let Some(e) = s.and_then(|s| s.error.clone()) {
        return (JobStatus::Failed, None, Some(e));
    }
    // What the runner did comes first: when it stops an overrunning
    // sandbox, the shim reports that stop as a cancel.
    if raw.cancelled {
        return (JobStatus::Cancelled, None, Some("cancelled".into()));
    }
    if raw.killed_on_timeout || s.is_some_and(|s| s.timed_out) {
        return (JobStatus::TimedOut, None, Some(format!("exceeded the {timeout_s} s timeout")));
    }
    if s.is_some_and(|s| s.cancelled) {
        return (JobStatus::Cancelled, None, Some("cancelled".into()));
    }
    if raw.oom_killed {
        return (JobStatus::Failed, None, Some(format!("killed: out of memory (limit {memory_mb} MB)")));
    }
    match s {
        Some(s) if s.signal.is_some() => {
            (JobStatus::Failed, None, Some(format!("killed by signal {}", s.signal.unwrap_or(0))))
        }
        Some(s) => match s.exit_code {
            Some(c) => (JobStatus::Completed, Some(c), None),
            None => (JobStatus::Failed, None, Some("the job ended without an exit code".into())),
        },
        None => (JobStatus::Failed, None, Some("the sandbox wrote no result".into())),
    }
}

/// Retry transient failures (network trouble, a busy or restarting relay)
/// with backoff for up to `patience`.
async fn retry<T, Fut: std::future::Future<Output = Result<T>>>(
    patience: Duration,
    f: impl Fn() -> Fut,
) -> Result<T> {
    let until = tokio::time::Instant::now() + patience;
    let mut delay = Duration::from_millis(500);
    loop {
        match f().await {
            Err(e) if is_transient(&e) && tokio::time::Instant::now() + delay < until => {
                tracing::warn!("relay unavailable, retrying in {} s: {e:#}", delay.as_secs_f32());
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(60));
            }
            r => return r,
        }
    }
}

/// A sealed item, as it goes over the wire.
struct Sealed {
    env: String,
    blob: Vec<u8>,
    item_ref: ItemRef,
}

/// What it takes to post items without holding the session view.
#[derive(Clone)]
struct Poster {
    relay: Relay,
    key: [u8; 32],
    session_id: String,
}

impl Poster {
    fn of(view: &View) -> Self {
        Poster {
            relay: view.relay.clone(),
            key: *view.session_key(),
            session_id: view.manifest.session_id.clone(),
        }
    }

    fn seal(
        &self,
        kp: &Keypair,
        kind: ItemKind,
        subkind: Option<ContentType>,
        refs: Vec<ItemRef>,
        p: Payload,
    ) -> Result<Sealed> {
        let new = NewItem {
            id: new_item_id(),
            session_id: self.session_id.clone(),
            kind,
            subkind,
            created_at_ms: now_ms(),
            refs,
        };
        let sealed = seal(&self.key, kp, new, &p.encode()?)?;
        let env = String::from_utf8(canonical_json(&sealed.envelope)?)?;
        Ok(Sealed { env, item_ref: ItemRef::to(&sealed), blob: sealed.blob })
    }

    /// Upload a sealed item, retrying for up to `patience`. One the relay
    /// already has (sent before a restart) counts as sent.
    async fn send(&self, env: &str, blob: &[u8], patience: Duration) -> Result<()> {
        match retry(patience, || self.relay.post_item(env, blob)).await {
            Err(e) if is_duplicate(&e) => Ok(()),
            r => r,
        }
    }

    /// Seal and upload an item; returns its reference.
    async fn post(
        &self,
        kp: &Keypair,
        kind: ItemKind,
        subkind: Option<ContentType>,
        refs: Vec<ItemRef>,
        p: Payload,
        patience: Duration,
    ) -> Result<ItemRef> {
        let item = self.seal(kp, kind, subkind, refs, p)?;
        self.send(&item.env, &item.blob, patience).await?;
        Ok(item.item_ref)
    }
}

/// The last `max` bytes of `path`, a file inside `work`, as text starting at
/// a line, and whether more came before. `None` while the file does not
/// exist (or is not a regular file inside `work`).
fn read_tail(work: &Path, path: &Path, max: usize) -> (Option<String>, bool) {
    use std::io::{Read, Seek, SeekFrom};
    let mut o = fs::OpenOptions::new();
    o.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut o, nix::fcntl::OFlag::O_NONBLOCK.bits());
    let Ok(mut f) = o.open(path) else { return (None, false) };
    // The job can swap links while this runs: check where the file that is
    // now open really is, not where its name pointed a moment ago.
    let inside = match (fs::canonicalize(work), opened_path(&f)) {
        (Ok(w), Some(real)) => real.starts_with(w),
        _ => false,
    };
    if !inside {
        return (None, false);
    }
    let len = match f.metadata() {
        Ok(m) if m.is_file() => m.len(),
        _ => return (None, false),
    };
    let max = max.min(MAX_PROGRESS_TAIL_BYTES / 2);
    let truncated = len > max as u64;
    if truncated && f.seek(SeekFrom::Start(len - max as u64)).is_err() {
        return (None, false);
    }
    let mut buf = Vec::with_capacity(max);
    if f.take(max as u64).read_to_end(&mut buf).is_err() {
        return (None, false);
    }
    let mut text = String::from_utf8_lossy(&buf).into_owned();
    // Start at a line: the cut lands mid-line (or mid-character).
    if truncated {
        if let Some(nl) = text.find('\n') {
            text.drain(..=nl);
        }
    }
    // Each invalid byte became a 3-byte U+FFFD: keep within the limit.
    let mut truncated = truncated;
    if text.len() > MAX_PROGRESS_TAIL_BYTES {
        let mut cut = text.len() - MAX_PROGRESS_TAIL_BYTES;
        while !text.is_char_boundary(cut) {
            cut += 1;
        }
        text.drain(..cut);
        truncated = true;
    }
    (Some(text), truncated)
}

/// Where an open file really is, from the OS; `None` where it cannot say.
fn opened_path(f: &fs::File) -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        fs::read_link(format!("/proc/self/fd/{}", f.as_raw_fd())).ok()
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsRawFd;
        let mut p = PathBuf::new();
        nix::fcntl::fcntl(f.as_raw_fd(), nix::fcntl::FcntlArg::F_GETPATH(&mut p)).ok().map(|_| p)
    }
    #[cfg(windows)]
    {
        crate::sandbox::winjob::final_path(f)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = f;
        None
    }
}

/// After a job's first hour, progress goes out at most this often, so a
/// day-long job stays well inside the relay's per-session item budget.
const LONG_JOB_PROGRESS: Duration = Duration::from_secs(5 * 60);

/// A task that is aborted when this is dropped, however its owner ends.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The tail of `file` (relative), found in the job's work dir or, failing
/// that, its out dir (`$AIRLOX_OUT`, where a tool may write its log).
/// `env` if clients accept it (`check_env`), else none: a result whose
/// `env` fails the check is rejected whole, so it goes without.
pub(crate) fn checked_env(env: Option<JobEnv>) -> Option<JobEnv> {
    let env = env?;
    match airlox_core::policy::check_env(&env) {
        Ok(()) => Some(env),
        Err(e) => {
            tracing::warn!("not reporting where jobs run in results, clients would reject it: {e}");
            None
        }
    }
}

/// The directories a job's output must not name, and what stands for each:
/// its own (`$WORK`, `$AIRLOX_OUT`, `$JOB`), the runner's runtime and cache
/// (`$RUNTIME`) and the user's home (`~`).
fn hidden_dirs(ctx: &Ctx, job: &PreparedJob) -> Vec<(PathBuf, &'static str)> {
    let mut dirs =
        vec![(job.work_dir(), "$WORK"), (job.out_dir(), "$AIRLOX_OUT"), (job.root.clone(), "$JOB")];
    dirs.extend(ctx.backend.runtime_dirs().into_iter().map(|d| (d, redact::RUNTIME)));
    dirs.extend(redact::home_dirs().into_iter().map(|h| (h, redact::HOME)));
    dirs
}

/// Take the directories in `hidden` out of everything a result says in text.
fn hide_dirs(result: &mut JobResult, hidden: &[(PathBuf, &'static str)]) {
    result.stdout = redact::hide(&result.stdout, hidden);
    result.stderr = redact::hide(&result.stderr, hidden);
    result.reason = result.reason.take().map(|r| redact::hide(&r, hidden));
}

fn read_progress_file(roots: &[PathBuf], file: &str, max: usize) -> (Option<String>, bool) {
    roots
        .iter()
        .map(|root| read_tail(root, &root.join(file), max))
        .find(|(t, _)| t.is_some())
        .unwrap_or_default()
}

/// Post the job's progress every `ctx.progress_interval` while the
/// returned guard lives.
fn spawn_progress(
    ctx: &Arc<Ctx>,
    poster: &Poster,
    job_ref: &ItemRef,
    roots: Vec<PathBuf>,
    file: Option<String>,
    hidden: Arc<Vec<(PathBuf, &'static str)>>,
) -> Option<AbortOnDrop> {
    if ctx.progress_interval.is_zero() {
        return None;
    }
    let (ctx, poster, job_ref) = (ctx.clone(), poster.clone(), job_ref.clone());
    Some(AbortOnDrop(tokio::spawn(async move {
        let start = tokio::time::Instant::now();
        let mut tick = tokio::time::interval_at(start + ctx.progress_interval, ctx.progress_interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut last = start;
        loop {
            tick.tick().await;
            let now = tokio::time::Instant::now();
            if now - start > Duration::from_secs(3600) && now - last < LONG_JOB_PROGRESS {
                continue;
            }
            last = now;
            let (roots, max) = (roots.clone(), ctx.progress_tail);
            let (tail, tail_truncated) = match file.clone() {
                Some(f) => tokio::task::spawn_blocking(move || read_progress_file(&roots, &f, max))
                    .await
                    .unwrap_or_default(),
                None => (None, false),
            };
            let tail = tail.map(|t| redact::hide(&t, &hidden));
            let p = JobProgress {
                job: job_ref.clone(),
                elapsed_ms: start.elapsed().as_millis() as u64,
                tail,
                tail_truncated,
                stream: None,
                offset: None,
                data: None,
                truncated: false,
            };
            let refs = vec![job_ref.clone()];
            // One try: the next tick says the same, and newer.
            let posted = poster
                .post(&ctx.keypair, ItemKind::Progress, None, refs, Payload::progress(p), Duration::ZERO)
                .await;
            if let Err(e) = posted {
                tracing::warn!(job = %job_ref.id, "could not post progress: {e:#}");
            }
        }
    })))
}

/// Handle one assigned (and already claimed) job to the end.
pub async fn handle(
    ctx: Arc<Ctx>,
    view: Arc<Mutex<View>>,
    job_id: String,
    cancel: watch::Receiver<bool>,
) -> Result<()> {
    let (job_ref, verdict) = {
        let mut v = view.lock().await;
        v.sync().await?;
        verify(&ctx, &mut v, &job_id).await?
    };
    let limits =
        view.lock().await.manifest.job_limits.clone().context("execute session without job limits")?;
    let mut result = JobResult {
        job: job_ref.clone(),
        exit_code: None,
        status: JobStatus::Refused,
        reason: None,
        wall_ms: 0,
        peak_mem_mb: 0,
        stdout: String::new(),
        stderr: String::new(),
        stdout_truncated: false,
        stderr_truncated: false,
        out_files: vec![],
        code_sha256: hex(&sha256(b"")),
        input_sha256: hex(&sha256(b"")),
        env: None,
    };
    let mut refs = vec![job_ref.clone()];
    let poster = Poster::of(&*view.lock().await);
    // At most once: recorded before anything runs, so a relay that refuses
    // the result cannot get the same signed job run again.
    if !matches!(verdict, Verdict::Interrupted) {
        record(&ctx, &job_id)?;
    }
    // Reassigned after a restart while its answer is still saved: send that
    // answer, never replace it with a "restarted" one.
    let saved = ctx.outbox.join(&job_id);
    if matches!(verdict, Verdict::Interrupted) && outbox::is_complete(&saved) {
        outbox::deliver(&ctx.keypair, &ctx.done_file, &poster, &saved, RESULT_PATIENCE).await?;
        tracing::info!(job = %job_id, "posted the saved result");
        return Ok(());
    }
    let mut outbox = outbox::Outbox::create(&ctx.outbox, &job_id)?;
    match verdict {
        Verdict::Interrupted => {
            tracing::warn!(job = %job_id, "this job was running when the runner stopped; not running it again");
            result.status = JobStatus::Failed;
            result.reason = Some(
                "the runner restarted while this job was running; a job never runs twice, so resubmit it"
                    .into(),
            );
        }
        Verdict::Refuse(why) => {
            tracing::warn!(job = %job_id, "refusing: {why}");
            result.reason = Some(why);
            let mut v = view.lock().await;
            v.ack(&job_id).await;
        }
        Verdict::Run(a) => {
            result.code_sha256 = hex(&sha256(a.spec.code.as_bytes()));
            result.input_sha256 = a.input_sha256.clone();
            result.env = ctx.env.clone();
            if let Some(t) = &a.spec.tree {
                tracing::info!(job = %job_id, tree = %t.id, workspace = a.workspace.is_some(), "the job carries a working tree");
            }
            let memory_mb =
                a.spec.memory_mb.unwrap_or(limits.memory_mb).min(ctx.memory_cap_mb.unwrap_or(u32::MAX));
            let dir = tempfile::Builder::new().prefix("job-").tempdir_in(&ctx.jobs_dir)?;
            let job = PreparedJob {
                id: job_id.clone(),
                root: dir.path().to_path_buf(),
                work: a.workspace.as_ref().map_or_else(|| dir.path().join("work"), Workspace::work),
                kind: a.spec.kind(),
                entry: a.spec.filename.clone(),
                shell: ctx.backend.shell().unwrap_or("sh"),
                cwd: a.spec.cwd.clone(),
                timeout_s: a.spec.timeout_s,
                memory_mb,
                network: ctx.network,
            };
            // A workspace's work dir is made ready with its inputs, below.
            let fresh_work = a.workspace.is_none().then(|| job.work_dir());
            for d in fresh_work.into_iter().chain([job.out_dir(), job.meta_dir()]) {
                fs::create_dir(&d)?;
                // A root runner runs docker jobs as nobody, who must be able to write here.
                #[cfg(unix)]
                if nix::unistd::getuid().is_root() && matches!(ctx.backend, Backend::Docker(_)) {
                    nix::unistd::chown(&d, Some(65534.into()), Some(65534.into()))?;
                }
            }
            {
                // Job and inputs are in our cache: the relay need not keep them for us.
                let mut v = view.lock().await;
                v.ack(&job_id).await;
                for (r, ..) in &a.inputs {
                    v.ack(&r.id).await;
                }
            }
            // A job run as a plain process saw its real directories; what it
            // prints (and reports as progress) must not carry where the
            // runner keeps them, nor whose home they are in.
            let hidden = Arc::new(hidden_dirs(&ctx, &job));
            let tree = a.spec.tree.as_ref().map(|t| load_tree(&a, t)).transpose();
            if let (Ok(Some(t)), Some(env)) = (&tree, &mut result.env) {
                env.tree = Some(t.info.clone());
            }
            let staged = tree.and_then(|tree| {
                stage(&job, &a, tree.as_ref())?;
                // Container users own what they will write to.
                #[cfg(unix)]
                if nix::unistd::getuid().is_root() && matches!(ctx.backend, Backend::Docker(_)) {
                    chown_for_container(&job.work_dir());
                }
                Ok(())
            });
            if let Err(e) = staged {
                result.reason = Some(format!("could not stage inputs: {e:#}"));
            } else {
                tracing::info!(job = %job_id, kind = job.kind.as_str(), "running");
                let progress = spawn_progress(
                    &ctx,
                    &poster,
                    &job_ref,
                    vec![job.work_dir(), job.out_dir()],
                    a.spec.progress_file.clone(),
                    hidden.clone(),
                );
                let output = stream::spawn(&ctx, &poster, &job_ref, job.meta_dir(), hidden.clone());
                let raw = ctx.backend.run(&job, cancel).await.unwrap_or_else(|e| RawResult {
                    error: Some(format!("the sandbox could not run the job: {e:#}")),
                    ..Default::default()
                });
                drop(progress);
                drop(output);
                let (status, exit_code, reason) = outcome(&raw, job.timeout_s, memory_mb);
                result.status = status;
                result.exit_code = exit_code;
                result.reason = reason;
                result.wall_ms = raw.shim.as_ref().map(|s| s.wall_ms).unwrap_or(raw.wall_ms);
                let peak_kb = raw.peak_mem_kb.or(raw.shim.as_ref().map(|s| s.peak_rss_kb)).unwrap_or(0);
                result.peak_mem_mb = (peak_kb / 1024) as u32;
                (result.stdout, result.stdout_truncated) = stdio(&job.meta_dir().join("stdout.txt"));
                (result.stderr, result.stderr_truncated) = stdio(&job.meta_dir().join("stderr.txt"));
                let mut notes = Vec::new();
                if limits.return_out {
                    // The payload adds a few hundred bytes of meta to the file.
                    let max = view.lock().await.manifest.max_item_bytes.saturating_sub(4096);
                    let outs = collect_out(&job.out_dir(), max, &mut notes).unwrap_or_else(|e| {
                        notes.push(format!("could not collect /out: {e:#}"));
                        vec![]
                    });
                    // Sealed and saved one at a time, so they are never all in memory.
                    for o in outs {
                        let size = o.body.len() as u64;
                        let name = o.name.clone();
                        let file = Payload::file(&o.name, &o.mime, o.body);
                        let saved = poster
                            .seal(&ctx.keypair, ItemKind::File, Some(o.subkind), vec![], file)
                            .and_then(|item| outbox.add_file(&item));
                        match saved {
                            Ok(r) => {
                                result.out_files.push(OutFile { name: o.name, size, item: r.clone() });
                                refs.push(r);
                            }
                            Err(e) => notes.push(format!("could not keep out/{name} for upload: {e:#}")),
                        }
                    }
                }
                for n in notes {
                    let line = format!("\n[airlox] {n}");
                    if result.stderr.len() + line.len() <= MAX_STDIO_BYTES {
                        result.stderr.push_str(&line);
                    }
                }
            }
            // One pass over everything that leaves: the job's own output,
            // and the reason and notes the runner wrote, whose errors name
            // the work directories. (Redacting never lengthens text.)
            hide_dirs(&mut result, &hidden);
            if let Some(ws) = a.workspace {
                // Measured now, so the sender's next job knows if it may run.
                let size = tokio::task::spawn_blocking(move || ws.finish()).await.unwrap_or(0);
                tracing::info!(job = %job_id, workspace_mb = size >> 20, "workspace kept");
            }
            crate::sandbox::make_removable(dir.path());
            drop(dir);
        }
    }
    if let Some(r) = &mut result.reason {
        if r.chars().count() > airlox_core::payload::MAX_REASON_CHARS {
            *r = r.chars().take(airlox_core::payload::MAX_REASON_CHARS).collect();
        }
    }
    let status = result.status;
    let saved = outbox.finish(&result, &refs)?;
    if ctx.exit_before_posting {
        tracing::warn!(job = %job_id, "--exit-before-posting: exiting with the answer saved");
        std::process::exit(3);
    }
    outbox::deliver(&ctx.keypair, &ctx.done_file, &poster, &saved, RESULT_PATIENCE).await?;
    tracing::info!(job = %job_id, ?status, "result posted");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn docker(image: Option<&str>) -> Backend {
        Backend::Docker(crate::sandbox::docker::Docker::new(
            "docker".into(),
            image.map(String::from),
            "1".into(),
            None,
            Path::new("/nonexistent"),
        ))
    }

    fn limits(kinds: Option<Vec<JobKind>>) -> JobLimits {
        JobLimits { kinds, ..Default::default() }
    }

    #[test]
    fn a_job_of_a_kind_the_runner_or_session_lacks_is_refused_with_a_stable_reason() {
        let both = limits(Some(vec![JobKind::Python, JobKind::Shell]));
        // A docker runner with no image offers python only, and says how to change that.
        let why = kind_refusal(JobKind::Shell, &both, &docker(None)).unwrap();
        assert!(why.starts_with("kind_not_supported: this runner does not run shell jobs"), "{why}");
        assert!(why.contains("--image"), "{why}");
        assert!(kind_refusal(JobKind::Python, &both, &docker(None)).is_none());
        // With an image it offers both.
        assert!(kind_refusal(JobKind::Shell, &both, &docker(Some("ci:latest"))).is_none());
        // A session that allows python only (no `kinds` at all).
        let why = kind_refusal(JobKind::Shell, &limits(None), &docker(Some("ci"))).unwrap();
        assert_eq!(why, "kind_not_supported: this session does not allow shell jobs");
        let shell_only = limits(Some(vec![JobKind::Shell]));
        assert!(kind_refusal(JobKind::Python, &shell_only, &docker(Some("ci"))).unwrap().contains("session"));
        // The core's own policy error for an unallowed kind gets the same prefix.
        let e = anyhow::Error::from(airlox_core::Error::Policy(
            "shell jobs are not allowed in this session".into(),
        ));
        assert!(open_failure(&e).starts_with("kind_not_supported: "), "{}", open_failure(&e));
        let e = anyhow::anyhow!("bad signature");
        assert!(open_failure(&e).starts_with("job did not verify: "));
    }

    #[test]
    fn a_workspace_is_held_by_one_job_until_its_lease_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let sender = Keypair::generate().public();
        let workspaces = Workspaces::new(dir.path(), 10, Duration::from_secs(60));
        let in_use = Arc::new(std::sync::Mutex::new(HashSet::new()));
        let mine = workspaces.of("ax_s", &sender);
        let lease = WorkspaceLease::take(&in_use, &mine).expect("free");
        assert!(WorkspaceLease::take(&in_use, &workspaces.of("ax_s", &sender)).is_none());
        // Another sender, or the same sender in another session, is not blocked.
        assert!(
            WorkspaceLease::take(&in_use, &workspaces.of("ax_s", &Keypair::generate().public())).is_some()
        );
        assert!(WorkspaceLease::take(&in_use, &workspaces.of("ax_t", &sender)).is_some());
        drop(lease);
        assert!(WorkspaceLease::take(&in_use, &mine).is_some());
    }

    #[test]
    fn what_the_runner_wrote_names_no_directory_either() {
        let (root, home) = ("/tmp/airlox-jobs-a1b2c3/job-x9", "/home/ann");
        let hidden = vec![
            (PathBuf::from(format!("{root}/work")), "$WORK"),
            (PathBuf::from(root), "$JOB"),
            (PathBuf::from(home), redact::HOME),
        ];
        let r#ref = ItemRef { id: "i".into(), blob_sha256: "h".into() };
        let mut result = JobResult {
            job: r#ref,
            exit_code: None,
            status: JobStatus::Failed,
            reason: Some(format!("could not stage inputs: {root}/work/a.csv: File exists (os error 17)")),
            wall_ms: 0,
            peak_mem_mb: 0,
            stdout: format!("in {home}/x"),
            // A note the runner appended, with its error.
            stderr: format!("\n[airlox] could not keep out/a.png for upload: {root}/out/a.png: disk full"),
            stdout_truncated: false,
            stderr_truncated: false,
            out_files: vec![],
            code_sha256: String::new(),
            input_sha256: String::new(),
            env: None,
        };
        hide_dirs(&mut result, &hidden);
        let said = format!("{:?} {} {}", result.reason, result.stdout, result.stderr);
        assert!(!said.contains("airlox-jobs") && !said.contains("ann"), "{said}");
        assert_eq!(
            result.reason.as_deref(),
            Some("could not stage inputs: $WORK/a.csv: File exists (os error 17)")
        );
    }

    #[test]
    fn an_env_clients_would_reject_is_dropped_not_the_result() {
        let mut env = JobEnv {
            python: "3.12.4".into(),
            packages: [("numpy".to_string(), "2.1.0".to_string())].into(),
            airlox: "0.1.2".into(),
            sandbox: airlox_core::cert::SandboxKind::Docker,
            interpreter: "docker:python".into(),
            kinds: None,
            shell: None,
            tree: None,
        };
        assert_eq!(checked_env(Some(env.clone())).unwrap().interpreter, "docker:python");
        env.interpreter = "x".repeat(129);
        assert!(checked_env(Some(env.clone())).is_none());
        env.interpreter = "docker:python".into();
        env.packages.insert("pandas".into(), String::new());
        assert!(checked_env(Some(env)).is_none());
        assert!(checked_env(None).is_none());
    }

    #[test]
    fn out_dir_becomes_images_and_one_zip() {
        let d = tempfile::tempdir().unwrap();
        let out = d.path();
        let mut png = Vec::new();
        image_png(&mut png);
        fs::write(out.join("chart.png"), &png).unwrap();
        fs::write(out.join("fake.png"), b"not a png").unwrap();
        fs::create_dir(out.join("tables")).unwrap();
        fs::write(out.join("tables/summary.csv"), b"a,b\n1,2\n").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("/etc/passwd", out.join("leak.txt")).unwrap();
        let mut notes = Vec::new();
        let items = collect_out(out, 1 << 20, &mut notes).unwrap();
        let names: Vec<_> = items.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, ["chart.png", "out.zip"]);
        let entries = airlox_core::validate::zip::inspect_zip(&items[1].body, &ZipLimits::default()).unwrap();
        let paths: Vec<_> = entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, ["fake.png", "tables/summary.csv"]);
        #[cfg(unix)]
        assert!(notes.iter().any(|n| n.contains("leak.txt")), "{notes:?}");
    }

    fn image_png(buf: &mut Vec<u8>) {
        let img = image::RgbImage::from_pixel(2, 2, image::Rgb([10, 20, 30]));
        img.write_to(&mut std::io::Cursor::new(buf), image::ImageFormat::Png).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn sandbox_files_cannot_hang_or_flood_the_runner() {
        let d = tempfile::tempdir().unwrap();
        // A FIFO would block a plain open forever.
        let fifo = d.path().join("stdout.txt");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRWXU).unwrap();
        let t = std::time::Instant::now();
        assert!(read_capped(&fifo, 1024).is_err());
        assert!(t.elapsed() < Duration::from_secs(1));
        assert_eq!(stdio(&fifo), (String::new(), false));
        // A link to an endless device is not followed.
        let link = d.path().join("result.json");
        std::os::unix::fs::symlink("/dev/zero", &link).unwrap();
        assert!(read_capped(&link, 1024).is_err());
        // Regular files are read up to the cap.
        let big = d.path().join("big");
        fs::write(&big, vec![b'x'; 5000]).unwrap();
        let (b, more) = read_capped(&big, 1024).unwrap();
        assert!(b.len() == 1024 && more);
    }

    #[test]
    fn stdio_is_capped_on_a_char_boundary() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("stdout.txt");
        fs::write(&p, "é".repeat(MAX_STDIO_BYTES)).unwrap();
        let (s, truncated) = stdio(&p);
        assert!(truncated && s.len() <= MAX_STDIO_BYTES && s.chars().all(|c| c == 'é'));
    }

    #[test]
    fn outcomes_follow_the_status_rules() {
        use airlox_core::shim::ShimResult;
        let shim = |exit: Option<i32>, sig: Option<i32>, timed_out: bool, cancelled: bool| RawResult {
            shim: Some(ShimResult {
                shim_version: 1,
                exit_code: exit,
                signal: sig,
                timed_out,
                cancelled,
                wall_ms: 1,
                peak_rss_kb: 1,
                error: None,
            }),
            ..Default::default()
        };
        assert_eq!(outcome(&shim(Some(1), None, false, false), 30, 512).0, JobStatus::Completed);
        assert_eq!(outcome(&shim(None, None, true, false), 30, 512).0, JobStatus::TimedOut);
        assert_eq!(outcome(&shim(None, None, false, true), 30, 512).0, JobStatus::Cancelled);
        assert_eq!(outcome(&shim(None, Some(9), false, false), 30, 512).0, JobStatus::Failed);
        // The runner stopped an overrunning sandbox; the shim calls that a cancel.
        let mut overran = shim(None, None, false, true);
        overran.killed_on_timeout = true;
        assert_eq!(outcome(&overran, 30, 512).0, JobStatus::TimedOut);
        let mut oom = shim(None, Some(9), false, false);
        oom.oom_killed = true;
        assert!(outcome(&oom, 30, 512).2.unwrap().contains("out of memory"));
        for raw in [shim(Some(0), None, false, false), shim(None, None, true, false), oom] {
            let (status, exit_code, reason) = outcome(&raw, 30, 512);
            let r = JobResult {
                job: ItemRef { id: b64e(&[1; 16]), blob_sha256: b64e(&[1; 32]) },
                exit_code,
                status,
                reason,
                wall_ms: 1,
                peak_mem_mb: 1,
                stdout: String::new(),
                stderr: String::new(),
                stdout_truncated: false,
                stderr_truncated: false,
                out_files: vec![],
                code_sha256: "a".repeat(64),
                input_sha256: "b".repeat(64),
                env: None,
            };
            airlox_core::policy::check_result(&r).unwrap();
        }
    }
}
