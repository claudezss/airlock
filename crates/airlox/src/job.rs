//! One job, from assignment to signed result.
//!
//! The runner checks everything itself before running (protocol §8): the
//! job and its inputs verify against the author's certificate, the author
//! holds the sender or owner role, the job fits the manifest limits, its
//! signed target names this runner, the owner's signed approval exists, and
//! the job has not run here before. Any failure becomes a `refused` result;
//! nothing runs.

use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use airlox_core::encoding::{b64e, canonical_json, hex, sha256};
use airlox_core::item::{new_item_id, seal, ItemKind, ItemRef, NewItem};
use airlox_core::keys::Keypair;
use airlox_core::payload::{JobResult, JobSpec, JobStatus, Meta, OutFile, Payload, MAX_STDIO_BYTES};
use airlox_core::policy::{check_file_name, target_matches};
use airlox_core::session::{ContentType, Role};
use airlox_core::validate::zip::{check_entry_path, extract_zip, ZipLimits};
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use tokio::sync::{watch, Mutex};

use crate::client::is_transient;
use crate::sandbox::{Backend, PreparedJob, RawResult};
use crate::view::View;

/// What stays fixed for a runner across jobs.
pub struct Ctx {
    pub keypair: Keypair,
    pub labels: Vec<String>,
    pub backend: Backend,
    /// Parent of per-job directories.
    pub jobs_dir: PathBuf,
    /// Job ids this runner has handled, so a relayed duplicate never runs twice.
    pub done_file: PathBuf,
    /// Upper bound on job memory from `--memory`, below the manifest's.
    pub memory_cap_mb: Option<u32>,
    pub network: bool,
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn done_set(ctx: &Ctx) -> HashSet<String> {
    fs::read_to_string(&ctx.done_file).unwrap_or_default().lines().map(str::to_string).collect()
}

fn mark_done(ctx: &Ctx, id: &str) -> Result<()> {
    let mut f = fs::OpenOptions::new().create(true).append(true).open(&ctx.done_file)?;
    writeln!(f, "{id}")?;
    Ok(())
}

/// A job that passed every check, with its inputs.
struct Accepted {
    spec: JobSpec,
    /// (item ref, file name, subkind, plaintext) per input.
    inputs: Vec<(ItemRef, String, ContentType, Vec<u8>)>,
    input_sha256: String,
}

enum Verdict {
    Run(Box<Accepted>),
    Refuse(String),
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
        Err(e) => return refuse(format!("job did not verify: {e:#}")),
    };
    let Meta::Job(spec) = job.meta else { return refuse("not a job".into()) };
    if !matches!(job.role, Role::Sender | Role::Owner) {
        return refuse("jobs must come from the sender or owner role".into());
    }
    if done_set(ctx).contains(job_id) {
        bail!("job {job_id} already ran here; ignoring the duplicate");
    }
    if !target_matches(&spec.target, ctx.keypair.public(), &ctx.labels) {
        return refuse("the job's signed target does not match this runner".into());
    }
    if !view.approved {
        return refuse("this runner has no signed approval from the session owner".into());
    }
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
    Ok((job_ref, Verdict::Run(Box::new(Accepted { spec, inputs, input_sha256 }))))
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

/// Place inputs and the entry file in `work`. ZIPs are unpacked (each into a
/// fresh directory first, as extraction requires, then moved over); no two
/// inputs may claim the same name.
fn stage_inputs(root: &Path, work: &Path, a: &Accepted) -> Result<()> {
    let limits = ZipLimits::default();
    for (i, (_, name, subkind, body)) in a.inputs.iter().enumerate() {
        if *subkind == ContentType::Zip {
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
    create_new(&work.join(&a.spec.filename), a.spec.code.as_bytes())
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

async fn retry<T, Fut: std::future::Future<Output = Result<T>>>(f: impl Fn() -> Fut) -> Result<T> {
    let mut delay = Duration::from_millis(500);
    for _ in 0..6 {
        match f().await {
            Err(e) if is_transient(&e) => {
                tracing::warn!("relay busy, retrying: {e:#}");
                tokio::time::sleep(delay).await;
                delay *= 2;
            }
            r => return r,
        }
    }
    f().await
}

/// Seal and upload an item; returns its reference.
async fn post(
    view: &View,
    kp: &Keypair,
    kind: ItemKind,
    subkind: Option<ContentType>,
    refs: Vec<ItemRef>,
    p: Payload,
) -> Result<ItemRef> {
    let new = NewItem {
        id: new_item_id(),
        session_id: view.manifest.session_id.clone(),
        kind,
        subkind,
        created_at_ms: now_ms(),
        refs,
    };
    let sealed = seal(view.session_key(), kp, new, &p.encode()?)?;
    let env = String::from_utf8(canonical_json(&sealed.envelope)?)?;
    retry(|| view.relay.post_item(&env, &sealed.blob)).await?;
    Ok(ItemRef::to(&sealed))
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
    };
    let mut refs = vec![job_ref.clone()];
    // At most once: recorded before anything runs, so a relay that refuses
    // the result cannot get the same signed job run again.
    mark_done(&ctx, &job_id)?;
    match verdict {
        Verdict::Refuse(why) => {
            tracing::warn!(job = %job_id, "refusing: {why}");
            result.reason = Some(why);
            let mut v = view.lock().await;
            v.ack(&job_id).await;
        }
        Verdict::Run(a) => {
            result.code_sha256 = hex(&sha256(a.spec.code.as_bytes()));
            result.input_sha256 = a.input_sha256.clone();
            let memory_mb =
                a.spec.memory_mb.unwrap_or(limits.memory_mb).min(ctx.memory_cap_mb.unwrap_or(u32::MAX));
            let dir = tempfile::Builder::new().prefix("job-").tempdir_in(&ctx.jobs_dir)?;
            let job = PreparedJob {
                id: job_id.clone(),
                root: dir.path().to_path_buf(),
                entry: a.spec.filename.clone(),
                timeout_s: a.spec.timeout_s,
                memory_mb,
                network: ctx.network,
            };
            for d in [job.work_dir(), job.out_dir(), job.meta_dir()] {
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
            if let Err(e) = stage_inputs(&job.root, &job.work_dir(), &a) {
                result.reason = Some(format!("could not stage inputs: {e:#}"));
            } else {
                tracing::info!(job = %job_id, entry = %job.entry, "running");
                let raw = ctx.backend.run(&job, cancel).await.unwrap_or_else(|e| RawResult {
                    error: Some(format!("the sandbox could not run the job: {e:#}")),
                    ..Default::default()
                });
                let (status, exit_code, reason) = outcome(&raw, job.timeout_s, memory_mb);
                result.status = status;
                result.exit_code = exit_code;
                result.reason = reason;
                result.wall_ms = raw.shim.as_ref().map(|s| s.wall_ms).unwrap_or(raw.wall_ms);
                result.peak_mem_mb = raw.shim.as_ref().map(|s| (s.peak_rss_kb / 1024) as u32).unwrap_or(0);
                (result.stdout, result.stdout_truncated) = stdio(&job.meta_dir().join("stdout.txt"));
                (result.stderr, result.stderr_truncated) = stdio(&job.meta_dir().join("stderr.txt"));
                let mut notes = Vec::new();
                if limits.return_out {
                    let v = view.lock().await;
                    // The payload adds a few hundred bytes of meta to the file.
                    let max = v.manifest.max_item_bytes.saturating_sub(4096);
                    let outs = collect_out(&job.out_dir(), max, &mut notes).unwrap_or_else(|e| {
                        notes.push(format!("could not collect /out: {e:#}"));
                        vec![]
                    });
                    for o in outs {
                        let size = o.body.len() as u64;
                        let name = o.name.clone();
                        let file = Payload::file(&o.name, &o.mime, o.body);
                        match post(&v, &ctx.keypair, ItemKind::File, Some(o.subkind), vec![], file).await {
                            Ok(r) => {
                                result.out_files.push(OutFile { name: o.name, size, item: r.clone() });
                                refs.push(r);
                            }
                            Err(e) => notes.push(format!("could not upload out/{name}: {e:#}")),
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
    let v = view.lock().await;
    post(&v, &ctx.keypair, ItemKind::Result, None, refs, Payload::result(result)).await?;
    tracing::info!(job = %job_id, ?status, "result posted");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
            };
            airlox_core::policy::check_result(&r).unwrap();
        }
    }
}
