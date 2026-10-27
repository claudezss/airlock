//! `airlox runner join`: join a session as a runner and run its jobs.
//!
//! One job at a time. The loop holds the assignment stream open, claims each
//! assignment at once, sends a heartbeat (and catches up on session events)
//! every 10 seconds, and forwards cancels to the running job.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use airlox_core::cert::{is_runner_token, issue_cert, sign_join, ClientKind, JoinRequest, RunnerInfo};
use airlox_core::encoding::canonical_json;
use airlox_core::invite::Invite;
use airlox_core::keys::Keypair;
use airlox_core::session::{Mode, Role, SignedManifest};
use anyhow::{bail, Context, Result};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;

use crate::client::{self, status_of, Relay};
use crate::job::{self, Ctx};
use crate::sandbox::{docker::Docker, local::Local, Backend, RuntimeSpec};
use crate::sse::SseParser;
use crate::view::{write_atomic, View};

pub const HEARTBEAT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum SandboxArg {
    Local,
    Docker,
}

#[derive(clap::Args, Debug)]
#[command(group(clap::ArgGroup::new("source").args(["invite", "code"]).required(true).multiple(true)))]
pub struct JoinArgs {
    /// The runner invite link (or set AIRLOX_INVITE).
    #[arg(long, env = "AIRLOX_INVITE", hide_env_values = true)]
    pub invite: Option<String>,
    /// A one-time transfer code for the runner invite, like 7-guitar-orbit,
    /// instead of --invite. The invite is saved for restarts.
    #[arg(long)]
    pub code: Option<String>,
    /// The relay the --code was made on.
    #[arg(long, env = "AIRLOX_RELAY", default_value = "https://airlox.app")]
    pub relay: String,
    /// This runner's name, shown to senders: [a-z0-9][a-z0-9._-]{0,62}.
    #[arg(long)]
    pub name: String,
    /// Labels senders can target, comma-separated.
    #[arg(long, value_delimiter = ',')]
    pub labels: Vec<String>,
    /// What this runner is, shown to senders choosing one (up to 280
    /// characters), e.g. "A100 80 GB, CUDA 12; data team".
    #[arg(long, env = "AIRLOX_RUNNER_DESCRIPTION")]
    pub description: Option<String>,
    #[arg(long, value_enum, default_value = "docker")]
    pub sandbox: SandboxArg,
    /// Keep jobs off the network even if the session allows it.
    #[arg(long)]
    pub no_network: bool,
    /// Cap job memory (MB) below the session's limit.
    #[arg(long)]
    pub memory: Option<u32>,
    /// Session cache and runtime directory (default: ~/.cache/airlox).
    #[arg(long, env = "AIRLOX_CACHE_DIR")]
    pub cache_dir: Option<PathBuf>,
    /// docker: use this image instead of building one from the allowlist.
    #[arg(long)]
    pub docker_image: Option<String>,
    /// docker: CPUs per job.
    #[arg(long, default_value = "1")]
    pub docker_cpus: String,
    /// docker: container runtime, e.g. runsc for gVisor.
    #[arg(long)]
    pub docker_runtime: Option<String>,
    /// local on Linux: run jobs as plain processes, without namespaces.
    /// Only for trusted code.
    #[arg(long)]
    pub unsandboxed: bool,
    /// Exit after this many jobs (for tests and one-shot use).
    #[arg(long, hide = true)]
    pub max_jobs: Option<usize>,
}

#[derive(Serialize, Deserialize)]
struct Identity {
    participant_seed: String,
    token: String,
    /// The relay that issued `token`; it is only ever sent there.
    #[serde(default)]
    base_url: Option<String>,
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// `~/.cache/airlox`, as the Python SDK's cache (so they share one), which on
/// Windows is under the user profile. Identities live here, so the temporary
/// directory, which gets cleaned, is a last resort.
pub fn default_cache_root() -> PathBuf {
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"));
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| home.map(|h| PathBuf::from(h).join(".cache")))
        .unwrap_or_else(std::env::temp_dir);
    base.join("airlox")
}

fn hostname() -> String {
    #[cfg(unix)]
    let raw = nix::unistd::gethostname().map(|h| h.to_string_lossy().into_owned()).unwrap_or_default();
    #[cfg(not(unix))]
    let raw = std::env::var("COMPUTERNAME").unwrap_or_default();
    let clean: String = raw.chars().filter(|c| !c.is_control()).take(128).collect();
    if clean.is_empty() {
        "unknown".into()
    } else {
        clean
    }
}

fn seed_from_hex(s: &str) -> Result<[u8; 32]> {
    let b: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2).unwrap_or("zz"), 16))
        .collect::<Result<_, _>>()
        .context("bad identity seed")?;
    b.try_into().map_err(|_| anyhow::anyhow!("bad identity seed length"))
}

/// Join as a new runner participant; returns `(keypair, token)`.
async fn join(
    http: &reqwest::Client,
    invite: &Invite,
    args: &JoinArgs,
    backend: &Backend,
) -> Result<(Keypair, String)> {
    let kp = Keypair::generate();
    let sid = &invite.session_id;
    let cert = issue_cert(&invite.role_keypair(), sid, Role::Runner, kp.public(), now_ms())?;
    let j = sign_join(
        &kp,
        JoinRequest {
            v: 1,
            session_id: sid.clone(),
            cert,
            display_name: args.name.clone(),
            description: args
                .description
                .as_deref()
                .map(str::trim)
                .filter(|d| !d.is_empty())
                .map(String::from),
            kind: ClientKind::Runner,
            runner: Some(RunnerInfo {
                name: args.name.clone(),
                labels: args.labels.clone(),
                host: hostname(),
                sandbox: backend.kind(),
                network_unblocked: backend.network_unblocked(),
            }),
            created_at_ms: now_ms(),
        },
    )?;
    let token = client::join(http, &invite.base_url, sid, String::from_utf8(canonical_json(&j)?)?).await?;
    Ok((kp, token))
}

pub async fn run(args: JoinArgs) -> Result<()> {
    for t in std::iter::once(&args.name).chain(&args.labels) {
        if !is_runner_token(t) {
            bail!("{t:?} is not a valid runner name or label: use [a-z0-9][a-z0-9._-]{{0,62}}");
        }
    }
    let http = client::http()?;
    let link = match (&args.code, &args.invite) {
        (Some(code), _) => client::receive_code(&http, &args.relay, code).await?,
        (None, Some(link)) => link.clone(),
        (None, None) => bail!("pass --invite or --code"),
    };
    let invite = Invite::parse(&link).context("not a valid invite link")?;
    if invite.role != Role::Runner {
        bail!("this is a {} invite; runners need the runner invite", invite.role.as_str());
    }
    let sid = invite.session_id.clone();
    let root = args.cache_dir.clone().unwrap_or_else(default_cache_root);
    let dir = root.join(&sid);
    // Rejoin as the same participant if this cache has an identity for this name.
    let id_path = dir.join(format!("identity-runner-{}.json", args.name));
    let saved: Option<Identity> = std::fs::read(&id_path).ok().and_then(|b| serde_json::from_slice(&b).ok());
    let base = invite.base_url.trim_end_matches('/').to_string();
    // The saved token belongs to the relay that issued it. An invite with
    // this session's keys but another relay (an altered link) must not get
    // it: that relay could take jobs as this approved runner. A token saved
    // before the relay was recorded is not reused at all.
    let saved = match saved {
        Some(i) if i.base_url.as_deref() == Some(base.as_str()) => Some(i),
        Some(Identity { base_url: Some(bound), .. }) => bail!(
            "this runner invite names relay {} but runner {} joined session {sid} on {}; refusing to send its \
             token to another relay (the link may have been altered)",
            crate::client::relay_text(&base),
            args.name,
            crate::client::relay_text(&bound)
        ),
        _ => None,
    };
    let signed = client::get_manifest(&http, &invite.base_url, &sid).await?;
    let manifest = SignedManifest::from_json(&signed)?.manifest;
    invite.check_against(&manifest)?;
    if manifest.mode != Mode::Execute {
        bail!("session {sid} is in relay mode; it has no jobs to run");
    }
    let limits = manifest.job_limits.clone().context("execute session without job limits")?;

    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    // A code works once: keep what it carried so the runner can restart.
    if args.code.is_some() {
        let saved = dir.join("invite-runner.txt");
        if !saved.exists() {
            crate::cli::write_private(&saved, &link)?;
        }
        eprintln!(
            "Saved the runner invite to {}. To restart this runner later:\n  AIRLOX_INVITE=\"$(cat {})\" airlox runner join --name {} ...",
            saved.display(),
            saved.display(),
            args.name
        );
    }
    let state_dir = root.join("runner");
    let mut backend = match args.sandbox {
        SandboxArg::Docker => Backend::Docker(Docker::new(
            std::env::var("AIRLOX_DOCKER").unwrap_or_else(|_| "docker".into()),
            args.docker_image.clone(),
            args.docker_cpus.clone(),
            args.docker_runtime.clone(),
            &state_dir,
        )),
        SandboxArg::Local => Backend::Local(Local::new(&state_dir, !args.unsandboxed)),
    };
    // The Linux sandbox maps the runner's own uid into the job: as root, the
    // job could read every root-only file on the host (/etc/shadow, keys).
    #[cfg(unix)]
    if nix::unistd::getuid().is_root() && matches!(args.sandbox, SandboxArg::Local) {
        bail!("refusing to run the local sandbox as root; run the runner as an unprivileged user, or use --sandbox docker");
    }
    // Join before preparing the sandbox, and say how that goes: a runner
    // that cannot start then shows as failed, with why, rather than missing.
    let (kp, token) = match saved {
        Some(i) => (Keypair::from_seed(&seed_from_hex(&i.participant_seed)?), i.token),
        None => join(&http, &invite, &args, &backend).await?,
    };
    let mut relay = Relay::new(http.clone(), &invite.base_url, &sid, &token);
    let (kp, relay) = match relay.report("preparing", None).await {
        Err(e) if status_of(&e) == Some(401) => {
            tracing::info!("saved identity is no longer valid; joining again");
            let (kp, token) = join(&http, &invite, &args, &backend).await?;
            relay = Relay::new(http.clone(), &invite.base_url, &sid, &token);
            save_identity(&id_path, &kp, &token, &base)?;
            relay.report("preparing", None).await?;
            (kp, relay)
        }
        Err(e) => return Err(e),
        Ok(_) => {
            save_identity(&id_path, &kp, &token, &base)?;
            (kp, relay)
        }
    };
    tracing::info!(
        session = %sid, name = %args.name, participant = %kp.public().fingerprint(),
        sandbox = ?backend.kind(), "joined as a runner"
    );
    let spec = RuntimeSpec { runtime: limits.runtime.clone(), packages: limits.packages.clone() };
    if let Err(e) = backend.prepare(&spec).await {
        let _ = relay.report("failed", Some(&failure_detail(&e))).await;
        return Err(e.context("preparing the sandbox"));
    }
    // Unsandboxed (the local backend off Linux): jobs are plain processes.
    let unsandboxed = backend.network_unblocked();
    if unsandboxed {
        tracing::warn!(
            "the local backend cannot sandbox jobs here: they run as plain processes that can read this \
             user's files and reach the network{}; only run code you trust, or use --sandbox docker",
            if limits.network { "" } else { " (this session says network: false)" }
        );
    }
    relay.report("ready", None).await?;

    let view = View::new(relay.clone(), signed, invite.session_key(), kp.public(), dir.clone())?;
    let view = Arc::new(Mutex::new(view));
    // Unsandboxed jobs see their real paths (in tracebacks, os.getcwd()):
    // under the system temp directory those do not name this user or where
    // the runner keeps its cache. Sandboxed jobs see /work.
    let temp_jobs =
        if unsandboxed { Some(tempfile::Builder::new().prefix("airlox-jobs-").tempdir()?) } else { None };
    let jobs_dir = match &temp_jobs {
        Some(t) => t.path().to_path_buf(),
        None => dir.join("jobs"),
    };
    let _ = std::fs::remove_dir_all(&jobs_dir);
    std::fs::create_dir_all(&jobs_dir)?;
    let ctx = Arc::new(Ctx {
        keypair: kp,
        labels: args.labels.clone(),
        backend,
        jobs_dir,
        done_file: dir.join(format!("jobs-done-{}.txt", args.name)),
        memory_cap_mb: args.memory,
        network: limits.network && !args.no_network,
    });
    let outcome = serve(&ctx, &view, &relay, args.max_jobs).await;
    drop(temp_jobs);
    let closed = view.lock().await.closed;
    if closed {
        tracing::info!("the session has ended");
        let _ = std::fs::remove_dir_all(&dir);
    }
    outcome
}

/// A setup error as one short line for the session: the first lines of its
/// chain, whitespace collapsed, within the relay's limit.
fn failure_detail(e: &anyhow::Error) -> String {
    let text = format!("preparing the sandbox: {e:#}");
    let line = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut out: String = line.chars().take(299).collect();
    if out.len() < line.len() {
        out.push('…');
    }
    out
}

fn save_identity(path: &std::path::Path, kp: &Keypair, token: &str, base_url: &str) -> Result<()> {
    let seed: String = kp.seed().iter().map(|b| format!("{b:02x}")).collect();
    let id =
        Identity { participant_seed: seed, token: token.to_string(), base_url: Some(base_url.to_string()) };
    write_atomic(path, &serde_json::to_vec(&id)?, 0o600)
}

struct Running {
    id: String,
    cancel: watch::Sender<bool>,
    task: JoinHandle<Result<()>>,
}

/// What the assignment stream tells the loop.
enum Msg {
    Assigned(String),
    Cancel(String),
    Rejected,
    /// The relay no longer has the session.
    Gone,
    /// The relay no longer accepts this runner's token.
    Unauthorized,
}

/// Hold the assignment stream open, reconnecting with backoff, and forward
/// its events. Runs apart from the main loop so reconnects never delay a
/// claim or a heartbeat.
async fn stream_assignments(relay: Relay, tx: tokio::sync::mpsc::Sender<Msg>) {
    let mut backoff = Duration::from_millis(500);
    loop {
        let resp = match relay.runner_stream().await {
            Ok(r) => r,
            Err(e) => {
                let terminal = match status_of(&e) {
                    Some(401) => Some(Msg::Unauthorized),
                    Some(404 | 410) => Some(Msg::Gone),
                    _ => None,
                };
                if let Some(m) = terminal {
                    let _ = tx.send(m).await;
                    return;
                }
                tracing::warn!("assignment stream unavailable, retrying: {e:#}");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(30));
                continue;
            }
        };
        backoff = Duration::from_millis(500);
        let mut body = resp.bytes_stream();
        let mut parser = SseParser::default();
        while let Some(Ok(chunk)) = body.next().await {
            for ev in parser.push(&chunk) {
                let data: Value = serde_json::from_str(&ev.data).unwrap_or(Value::Null);
                let job = data["job"].as_str().unwrap_or_default().to_string();
                let msg = match ev.event.as_str() {
                    "job_assigned" => Msg::Assigned(job),
                    "job_cancel" => Msg::Cancel(job),
                    "rejected" => Msg::Rejected,
                    _ => continue,
                };
                if tx.send(msg).await.is_err() {
                    return;
                }
            }
        }
        // Ended: the relay restarted, the session closed, or we fell behind.
        tokio::time::sleep(backoff).await;
    }
}

/// Heartbeat every 10 s with the current job, whatever the stream is doing.
/// Ends (and says so) once the relay refuses the token.
async fn heartbeats(relay: Relay, current: Arc<std::sync::Mutex<Option<String>>>, lost: watch::Sender<bool>) {
    let mut tick = tokio::time::interval(HEARTBEAT);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let job = current.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if let Err(e) = relay.heartbeat(job.as_deref()).await {
            if status_of(&e) == Some(401) {
                let _ = lost.send(true);
                return;
            }
            tracing::warn!("heartbeat failed: {e:#}");
        }
    }
}

/// The assignment loop. Returns when the session ends, the runner is
/// rejected, or on Ctrl-C.
async fn serve(
    ctx: &Arc<Ctx>,
    view: &Arc<Mutex<View>>,
    relay: &Relay,
    max_jobs: Option<usize>,
) -> Result<()> {
    view.lock().await.sync().await?;
    if !view.lock().await.approved {
        tracing::info!("waiting for the owner's approval");
    }
    let current_id = Arc::new(std::sync::Mutex::new(None::<String>));
    let (lost_tx, mut lost) = watch::channel(false);
    let hb = tokio::spawn(heartbeats(relay.clone(), current_id.clone(), lost_tx));
    let (tx, mut rx) = tokio::sync::mpsc::channel(64);
    let streamer = tokio::spawn(stream_assignments(relay.clone(), tx));
    let mut current: Option<Running> = None;
    // An assignment that arrived while the previous job was still finishing.
    let mut pending: Option<String> = None;
    let mut syncing: Option<JoinHandle<()>> = None;
    let mut handled = 0usize;
    let mut tick = tokio::time::interval(HEARTBEAT);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Ctrl-C, or SIGTERM from `kill` or a service manager: stop cleanly, so
    // the running job is cancelled and its files are removed.
    let stop = async {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            match signal(SignalKind::terminate()) {
                Ok(mut term) => tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                },
                Err(_) => {
                    let _ = tokio::signal::ctrl_c().await;
                }
            }
        }
        #[cfg(not(unix))]
        let _ = tokio::signal::ctrl_c().await;
    };
    tokio::pin!(stop);

    let start = async |job: String| -> Option<Running> {
        match relay.claim(&job).await {
            Ok(true) => {
                tracing::info!(job = %job, "claimed");
                *current_id.lock().unwrap_or_else(|e| e.into_inner()) = Some(job.clone());
                let (tx, rx) = watch::channel(false);
                let task = tokio::spawn(job::handle(ctx.clone(), view.clone(), job.clone(), rx));
                Some(Running { id: job, cancel: tx, task })
            }
            Ok(false) => {
                tracing::info!(job = %job, "assignment withdrawn before claim");
                None
            }
            Err(e) => {
                // The relay fails it as unclaimed; keep serving.
                tracing::warn!(job = %job, "claim failed: {e:#}");
                None
            }
        }
    };

    let result = loop {
        let done = async {
            match current.as_mut() {
                Some(r) => Some((&mut r.task).await),
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            msg = rx.recv() => match msg {
                Some(Msg::Assigned(job)) => {
                    if current.as_ref().is_some_and(|c| c.id == job) {
                        continue; // a repeat after reconnecting
                    }
                    if current.is_some() {
                        pending = Some(job);
                    } else {
                        current = start(job).await;
                    }
                }
                Some(Msg::Cancel(job)) => {
                    if let Some(r) = current.as_ref().filter(|r| r.id == job) {
                        tracing::info!(job = %job, "cancel requested");
                        let _ = r.cancel.send(true);
                    }
                    if pending.as_deref() == Some(job.as_str()) {
                        pending = None;
                    }
                }
                Some(Msg::Rejected) => break Err(anyhow::anyhow!("the owner rejected this runner")),
                Some(Msg::Unauthorized) => {
                    break Err(anyhow::anyhow!("the relay no longer accepts this runner (rejected, revoked or left)"))
                }
                Some(Msg::Gone) | None => {
                    view.lock().await.closed = true;
                    break Ok(());
                }
            },
            Some(r) = done => {
                let id = current.take().map(|c| c.id).unwrap_or_default();
                *current_id.lock().unwrap_or_else(|e| e.into_inner()) = None;
                match r {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => tracing::error!(job = %id, "job failed: {e:#}"),
                    Err(e) => tracing::error!(job = %id, "job task panicked: {e}"),
                }
                handled += 1;
                let _ = relay.heartbeat(None).await;
                if max_jobs.is_some_and(|m| handled >= m) {
                    break Ok(());
                }
                if let Some(job) = pending.take() {
                    current = start(job).await;
                }
            }
            _ = tick.tick() => {
                // Catch up on approvals and closure between jobs, off the loop.
                if current.is_none() && syncing.as_ref().is_none_or(|t| t.is_finished()) {
                    let v = view.clone();
                    syncing = Some(tokio::spawn(async move {
                        if let Err(e) = v.lock().await.sync().await {
                            tracing::warn!("sync failed: {e:#}");
                        }
                    }));
                }
                if let Ok(v) = view.try_lock() {
                    if v.closed {
                        break Ok(());
                    }
                    if v.rejected {
                        break Err(anyhow::anyhow!("the owner rejected this runner"));
                    }
                }
            }
            _ = lost.changed() => {
                break Err(anyhow::anyhow!("the relay no longer accepts this runner"));
            }
            _ = &mut stop => {
                tracing::info!("interrupted");
                break Ok(());
            }
        }
    };
    streamer.abort();
    if let Some(r) = current.take() {
        let _ = r.cancel.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(20), r.task).await;
    }
    hb.abort();
    if let Some(t) = syncing {
        t.abort();
    }
    result
}
