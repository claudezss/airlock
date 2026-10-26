//! `airlock runner join`: join a session as a runner and run its jobs.
//!
//! One job at a time. The loop holds the assignment stream open, claims each
//! assignment at once, sends a heartbeat (and catches up on session events)
//! every 10 seconds, and forwards cancels to the running job.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use airlock_core::cert::{is_runner_token, issue_cert, sign_join, ClientKind, JoinRequest, RunnerInfo};
use airlock_core::encoding::canonical_json;
use airlock_core::invite::Invite;
use airlock_core::keys::Keypair;
use airlock_core::session::{Mode, Role, SignedManifest};
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
pub struct JoinArgs {
    /// The runner invite link (or set AIRLOCK_INVITE).
    #[arg(long, env = "AIRLOCK_INVITE", hide_env_values = true)]
    pub invite: String,
    /// This runner's name, shown to senders: [a-z0-9][a-z0-9._-]{0,62}.
    #[arg(long)]
    pub name: String,
    /// Labels senders can target, comma-separated.
    #[arg(long, value_delimiter = ',')]
    pub labels: Vec<String>,
    #[arg(long, value_enum, default_value = "docker")]
    pub sandbox: SandboxArg,
    /// Keep jobs off the network even if the session allows it.
    #[arg(long)]
    pub no_network: bool,
    /// Cap job memory (MB) below the session's limit.
    #[arg(long)]
    pub memory: Option<u32>,
    /// Session cache and runtime directory (default: ~/.cache/airlock).
    #[arg(long, env = "AIRLOCK_CACHE_DIR")]
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
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

pub fn default_cache_root() -> PathBuf {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .unwrap_or_else(std::env::temp_dir);
    base.join("airlock")
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
    let invite = Invite::parse(&args.invite).context("not a valid invite link")?;
    if invite.role != Role::Runner {
        bail!("this is a {} invite; runners need the runner invite", invite.role.as_str());
    }
    let sid = invite.session_id.clone();
    let http = client::http()?;
    let signed = client::get_manifest(&http, &invite.base_url, &sid).await?;
    let manifest = SignedManifest::from_json(&signed)?.manifest;
    invite.check_against(&manifest)?;
    if manifest.mode != Mode::Execute {
        bail!("session {sid} is in relay mode; it has no jobs to run");
    }
    let limits = manifest.job_limits.clone().context("execute session without job limits")?;

    let root = args.cache_dir.clone().unwrap_or_else(default_cache_root);
    let dir = root.join(&sid);
    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let state_dir = root.join("runner");
    let mut backend = match args.sandbox {
        SandboxArg::Docker => Backend::Docker(Docker::new(
            std::env::var("AIRLOCK_DOCKER").unwrap_or_else(|_| "docker".into()),
            args.docker_image.clone(),
            args.docker_cpus.clone(),
            args.docker_runtime.clone(),
            &state_dir,
        )),
        SandboxArg::Local => Backend::Local(Local::new(&state_dir, !args.unsandboxed)),
    };
    let spec = RuntimeSpec { runtime: limits.runtime.clone(), packages: limits.packages.clone() };
    backend.prepare(&spec).await.context("preparing the sandbox")?;
    if backend.network_unblocked() && !limits.network {
        tracing::warn!(
            "the local backend cannot block network access here, but this session says network: false; \
             only run code you trust, or use --sandbox docker"
        );
    }

    // Rejoin as the same participant if this cache has an identity for this name.
    let id_path = dir.join(format!("identity-runner-{}.json", args.name));
    let saved: Option<Identity> = std::fs::read(&id_path).ok().and_then(|b| serde_json::from_slice(&b).ok());
    let (kp, token) = match saved {
        Some(i) => (Keypair::from_seed(&seed_from_hex(&i.participant_seed)?), i.token),
        None => join(&http, &invite, &args, &backend).await?,
    };
    let mut relay = Relay::new(http.clone(), &invite.base_url, &sid, &token);
    let (kp, relay) = match relay.heartbeat(None).await {
        Err(e) if status_of(&e) == Some(401) => {
            tracing::info!("saved identity is no longer valid; joining again");
            let (kp, token) = join(&http, &invite, &args, &backend).await?;
            relay = Relay::new(http.clone(), &invite.base_url, &sid, &token);
            save_identity(&id_path, &kp, &token)?;
            (kp, relay)
        }
        Err(e) => return Err(e),
        Ok(_) => {
            save_identity(&id_path, &kp, &token)?;
            (kp, relay)
        }
    };
    tracing::info!(
        session = %sid, name = %args.name, participant = %kp.public().fingerprint(),
        sandbox = ?backend.kind(), "joined as a runner"
    );

    let view = View::new(relay.clone(), signed, invite.session_key(), kp.public(), dir.clone())?;
    let view = Arc::new(Mutex::new(view));
    let jobs_dir = dir.join("jobs");
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
    let closed = view.lock().await.closed;
    if closed {
        tracing::info!("the session has ended");
        let _ = std::fs::remove_dir_all(&dir);
    }
    outcome
}

fn save_identity(path: &std::path::Path, kp: &Keypair, token: &str) -> Result<()> {
    let seed: String = kp.seed().iter().map(|b| format!("{b:02x}")).collect();
    let id = Identity { participant_seed: seed, token: token.to_string() };
    write_atomic(path, &serde_json::to_vec(&id)?, 0o600)
}

struct Running {
    id: String,
    cancel: watch::Sender<bool>,
    task: JoinHandle<Result<()>>,
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
    let mut current: Option<Running> = None;
    let mut handled = 0usize;
    let mut tick = tokio::time::interval(HEARTBEAT);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut backoff = Duration::from_millis(500);
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    let result = 'outer: loop {
        let resp = match relay.runner_stream().await {
            Ok(r) => r,
            Err(e) => match status_of(&e) {
                Some(401) => {
                    break Err(anyhow::anyhow!("the relay no longer accepts this runner (rejected or left)"))
                }
                Some(404 | 410) => break Ok(()),
                _ => {
                    tracing::warn!("assignment stream unavailable, retrying: {e:#}");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                    continue;
                }
            },
        };
        backoff = Duration::from_millis(500);
        if !view.lock().await.approved {
            tracing::info!("waiting for the owner's approval");
        }
        let mut body = resp.bytes_stream();
        let mut parser = SseParser::default();
        loop {
            let done = async {
                match current.as_mut() {
                    Some(r) => Some((&mut r.task).await),
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                chunk = body.next() => {
                    let Some(Ok(chunk)) = chunk else { break };
                    for ev in parser.push(&chunk) {
                        let data: Value = serde_json::from_str(&ev.data).unwrap_or(Value::Null);
                        let job = data["job"].as_str().unwrap_or_default().to_string();
                        match ev.event.as_str() {
                            "job_assigned" if current.is_none() => {
                                if !relay.claim(&job).await? {
                                    tracing::info!(job = %job, "assignment withdrawn before claim");
                                    continue;
                                }
                                tracing::info!(job = %job, "claimed");
                                let (tx, rx) = watch::channel(false);
                                let task = tokio::spawn(job::handle(ctx.clone(), view.clone(), job.clone(), rx));
                                current = Some(Running { id: job, cancel: tx, task });
                            }
                            "job_assigned" => {}
                            "job_cancel" => {
                                if let Some(r) = current.as_ref().filter(|r| r.id == job) {
                                    tracing::info!(job = %job, "cancel requested");
                                    let _ = r.cancel.send(true);
                                }
                            }
                            "rejected" => break 'outer Err(anyhow::anyhow!("the owner rejected this runner")),
                            _ => {}
                        }
                    }
                }
                Some(r) = done => {
                    let id = current.take().map(|c| c.id).unwrap_or_default();
                    match r {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => tracing::error!(job = %id, "job failed: {e:#}"),
                        Err(e) => tracing::error!(job = %id, "job task panicked: {e}"),
                    }
                    handled += 1;
                    let _ = relay.heartbeat(None).await;
                    if max_jobs.is_some_and(|m| handled >= m) {
                        break 'outer Ok(());
                    }
                }
                _ = tick.tick() => {
                    let job = current.as_ref().map(|c| c.id.clone());
                    if let Err(e) = relay.heartbeat(job.as_deref()).await {
                        if status_of(&e) == Some(401) {
                            break 'outer Err(anyhow::anyhow!("the relay no longer accepts this runner"));
                        }
                        tracing::warn!("heartbeat failed: {e:#}");
                    }
                    // Catch up on approvals, cancels and closure between jobs.
                    if current.is_none() {
                        let mut v = view.lock().await;
                        if let Err(e) = v.sync().await {
                            tracing::warn!("sync failed: {e:#}");
                        }
                        if v.closed {
                            break 'outer Ok(());
                        }
                        if v.rejected {
                            break 'outer Err(anyhow::anyhow!("the owner rejected this runner"));
                        }
                    }
                }
                _ = &mut ctrl_c => {
                    tracing::info!("interrupted");
                    break 'outer Ok(());
                }
            }
        }
        // The stream ended: the session may have closed, or the relay restarted.
        let mut v = view.lock().await;
        let _ = v.sync().await;
        if v.closed {
            break Ok(());
        }
        drop(v);
        tokio::time::sleep(backoff).await;
    };
    if let Some(r) = current.take() {
        let _ = r.cancel.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(20), r.task).await;
    }
    result
}
