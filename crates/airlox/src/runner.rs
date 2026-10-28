//! `airlox runner join`: join a session as a runner and run its jobs.
//!
//! One job at a time. The loop holds the assignment stream open, claims each
//! assignment at once, sends a heartbeat (and catches up on session events)
//! every 10 seconds, and forwards cancels to the running job. A dropped
//! connection does not stop a running job: the stream and heartbeats
//! reconnect with backoff, and the result is posted once the relay answers.

use std::path::PathBuf;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use airlox_core::cert::{is_runner_token, issue_cert, sign_join, ClientKind, JoinRequest, RunnerInfo};
use airlox_core::encoding::canonical_json;
use airlox_core::invite::Invite;
use airlox_core::keys::Keypair;
use airlox_core::payload::JobKind;
use airlox_core::session::{Mode, Role, SignedManifest};
use anyhow::{bail, Context, Result};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;

use crate::client::{self, status_of, Relay};
use crate::job::{self, Ctx, Workspaces};
use crate::sandbox::local::{probe_python, Local, LocalOpts};
use crate::sandbox::{docker::Docker, Backend, RuntimeSpec};
use crate::sse::SseParser;
use crate::view::{write_atomic, View};

pub const HEARTBEAT: Duration = Duration::from_secs(10);

/// Where `--code` is claimed when no relay is named.
pub const DEFAULT_RELAY: &str = "https://airlox.app";

/// Set to `true` to stop the runner the way Ctrl-C does (the running job is
/// cancelled and its files removed): the Windows service's stop control.
pub static SHUTDOWN: LazyLock<watch::Sender<bool>> = LazyLock::new(|| watch::channel(false).0);

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum SandboxArg {
    /// uv runtime; namespaces and Landlock on Linux, a plain process elsewhere.
    Local,
    /// A container per job.
    Docker,
    /// A plain process with the --python interpreter (or a uv runtime); on
    /// Windows each job runs in a Job Object. No network isolation.
    Process,
}

/// The shell that runs shell jobs on a Windows runner.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum ShellArg {
    /// PowerShell 7 (`pwsh -NoProfile -Command`).
    Pwsh,
}

#[derive(clap::Args, Debug)]
#[command(group(
    clap::ArgGroup::new("source").args(["invite", "code", "invite_file"]).required(true).multiple(true)
))]
pub struct JoinArgs {
    /// The runner invite link (or set AIRLOX_INVITE).
    #[arg(long, env = "AIRLOX_INVITE", hide_env_values = true)]
    pub invite: Option<String>,
    /// Read the runner invite link from this file instead: nothing secret on
    /// the command line or in the environment. Keep the file readable only
    /// by the user the runner runs as.
    #[arg(long, conflicts_with = "code")]
    pub invite_file: Option<PathBuf>,
    /// A one-time transfer code for the runner invite, like 7-guitar-orbit,
    /// instead of --invite. The invite is saved for restarts.
    #[arg(long)]
    pub code: Option<String>,
    /// The relay to talk to: where --code is claimed (default: AIRLOX_RELAY,
    /// else https://airlox.app), and where the runner connects instead of
    /// the host in the invite, such as a port-forward
    /// (http://127.0.0.1:8080): https, http to this machine, or http to the
    /// host the session allows (--insecure-http-host). Only this flag
    /// redirects the runner, never the environment. The session's keys
    /// still come only from the invite.
    #[arg(long)]
    pub relay: Option<String>,
    /// Claim --code over plain http:// to a host other than this machine (a
    /// relay inside a cluster). The code and the invite it carries then
    /// cross that network in the clear: only for a network you trust.
    #[arg(long, requires = "code")]
    pub allow_insecure_http: bool,
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
    /// How jobs are isolated. `process` must be chosen explicitly; nothing
    /// falls back to it.
    #[arg(long, value_enum, default_value = "docker")]
    pub sandbox: SandboxArg,
    /// local, process: run jobs with this interpreter, e.g. an existing
    /// venv's Scripts\python.exe, instead of building one with uv. It must
    /// be the session's Python version and already have every allowlisted
    /// package; the runner never installs anything into it.
    #[arg(long)]
    pub python: Option<PathBuf>,
    /// local, process: also give jobs these variables from the runner's
    /// environment, comma-separated (a license server, say). PATH is
    /// appended to the job's own. AIRLOX_* variables are never passed.
    #[arg(long, value_delimiter = ',')]
    pub pass_env: Vec<String>,
    /// process: run the jobs of a session that says network: false although
    /// this sandbox cannot block network access. Without it such a session
    /// is refused.
    #[arg(long)]
    pub accept_network_gap: bool,
    /// Keep jobs off the network even if the session allows it.
    #[arg(long)]
    pub no_network: bool,
    /// Cap job memory (MB) below the session's limit.
    #[arg(long)]
    pub memory: Option<u32>,
    /// Session cache and runtime directory (default: ~/.cache/airlox).
    #[arg(long, env = "AIRLOX_CACHE_DIR")]
    pub cache_dir: Option<PathBuf>,
    /// Put the jobs' directories under this directory (created if needed),
    /// not the system temporary directory. A job run as a plain process
    /// (--sandbox process, or local off Linux) sees its real paths in
    /// tracebacks and os.getcwd(); on Windows the temporary directory is
    /// under the user's profile (C:\Users\<name>\AppData\Local\Temp), which
    /// names the account. Choose a neutral place such as C:\airlox-work. The
    /// jobs' stdout and stderr also have the job's directories replaced by
    /// $WORK and $AIRLOX_OUT before the result is signed.
    #[arg(long, env = "AIRLOX_WORK_ROOT")]
    pub work_root: Option<PathBuf>,
    /// docker: run jobs in this image instead of building one from the
    /// allowlist. The runner pins it by digest, and offers shell jobs in it.
    /// The image needs python3 (the job shim is a Python script).
    #[arg(long, visible_alias = "image")]
    pub docker_image: Option<String>,
    /// Windows, local or process: also run shell jobs, with this shell.
    /// Without it a Windows runner runs Python jobs only.
    #[arg(long, value_enum)]
    pub shell: Option<ShellArg>,
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
    /// Jobs run at once. Only 1 is supported: while busy, the relay refuses
    /// new jobs for this runner with `runner_busy` instead of queueing them.
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..=1))]
    pub max_jobs: u32,
    /// How often a running job's progress is posted (elapsed time and the
    /// tail of its progress file); 0s for never.
    #[arg(long, default_value = "60s", value_parser = crate::cli::parse_duration)]
    pub progress_interval: Duration,
    /// Most bytes of a job's progress file sent each time.
    #[arg(long, default_value_t = 4096, value_parser = clap::value_parser!(u32).range(0..=32768))]
    pub progress_tail: u32,
    /// Most output chunks posted per minute while a job runs; more output
    /// waits and goes out together. 0 turns streaming off.
    #[arg(long, default_value_t = 120)]
    pub progress_rate: u32,
    /// Most output streamed per job, stdout and stderr together; the signed
    /// result still carries the output.
    #[arg(long, default_value_t = 16, value_name = "MB")]
    pub stream_max_mb: u64,
    /// Keep a work directory for each sender between their jobs, in sessions
    /// that allow it: a working tree is synced into it, and dependencies and
    /// build caches survive from one job to the next. Under
    /// <cache-dir>/workspaces.
    #[arg(long)]
    pub workspace: bool,
    /// A workspace over this size (MB) after a job refuses its sender's next
    /// job (`workspace_full`) until that job asks for a fresh one.
    #[arg(long, default_value_t = 10240, value_name = "MB")]
    pub workspace_max_mb: u64,
    /// Remove workspaces unused for this long.
    #[arg(long, default_value = "14d", value_parser = crate::cli::parse_duration)]
    pub workspace_ttl: Duration,
    /// Exit after this many jobs (for tests and one-shot use).
    #[arg(long, hide = true)]
    pub exit_after: Option<usize>,
    /// Exit with status 3 once a job's answer is saved, before posting it
    /// (for tests of delivery after a restart).
    #[arg(long, hide = true)]
    pub exit_before_posting: bool,
    /// Run under the Windows service manager as this service (set by
    /// `airlox runner service install`).
    #[arg(long, hide = true)]
    pub windows_service: Option<String>,
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
    base_url: &str,
    invite: &Invite,
    args: &JoinArgs,
    backend: &Backend,
    python: Option<&str>,
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
                version: Some(env!("CARGO_PKG_VERSION").to_string()),
                python: python.map(String::from),
            }),
            created_at_ms: now_ms(),
        },
    )?;
    let token = client::join(http, base_url, sid, String::from_utf8(canonical_json(&j)?)?).await?;
    Ok((kp, token))
}

fn private_dir(dir: &std::path::Path) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Keep an invite received with a code at `<session dir>/invite-<role>.txt`
/// (mode 0600), replacing an older one.
fn save_invite(dir: &std::path::Path, invite: &Invite, link: &str) -> Result<PathBuf> {
    private_dir(dir)?;
    let path = dir.join(format!("invite-{}.txt", invite.role.as_str()));
    if std::fs::read_to_string(&path).is_ok_and(|s| s.trim() == link) {
        return Ok(path);
    }
    let _ = std::fs::remove_file(&path);
    crate::cli::write_private(&path, link)?;
    Ok(path)
}

impl JoinArgs {
    fn image(&self) -> Option<&String> {
        self.docker_image.as_ref()
    }
}

/// Flags that only make sense with some sandboxes, and environment names a
/// job must never get.
fn check_args(args: &JoinArgs) -> Result<()> {
    for t in std::iter::once(&args.name).chain(&args.labels) {
        if !is_runner_token(t) {
            bail!("{t:?} is not a valid runner name or label: use [a-z0-9][a-z0-9._-]{{0,62}}");
        }
    }
    let docker = args.sandbox == SandboxArg::Docker;
    if docker && (args.python.is_some() || !args.pass_env.is_empty()) {
        bail!("--python and --pass-env are for --sandbox local or process");
    }
    if args.sandbox == SandboxArg::Local
        && !args.unsandboxed
        && cfg!(target_os = "linux")
        && !args.pass_env.is_empty()
    {
        bail!("--pass-env does not reach jobs in the Linux sandbox; use --sandbox process or --unsandboxed");
    }
    if args.shell.is_some() && (docker || !cfg!(windows)) {
        bail!(
            "--shell is for --sandbox local or process on Windows; shell jobs run under sh everywhere else \
             (docker needs --image)"
        );
    }
    if args.image().is_some() && !docker {
        bail!("--image is for --sandbox docker");
    }
    if !args.workspace && (args.workspace_max_mb != 10240 || args.workspace_ttl != Duration::from_secs(14 * 86400)) {
        bail!("--workspace-max-mb and --workspace-ttl are for runners started with --workspace");
    }
    if args.accept_network_gap && args.sandbox != SandboxArg::Process {
        bail!("--accept-network-gap is for --sandbox process");
    }
    for name in &args.pass_env {
        let ok = !name.is_empty()
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            && !name.to_ascii_uppercase().starts_with("AIRLOX_");
        if !ok {
            bail!("--pass-env {name:?}: use variable names of [A-Za-z0-9_]; AIRLOX_* variables are never passed");
        }
    }
    Ok(())
}

/// Text from a file a Windows tool may have written: UTF-8 with or without
/// a byte-order mark, or UTF-16 (PowerShell 5's `>` writes little-endian
/// with a mark; a file with no mark is taken as UTF-16 when its first
/// character is ASCII, whose other byte is then zero).
fn decode_text(bytes: &[u8]) -> Result<String> {
    let utf16 = |b: &[u8], le: bool| {
        if b.len() % 2 != 0 {
            bail!("a UTF-16 file has an odd number of bytes; it was cut short");
        }
        let units = b.chunks_exact(2).map(|c| {
            if le {
                u16::from_le_bytes([c[0], c[1]])
            } else {
                u16::from_be_bytes([c[0], c[1]])
            }
        });
        String::from_utf16(&units.collect::<Vec<_>>()).map_err(anyhow::Error::from)
    };
    let text = match bytes {
        [0xFF, 0xFE, rest @ ..] => utf16(rest, true)?,
        [0xFE, 0xFF, rest @ ..] => utf16(rest, false)?,
        [0xEF, 0xBB, 0xBF, rest @ ..] => String::from_utf8(rest.to_vec())?,
        [a, 0, ..] if *a != 0 => utf16(bytes, true)?,
        [0, b, ..] if *b != 0 => utf16(bytes, false)?,
        _ => String::from_utf8(bytes.to_vec())?,
    };
    // A second mark (a file converted twice) is not part of the text either.
    Ok(text.trim_start_matches('\u{feff}').to_string())
}

/// The runner invite link in a file, however a Windows tool wrote it.
fn read_invite_file(path: &std::path::Path) -> Result<String> {
    let bytes =
        std::fs::read(path).with_context(|| format!("could not read the invite file {}", path.display()))?;
    let text = decode_text(&bytes)
        .with_context(|| format!("the invite file {} is not text", path.display()))?
        .trim()
        .to_string();
    if text.is_empty() {
        bail!("the invite file {} is empty", path.display());
    }
    Ok(text)
}

/// The invite link, from wherever the operator put it.
pub(crate) async fn invite_link(
    http: &reqwest::Client,
    args: &JoinArgs,
    root: &std::path::Path,
) -> Result<String> {
    if let Some(path) = &args.invite_file {
        if args.invite.is_some() {
            eprintln!("note: using --invite-file; ignoring the invite from --invite or AIRLOX_INVITE");
        }
        return read_invite_file(path);
    }
    match (&args.code, &args.invite) {
        (Some(code), invite) => {
            if invite.is_some() {
                eprintln!("note: using --code; ignoring the invite from --invite or AIRLOX_INVITE");
            }
            let env = std::env::var("AIRLOX_RELAY").ok().filter(|r| !r.is_empty());
            let relay = args.relay.clone().or(env).unwrap_or_else(|| DEFAULT_RELAY.into());
            client::receive_code(http, &relay, code, args.allow_insecure_http).await.map_err(|e| {
                anyhow::anyhow!(
                    "{e:#}\nA code works once. If this runner already used it, restart it with the invite it saved:\n  \
                     airlox runner join --invite-file '{}' --name {} ...",
                    root.join("<session>").join("invite-runner.txt").display(),
                    args.name
                )
            })
        }
        (None, Some(link)) => Ok(link.clone()),
        (None, None) => bail!("pass --invite, --invite-file or --code"),
    }
}

pub async fn run(args: JoinArgs) -> Result<()> {
    check_args(&args)?;
    let http = client::http()?;
    let root = args.cache_dir.clone().unwrap_or_else(default_cache_root);
    let link = invite_link(&http, &args, &root).await?;
    let invite = Invite::parse(&link).context("not a valid invite link")?;
    let sid = invite.session_id.clone();
    let dir = root.join(&sid);
    // A code works once: save what it carried before anything else can fail,
    // so neither a failed start nor a restart needs a new code.
    if args.code.is_some() {
        let saved = save_invite(&dir, &invite, &link)?;
        let quoted = format!("'{}'", saved.display().to_string().replace('\'', r"'\''"));
        eprintln!("Saved the {} invite to {quoted}.", invite.role.as_str());
        if invite.role == Role::Runner {
            eprintln!(
                "To restart this runner later:\n  airlox runner join --invite-file {quoted} --name {} ...",
                args.name
            );
        }
    }
    if invite.role != Role::Runner {
        bail!("this is a {} invite; runners need the runner invite", invite.role.as_str());
    }
    // Rejoin as the same participant if this cache has an identity for this name.
    let id_path = dir.join(format!("identity-runner-{}.json", args.name));
    let saved: Option<Identity> = std::fs::read(&id_path).ok().and_then(|b| serde_json::from_slice(&b).ok());
    let base = invite.base_url.trim_end_matches('/').to_string();
    // Where requests go: the invite's relay, or the operator's route to it.
    // The identity stays bound to the invite's relay either way.
    let url = match args.relay.as_deref() {
        Some(r) if r.trim_end_matches('/') != base => {
            let r = r.trim_end_matches('/').to_string();
            // Plain http to another machine waits for the manifest, below:
            // only fetching it (it names nothing secret) goes there first.
            if let Err(e) = airlox_core::invite::check_transport(&r, None) {
                if !r.starts_with("http://") {
                    bail!("--relay {r}: {e}");
                }
            }
            tracing::info!(relay = %r, invite_relay = %base, "connecting through the given relay URL");
            r
        }
        _ => base.clone(),
    };
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
    let signed = client::get_manifest(&http, &url, &sid).await?;
    let manifest = SignedManifest::from_json(&signed)?.manifest;
    invite.check_against(&manifest)?;
    if url != base {
        airlox_core::invite::check_transport(&url, manifest.insecure_http_host.as_deref())
            .with_context(|| format!("--relay {url}"))?;
    }
    if manifest.mode != Mode::Execute {
        bail!("session {sid} is in relay mode; it has no jobs to run");
    }
    let limits = manifest.job_limits.clone().context("execute session without job limits")?;

    private_dir(&dir)?;
    let state_dir = root.join("runner");
    let mut backend = match args.sandbox {
        SandboxArg::Docker => Backend::Docker(Docker::new(
            std::env::var("AIRLOX_DOCKER").unwrap_or_else(|_| "docker".into()),
            args.docker_image.clone(),
            args.docker_cpus.clone(),
            args.docker_runtime.clone(),
            &state_dir,
        )),
        SandboxArg::Local | SandboxArg::Process => Backend::Local(Local::new(
            &state_dir,
            LocalOpts {
                sandboxed: !args.unsandboxed,
                process: args.sandbox == SandboxArg::Process,
                python: args.python.clone(),
                pass_env: args.pass_env.clone(),
                pwsh: match args.shell {
                    Some(ShellArg::Pwsh) => Some(crate::sandbox::local::which("pwsh").context(
                        "--shell pwsh: pwsh was not found on PATH; install PowerShell 7 (https://aka.ms/powershell)",
                    )?),
                    None => None,
                },
            },
        )),
    };
    // The Linux sandbox maps the runner's own uid into the job: as root, the
    // job could read every root-only file on the host (/etc/shadow, keys).
    #[cfg(unix)]
    if nix::unistd::getuid().is_root() && args.sandbox != SandboxArg::Docker {
        bail!("refusing to run the local sandbox as root; run the runner as an unprivileged user, or use --sandbox docker");
    }
    // Process-sandbox jobs run as the runner's own user: an administrator's
    // or SYSTEM's rights would be theirs too. (`local` off Linux is the
    // development mode for trusted code, and says so when it starts.)
    #[cfg(windows)]
    if args.sandbox == SandboxArg::Process {
        if let Some(who) = crate::sandbox::winjob::privileged() {
            bail!(
                "refusing to run jobs as {who}: they would get the same rights. Run the runner as an ordinary \
                 user (`airlox runner service install` runs it as its own virtual account)"
            );
        }
    }
    // The interpreter's version is part of the join; a bad --python shows
    // up below as a failed setup, with why.
    let python = match &args.python {
        Some(p) => probe_python(p, &[], &args.pass_env).await.ok().map(|i| i.version),
        None => None,
    };
    // Join before preparing the sandbox, and say how that goes: a runner
    // that cannot start then shows as failed, with why, rather than missing.
    let (kp, token) = match saved {
        Some(i) => (Keypair::from_seed(&seed_from_hex(&i.participant_seed)?), i.token),
        None => join(&http, &url, &invite, &args, &backend, python.as_deref()).await?,
    };
    // A job this runner started before it last stopped and still owes an
    // answer for: named in the setup heartbeats, so the relay keeps it
    // running until the answer arrives (runners take one job at a time).
    let done_file = dir.join(format!("jobs-done-{}.txt", args.name));
    let owed = job::unanswered(&done_file).pop();
    let owed = owed.as_deref();
    let mut relay = Relay::new(http.clone(), &url, &sid, &token);
    let (kp, relay) = match relay.report("preparing", None, owed).await {
        Err(e) if status_of(&e) == Some(401) => {
            tracing::info!("saved identity is no longer valid; joining again");
            let (kp, token) = join(&http, &url, &invite, &args, &backend, python.as_deref()).await?;
            relay = Relay::new(http.clone(), &url, &sid, &token);
            save_identity(&id_path, &kp, &token, &base)?;
            relay.report("preparing", None, owed).await?;
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
    let view = View::new(relay.clone(), signed, invite.session_key(), kp.public(), dir.clone())?;
    let view = Arc::new(Mutex::new(view));
    let outbox = dir.join(format!("outbox-{}", args.name));
    job::deliver_saved(&kp, &done_file, &outbox, &view).await;

    let spec = RuntimeSpec { runtime: limits.runtime.clone(), packages: limits.packages.clone() };
    // A session that keeps jobs off the network cannot have that from the
    // process sandbox, unless the operator accepted the gap.
    let no_network = !limits.network || args.no_network;
    if args.sandbox == SandboxArg::Process && no_network && !args.accept_network_gap {
        let e = anyhow::anyhow!(
            "this session runs jobs without network access, but --sandbox process cannot block it; restart \
             with --accept-network-gap to run them anyway, or use --sandbox docker"
        );
        let _ = relay.report("failed", Some(&failure_detail(&e)), None).await;
        return Err(e);
    }
    if let Err(e) = backend.prepare(&spec).await {
        let _ = relay.report("failed", Some(&failure_detail(&e)), None).await;
        return Err(e.context("preparing the sandbox"));
    }
    // A cap below what importing the allowlist takes fails every job that
    // imports it, with only an out-of-memory notice to say why.
    let cap_mb = limits.memory_mb.min(args.memory.unwrap_or(u32::MAX));
    match backend.import_footprint(&spec, cap_mb).await {
        Some(f) => {
            tracing::info!(peak_mb = f.peak_mb, cap_mb, "memory used by importing the allowlisted packages");
            for m in &f.failed {
                tracing::warn!("`import {m}` failed in the job runtime; jobs that import it will fail too");
            }
            if !f.inferred.is_empty() {
                tracing::info!(
                    "the package metadata does not name the modules of {}; the measurement guessed them and \
                     may be low",
                    f.inferred.join(", ")
                );
            }
            if f.hit_cap || f.peak_mb * 10 >= cap_mb as u64 * 8 {
                let fix = if args.memory.is_some_and(|m| m < limits.memory_mb) {
                    "raise this runner's --memory, or ask the owner for a new session with a larger --job-memory"
                } else {
                    "ask the owner for a new session with a larger --job-memory (the cap is fixed when a \
                     session is created)"
                };
                tracing::warn!(
                    "importing the allowlisted packages alone takes {} of the {cap_mb} MB jobs may use; jobs \
                     that import them will likely run out of memory: {fix}",
                    if f.hit_cap { "more than all".to_string() } else { format!("{} MB", f.peak_mb) }
                );
            }
        }
        None if !limits.packages.is_empty() && args.sandbox != SandboxArg::Process => tracing::info!(
            "the job memory cap is {cap_mb} MB; the runner checks it against what importing the allowlist takes \
             only with --sandbox process"
        ),
        None => {}
    }
    // Unsandboxed (the local backend off Linux, or process mode): jobs are
    // plain processes.
    let unsandboxed = backend.network_unblocked();
    if unsandboxed {
        tracing::warn!(
            "jobs run as plain processes that can read this user's files and reach the network{}; only run \
             code you trust, or use --sandbox docker",
            if no_network { " (this session says network: false)" } else { "" }
        );
    }
    let ctx_env = job::checked_env(backend.env());
    let kinds: Vec<_> = backend.kinds().iter().map(JobKind::as_str).collect();
    tracing::info!(kinds = ?kinds, "this runner runs these kinds of job");
    // A session that wants shell jobs, on a runner that cannot run them:
    // say so where the session can see it, not only in a refusal.
    let offered = limits.allows_kind(JobKind::Shell) && backend.shell().is_none();
    let note = offered.then(|| format!("shell jobs are not offered{}", backend.no_shell_hint()));
    if let Some(n) = &note {
        tracing::warn!("{n}");
    }
    if limits.workspace && !args.workspace {
        tracing::info!("the session allows workspaces; start the runner with --workspace to keep them");
    }
    relay.report("ready", note.as_deref(), owed).await?;

    // Unsandboxed jobs see their real paths (in tracebacks, os.getcwd()):
    // under the system temp directory those do not say where the runner
    // keeps its cache (but on Windows they name the user: --work-root).
    // Sandboxed jobs see /work.
    let work_root = match &args.work_root {
        Some(r) => {
            std::fs::create_dir_all(r)
                .with_context(|| format!("could not create --work-root {}", r.display()))?;
            Some(std::path::absolute(r)?)
        }
        None => None,
    };
    let temp_jobs = if unsandboxed || work_root.is_some() {
        let mut b = tempfile::Builder::new();
        b.prefix("airlox-jobs-");
        Some(match &work_root {
            Some(r) => {
                b.tempdir_in(r).with_context(|| format!("could not use --work-root {}", r.display()))?
            }
            None => b.tempdir()?,
        })
    } else {
        None
    };
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
        done_file,
        memory_cap_mb: args.memory,
        network: limits.network && !args.no_network,
        progress_interval: args.progress_interval,
        progress_tail: args.progress_tail as usize,
        progress_rate: args.progress_rate,
        stream_max_bytes: args.stream_max_mb.saturating_mul(1 << 20),
        workspaces: args
            .workspace
            .then(|| Workspaces::new(&root, args.workspace_max_mb, args.workspace_ttl)),
        outbox,
        exit_before_posting: args.exit_before_posting,
        env: ctx_env,
    });
    job::report_interrupted(&ctx, &view).await;
    // Idle workspaces go at startup and then every hour.
    let sweeper = ctx.workspaces.clone().map(|w| {
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(3600));
            loop {
                tick.tick().await;
                let w = w.clone();
                let _ = tokio::task::spawn_blocking(move || w.sweep()).await;
            }
        })
    });
    let outcome = serve(&ctx, &view, &relay, args.exit_after).await;
    if let Some(s) = sweeper {
        s.abort();
    }
    drop(temp_jobs);
    let closed = view.lock().await.closed;
    if closed {
        tracing::info!("the session has ended");
        let _ = std::fs::remove_dir_all(&dir);
        // And everything kept for its senders.
        if let Some(w) = &ctx.workspaces {
            w.remove_session(&sid);
        }
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

/// Ctrl-C, or SIGTERM on unix. Never resolves if they cannot be watched.
async fn signals() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            tokio::select! {
                r = tokio::signal::ctrl_c() => {
                    if r.is_err() {
                        std::future::pending::<()>().await
                    }
                }
                _ = term.recv() => {}
            }
            return;
        }
    }
    if tokio::signal::ctrl_c().await.is_err() {
        std::future::pending::<()>().await;
    }
}

/// The assignment loop. Returns when the session ends, the runner is
/// rejected, or on Ctrl-C.
async fn serve(
    ctx: &Arc<Ctx>,
    view: &Arc<Mutex<View>>,
    relay: &Relay,
    exit_after: Option<usize>,
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
    // Ctrl-C, SIGTERM from `kill` or a service manager, or the Windows
    // service's stop: stop cleanly, so the running job is cancelled and its
    // files are removed.
    let mut shutdown = SHUTDOWN.subscribe();
    let stop = async move {
        tokio::select! {
            _ = signals() => {}
            _ = shutdown.wait_for(|s| *s) => {}
        }
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
                if exit_after.is_some_and(|m| handled >= m) {
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

#[cfg(test)]
mod tests {
    use super::*;

    const LINK: &str = "https://airlox.example/s#ax_abcdefghijklmnopqrstuvwxyz/AbC-_123=";

    fn utf16(text: &str, le: bool, bom: bool) -> Vec<u8> {
        let mut out = Vec::new();
        if bom {
            out.extend(if le { [0xFF, 0xFE] } else { [0xFE, 0xFF] });
        }
        for u in text.encode_utf16() {
            out.extend(if le { u.to_le_bytes() } else { u.to_be_bytes() });
        }
        out
    }

    fn file(bytes: &[u8]) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("runner-invite.txt");
        std::fs::write(&path, bytes).unwrap();
        (dir, path)
    }

    #[test]
    fn an_invite_file_reads_as_utf8_with_or_without_a_mark() {
        for bytes in [
            LINK.as_bytes().to_vec(),
            [&[0xEF, 0xBB, 0xBF][..], LINK.as_bytes()].concat(),
            [&[0xEF, 0xBB, 0xBF][..], LINK.as_bytes(), b"\r\n"].concat(),
        ] {
            let (_dir, path) = file(&bytes);
            assert_eq!(read_invite_file(&path).unwrap(), LINK);
        }
    }

    #[test]
    fn an_invite_file_reads_as_utf16_either_way_round() {
        // PowerShell 5's `>`: little-endian, a mark, CRLF after the line.
        for text in [LINK.to_string(), format!("{LINK}\r\n"), format!("  {LINK} \t\r\n\r\n")] {
            for le in [true, false] {
                let (_dir, path) = file(&utf16(&text, le, true));
                assert_eq!(read_invite_file(&path).unwrap(), LINK, "le={le} {text:?}");
            }
        }
        // No mark: ASCII text shows itself by its zero bytes.
        for le in [true, false] {
            let (_dir, path) = file(&utf16(&format!("{LINK}\r\n"), le, false));
            assert_eq!(read_invite_file(&path).unwrap(), LINK, "le={le}");
        }
        // A mark is not part of the text, however many bytes precede it.
        assert_eq!(decode_text(&utf16("\u{feff}x", true, true)).unwrap(), "x");
    }

    #[test]
    fn trailing_whitespace_of_every_kind_is_dropped() {
        for tail in ["", "\n", "\r\n", " \r\n", "\r\n\r\n", "\t \n \n"] {
            let (_dir, path) = file(format!("{LINK}{tail}").as_bytes());
            assert_eq!(read_invite_file(&path).unwrap(), LINK, "{tail:?}");
        }
    }

    #[test]
    fn a_bad_invite_file_says_what_is_wrong() {
        let (_dir, path) = file(b"");
        assert!(read_invite_file(&path).unwrap_err().to_string().contains("is empty"));
        let (_dir, path) = file(&[0xEF, 0xBB, 0xBF, b'\r', b'\n']);
        assert!(read_invite_file(&path).unwrap_err().to_string().contains("is empty"));
        // Not text at all.
        let (_dir, path) = file(&[0x80, 0x81, 0x82]);
        assert!(format!("{:#}", read_invite_file(&path).unwrap_err()).contains("is not text"));
        // UTF-16 cut in the middle of a character, or with a lone surrogate.
        let mut cut = utf16(LINK, true, true);
        cut.pop();
        let (_dir, path) = file(&cut);
        assert!(format!("{:#}", read_invite_file(&path).unwrap_err()).contains("cut short"));
        let (_dir, path) = file(&[0xFF, 0xFE, 0x00, 0xD8, 0x41, 0x00]);
        assert!(read_invite_file(&path).is_err());
        let gone = path.with_file_name("missing.txt");
        assert!(read_invite_file(&gone).unwrap_err().to_string().contains("could not read the invite file"));
    }
}
