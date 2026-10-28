//! Sandbox backends. Every backend runs the same embedded job shim
//! (protocol §11) on a prepared job directory:
//!
//! ```text
//! <root>/work   code and inputs; the job's cwd        (/work in containers)
//! <root>/out    files the job wants returned          (/out, also $AIRLOX_OUT)
//! <root>/meta   result.json, stdout.txt, stderr.txt   (/meta)
//! ```
//!
//! The runner enforces the wall clock itself as well: if the shim does not
//! finish within the job timeout plus a grace period, the sandbox is killed.

pub mod docker;
#[cfg(target_os = "linux")]
pub mod linux;
pub mod local;
#[cfg(windows)]
pub mod winjob;

use std::path::PathBuf;
use std::process::ExitStatus;
use std::time::{Duration, Instant};

use airlox_core::cert::SandboxKind;
use airlox_core::encoding::{hex, sha256};
use airlox_core::payload::JobEnv;
use airlox_core::shim::ShimResult;
use anyhow::{Context, Result};
use tokio::sync::watch;

/// Time the shim gets beyond the job timeout before the runner kills it.
pub const KILL_GRACE: Duration = Duration::from_secs(10);
/// After a polite stop (SIGTERM), how long before a hard kill.
pub const STOP_GRACE: Duration = Duration::from_secs(5);

/// The `env` a runner reports, shaped so that every client accepts it
/// (`check_env`): control characters out, the interpreter label at most 128
/// characters with a digest-pinned image's digest cut to 12 hex digits, and
/// a package whose version is empty or too long left out rather than
/// reported wrongly.
pub fn job_env(
    python: &str,
    packages: impl IntoIterator<Item = (String, String)>,
    sandbox: SandboxKind,
    interpreter: &str,
) -> JobEnv {
    let plain = |s: &str| -> String { s.chars().filter(|c| !c.is_control()).collect() };
    let mut label = plain(interpreter);
    if let Some(at) = label.rfind("@sha256:") {
        let digest = &label[at + 8..];
        if digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()) {
            label.truncate(at + 8 + 12);
        }
    }
    let label: String = label.chars().take(128).collect();
    JobEnv {
        python: plain(python),
        packages: packages
            .into_iter()
            .filter(|(_, v)| !v.is_empty() && v.chars().count() <= 64 && !v.chars().any(char::is_control))
            .take(airlox_core::payload::MAX_ENV_PACKAGES)
            .collect(),
        airlox: env!("CARGO_PKG_VERSION").to_string(),
        sandbox,
        interpreter: if label.is_empty() { "unknown".into() } else { label },
    }
}

/// The interpreter and package allowlist a session's jobs run with. Built
/// once, with network, before the runner takes jobs.
#[derive(Clone, Debug)]
pub struct RuntimeSpec {
    /// e.g. "python3.12"
    pub runtime: String,
    /// The manifest's allowlist entries: normalized names, each optionally
    /// with a version specifier (`cugrid==0.1.0`).
    pub packages: Vec<String>,
}

impl RuntimeSpec {
    /// The allowlisted package names, without version specifiers.
    pub fn names(&self) -> Vec<String> {
        self.packages.iter().map(|p| airlox_core::policy::allowlist_name(p).to_string()).collect()
    }

    /// The entries that carry a version specifier, parsed.
    pub fn pins(&self) -> Vec<airlox_core::policy::AllowedPackage> {
        self.packages
            .iter()
            .filter_map(|p| airlox_core::policy::AllowedPackage::parse(p).ok())
            .filter(|p| p.specifier.is_some())
            .collect()
    }

    /// What the session's pins say about the installed `packages`: one line
    /// for each pinned package that is installed at a version its entry does
    /// not allow, such as "--python has cugrid 0.2.1, but the session pins
    /// cugrid==0.1.0". (A package that is not installed at all is not a
    /// conflict here; the backends check for missing ones.)
    pub fn pin_conflicts(&self, what: &str, installed: &[local::PackageInfo]) -> Vec<String> {
        let mut out = Vec::new();
        for pin in self.pins() {
            if let Some(i) = installed.iter().find(|i| i.name == pin.name) {
                if !pin.allows_version(&i.version) {
                    out.push(format!(
                        "{what} has {} {}, but the session pins {}",
                        pin.name,
                        if i.version.is_empty() { "(no version)" } else { &i.version },
                        pin.canonical()
                    ));
                }
            }
        }
        out
    }

    /// "3.12" from "python3.12".
    pub fn python_version(&self) -> &str {
        self.runtime.strip_prefix("python").unwrap_or(&self.runtime)
    }

    /// Identifies a built runtime: `sha256(runtime + sorted(packages))`, the
    /// entries with their version specifiers, so a different pin is a
    /// different runtime (and an allowlist of bare names hashes as it always
    /// did).
    pub fn hash(&self) -> String {
        let mut p = self.packages.clone();
        p.sort();
        let s = format!("{}\n{}", self.runtime, p.join("\n"));
        hex(&sha256(s.as_bytes()))[..16].to_string()
    }
}

pub struct PreparedJob {
    pub id: String,
    pub root: PathBuf,
    pub entry: String,
    pub timeout_s: u32,
    pub memory_mb: u32,
    /// Jobs may reach the network (the manifest allows it and the runner
    /// operator did not pass `--no-network`).
    pub network: bool,
}

impl PreparedJob {
    pub fn work_dir(&self) -> PathBuf {
        self.root.join("work")
    }
    pub fn out_dir(&self) -> PathBuf {
        self.root.join("out")
    }
    pub fn meta_dir(&self) -> PathBuf {
        self.root.join("meta")
    }
}

/// What a sandbox run produced, before it becomes a signed result.
#[derive(Debug, Default)]
pub struct RawResult {
    /// The shim's result.json, if it wrote one.
    pub shim: Option<ShimResult>,
    /// Wall time measured by the runner.
    pub wall_ms: u64,
    /// The runner killed the sandbox because the shim overran its timeout.
    pub killed_on_timeout: bool,
    /// A cancel arrived while it ran.
    pub cancelled: bool,
    /// The container was killed for exceeding its memory limit.
    pub oom_killed: bool,
    /// Peak memory measured by the sandbox (a Windows Job Object), when the
    /// shim cannot measure it itself.
    pub peak_mem_kb: Option<u64>,
    /// Why the sandbox itself failed, if it did.
    pub error: Option<String>,
}

pub enum Backend {
    Local(local::Local),
    Docker(docker::Docker),
}

impl Backend {
    pub fn kind(&self) -> SandboxKind {
        match self {
            Backend::Local(l) => l.kind(),
            Backend::Docker(_) => SandboxKind::Docker,
        }
    }

    /// True when jobs can reach the network although the session says no.
    pub fn network_unblocked(&self) -> bool {
        match self {
            Backend::Local(l) => !l.sandboxed(),
            Backend::Docker(_) => false,
        }
    }

    /// The runner's own runtime and cache directories, which job output
    /// must not name (none for Docker, whose jobs see the image).
    pub fn runtime_dirs(&self) -> Vec<PathBuf> {
        match self {
            Backend::Local(b) => b.runtime_dirs(),
            Backend::Docker(_) => vec![],
        }
    }

    pub async fn prepare(&mut self, spec: &RuntimeSpec) -> Result<()> {
        match self {
            Backend::Local(b) => b.prepare(spec).await,
            Backend::Docker(b) => b.prepare(spec).await,
        }
    }

    /// Where jobs run, as measured when the runtime was prepared (not per
    /// job); `None` if it could not be.
    pub fn env(&self) -> Option<JobEnv> {
        match self {
            Backend::Local(b) => b.env(),
            Backend::Docker(b) => b.env(),
        }
    }

    /// What importing the allowlist takes, where it can be measured without
    /// leaving the sandbox (process mode).
    pub async fn import_footprint(&self, spec: &RuntimeSpec, cap_mb: u32) -> Option<local::Footprint> {
        match self {
            Backend::Local(b) => b.import_footprint(spec, cap_mb).await,
            Backend::Docker(_) => None,
        }
    }

    pub async fn run(&self, job: &PreparedJob, cancel: watch::Receiver<bool>) -> Result<RawResult> {
        match self {
            Backend::Local(b) => b.run(job, cancel).await,
            Backend::Docker(b) => b.run(job, cancel).await,
        }
    }
}

/// How a run ended, as seen from the runner.
pub(crate) struct Waited {
    pub status: Option<ExitStatus>,
    pub wall_ms: u64,
    pub killed_on_timeout: bool,
    pub cancelled: bool,
}

/// Wait for a sandbox process, stopping it politely on cancel or when it
/// overruns `deadline`, and hard-killing it if that does not work.
/// `stop` and `kill` are only polled if needed (futures are lazy).
pub(crate) async fn supervise(
    child: &mut tokio::process::Child,
    deadline: Duration,
    mut cancel: watch::Receiver<bool>,
    stop: impl std::future::Future<Output = ()>,
    kill: impl std::future::Future<Output = ()>,
) -> Result<Waited> {
    let start = Instant::now();
    let mut killed_on_timeout = false;
    let mut cancelled = *cancel.borrow();
    if !cancelled {
        tokio::select! {
            r = child.wait() => {
                let status = r.context("waiting for the sandbox")?;
                return Ok(Waited { status: Some(status), wall_ms: start.elapsed().as_millis() as u64, killed_on_timeout, cancelled });
            }
            _ = tokio::time::sleep(deadline) => killed_on_timeout = true,
            _ = async { while cancel.changed().await.is_ok() { if *cancel.borrow() { break } } } => cancelled = *cancel.borrow(),
        }
    }
    // Stop: the shim turns SIGTERM into a "cancelled" result and kills the job.
    stop.await;
    let status = match tokio::time::timeout(STOP_GRACE, child.wait()).await {
        Ok(r) => Some(r?),
        Err(_) => {
            kill.await;
            let _ = child.start_kill();
            tokio::time::timeout(STOP_GRACE, child.wait()).await.ok().and_then(|r| r.ok())
        }
    };
    Ok(Waited { status, wall_ms: start.elapsed().as_millis() as u64, killed_on_timeout, cancelled })
}

/// Read a file the sandbox wrote, at most `max` bytes. The job can replace
/// anything in its directories, so: no following links, no blocking on a
/// FIFO, regular files only. Returns the bytes and whether more were there.
pub fn read_sandbox_file(path: &std::path::Path, max: u64) -> Result<(Vec<u8>, bool)> {
    use std::io::Read;
    let mut o = std::fs::OpenOptions::new();
    o.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(
        &mut o,
        (nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_NONBLOCK).bits(),
    );
    let f = o.open(path)?;
    if !f.metadata()?.is_file() {
        anyhow::bail!("{} is not a regular file", path.display());
    }
    let mut buf = Vec::new();
    f.take(max + 1).read_to_end(&mut buf)?;
    let more = buf.len() as u64 > max;
    buf.truncate(max as usize);
    Ok((buf, more))
}

/// Read the shim's result.json, if it wrote a valid one.
pub(crate) fn read_shim_result(job: &PreparedJob) -> Option<ShimResult> {
    let (raw, more) = read_sandbox_file(&job.meta_dir().join("result.json"), 64 * 1024).ok()?;
    if more {
        return None;
    }
    serde_json::from_slice(&raw).ok()
}

/// Make a job directory deletable again: a job may have removed the owner's
/// write or search permission on directories it created.
pub fn make_removable(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let Ok(meta) = std::fs::symlink_metadata(path) else { return };
        if meta.is_dir() {
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
            if let Ok(entries) = std::fs::read_dir(path) {
                for e in entries.flatten() {
                    make_removable(&e.path());
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        // A job may have marked its files read-only, which Windows will not delete.
        let Ok(meta) = std::fs::symlink_metadata(path) else { return };
        if meta.permissions().readonly() {
            let mut p = meta.permissions();
            #[allow(clippy::permissions_set_readonly_false)]
            p.set_readonly(false);
            let _ = std::fs::set_permissions(path, p);
        }
        if meta.is_dir() {
            if let Ok(entries) = std::fs::read_dir(path) {
                for e in entries.flatten() {
                    make_removable(&e.path());
                }
            }
        }
    }
}

/// Send `sig` to a process group (the sandbox's), ignoring "already gone".
#[cfg(unix)]
pub(crate) fn signal_group(pid: Option<u32>, sig: nix::sys::signal::Signal) {
    if let Some(pid) = pid {
        let _ = nix::sys::signal::killpg(nix::unistd::Pid::from_raw(pid as i32), sig);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(interpreter: &str, packages: &[(&str, &str)]) -> JobEnv {
        let pkgs = packages.iter().map(|(n, v)| (n.to_string(), v.to_string()));
        job_env("3.12.4", pkgs, SandboxKind::Docker, interpreter)
    }

    #[test]
    fn a_digest_pinned_image_is_named_by_a_short_digest() {
        let digest = "0123456789abcdef".repeat(4);
        let long =
            format!("registry.example.com/team/some-long-repository-name:3.12-slim-bookworm@sha256:{digest}");
        let e = env(&format!("docker:{long}"), &[]);
        assert!(e.interpreter.ends_with("@sha256:0123456789ab"), "{}", e.interpreter);
        assert!(airlox_core::policy::check_env(&e).is_ok());
        // Not a 64-digit digest: left alone.
        assert_eq!(env("docker:repo@sha256:abc", &[]).interpreter, "docker:repo@sha256:abc");
    }

    #[test]
    fn any_interpreter_label_is_capped_on_a_char_boundary_and_printable() {
        let e = env(&"é".repeat(300), &[]);
        assert_eq!(e.interpreter.chars().count(), 128);
        assert!(airlox_core::policy::check_env(&e).is_ok());
        assert_eq!(env("a\nb\x1b", &[]).interpreter, "ab");
        assert_eq!(env("", &[]).interpreter, "unknown");
    }

    #[test]
    fn a_package_without_a_usable_version_is_left_out() {
        let e = env("uv-runtime", &[("numpy", "2.1.0"), ("nover", ""), ("long", &"1".repeat(65))]);
        assert_eq!(e.packages.keys().collect::<Vec<_>>(), ["numpy"]);
        assert!(airlox_core::policy::check_env(&e).is_ok());
    }
}
