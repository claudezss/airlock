//! The local backend: the job runs on this machine.
//!
//! - **Linux**: the shim runs inside new user, mount, network, PID, IPC and
//!   UTS namespaces, in a minimal root built from read-only bind mounts with
//!   `/work`, `/out` and `/meta` writable, no network interfaces, all
//!   capabilities dropped, `no_new_privs` and a Landlock ruleset
//!   ([`super::linux`]). Memory is capped with `RLIMIT_AS`.
//! - **Elsewhere**: a plain process with the shim's scrubbed environment,
//!   rlimits and process-group kill. Network cannot be blocked and a job that
//!   calls `setsid()` can outlive the shim, so this is for trusted code only.
//!
//! The runtime is a `uv` virtual environment with the package allowlist,
//! built once at prepare time.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{bail, Context, Result};
use tokio::process::Command;
use tokio::sync::watch;

use super::{read_shim_result, supervise, PreparedJob, RawResult, RuntimeSpec, KILL_GRACE};

pub struct Local {
    state_dir: PathBuf,
    /// The interpreter jobs run with (inside the runtime venv).
    python: Option<PathBuf>,
    /// Directories the interpreter needs, mounted read-only in the sandbox.
    runtime_dirs: Vec<PathBuf>,
    shim: PathBuf,
    sandboxed: bool,
}

/// Every symlink met while resolving `p` (e.g. uv's `cpython-3.12-…` link
/// to the patch release), so the sandbox can recreate the same chain.
fn symlinks_on_path(p: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut cur = p.to_path_buf();
    for _ in 0..40 {
        let mut prefix = PathBuf::new();
        let mut next = None;
        for c in cur.components() {
            prefix.push(c);
            if let Ok(target) = std::fs::read_link(&prefix) {
                let resolved = prefix.parent().unwrap_or(Path::new("/")).join(target);
                let rest = cur.strip_prefix(&prefix).unwrap_or(Path::new("")).to_path_buf();
                out.push(prefix.clone());
                next = Some(resolved.join(rest));
                break;
            }
        }
        match next {
            Some(n) => cur = n,
            None => break,
        }
    }
    out
}

fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).map(|d| d.join(name)).find(|p| p.is_file())
}

async fn run_ok(cmd: &mut Command, what: &str) -> Result<()> {
    let out = cmd.stdin(Stdio::null()).output().await.with_context(|| format!("could not run {what}"))?;
    if !out.status.success() {
        bail!("{what} failed:\n{}", String::from_utf8_lossy(&out.stderr));
    }
    Ok(())
}

impl Local {
    /// `sandboxed` is only honoured on Linux.
    pub fn new(state_dir: &Path, sandboxed: bool) -> Self {
        Local {
            state_dir: state_dir.to_path_buf(),
            python: None,
            runtime_dirs: vec![],
            shim: state_dir.join("shim.py"),
            sandboxed: sandboxed && cfg!(target_os = "linux"),
        }
    }

    pub fn sandboxed(&self) -> bool {
        self.sandboxed
    }

    pub async fn prepare(&mut self, spec: &RuntimeSpec) -> Result<()> {
        std::fs::create_dir_all(&self.state_dir)?;
        crate::view::write_atomic(&self.shim, airlox_core::shim::SHIM_PY.as_bytes(), 0o644)?;
        let venv = self.state_dir.join("runtimes").join(spec.hash());
        let python = venv.join(if cfg!(windows) { "Scripts/python.exe" } else { "bin/python" });
        if !venv.join(".ready").exists() {
            let Some(uv) = which("uv") else {
                bail!(
                    "the local backend builds its runtime with uv; install it (https://docs.astral.sh/uv/) \
                     or use --sandbox docker"
                );
            };
            let _ = std::fs::remove_dir_all(&venv);
            tracing::info!(runtime = %spec.runtime, packages = ?spec.packages, "building the job runtime");
            run_ok(
                Command::new(&uv).args(["venv", "--quiet", "--python", spec.python_version()]).arg(&venv),
                "uv venv",
            )
            .await?;
            if !spec.packages.is_empty() {
                run_ok(
                    Command::new(&uv)
                        // Wheels only: an sdist's build script would run
                        // here, on the host, outside the sandbox.
                        .args(["pip", "install", "--quiet", "--only-binary", ":all:", "--python"])
                        .arg(&python)
                        .args(&spec.packages),
                    "uv pip install",
                )
                .await?;
            }
            std::fs::write(venv.join(".ready"), b"")?;
        }
        // The venv's interpreter is a link into a Python installation that
        // the sandbox must also see.
        let real = std::fs::canonicalize(&python)?;
        let install = real.parent().and_then(Path::parent).context("unexpected interpreter layout")?;
        self.runtime_dirs = vec![std::fs::canonicalize(&venv)?, install.to_path_buf()];
        self.runtime_dirs.extend(symlinks_on_path(&python));
        self.python = Some(python);
        Ok(())
    }

    fn command(&self, job: &PreparedJob) -> Result<Command> {
        let python = self.python.as_ref().context("local backend was not prepared")?;
        #[cfg(target_os = "linux")]
        if self.sandboxed {
            let spec = super::linux::SandboxSpec {
                rootfs: job.root.join("rootfs"),
                work: job.work_dir(),
                out: job.out_dir(),
                meta: job.meta_dir(),
                shim: self.shim.clone(),
                python: python.clone(),
                runtime_dirs: self.runtime_dirs.clone(),
                entry: job.entry.clone(),
                timeout_s: job.timeout_s,
                memory_mb: job.memory_mb,
                network: job.network,
            };
            let spec_path = job.root.join("sandbox.json");
            std::fs::write(&spec_path, serde_json::to_vec(&spec)?)?;
            let mut c = Command::new(std::env::current_exe()?);
            c.arg(super::linux::STAGE1).arg(spec_path);
            return Ok(c);
        }
        let mut c = Command::new(python);
        c.arg(&self.shim)
            .arg("--work")
            .arg(job.work_dir())
            .args(["--entry", &job.entry, "--timeout", &job.timeout_s.to_string()])
            .arg("--result")
            .arg(job.meta_dir().join("result.json"))
            .arg("--out")
            .arg(job.out_dir())
            .args(["--memory-mb", &job.memory_mb.to_string()]);
        Ok(c)
    }

    pub async fn run(&self, job: &PreparedJob, cancel: watch::Receiver<bool>) -> Result<RawResult> {
        let mut cmd = self.command(job)?;
        cmd.env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .current_dir(&job.root)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        // Its own process group, so a stop reaches the shim (and on Linux the
        // namespace init) but not the runner.
        #[cfg(unix)]
        cmd.process_group(0);
        let mut child = cmd.spawn().context("could not start the sandbox")?;
        let pid = child.id();
        let deadline = std::time::Duration::from_secs(job.timeout_s as u64) + KILL_GRACE;
        #[cfg(unix)]
        let (stop, kill) = (async { super::signal_group(pid, nix::sys::signal::Signal::SIGTERM) }, async {
            super::signal_group(pid, nix::sys::signal::Signal::SIGKILL)
        });
        #[cfg(not(unix))]
        let (stop, kill) = (async {}, async {});
        let _ = pid;
        let waited = supervise(&mut child, deadline, cancel, stop, kill).await?;
        let mut stderr = String::new();
        if let Some(mut e) = child.stderr.take() {
            use tokio::io::AsyncReadExt;
            let _ = e.read_to_string(&mut stderr).await;
        }
        let shim = read_shim_result(job);
        let error = match (&shim, waited.status) {
            (None, Some(s)) if !waited.cancelled && !waited.killed_on_timeout => {
                Some(format!("sandbox failed ({s}): {}", stderr.trim()))
            }
            _ => None,
        };
        Ok(RawResult {
            shim,
            wall_ms: waited.wall_ms,
            killed_on_timeout: waited.killed_on_timeout,
            cancelled: waited.cancelled,
            oom_killed: false,
            error,
        })
    }
}
