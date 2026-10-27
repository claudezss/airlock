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
//! - **`--sandbox process`**: a plain process as above. On Windows each job
//!   runs in its own Job Object ([`super::winjob`]): memory capped for the
//!   whole process tree, and every process in it killed when the job ends.
//!   Network cannot be blocked.
//!
//! The runtime is a `uv` virtual environment with the package allowlist,
//! built once at prepare time, or the interpreter the operator names with
//! `--python` (such as an existing venv's), which is checked against the
//! allowlist and never changed.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use airlox_core::cert::SandboxKind;
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use tokio::process::Command;
use tokio::sync::watch;

use super::{read_shim_result, supervise, PreparedJob, RawResult, RuntimeSpec, KILL_GRACE};

/// How the local backend runs jobs, from the runner's flags.
#[derive(Clone, Debug, Default)]
pub struct LocalOpts {
    /// Namespaces and Landlock; only honoured on Linux, never in process mode.
    pub sandboxed: bool,
    /// `--sandbox process`: report as such and, on Windows, contain each job
    /// in a Job Object.
    pub process: bool,
    /// Run jobs with this interpreter instead of building a runtime with uv.
    pub python: Option<PathBuf>,
    /// Variables from the runner's environment that jobs also get.
    pub pass_env: Vec<String>,
}

pub struct Local {
    state_dir: PathBuf,
    /// The interpreter jobs run with (inside the runtime venv).
    python: Option<PathBuf>,
    /// Directories the interpreter needs, mounted read-only in the sandbox.
    runtime_dirs: Vec<PathBuf>,
    shim: PathBuf,
    opts: LocalOpts,
    /// The allowlisted packages as the operator's interpreter reported them.
    packages: Option<Vec<PackageInfo>>,
}

/// What an interpreter reports about itself.
#[derive(Debug, Deserialize)]
pub struct PythonInfo {
    /// e.g. "3.12.4"
    pub version: String,
    /// Allowlisted packages it does not have.
    pub missing: Vec<String>,
    /// `sys.executable`.
    #[serde(default)]
    pub executable: Option<String>,
    /// Where each allowlisted package it has comes from.
    #[serde(default)]
    pub packages: Vec<PackageInfo>,
}

/// An installed distribution, and where its top-level modules import from.
#[derive(Debug, Deserialize)]
pub struct PackageInfo {
    pub name: String,
    pub version: String,
    /// The directory holding its `.dist-info`.
    pub location: String,
    /// Installed with `pip install -e`: jobs import a source checkout.
    #[serde(default)]
    pub editable: bool,
    /// For an editable install, the checkout it points at (a `file://` URL).
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub imports: Vec<ModuleOrigin>,
    /// The module names were guessed from the package name (Python 3.9 has
    /// no `packages_distributions`, and the package no `top_level.txt`), and
    /// may be wrong.
    #[serde(default)]
    pub inferred: bool,
}

#[derive(Debug, Deserialize)]
pub struct ModuleOrigin {
    pub module: String,
    /// The file or directory `import module` would load, if found.
    pub origin: Option<String>,
}

impl PackageInfo {
    /// Modules that import from somewhere other than where the package is
    /// installed: an editable checkout, or a copy earlier on `sys.path`.
    pub fn elsewhere(&self) -> Vec<&ModuleOrigin> {
        // Windows paths compare without case.
        let fold = |p: &str| if cfg!(windows) { p.to_lowercase() } else { p.to_string() };
        let home = fold(&self.location);
        self.imports
            .iter()
            .filter(|m| m.origin.as_deref().is_some_and(|o| !Path::new(&fold(o)).starts_with(&home)))
            .collect()
    }
}

/// What importing the allowlisted packages took.
#[derive(Debug)]
pub struct Footprint {
    /// Peak memory in MB, counted as jobs are capped: commit under a Windows
    /// Job Object, virtual size on Linux, resident size on macOS.
    pub peak_mb: u64,
    /// Windows refused an allocation at the job's cap.
    pub hit_cap: bool,
    /// Modules that did not import, with the exception's name.
    pub failed: Vec<String>,
    /// Packages whose module names were guessed, so may not have been imported.
    pub inferred: Vec<String>,
}

/// Reports the interpreter's version and which of the package names in argv
/// (PEP 503 normalized) are not installed, and for those that are, where
/// they come from: version, location, whether the install is editable, and
/// the file each top-level module would load from (found, not imported).
/// Standard library only.
const PROBE_PY: &str = r#"
import json, platform, re, sys
from importlib import metadata, util
def norm(n):
    return re.sub(r"[-_.]+", "-", n or "").lower()
want = sys.argv[1:]
dists = {}
mods = {}
if want:
    for d in metadata.distributions():
        try:
            dists.setdefault(norm(d.metadata.get("Name")), d)
        except Exception:
            pass
    try:
        top = metadata.packages_distributions()
    except Exception:
        top = {}
    for m, names in top.items():
        for n in names:
            if not m.startswith("_"):
                mods.setdefault(norm(n), set()).add(m)
def origin(m):
    try:
        s = util.find_spec(m)
    except Exception:
        return None
    if s is None:
        return None
    if s.origin and s.has_location:
        return s.origin
    locs = list(s.submodule_search_locations or [])
    return locs[0] if locs else None
pkgs = []
for p in want:
    d = dists.get(p)
    if d is None:
        continue
    editable, source = False, None
    try:
        du = json.loads(d.read_text("direct_url.json") or "{}")
        editable = bool(du.get("dir_info", {}).get("editable"))
        source = du.get("url") if editable else None
    except Exception:
        pass
    try:
        location = str(d.locate_file(""))
    except Exception:
        location = ""
    names = set(mods.get(p) or ())
    if not names:
        try:
            names = {l.strip() for l in (d.read_text("top_level.txt") or "").splitlines()}
            names = {n for n in names if n and not n.startswith("_")}
        except Exception:
            names = set()
    names = sorted(names)[:5]
    pkgs.append({"name": p, "version": d.version or "", "location": location, "editable": editable,
                 "source": source, "inferred": not names,
                 "imports": [{"module": m, "origin": origin(m)} for m in names or [p.replace("-", "_")]]})
print(json.dumps({"version": platform.python_version(), "executable": sys.executable,
                  "missing": [p for p in want if p not in dists], "packages": pkgs}))
"#;

/// Imports the given modules, then prints which failed and the process's
/// peak memory in MB as jobs are capped there: virtual size on Linux
/// (`RLIMIT_AS`), resident size on macOS. On Windows the runner reads the
/// peak commit from the Job Object instead. Standard library only.
const FOOTPRINT_PY: &str = r#"
import importlib, json, sys
failed = []
for m in sys.argv[1:]:
    try:
        importlib.import_module(m)
    except BaseException as e:
        failed.append("%s (%s)" % (m, type(e).__name__))
peak = None
try:
    with open("/proc/self/status") as f:
        for line in f:
            if line.startswith("VmPeak:"):
                peak = int(line.split()[1]) // 1024
except OSError:
    if sys.platform != "win32":
        import resource
        r = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        peak = r // (1 << 20) if sys.platform == "darwin" else r // 1024
print(json.dumps({"peak_mb": peak, "failed": failed}))
"#;

/// Windows variables that describe the machine, not the user, and that
/// programs (license managers, `cmd`, Python's `shell=True`) expect. The
/// shim's `WINDOWS_SYSTEM_ENV` passes the same names on to the job.
#[cfg(windows)]
const WINDOWS_SYSTEM_ENV: &[&str] = &[
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
    "OS",
    "SystemDrive",
    "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE",
    "PROCESSOR_IDENTIFIER",
    "PROCESSOR_LEVEL",
    "PROCESSOR_REVISION",
    "ProgramData",
    "ALLUSERSPROFILE",
    "PUBLIC",
    "ProgramFiles",
    "ProgramFiles(x86)",
    "ProgramW6432",
    "CommonProgramFiles",
    "CommonProgramFiles(x86)",
    "CommonProgramW6432",
];

/// The environment every process the backend starts begins with: nothing
/// of the runner's (its invite, its keys) but what the OS needs, then the
/// operator's `--pass-env` variables.
fn base_env(cmd: &mut Command, pass_env: &[String]) {
    cmd.env_clear();
    #[cfg(windows)]
    {
        let root = std::env::var_os("SYSTEMROOT").unwrap_or_else(|| r"C:\Windows".into());
        let mut path = PathBuf::from(&root);
        path.push("System32");
        let path = std::env::join_paths([path, PathBuf::from(&root)]).unwrap_or_default();
        cmd.env("SYSTEMROOT", &root).env("PATH", path);
        for name in WINDOWS_SYSTEM_ENV {
            if let Some(v) = std::env::var_os(name) {
                cmd.env(name, v);
            }
        }
    }
    #[cfg(not(windows))]
    cmd.env("PATH", "/usr/local/bin:/usr/bin:/bin");
    for name in pass_env {
        if let Some(v) = std::env::var_os(name) {
            cmd.env(name, v);
        }
    }
}

/// Ask `python` for its version and which `packages` it lacks.
pub async fn probe_python(python: &Path, packages: &[String], pass_env: &[String]) -> Result<PythonInfo> {
    let mut cmd = Command::new(python);
    base_env(&mut cmd, pass_env);
    cmd.args(["-I", "-c", PROBE_PY]).args(packages).stdin(Stdio::null()).kill_on_drop(true);
    #[cfg(windows)]
    cmd.creation_flags(super::winjob::NO_WINDOW);
    let out = tokio::time::timeout(std::time::Duration::from_secs(60), cmd.output())
        .await
        .with_context(|| format!("{} did not answer within 60 s", python.display()))?
        .with_context(|| format!("could not run {}", python.display()))?;
    if !out.status.success() {
        bail!(
            "{} failed ({}):\n{}",
            python.display(),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    serde_json::from_slice(&out.stdout)
        .with_context(|| format!("unexpected answer from {}", python.display()))
}

/// Say where each allowlisted package imports from, and warn about the
/// ones that do not import from the installed distribution.
fn report_packages(packages: &[PackageInfo]) {
    for p in packages {
        tracing::info!(package = %p.name, version = %p.version, from = %p.location, "allowlisted package");
        let elsewhere = p.elsewhere();
        if p.editable {
            tracing::warn!(
                "{} is an editable install{}: jobs import that checkout as it is now, not a built wheel. If \
                 that is not what you want, `pip install` the package normally into this interpreter",
                p.name,
                p.source.as_deref().map(|s| format!(" of {s}")).unwrap_or_default()
            );
        } else if let Some(m) = elsewhere.first() {
            tracing::warn!(
                "`import {}` loads {}, not the {} {} installed in {}: something earlier on sys.path shadows it. \
                 Remove the other copy, or the PYTHONPATH or .pth entry that adds it",
                m.module,
                m.origin.as_deref().unwrap_or("?"),
                p.name,
                p.version,
                p.location
            );
        }
    }
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
    let names: Vec<String> =
        if cfg!(windows) { vec![format!("{name}.exe"), name.to_string()] } else { vec![name.to_string()] };
    std::env::split_paths(&path).flat_map(|d| names.iter().map(move |n| d.join(n))).find(|p| p.is_file())
}

/// An exclusive lock on `path`, held until the returned file is dropped:
/// opened sharing nothing, which Windows releases when the process dies.
#[cfg(windows)]
async fn lock(path: PathBuf) -> Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    const SHARING_VIOLATION: i32 = 32;
    loop {
        let opened =
            std::fs::OpenOptions::new().create(true).truncate(false).write(true).share_mode(0).open(&path);
        match opened {
            Ok(f) => return Ok(f),
            Err(e) if e.raw_os_error() == Some(SHARING_VIOLATION) => {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await
            }
            Err(e) => return Err(anyhow::anyhow!("locking {}: {e}", path.display())),
        }
    }
}

/// An exclusive lock on `path`, held until the returned guard is dropped.
#[cfg(unix)]
async fn lock(path: PathBuf) -> Result<nix::fcntl::Flock<std::fs::File>> {
    tokio::task::spawn_blocking(move || {
        let f = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(&path)?;
        nix::fcntl::Flock::lock(f, nix::fcntl::FlockArg::LockExclusive)
            .map_err(|(_, e)| anyhow::anyhow!("locking {}: {e}", path.display()))
    })
    .await?
}

async fn run_ok(cmd: &mut Command, what: &str) -> Result<()> {
    let out = cmd.stdin(Stdio::null()).output().await.with_context(|| format!("could not run {what}"))?;
    if !out.status.success() {
        bail!("{what} failed:\n{}", String::from_utf8_lossy(&out.stderr));
    }
    Ok(())
}

impl Local {
    pub fn new(state_dir: &Path, mut opts: LocalOpts) -> Self {
        opts.sandboxed = opts.sandboxed && !opts.process && cfg!(target_os = "linux");
        Local {
            state_dir: state_dir.to_path_buf(),
            python: None,
            runtime_dirs: vec![],
            shim: state_dir.join("shim.py"),
            opts,
            packages: None,
        }
    }

    pub fn sandboxed(&self) -> bool {
        self.opts.sandboxed
    }

    pub fn kind(&self) -> SandboxKind {
        if self.opts.process {
            SandboxKind::Process
        } else {
            SandboxKind::Local
        }
    }

    pub async fn prepare(&mut self, spec: &RuntimeSpec) -> Result<()> {
        std::fs::create_dir_all(&self.state_dir)?;
        // Runners sharing a cache start together; on Windows replacing a
        // file another one is replacing (or reading) fails, so only write a
        // shim that differs, and accept the race if the result is right.
        let shim = airlox_core::shim::SHIM_PY.as_bytes();
        let current = || std::fs::read(&self.shim).ok();
        if current().as_deref() != Some(shim) {
            if let Err(e) = crate::view::write_atomic(&self.shim, shim, 0o644) {
                if current().as_deref() != Some(shim) {
                    return Err(e);
                }
            }
        }
        let python = match self.opts.python.clone() {
            Some(p) => {
                let (python, packages) = self.check_python(&p, spec).await?;
                self.packages = Some(packages);
                python
            }
            None => self.build_runtime(spec).await?,
        };
        // The venv's interpreter is a link into a Python installation that
        // the sandbox must also see.
        if self.opts.sandboxed {
            let venv = python.parent().and_then(Path::parent).context("unexpected interpreter layout")?;
            let real = std::fs::canonicalize(&python)?;
            let install = real.parent().and_then(Path::parent).context("unexpected interpreter layout")?;
            self.runtime_dirs = vec![std::fs::canonicalize(venv)?, install.to_path_buf()];
            self.runtime_dirs.extend(symlinks_on_path(&python));
        }
        self.python = Some(python);
        Ok(())
    }

    /// The operator's interpreter: it must run the session's Python and
    /// already have every allowlisted package. Nothing is installed.
    async fn check_python(&self, python: &Path, spec: &RuntimeSpec) -> Result<(PathBuf, Vec<PackageInfo>)> {
        if !python.is_file() {
            bail!("--python {} is not a file", python.display());
        }
        let python = std::path::absolute(python)?;
        let info = probe_python(&python, &spec.packages, &self.opts.pass_env).await?;
        let want = spec.python_version();
        if info.version != want && !info.version.starts_with(&format!("{want}.")) {
            bail!(
                "--python {} is Python {}, but the session runs {}; point --python at a Python {want} interpreter",
                python.display(),
                info.version,
                spec.runtime
            );
        }
        if !info.missing.is_empty() {
            bail!(
                "packages the session allows are missing from --python: {}. Install them into {}; the runner \
                 never installs anything into it",
                info.missing.join(", "),
                python.display()
            );
        }
        tracing::info!(
            python = %info.executable.as_deref().unwrap_or(&python.display().to_string()),
            version = %info.version,
            "using the operator's interpreter"
        );
        report_packages(&info.packages);
        Ok((python, info.packages))
    }

    /// How much memory importing the allowlisted packages takes, for
    /// process mode, where jobs are plain processes anyway: a cap below it
    /// fails every job that imports them. The import runs as a job would:
    /// its own process group, or on Windows a Job Object with the job's cap,
    /// killed whole after 120 s. `None` in other modes (importing here would
    /// run package code outside the sandbox), or if it cannot tell.
    pub async fn import_footprint(&self, spec: &RuntimeSpec, cap_mb: u32) -> Option<Footprint> {
        if !self.opts.process || spec.packages.is_empty() {
            return None;
        }
        let python = self.python.as_ref()?;
        let probed;
        let packages = match &self.packages {
            Some(p) => p,
            None => {
                probed = probe_python(python, &spec.packages, &self.opts.pass_env).await.ok()?.packages;
                &probed
            }
        };
        let modules: Vec<&str> =
            packages.iter().flat_map(|p| p.imports.iter().map(|m| m.module.as_str())).collect();
        let inferred: Vec<String> = packages.iter().filter(|p| p.inferred).map(|p| p.name.clone()).collect();
        tracing::info!("importing the allowlisted packages once to measure their memory, as a job would");
        let mut cmd = Command::new(python);
        base_env(&mut cmd, &self.opts.pass_env);
        cmd.args(["-I", "-c", FOOTPRINT_PY])
            .args(&modules)
            .current_dir(&self.state_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        #[cfg(unix)]
        cmd.process_group(0);
        #[cfg(windows)]
        let winjob = {
            cmd.creation_flags(super::winjob::NO_WINDOW | super::winjob::SUSPENDED);
            super::winjob::WinJob::new(cap_mb).ok()?
        };
        let _ = cap_mb;
        let mut child = cmd.spawn().ok()?;
        let pid = child.id();
        #[cfg(windows)]
        if winjob.adopt(child.raw_handle()? as _, pid?).is_err() {
            let _ = child.start_kill();
            return None;
        }
        let mut stdout = child.stdout.take()?;
        let read = async {
            use tokio::io::AsyncReadExt;
            let mut out = String::new();
            let _ = stdout.read_to_string(&mut out).await;
            let _ = child.wait().await;
            out
        };
        let out = tokio::time::timeout(std::time::Duration::from_secs(120), read).await;
        #[cfg(unix)]
        super::signal_group(pid, nix::sys::signal::Signal::SIGKILL);
        #[cfg(windows)]
        winjob.terminate();
        let _ = pid;
        let v: serde_json::Value = serde_json::from_str(out.ok()?.trim()).ok()?;
        // A guessed module name that does not import says nothing about jobs.
        let guessed: Vec<&str> = packages
            .iter()
            .filter(|p| p.inferred)
            .flat_map(|p| p.imports.iter().map(|m| m.module.as_str()))
            .collect();
        let failed: Vec<String> = serde_json::from_value::<Vec<String>>(v["failed"].clone())
            .unwrap_or_default()
            .into_iter()
            .filter(|f| !guessed.contains(&f.split(' ').next().unwrap_or("")))
            .collect();
        #[cfg(windows)]
        let (peak_mb, hit_cap) = (winjob.peak_kb() / 1024, winjob.hit_memory_limit());
        #[cfg(not(windows))]
        let (peak_mb, hit_cap) = (v["peak_mb"].as_u64()?, false);
        Some(Footprint { peak_mb, hit_cap, failed, inferred })
    }

    /// A uv venv with the allowlist, shared by runners using the same cache.
    async fn build_runtime(&self, spec: &RuntimeSpec) -> Result<PathBuf> {
        let venv = self.state_dir.join("runtimes").join(spec.hash());
        let python = venv.join(if cfg!(windows) { "Scripts/python.exe" } else { "bin/python" });
        // Runners sharing a cache (the default) may start together: one
        // builds the runtime while the others wait, instead of each deleting
        // the venv another is building.
        std::fs::create_dir_all(self.state_dir.join("runtimes"))?;
        #[cfg(any(unix, windows))]
        let _building = lock(self.state_dir.join("runtimes").join(format!("{}.lock", spec.hash()))).await?;
        if !venv.join(".ready").exists() {
            let Some(uv) = which("uv") else {
                bail!(
                    "the local backend builds its runtime with uv; install it (https://docs.astral.sh/uv/), \
                     pass --python with an existing interpreter, or use --sandbox docker"
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
        Ok(python)
    }

    fn command(&self, job: &PreparedJob) -> Result<Command> {
        let python = self.python.as_ref().context("local backend was not prepared")?;
        #[cfg(target_os = "linux")]
        if self.opts.sandboxed {
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
        // -I: the shim's own folder is not importable, nor PYTHON* honoured.
        c.arg("-I")
            .arg(&self.shim)
            .arg("--work")
            .arg(job.work_dir())
            .args(["--entry", &job.entry, "--timeout", &job.timeout_s.to_string()])
            .arg("--result")
            .arg(job.meta_dir().join("result.json"))
            .arg("--out")
            .arg(job.out_dir())
            .args(["--memory-mb", &job.memory_mb.to_string()]);
        for name in &self.opts.pass_env {
            c.args(["--pass-env", name]);
        }
        Ok(c)
    }

    pub async fn run(&self, job: &PreparedJob, cancel: watch::Receiver<bool>) -> Result<RawResult> {
        let mut cmd = self.command(job)?;
        // The sandboxed path builds its own environment inside the namespaces.
        base_env(&mut cmd, if self.opts.sandboxed { &[] } else { &self.opts.pass_env });
        cmd.current_dir(&job.root)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        // Its own process group, so a stop reaches the shim (and on Linux the
        // namespace init) but not the runner.
        #[cfg(unix)]
        cmd.process_group(0);
        // On Windows the shim starts suspended and runs only once it is in
        // its Job Object, so nothing it starts is ever outside it.
        #[cfg(windows)]
        let winjob = if self.opts.process {
            cmd.creation_flags(super::winjob::SUSPENDED);
            Some(super::winjob::WinJob::new(job.memory_mb)?)
        } else {
            None
        };
        let mut child = cmd.spawn().context("could not start the sandbox")?;
        let pid = child.id();
        #[cfg(windows)]
        if let Some(j) = &winjob {
            let adopted = match (child.raw_handle(), pid) {
                (Some(h), Some(pid)) => j.adopt(h as _, pid),
                _ => Err(anyhow::anyhow!("the shim exited before it could start")),
            };
            if let Err(e) = adopted {
                let _ = child.start_kill();
                return Err(e.context("could not put the job in a Job Object"));
            }
        }
        let deadline = std::time::Duration::from_secs(job.timeout_s as u64) + KILL_GRACE;
        #[cfg(unix)]
        let (stop, kill) = (async { super::signal_group(pid, nix::sys::signal::Signal::SIGTERM) }, async {
            super::signal_group(pid, nix::sys::signal::Signal::SIGKILL)
        });
        // Windows has no polite stop: the Job Object ends the whole tree.
        #[cfg(windows)]
        let (stop, kill) = (
            async {
                if let Some(j) = &winjob {
                    j.terminate();
                }
            },
            async {},
        );
        #[cfg(not(any(unix, windows)))]
        let (stop, kill) = (async {}, async {});
        let _ = pid;
        let waited = supervise(&mut child, deadline, cancel, stop, kill).await?;
        let mut stderr = String::new();
        if let Some(mut e) = child.stderr.take() {
            use tokio::io::AsyncReadExt;
            let _ = e.read_to_string(&mut stderr).await;
        }
        let shim = read_shim_result(job);
        #[allow(unused_mut)]
        let (mut peak_mem_kb, mut oom_killed) = (None, false);
        #[cfg(windows)]
        if let Some(j) = winjob {
            peak_mem_kb = Some(j.peak_kb());
            // Windows refused an allocation at the cap, and the job then failed.
            oom_killed =
                j.hit_memory_limit() && shim.as_ref().is_some_and(|s| s.exit_code.is_some_and(|c| c != 0));
            // Dropping the job kills anything the job left running.
            drop(j);
        }
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
            oom_killed,
            peak_mem_kb,
            error,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_package_importing_from_outside_its_install_is_flagged() {
        let info: PythonInfo = serde_json::from_str(
            r#"{"version": "3.12.4", "missing": [], "executable": "/v/bin/python", "packages": [
                {"name": "numpy", "version": "2.1.0", "location": "/v/lib/site-packages",
                 "imports": [{"module": "numpy", "origin": "/v/lib/site-packages/numpy/__init__.py"}]},
                {"name": "cugrid", "version": "0.3.0", "location": "/v/lib/site-packages", "editable": true,
                 "source": "file:///src/cugrid",
                 "imports": [{"module": "cugrid", "origin": "/src/cugrid/cugrid/__init__.py"},
                             {"module": "gone", "origin": null}]}]}"#,
        )
        .unwrap();
        assert!(info.packages[0].elsewhere().is_empty());
        let out: Vec<_> = info.packages[1].elsewhere().iter().map(|m| m.module.as_str()).collect();
        assert_eq!(out, ["cugrid"]);
        // What older probes (and runners) report still parses.
        let old: PythonInfo = serde_json::from_str(r#"{"version": "3.12.4", "missing": ["x"]}"#).unwrap();
        assert!(old.packages.is_empty() && old.executable.is_none());
    }

    /// Some Python 3 on PATH to run the embedded scripts with, if any.
    fn some_python() -> Option<PathBuf> {
        which("python3").or_else(|| which("python"))
    }

    #[tokio::test]
    async fn the_probe_runs_and_reports_what_is_missing() {
        let Some(py) = some_python() else { return };
        let none = probe_python(&py, &[], &[]).await.unwrap();
        assert!(none.missing.is_empty() && none.packages.is_empty() && none.executable.is_some());
        let info = probe_python(&py, &["airlox-no-such-package".into()], &[]).await.unwrap();
        assert_eq!(info.missing, ["airlox-no-such-package"]);
    }

    #[tokio::test]
    async fn the_footprint_script_measures_and_names_failed_imports() {
        let Some(py) = some_python() else { return };
        let mut cmd = Command::new(&py);
        base_env(&mut cmd, &[]);
        let out =
            cmd.args(["-I", "-c", FOOTPRINT_PY, "json", "airlox_no_such_module"]).output().await.unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(v["failed"], serde_json::json!(["airlox_no_such_module (ModuleNotFoundError)"]));
        if cfg!(unix) {
            assert!(v["peak_mb"].as_u64().unwrap() > 0, "{v}");
        }
    }
}
