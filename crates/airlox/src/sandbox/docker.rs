//! The docker backend: a fresh container per job, driven through the
//! `docker` CLI.
//!
//! `prepare` builds `airlox-rt:<hash>` once, with network, from
//! `python:<version>-slim` plus the session's package allowlist. Each job then
//! runs with no network, a read-only root, all capabilities dropped,
//! `no-new-privileges`, memory, CPU and process limits, and only `/work`,
//! `/out` and `/meta` mounted writable.
//!
//! The shim and the job share a user inside the container, so a job can
//! overwrite `/meta/result.json`. That only lets it misreport its own
//! outcome; the runner measures wall time and enforces the timeout itself,
//! and reads OOM kills from docker.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{bail, Context, Result};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::sync::watch;

use super::{read_shim_result, supervise, PreparedJob, RawResult, RuntimeSpec, KILL_GRACE};

pub struct Docker {
    /// The docker CLI.
    pub bin: String,
    /// Use this image instead of building one (`--image`).
    pub image: Option<String>,
    pub cpus: String,
    pub pids_limit: u32,
    /// e.g. "runsc" for gVisor.
    pub runtime: Option<String>,
    /// The embedded shim, written once at prepare time.
    shim: PathBuf,
    resolved_image: Option<String>,
}

async fn docker_ok(bin: &str, args: &[&str]) -> Result<bool> {
    Ok(Command::new(bin)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .with_context(|| format!("could not run {bin}; is Docker installed?"))?
        .success())
}

impl Docker {
    pub fn new(
        bin: String,
        image: Option<String>,
        cpus: String,
        runtime: Option<String>,
        state_dir: &Path,
    ) -> Self {
        Docker {
            bin,
            image,
            cpus,
            pids_limit: 256,
            runtime,
            shim: state_dir.join("shim.py"),
            resolved_image: None,
        }
    }

    pub fn dockerfile(spec: &RuntimeSpec) -> String {
        let mut f = format!("FROM python:{}-slim\n", spec.python_version());
        if !spec.packages.is_empty() {
            f += &format!(
                // Wheels only: no build scripts from the session's packages.
                "RUN pip install --no-cache-dir --disable-pip-version-check --only-binary :all: {}\n",
                spec.packages.join(" ")
            );
        }
        // Writable paths are mounts; give them a home in the image.
        f += "RUN mkdir -p /work /out /meta /airlox\n";
        f
    }

    pub async fn prepare(&mut self, spec: &RuntimeSpec) -> Result<()> {
        if !docker_ok(&self.bin, &["version"]).await? {
            bail!("`{} version` failed; is the Docker daemon running and reachable?", self.bin);
        }
        if let Some(parent) = self.shim.parent() {
            std::fs::create_dir_all(parent)?;
        }
        crate::view::write_atomic(&self.shim, airlox_core::shim::SHIM_PY.as_bytes(), 0o644)?;
        if let Some(img) = &self.image {
            if !docker_ok(&self.bin, &["image", "inspect", img]).await? {
                bail!("image {img} not found locally; pull it first");
            }
            self.resolved_image = Some(img.clone());
            return Ok(());
        }
        let tag = format!("airlox-rt:{}", spec.hash());
        if !docker_ok(&self.bin, &["image", "inspect", &tag]).await? {
            tracing::info!(image = %tag, packages = ?spec.packages, "building the job runtime image");
            let mut child = Command::new(&self.bin)
                .args(["build", "--quiet", "-t", &tag, "-"])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()?;
            let mut stdin = child.stdin.take().expect("piped");
            stdin.write_all(Self::dockerfile(spec).as_bytes()).await?;
            drop(stdin);
            let out = child.wait_with_output().await?;
            if !out.status.success() {
                bail!("building {tag} failed:\n{}", String::from_utf8_lossy(&out.stderr));
            }
        }
        self.resolved_image = Some(tag);
        Ok(())
    }

    fn container_name(job: &PreparedJob) -> String {
        let safe: String = job.id.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).collect();
        format!("airlox-job-{safe}")
    }

    fn user() -> String {
        #[cfg(unix)]
        {
            let (uid, gid) = (nix::unistd::getuid().as_raw(), nix::unistd::getgid().as_raw());
            // Never run jobs as root, even when the runner is.
            if uid == 0 {
                return "65534:65534".into();
            }
            format!("{uid}:{gid}")
        }
        #[cfg(not(unix))]
        "65534:65534".into()
    }

    /// The full `docker run` argument list for a job.
    pub fn run_args(&self, job: &PreparedJob, image: &str) -> Vec<String> {
        let mount = |src: PathBuf, dst: &str, ro: bool| {
            format!("type=bind,source={},target={dst}{}", src.display(), if ro { ",readonly" } else { "" })
        };
        let mem = format!("{}m", job.memory_mb);
        let mut a: Vec<String> = vec![
            "run".into(),
            "--name".into(),
            Self::container_name(job),
            "--network".into(),
            (if job.network { "bridge" } else { "none" }).into(),
            "--memory".into(),
            mem.clone(),
            "--memory-swap".into(),
            mem,
            "--cpus".into(),
            self.cpus.clone(),
            "--pids-limit".into(),
            self.pids_limit.to_string(),
            "--ulimit".into(),
            "nofile=1024:1024".into(),
            "--read-only".into(),
            "--tmpfs".into(),
            "/tmp:rw,nosuid,nodev,size=64m".into(),
            "--cap-drop".into(),
            "ALL".into(),
            "--security-opt".into(),
            "no-new-privileges".into(),
            "--user".into(),
            Self::user(),
            "--workdir".into(),
            "/work".into(),
            "--mount".into(),
            mount(job.work_dir(), "/work", false),
            "--mount".into(),
            mount(job.out_dir(), "/out", false),
            "--mount".into(),
            mount(job.meta_dir(), "/meta", false),
            "--mount".into(),
            mount(self.shim.clone(), "/airlox/shim.py", true),
        ];
        if let Some(rt) = &self.runtime {
            a.push("--runtime".into());
            a.push(rt.clone());
        }
        a.push(image.into());
        a.extend(
            [
                "python3",
                "/airlox/shim.py",
                "--work",
                "/work",
                "--entry",
                &job.entry,
                "--timeout",
                &job.timeout_s.to_string(),
                "--result",
                "/meta/result.json",
                "--out",
                "/out",
            ]
            .map(String::from),
        );
        a
    }

    pub async fn run(&self, job: &PreparedJob, cancel: watch::Receiver<bool>) -> Result<RawResult> {
        let image = self.resolved_image.as_deref().context("docker backend was not prepared")?;
        let name = Self::container_name(job);
        // A leftover container from a crashed runner would block the name.
        let _ = docker_ok(&self.bin, &["rm", "-f", &name]).await;
        let mut child = Command::new(&self.bin)
            .args(self.run_args(job, image))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .context("could not start docker")?;
        let deadline = std::time::Duration::from_secs(job.timeout_s as u64) + KILL_GRACE;
        let stop = async {
            let _ = docker_ok(&self.bin, &["kill", "--signal", "TERM", &name]).await;
        };
        let kill = async {
            let _ = docker_ok(&self.bin, &["kill", &name]).await;
        };
        let waited = supervise(&mut child, deadline, cancel, stop, kill).await?;
        let mut stderr = String::new();
        if let Some(mut e) = child.stderr.take() {
            use tokio::io::AsyncReadExt;
            let _ = e.read_to_string(&mut stderr).await;
        }
        let oom = Command::new(&self.bin)
            .args(["inspect", "--format", "{{.State.OOMKilled}}", &name])
            .output()
            .await
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "true")
            .unwrap_or(false);
        let _ = docker_ok(&self.bin, &["rm", "-f", &name]).await;
        let shim = read_shim_result(job);
        let error = match (&shim, waited.status) {
            (None, Some(s)) if !s.success() && !waited.cancelled && !waited.killed_on_timeout && !oom => {
                Some(format!("container failed ({s}): {}", stderr.trim()))
            }
            _ => None,
        };
        Ok(RawResult {
            shim,
            wall_ms: waited.wall_ms,
            killed_on_timeout: waited.killed_on_timeout,
            cancelled: waited.cancelled,
            oom_killed: oom,
            error,
        })
    }
}
