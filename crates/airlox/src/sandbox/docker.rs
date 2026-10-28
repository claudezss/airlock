//! The docker backend: a fresh container per job, driven through the
//! `docker` CLI.
//!
//! `prepare` builds `airlox-rt:<hash>` once, with network, from
//! `python:<version>-slim` plus the session's package allowlist, or, with an
//! operator's `--image`, pins that image by digest and offers shell jobs in
//! it (the shim is Python, so the image needs `python3`). Each job then
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

use airlox_core::cert::SandboxKind;
use airlox_core::payload::JobEnv;
use anyhow::{bail, Context, Result};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::sync::watch;

use super::local::{PythonInfo, PROBE_PY};
use super::{read_shim_result, supervise, PreparedJob, RawResult, RuntimeSpec, KILL_GRACE};

/// An image as jobs run it: the reference `docker run` gets, and the label
/// that goes in results.
#[derive(Debug, PartialEq, Eq)]
struct Pin {
    run: String,
    /// `docker:<repo>@sha256:<digest>`.
    label: String,
}

impl Pin {
    /// From `image` as the operator named it and `docker image inspect
    /// --format '{{.Id}} {{json .RepoDigests}}'`.
    fn parse(image: &str, inspected: &str) -> Result<Pin> {
        let (id, digests) = inspected.trim().split_once(' ').context("unexpected answer from docker")?;
        let digests: Vec<String> = serde_json::from_str(digests).unwrap_or_default();
        let repo = image_repo(image);
        // A tag is not a pin; the digest of this repository's pull is.
        let digest = digests
            .iter()
            .find(|d| d.split('@').next() == Some(repo))
            .or_else(|| digests.first())
            .cloned()
            .or_else(|| image.contains("@sha256:").then(|| image.to_string()));
        Ok(match digest {
            Some(d) => Pin { label: format!("docker:{d}"), run: d },
            None => {
                // Never pulled (built here): the content id still names it.
                anyhow::ensure!(id.starts_with("sha256:"), "docker reported no image id");
                Pin { label: format!("docker:{repo}@{id}"), run: id.to_string() }
            }
        })
    }
}

/// `ghcr.io/me/ci` from `ghcr.io/me/ci:latest` or `ghcr.io/me/ci@sha256:…`
/// (a registry's port colon is before the last slash, and stays).
fn image_repo(image: &str) -> &str {
    let image = image.split('@').next().unwrap_or(image);
    match image.rsplit_once(':') {
        Some((repo, tag)) if !tag.contains('/') => repo,
        _ => image,
    }
}

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
    /// Where jobs run, measured once in `prepare`.
    env: Option<JobEnv>,
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
            env: None,
        }
    }

    /// Where jobs run (see [`super::Backend::env`]).
    pub fn env(&self) -> Option<JobEnv> {
        self.env.clone()
    }

    /// Shell jobs run in the operator's image; the image built from the
    /// allowlist has no toolchain to offer them.
    pub fn shell(&self) -> Option<&'static str> {
        self.image.as_ref().map(|_| "sh")
    }

    pub fn dockerfile(spec: &RuntimeSpec) -> String {
        let mut f = format!("FROM python:{}-slim\n", spec.python_version());
        if !spec.packages.is_empty() {
            // Entries are validated to name characters and PEP 440 operators
            // and versions (`numpy>=1.26,<3`): quoted, the shell leaves
            // `<` and `>` alone.
            let quoted: Vec<String> = spec.packages.iter().map(|p| format!("'{p}'")).collect();
            f += &format!(
                // Wheels only: no build scripts from the session's packages.
                "RUN pip install --no-cache-dir --disable-pip-version-check --only-binary :all: {}\n",
                quoted.join(" ")
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
        if let Some(img) = self.image.clone() {
            if !docker_ok(&self.bin, &["image", "inspect", &img]).await? {
                bail!("image {img} not found locally; pull it first");
            }
            // Jobs run the image as it is now, however its tag moves later.
            let pin = self.pin_image(&img).await.with_context(|| format!("pinning image {img}"))?;
            // The image is the operator's: nothing installs into it, so
            // check it against the session's pins like --python.
            let info = self.probe_image(&img, spec).await.with_context(|| format!("checking image {img}"))?;
            if !info.missing.is_empty() {
                tracing::warn!(
                    "image {img} lacks packages the session allows: {}; jobs that import them will fail",
                    info.missing.join(", ")
                );
            }
            let conflicts = spec.pin_conflicts("the image", &info.packages);
            if !conflicts.is_empty() {
                bail!(
                    "{}. Use an image with the pinned versions, or leave out --image to build one",
                    conflicts.join("; ")
                );
            }
            self.set_env(&info, &pin.label);
            self.resolved_image = Some(pin.run);
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
        match self.probe_image(&tag, spec).await {
            Ok(info) => self.set_env(&info, &format!("docker:{tag}")),
            Err(e) => tracing::warn!("could not read the installed versions from {tag}: {e:#}"),
        }
        self.resolved_image = Some(tag);
        Ok(())
    }

    /// The image's digest, from docker: a pulled image's repo digest, else
    /// (a locally built one) its content id.
    async fn pin_image(&self, image: &str) -> Result<Pin> {
        let out = Command::new(&self.bin)
            .args(["image", "inspect", "--format", "{{.Id}} {{json .RepoDigests}}", image])
            .stdin(Stdio::null())
            .output()
            .await
            .context("could not run docker")?;
        if !out.status.success() {
            bail!("docker image inspect failed:\n{}", String::from_utf8_lossy(&out.stderr).trim());
        }
        Pin::parse(image, &String::from_utf8_lossy(&out.stdout))
    }

    /// `interpreter` is the label results carry, such as `docker:repo@sha256:…`.
    fn set_env(&mut self, info: &PythonInfo, interpreter: &str) {
        self.env = Some(super::job_env(
            &info.version,
            info.packages.iter().map(|p| (p.name.clone(), p.version.clone())),
            SandboxKind::Docker,
            interpreter,
        ));
    }

    /// What the image's `python3` reports about itself and the allowlisted
    /// packages (read from their metadata; nothing is imported), in a
    /// throwaway container with no network.
    async fn probe_image(&self, image: &str, spec: &RuntimeSpec) -> Result<PythonInfo> {
        let mut cmd = Command::new(&self.bin);
        cmd.args(["run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL"])
            .args(["--security-opt", "no-new-privileges", "--memory", "256m", "--pids-limit", "64"])
            .args(["--user", &Self::user()]);
        if let Some(rt) = &self.runtime {
            cmd.args(["--runtime", rt]);
        }
        cmd.arg(image).args(["python3", "-I", "-c", PROBE_PY]).args(spec.names());
        let out = tokio::time::timeout(
            std::time::Duration::from_secs(120),
            cmd.stdin(Stdio::null()).kill_on_drop(true).output(),
        )
        .await
        .context("python3 in the image did not answer within 120 s")?
        .context("could not run docker")?;
        if !out.status.success() {
            let said = String::from_utf8_lossy(&out.stderr);
            if matches!(out.status.code(), Some(126 | 127)) || said.contains("executable file not found") {
                bail!(
                    "the image has no python3: airlox's job shim is a Python script, so every image it runs \
                     needs python3 (3.8 or newer), shell jobs included. Add it to the image\n{}",
                    said.trim()
                );
            }
            bail!("python3 failed in the image ({}):\n{}", out.status, said.trim());
        }
        serde_json::from_slice(&out.stdout).context("unexpected answer from python3 in the image")
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
                "--result",
                "/meta/result.json",
                "--out",
                "/out",
            ]
            .map(String::from),
        );
        a.extend(job.shim_job_args("/work", &format!("/meta/{}", super::SCRIPT_FILE)));
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
            peak_mem_kb: None,
            error,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_image_is_pinned_by_the_digest_of_its_repository() {
        let digest = "0123456789abcdef".repeat(4);
        let id = format!("sha256:{}", "f".repeat(64));
        let pulled = format!(r#"{id} ["other/ci@sha256:{}","ghcr.io/me/ci@sha256:{digest}"]"#, "a".repeat(64));
        let pin = Pin::parse("ghcr.io/me/ci:latest", &pulled).unwrap();
        assert_eq!(pin.run, format!("ghcr.io/me/ci@sha256:{digest}"));
        assert_eq!(pin.label, format!("docker:ghcr.io/me/ci@sha256:{digest}"));
        // Built here, never pulled: the content id stands in for a digest.
        let built = Pin::parse("localhost:5000/ci:dev", &format!("{id} []")).unwrap();
        assert_eq!(built.run, id);
        assert_eq!(built.label, format!("docker:localhost:5000/ci@{id}"));
        // And it reads as a short digest in a result's env.
        let env = super::super::job_env("3.12.4", [], SandboxKind::Docker, &built.label);
        assert!(env.interpreter.ends_with("@sha256:ffffffffffff"), "{}", env.interpreter);
        assert!(airlox_core::policy::check_env(&env).is_ok());
        assert!(Pin::parse("ci", "garbage").is_err());
    }

    #[test]
    fn image_names_lose_their_tag_not_their_registry_port() {
        assert_eq!(image_repo("ci"), "ci");
        assert_eq!(image_repo("ci:1.2"), "ci");
        assert_eq!(image_repo("localhost:5000/team/ci"), "localhost:5000/team/ci");
        assert_eq!(image_repo("localhost:5000/team/ci:1.2@sha256:abc"), "localhost:5000/team/ci");
    }

    #[test]
    fn the_dockerfile_installs_pins_through_the_shell_unharmed() {
        let spec = RuntimeSpec {
            runtime: "python3.12".into(),
            packages: vec!["cugrid==0.1.0".into(), "numpy>=1.26,<3".into(), "pandas".into()],
        };
        let f = Docker::dockerfile(&spec);
        assert!(f.contains(" 'cugrid==0.1.0' 'numpy>=1.26,<3' 'pandas'\n"), "{f}");
        let bare = RuntimeSpec { runtime: "python3.12".into(), packages: vec![] };
        assert_eq!(Docker::dockerfile(&bare).lines().count(), 2);
    }
}
