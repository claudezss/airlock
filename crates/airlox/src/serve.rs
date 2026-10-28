//! `airlox runner serve` and `airlox runner install-service`: a runner that
//! stays up.
//!
//! `serve` is `runner join` that starts again after a failure, with backoff,
//! and can log to a file. It claims a `--code` once, before the first start,
//! and restarts from the invite it saved. A runner already keeps a finished
//! job's answer until the relay has it, so a restart in the middle of a job
//! loses nothing (protocol §8).
//!
//! `install-service` claims the code (or copies the invite) into a file only
//! this user can read, then writes and starts a `systemd --user` unit (Linux)
//! or a launchd agent (macOS) that runs `serve`. On Windows it is `runner
//! service install`.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use crate::runner::{self, JoinArgs};

#[derive(clap::Args, Debug)]
pub struct ServeArgs {
    /// Append the runner's log here instead of printing it.
    #[arg(long)]
    pub log_file: Option<PathBuf>,
    #[command(flatten)]
    pub join: JoinArgs,
}

#[derive(clap::Args, Debug)]
pub struct InstallArgs {
    /// The service's name (default: airlox-runner-<runner name>).
    #[arg(long)]
    pub service_name: Option<String>,
    /// Write the service without starting it.
    #[arg(long)]
    pub no_start: bool,
    #[command(flatten)]
    pub join: JoinArgs,
}

/// Longest pause between two starts.
const MAX_BACKOFF: Duration = Duration::from_secs(300);
/// A run this long resets the backoff: it was working.
const HEALTHY: Duration = Duration::from_secs(600);

/// The pause before start number `failures + 1`: 2 s, doubling, at most 5 min.
fn backoff(failures: u32) -> Duration {
    Duration::from_secs(2u64.saturating_mul(1 << failures.min(10))).min(MAX_BACKOFF)
}

pub async fn serve(a: ServeArgs) -> Result<()> {
    let mut args = a.join;
    // Claim the code once; every start after that uses the invite it saved.
    if args.code.is_some() && args.invite_file.is_none() {
        let root = args.cache_dir.clone().unwrap_or_else(runner::default_cache_root);
        let (_, saved) = runner::claim_code(&crate::client::http()?, &args, &root).await?;
        args.code = None;
        args.invite = None;
        args.invite_file = Some(saved);
    }
    let mut failures = 0u32;
    let mut stop = runner::SHUTDOWN.subscribe();
    loop {
        let started = Instant::now();
        match runner::run(args.clone()).await {
            // The session ended, the runner was turned away, or it was told to stop.
            Ok(()) => return Ok(()),
            Err(e) => {
                if *stop.borrow() {
                    return Err(e);
                }
                if started.elapsed() >= HEALTHY {
                    failures = 0;
                }
                let pause = backoff(failures);
                failures = failures.saturating_add(1);
                tracing::error!("the runner stopped: {e:#}; starting again in {} s", pause.as_secs());
                tokio::select! {
                    _ = tokio::time::sleep(pause) => {}
                    _ = tokio::signal::ctrl_c() => return Err(e),
                    _ = stop.wait_for(|s| *s) => return Err(e),
                }
            }
        }
    }
}

/// The `runner join` flags given to `install-service` that the service
/// passes on to `serve`: everything but where the invite comes from.
fn passthrough(raw: &[OsString]) -> Vec<OsString> {
    // Flags `install-service` consumes itself, and whether each takes a value.
    const DROP: &[(&str, bool)] = &[
        ("--invite", true),
        ("--invite-file", true),
        ("--code", true),
        ("--service-name", true),
        ("--no-start", false),
    ];
    let start = raw.iter().position(|a| a == "install-service").map_or(raw.len(), |i| i + 1);
    let mut out = Vec::new();
    let mut it = raw[start..].iter();
    while let Some(a) = it.next() {
        let s = a.to_string_lossy();
        let flag = s.split_once('=').map_or(s.as_ref(), |(f, _)| f);
        match DROP.iter().find(|(f, _)| *f == flag) {
            Some((_, takes_value)) => {
                if *takes_value && !s.contains('=') {
                    it.next();
                }
            }
            None => out.push(a.clone()),
        }
    }
    out
}

/// `s` as one word for a systemd `ExecStart=` line.
fn systemd_quote(s: &str) -> String {
    if !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || "-_./:@=+,".contains(c)) {
        s.to_string()
    } else {
        format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"").replace('%', "%%").replace('$', "$$"))
    }
}

/// `s` as one value for a systemd `Environment=` line, which expands `%`
/// specifiers but not `$`.
fn systemd_env_quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"").replace('%', "%%"))
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// A `systemd --user` unit running `argv` with `PATH` set to `path`: a user
/// manager's own PATH leaves out `~/.local/bin` and the like, where `uv`
/// and a job's tools often are.
pub fn systemd_unit(name: &str, argv: &[String], path: Option<&str>) -> String {
    let exec: Vec<String> = argv.iter().map(|a| systemd_quote(a)).collect();
    let env =
        path.map_or(String::new(), |p| format!("Environment={}\n", systemd_env_quote(&format!("PATH={p}"))));
    format!(
        "[Unit]\nDescription=Airlox runner {name}\nWants=network-online.target\nAfter=network-online.target\n\n\
         [Service]\n{env}ExecStart={}\nRestart=on-failure\nRestartSec=10\n\n[Install]\nWantedBy=default.target\n",
        exec.join(" ")
    )
}

/// A launchd agent running `argv` with `PATH` set to `path` (launchd's is
/// `/usr/bin:/bin:/usr/sbin:/sbin`), kept alive while it fails.
pub fn launchd_plist(label: &str, argv: &[String], path: Option<&str>, log: &Path) -> String {
    let args: String = argv.iter().map(|a| format!("    <string>{}</string>\n", xml_escape(a))).collect();
    let env = path.map_or(String::new(), |p| {
        format!(
            "<key>EnvironmentVariables</key>\n  <dict>\n    <key>PATH</key>\n    <string>{}</string>\n  </dict>\n  ",
            xml_escape(p)
        )
    });
    let log = xml_escape(&log.display().to_string());
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n<dict>\n  <key>Label</key>\n  <string>{}</string>\n  \
         <key>ProgramArguments</key>\n  <array>\n{args}  </array>\n  {env}<key>RunAtLoad</key>\n  <true/>\n  \
         <key>KeepAlive</key>\n  <dict>\n    <key>SuccessfulExit</key>\n    <false/>\n  </dict>\n  \
         <key>ThrottleInterval</key>\n  <integer>10</integer>\n  <key>StandardOutPath</key>\n  <string>{log}</string>\n  \
         <key>StandardErrorPath</key>\n  <string>{log}</string>\n</dict>\n</plist>\n",
        xml_escape(label)
    )
}

fn check_service_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 80
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
    if !ok {
        bail!("{name:?} is not a valid service name: use up to 80 of [A-Za-z0-9._-]");
    }
    Ok(())
}

fn run_ok(cmd: &str, args: &[&str]) -> Result<()> {
    let out = std::process::Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("could not run {cmd}"))?;
    if !out.status.success() {
        bail!("{cmd} {} failed: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

pub async fn install(a: InstallArgs) -> Result<()> {
    #[cfg(windows)]
    {
        let _ = a;
        bail!("on Windows, install the runner as a service with `airlox runner service install` (elevated)");
    }
    #[cfg(not(windows))]
    {
        let service = a.service_name.clone().unwrap_or_else(|| format!("airlox-runner-{}", a.join.name));
        check_service_name(&service)?;
        let root = a.join.cache_dir.clone().unwrap_or_else(runner::default_cache_root);
        let http = crate::client::http()?;
        // The invite first: a code works once, so nothing below may need another.
        let invite_file = match (&a.join.code, &a.join.invite_file) {
            (Some(_), None) => runner::claim_code(&http, &a.join, &root).await?.1,
            _ => {
                let link = runner::invite_link(&http, &a.join, &root).await?;
                let invite = airlox_core::invite::Invite::parse(&link).context("not a valid invite link")?;
                if invite.role != airlox_core::session::Role::Runner {
                    bail!("this is a {} invite; runners need the runner invite", invite.role.as_str());
                }
                let dir = root.join("services").join(&service);
                std::fs::create_dir_all(&dir)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
                }
                let path = dir.join("invite-runner.txt");
                crate::view::write_atomic(&path, format!("{link}\n").as_bytes(), 0o600)?;
                path
            }
        };
        let logs = root.join("runner").join("logs");
        std::fs::create_dir_all(&logs)?;
        let log = logs.join(format!("{service}.log"));
        let exe = std::env::current_exe()?;
        let exe_text = exe.display().to_string();
        if exe_text.contains("/_npx/") || exe_text.contains("/.cache/uv/") || exe_text.contains("/target/") {
            eprintln!(
                "note: the service runs {exe_text}, which may not stay there; install airlox somewhere stable \
                 (cargo install, pipx, a package) and install the service from that binary"
            );
        }
        let mut argv: Vec<String> = vec![exe_text, "runner".into(), "serve".into()];
        argv.extend(["--invite-file".into(), invite_file.display().to_string()]);
        if a.join.cache_dir.is_none() {
            argv.extend(["--cache-dir".into(), root.display().to_string()]);
        }
        let raw: Vec<OsString> = std::env::args_os().collect();
        argv.extend(passthrough(&raw).into_iter().map(|a| a.to_string_lossy().into_owned()));
        let home = std::env::var_os("HOME").map(PathBuf::from).context("HOME is not set")?;
        // The service finds `uv`, `docker` and a job's tools where this shell does.
        let env_path = std::env::var("PATH").ok().filter(|p| !p.is_empty());
        if cfg!(target_os = "macos") {
            let label = format!("app.airlox.{service}");
            let path = home.join("Library/LaunchAgents").join(format!("{label}.plist"));
            std::fs::create_dir_all(path.parent().expect("has a parent"))?;
            std::fs::write(&path, launchd_plist(&label, &argv, env_path.as_deref(), &log))?;
            eprintln!("Wrote {}.", path.display());
            if !a.no_start {
                let uid = nix::unistd::getuid().as_raw();
                // Replace a loaded copy; a missing one is fine.
                let _ = run_ok("launchctl", &["bootout", &format!("gui/{uid}/{label}")]);
                run_ok("launchctl", &["bootstrap", &format!("gui/{uid}"), &path.display().to_string()])?;
                eprintln!("Started {label}. It starts again at login and after a failure.");
            } else {
                eprintln!("Start it with: launchctl bootstrap gui/$(id -u) '{}'", path.display());
            }
        } else {
            let dir = std::env::var_os("XDG_CONFIG_HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| home.join(".config"))
                .join("systemd/user");
            std::fs::create_dir_all(&dir)?;
            let path = dir.join(format!("{service}.service"));
            let mut argv = argv;
            argv.extend(["--log-file".into(), log.display().to_string()]);
            std::fs::write(&path, systemd_unit(&a.join.name, &argv, env_path.as_deref()))?;
            eprintln!("Wrote {}.", path.display());
            if !a.no_start {
                let unit = format!("{service}.service");
                run_ok("systemctl", &["--user", "daemon-reload"])?;
                run_ok("systemctl", &["--user", "enable", &unit])?;
                // Restart, not start: a copy already running keeps its old flags otherwise.
                run_ok("systemctl", &["--user", "restart", &unit])?;
                eprintln!(
                    "Started {service}. To keep it running after you log out: loginctl enable-linger $USER"
                );
            } else {
                eprintln!("Start it with: systemctl --user enable --now {service}");
            }
        }
        eprintln!("Log: {}", log.display());
        eprintln!("The session owner approves it once it joins (`airlox machine add` does that by itself).");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_up_to_five_minutes() {
        assert_eq!(backoff(0), Duration::from_secs(2));
        assert_eq!(backoff(1), Duration::from_secs(4));
        assert_eq!(backoff(7), Duration::from_secs(256));
        assert_eq!(backoff(8), MAX_BACKOFF);
        assert_eq!(backoff(40), MAX_BACKOFF);
    }

    #[test]
    fn the_service_gets_the_join_flags_but_not_the_invite() {
        let raw: Vec<OsString> = [
            "airlox",
            "runner",
            "install-service",
            "--code",
            "7-a-b",
            "--name",
            "gpu-box",
            "--service-name=x",
            "--labels",
            "gpu",
            "--no-start",
            "--concurrency",
            "4",
            "--workspace",
        ]
        .iter()
        .map(OsString::from)
        .collect();
        let got: Vec<String> = passthrough(&raw).iter().map(|a| a.to_string_lossy().into_owned()).collect();
        assert_eq!(got, ["--name", "gpu-box", "--labels", "gpu", "--concurrency", "4", "--workspace"]);
    }

    #[test]
    fn units_quote_what_needs_it() {
        let argv = vec![
            "/usr/bin/airlox".to_string(),
            "runner".into(),
            "--description".into(),
            "A100 $5 \"x\"".into(),
        ];
        let unit = systemd_unit("gpu-box", &argv, None);
        assert!(
            unit.contains(r#"ExecStart=/usr/bin/airlox runner --description "A100 $$5 \"x\"""#),
            "{unit}"
        );
        assert!(unit.contains("Restart=on-failure"));
        assert!(!unit.contains("Environment="), "{unit}");
        let plist = launchd_plist("app.airlox.r", &argv, None, Path::new("/tmp/r.log"));
        assert!(plist.contains("<string>A100 $5 &quot;x&quot;</string>"), "{plist}");
        assert!(plist.contains("<key>SuccessfulExit</key>\n    <false/>"), "{plist}");
        assert!(!plist.contains("EnvironmentVariables"), "{plist}");
    }

    #[test]
    fn services_keep_the_installers_path() {
        let argv = vec!["/usr/bin/airlox".to_string(), "runner".into(), "serve".into()];
        let path = "/home/me/.local/bin:/opt/50%/bin:/usr/bin";
        let unit = systemd_unit("gpu-box", &argv, Some(path));
        assert!(
            unit.contains(
                "[Service]\nEnvironment=\"PATH=/home/me/.local/bin:/opt/50%%/bin:/usr/bin\"\nExecStart="
            ),
            "{unit}"
        );
        let plist = launchd_plist("app.airlox.r", &argv, Some("/a&b:/usr/bin"), Path::new("/tmp/r.log"));
        assert!(
            plist.contains(
                "<key>EnvironmentVariables</key>\n  <dict>\n    <key>PATH</key>\n    <string>/a&amp;b:/usr/bin</string>\n  </dict>\n  <key>RunAtLoad</key>"
            ),
            "{plist}"
        );
    }
}
