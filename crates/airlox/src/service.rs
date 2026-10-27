//! The runner as a Windows service: `airlox runner service install` and
//! `uninstall`, and `runner join --windows-service`, which the service
//! manager starts.
//!
//! The service runs as its own virtual account (`NT SERVICE\<name>`): not
//! an administrator and not SYSTEM, so the runner's privilege check passes
//! and jobs get no more rights than that account. Everything it keeps (the
//! invite, its identity, the job cache, logs) lives in one data folder that
//! only that account, SYSTEM and administrators can open. The service starts
//! with Windows and the service manager restarts it whenever it exits with
//! an error; a session that ends stops it cleanly.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::runner::JoinArgs;

#[derive(clap::Subcommand, Debug)]
pub enum ServiceCmd {
    /// Install (and start) the runner as a Windows service, from an
    /// elevated prompt. Takes the `runner join` flags; the invite comes from
    /// --invite-file, --code or --invite and is kept where only the service
    /// can read it.
    Install(Box<InstallArgs>),
    /// Stop and remove a runner service. Its data folder is kept unless
    /// --purge is given.
    Uninstall(UninstallArgs),
}

#[derive(clap::Args, Debug)]
pub struct InstallArgs {
    /// The service's name (default: airlox-runner-<runner name>).
    #[arg(long)]
    pub service_name: Option<String>,
    /// The service's data folder (default: %ProgramData%\airlox\<service name>).
    #[arg(long)]
    pub data_dir: Option<PathBuf>,
    /// Install without starting it.
    #[arg(long)]
    pub no_start: bool,
    #[command(flatten)]
    pub join: JoinArgs,
}

#[derive(clap::Args, Debug)]
pub struct UninstallArgs {
    /// The service's name, e.g. airlox-runner-runner-01.
    pub service_name: String,
    /// Also delete its data folder (default: %ProgramData%\airlox\<service name>),
    /// with the saved invite and the runner's identity.
    #[arg(long)]
    pub purge: bool,
    /// The data folder, if install was given --data-dir.
    #[arg(long)]
    pub data_dir: Option<PathBuf>,
}

/// Service names: letters, digits, `-`, `_` and `.`, at most 80.
fn check_service_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 80
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
    if !ok {
        bail!("{name:?} is not a valid service name: use up to 80 of [A-Za-z0-9._-]");
    }
    Ok(())
}

fn default_data_dir(service: &str) -> PathBuf {
    let base = std::env::var_os("ProgramData").map(PathBuf::from).unwrap_or_else(|| r"C:\ProgramData".into());
    base.join("airlox").join(service)
}

/// The `runner join` flags given to `install` that the service passes on:
/// everything but where the invite, cache and service live.
fn passthrough(raw: &[OsString]) -> Vec<OsString> {
    // Flags `install` consumes itself, and whether each takes a value.
    const DROP: &[(&str, bool)] = &[
        ("--invite", true),
        ("--invite-file", true),
        ("--code", true),
        ("--cache-dir", true),
        ("--service-name", true),
        ("--data-dir", true),
        ("--windows-service", true),
        ("--no-start", false),
    ];
    let start = raw.iter().position(|a| a == "install").map_or(raw.len(), |i| i + 1);
    let mut out = Vec::new();
    let mut it = raw[start..].iter();
    while let Some(a) = it.next() {
        let s = a.to_string_lossy();
        let (flag, inline) = match s.split_once('=') {
            Some((f, _)) => (f.to_string(), true),
            None => (s.to_string(), false),
        };
        match DROP.iter().find(|(f, _)| *f == flag) {
            Some((_, takes_value)) => {
                if *takes_value && !inline {
                    it.next();
                }
            }
            None => out.push(a.clone()),
        }
    }
    out
}

/// Run icacls with these arguments.
fn icacls(args: &[&std::ffi::OsStr]) -> Result<()> {
    let out = std::process::Command::new("icacls").args(args).output().context("could not run icacls")?;
    if !out.status.success() {
        bail!(
            "icacls {} failed: {}",
            args.iter().map(|a| a.to_string_lossy()).collect::<Vec<_>>().join(" "),
            String::from_utf8_lossy(&out.stdout).trim()
        );
    }
    Ok(())
}

/// Create `dir` (and `%ProgramData%\airlox` above a default one) owned by
/// Administrators and open only to them and SYSTEM, whatever was there
/// before: anyone may create folders in ProgramData, so one made in advance
/// (or a junction elsewhere) must not keep its creator's access.
fn lock_down(dir: &Path) -> Result<()> {
    for d in dir.ancestors().take(2).collect::<Vec<_>>().into_iter().rev() {
        if std::fs::symlink_metadata(d).is_ok_and(|m| m.file_type().is_symlink()) {
            bail!("{} is a link or junction; remove it and install again", d.display());
        }
    }
    std::fs::create_dir_all(dir)?;
    let admins = "*S-1-5-32-544";
    icacls(&[
        dir.as_os_str(),
        "/setowner".as_ref(),
        admins.as_ref(),
        "/T".as_ref(),
        "/C".as_ref(),
        "/Q".as_ref(),
    ])?;
    icacls(&[dir.as_os_str(), "/reset".as_ref(), "/T".as_ref(), "/C".as_ref(), "/Q".as_ref()])?;
    icacls(&[
        dir.as_os_str(),
        "/inheritance:r".as_ref(),
        "/grant:r".as_ref(),
        "*S-1-5-32-544:(OI)(CI)F".as_ref(),
        "*S-1-5-18:(OI)(CI)F".as_ref(),
        "/Q".as_ref(),
    ])?;
    // The default parent: owned by Administrators, and no one else may add to it.
    if let Some(parent) = dir.parent().filter(|p| p.file_name().is_some_and(|n| n == "airlox")) {
        icacls(&[parent.as_os_str(), "/setowner".as_ref(), admins.as_ref(), "/Q".as_ref()])?;
        icacls(&[
            parent.as_os_str(),
            "/inheritance:r".as_ref(),
            "/grant:r".as_ref(),
            "*S-1-5-32-544:(OI)(CI)F".as_ref(),
            "*S-1-5-18:(OI)(CI)F".as_ref(),
            "*S-1-5-32-545:RX".as_ref(),
            "/Q".as_ref(),
        ])?;
    }
    Ok(())
}

/// Let the service account read and run what `python` needs: its venv and,
/// from `pyvenv.cfg`, the base installation (often under a user profile,
/// which a service account cannot read by default).
fn grant_python(python: &Path, account: &str) -> Result<Vec<PathBuf>> {
    let python = std::path::absolute(python)?;
    let mut dirs = Vec::new();
    let venv = python.parent().and_then(Path::parent).filter(|v| v.join("pyvenv.cfg").is_file());
    match venv {
        Some(v) => {
            dirs.push(v.to_path_buf());
            let cfg = std::fs::read_to_string(v.join("pyvenv.cfg")).unwrap_or_default();
            let home = cfg.lines().find_map(|l| {
                let (k, v) = l.split_once('=')?;
                (k.trim() == "home").then(|| PathBuf::from(v.trim()))
            });
            dirs.extend(home);
        }
        None => dirs.extend(python.parent().map(Path::to_path_buf)),
    }
    let grant = OsString::from(format!("{account}:(OI)(CI)RX"));
    for d in &dirs {
        icacls(&[d.as_os_str(), "/grant".as_ref(), &grant, "/T".as_ref(), "/C".as_ref(), "/Q".as_ref()])?;
    }
    Ok(dirs)
}

pub async fn install(a: InstallArgs) -> Result<()> {
    use windows_service::service::{
        ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl, ServiceFailureActions,
        ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceType,
    };
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let service = a.service_name.clone().unwrap_or_else(|| format!("airlox-runner-{}", a.join.name));
    check_service_name(&service)?;
    if crate::sandbox::winjob::privileged().is_none() {
        bail!("installing a service needs an elevated prompt (Run as administrator)");
    }
    let account = format!(r"NT SERVICE\{service}");
    let data = a.data_dir.clone().unwrap_or_else(|| default_data_dir(&service));

    // The invite first: a code works once, so nothing below may need another.
    let http = crate::client::http()?;
    let link = crate::runner::invite_link(&http, &a.join, &data).await?;
    let invite = airlox_core::invite::Invite::parse(&link).context("not a valid invite link")?;
    if invite.role != airlox_core::session::Role::Runner {
        bail!("this is a {} invite; runners need the runner invite", invite.role.as_str());
    }

    // Keep it at once, where only SYSTEM and administrators can read it
    // until the service account exists and is let in.
    lock_down(&data)?;
    let invite_file = data.join("invite-runner.txt");
    crate::view::write_atomic(&invite_file, link.as_bytes(), 0o600)?;

    // The binary the service runs, where only administrators can change it.
    let exe = std::env::current_exe()?;
    let program_files =
        std::env::var_os("ProgramFiles").map(PathBuf::from).unwrap_or_else(|| r"C:\Program Files".into());
    let installed = program_files.join("airlox").join("airlox.exe");
    if !installed.exists() || std::fs::canonicalize(&exe)? != std::fs::canonicalize(&installed)? {
        std::fs::create_dir_all(installed.parent().expect("has a parent"))?;
        std::fs::copy(&exe, &installed).with_context(|| {
            format!(
                "could not copy airlox to {} (is a runner service using it? stop it first)",
                installed.display()
            )
        })?;
    }

    let mut args: Vec<OsString> =
        vec!["runner".into(), "join".into(), "--windows-service".into(), service.clone().into()];
    args.extend(["--invite-file".into(), invite_file.clone().into_os_string()]);
    args.extend(["--cache-dir".into(), data.join("cache").into_os_string()]);
    args.extend(passthrough(&std::env::args_os().collect::<Vec<_>>()));

    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?;
    let info = ServiceInfo {
        name: service.clone().into(),
        display_name: format!("Airlox runner {}", a.join.name).into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: installed.clone(),
        launch_arguments: args,
        dependencies: vec![],
        account_name: Some(account.clone().into()),
        account_password: None,
    };
    let svc = manager
        .create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
        .with_context(|| {
            format!(
                "could not create service {service} (does it already exist? remove it with `airlox runner \
                 service uninstall {service}`); the invite is saved in {}, so retry with --invite-file",
                invite_file.display()
            )
        })?;
    svc.set_description("Runs airlox jobs for one session; see `airlox runner join --help`.")?;
    // Restart on any failure: after 10 s, 30 s, then every 60 s.
    let restart = |s| ServiceAction {
        action_type: ServiceActionType::Restart,
        delay: std::time::Duration::from_secs(s),
    };
    svc.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(std::time::Duration::from_secs(24 * 3600)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![restart(10), restart(30), restart(60)]),
    })?;
    svc.set_failure_actions_on_non_crash_failures(true)?;
    // Only the privilege every process needs. Service accounts otherwise hold
    // SeImpersonatePrivilege, which a job could use to become SYSTEM (and
    // which the runner refuses to start with).
    let privs = std::process::Command::new("sc.exe")
        .args([OsString::from("privs"), service.clone().into(), "SeChangeNotifyPrivilege".into()])
        .output()
        .context("could not run sc.exe")?;
    if !privs.status.success() {
        bail!("sc.exe privs {service} failed: {}", String::from_utf8_lossy(&privs.stdout).trim());
    }

    // Now the account exists: let it into the data folder.
    let owner = OsString::from(format!("{account}:(OI)(CI)M"));
    icacls(&[data.as_os_str(), "/grant".as_ref(), &owner, "/T".as_ref(), "/Q".as_ref()])?;
    eprintln!("Installed service {service}, running as {account}.");
    eprintln!("Its invite, identity, cache and logs are in {}.", data.display());
    if a.join.invite_file.is_some() {
        eprintln!("The invite is copied there; you can delete the file you passed.");
    }
    if let Some(p) = &a.join.python {
        for d in grant_python(p, &account)? {
            eprintln!("Granted {account} read access to {}.", d.display());
        }
    }
    eprintln!("It also needs read access to anything else jobs use (a simulator's folder, its license).");
    if a.no_start {
        eprintln!("Start it with: sc.exe start {service}");
    } else {
        let svc = manager.open_service(&service, ServiceAccess::START)?;
        svc.start::<&str>(&[]).with_context(|| format!("installed {service}, but it did not start"))?;
        let log = data.join("cache").join("runner").join("logs").join(format!("{service}.log"));
        eprintln!("Started. Log: {}", log.display());
        eprintln!("Check that it joined with `airlox runner list`; the session owner must approve it.");
    }
    Ok(())
}

pub fn uninstall(a: UninstallArgs) -> Result<()> {
    use windows_service::service::{ServiceAccess, ServiceState};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    check_service_name(&a.service_name)?;
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let svc = manager
        .open_service(
            &a.service_name,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )
        .with_context(|| format!("no service {} (or this prompt is not elevated)", a.service_name))?;
    if svc.query_status()?.current_state != ServiceState::Stopped {
        let _ = svc.stop();
        for _ in 0..60 {
            if svc.query_status()?.current_state == ServiceState::Stopped {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    }
    svc.delete()?;
    eprintln!("Removed service {}.", a.service_name);
    let data = a.data_dir.unwrap_or_else(|| default_data_dir(&a.service_name));
    if a.purge {
        std::fs::remove_dir_all(&data).with_context(|| format!("could not delete {}", data.display()))?;
        eprintln!("Deleted {}.", data.display());
    } else if data.exists() {
        eprintln!("Kept {} (the saved invite and identity); --purge deletes it.", data.display());
    }
    Ok(())
}

/// The join flags `main` parsed, for the service's own thread.
static ARGS: std::sync::Mutex<Option<JoinArgs>> = std::sync::Mutex::new(None);

/// The service entry point the dispatcher calls. The macro's FFI glue is
/// the only unsafe code here.
#[allow(unsafe_code)]
mod ffi {
    windows_service::define_windows_service!(ffi_service_main, service_main);

    fn service_main(_args: Vec<std::ffi::OsString>) {
        super::service_main();
    }

    pub fn main_fn() -> extern "system" fn(u32, *mut *mut u16) {
        ffi_service_main
    }
}

/// Hand this process to the service manager. Returns once the service has
/// stopped.
pub fn run(args: JoinArgs) -> Result<()> {
    let name = args.windows_service.clone().context("not started as a service")?;
    *ARGS.lock().unwrap_or_else(|e| e.into_inner()) = Some(args);
    windows_service::service_dispatcher::start(name, ffi::main_fn())
        .context("could not reach the service manager; --windows-service is for `runner service install`")
}

fn service_main() {
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};

    let Some(args) = ARGS.lock().unwrap_or_else(|e| e.into_inner()).take() else { return };
    let name = args.windows_service.clone().unwrap_or_default();
    let handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            // Kept even with nobody listening yet (a stop during startup).
            crate::runner::SHUTDOWN.send_replace(true);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let Ok(status) = service_control_handler::register(&name, handler) else { return };
    let set = |state, accept, code| {
        let _ = status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code: code,
            checkpoint: 0,
            // A stop cancels the running job and waits up to 20 s for it.
            wait_hint: std::time::Duration::from_secs(30),
            process_id: None,
        });
    };
    set(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        ServiceExitCode::Win32(0),
    );
    let outcome = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(anyhow::Error::from)
        .and_then(|rt| rt.block_on(crate::runner::run(args)));
    // A non-zero exit has the service manager restart the runner.
    let code = match outcome {
        Ok(()) => ServiceExitCode::Win32(0),
        Err(e) => {
            tracing::error!("the runner stopped: {e:#}");
            ServiceExitCode::ServiceSpecific(1)
        }
    };
    set(ServiceState::Stopped, ServiceControlAccept::empty(), code);
}

/// Where the service logs: `<cache>/runner/logs/<service>.log`, the
/// previous run's log kept as `.log.1` once it passes 10 MiB.
pub fn log_file(args: &JoinArgs) -> Result<std::fs::File> {
    let root = args.cache_dir.clone().unwrap_or_else(crate::runner::default_cache_root);
    let dir = root.join("runner").join("logs");
    std::fs::create_dir_all(&dir)?;
    let name = args.windows_service.clone().unwrap_or_else(|| "runner".into());
    let path = dir.join(format!("{name}.log"));
    if std::fs::metadata(&path).is_ok_and(|m| m.len() > 10 << 20) {
        let _ = std::fs::rename(&path, dir.join(format!("{name}.log.1")));
    }
    Ok(std::fs::OpenOptions::new().create(true).append(true).open(path)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_on_join_flags_only() {
        let raw: Vec<OsString> = [
            "airlox",
            "runner",
            "service",
            "install",
            "--code",
            "7-a-b",
            "--name",
            "r1",
            "--sandbox=process",
            "--invite-file=x",
            "--no-start",
            "--python",
            r"C:\v\Scripts\python.exe",
            "--data-dir",
            "d",
        ]
        .iter()
        .map(OsString::from)
        .collect();
        let out: Vec<String> = passthrough(&raw).iter().map(|s| s.to_string_lossy().into_owned()).collect();
        assert_eq!(out, ["--name", "r1", "--sandbox=process", "--python", r"C:\v\Scripts\python.exe"]);
    }
}
