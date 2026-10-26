//! The Linux local sandbox, built from unprivileged namespaces.
//!
//! The runner re-executes its own binary twice, so each step starts as a
//! fresh single-threaded process:
//!
//! 1. **stage 1** (`airlock __sandbox <spec>`) unshares user, mount,
//!    network, PID, IPC and UTS namespaces, maps the runner's uid and gid to
//!    0 inside, and starts stage 2. It ignores SIGTERM so that a polite stop
//!    reaches the shim and stage 1 still collects its exit.
//! 2. **stage 2** (`airlock __sandbox-init <spec>`) is PID 1 of the new PID
//!    namespace. It builds a minimal root on a tmpfs from read-only bind
//!    mounts (`/usr`, `/bin`, `/lib*`, `/etc`, the runtime venv and its
//!    Python), binds `/work`, `/out` and `/meta` writable, mounts a fresh
//!    `/proc` and a `/tmp` tmpfs, pivots into it and detaches the old root.
//!    It then sets `no_new_privs`, applies a Landlock ruleset (best effort,
//!    depending on the kernel), drops every capability including the
//!    bounding set, and execs the shim.
//!
//! The network namespace has no interfaces but a down loopback, so
//! `network: false` holds. When the shim (PID 1's replacement) exits, the
//! kernel kills everything left in the namespace. Memory is capped with
//! `RLIMIT_AS` through the shim; cgroup limits are not used here.

use std::convert::Infallible;
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use anyhow::{Context, Result};
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sched::{unshare, CloneFlags};
use nix::sys::statvfs::{statvfs, FsFlags};
use serde::{Deserialize, Serialize};

pub const STAGE1: &str = "__sandbox";
pub const STAGE2: &str = "__sandbox-init";

/// System directories bound read-only into the sandbox when present.
const SYSTEM_DIRS: &[&str] = &["/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/etc"];
const DEVICES: &[&str] = &["null", "zero", "random", "urandom"];

#[derive(Serialize, Deserialize, Debug)]
pub struct SandboxSpec {
    /// An empty directory to build the new root in.
    pub rootfs: PathBuf,
    pub work: PathBuf,
    pub out: PathBuf,
    pub meta: PathBuf,
    pub shim: PathBuf,
    pub python: PathBuf,
    pub runtime_dirs: Vec<PathBuf>,
    pub entry: String,
    pub timeout_s: u32,
    pub memory_mb: u32,
    /// Keep the host network (the session allows network access).
    pub network: bool,
}

/// Run a sandbox stage if `args` asks for one. Called first thing in `main`,
/// before any thread exists (unsharing a user namespace requires that).
pub fn dispatch(args: &[String]) -> Option<i32> {
    let stage = args.get(1)?.as_str();
    if stage != STAGE1 && stage != STAGE2 {
        return None;
    }
    let run = || -> Result<i32> {
        let path = args.get(2).context("missing sandbox spec")?;
        let spec: SandboxSpec = serde_json::from_slice(&fs::read(path)?)?;
        if stage == STAGE1 {
            stage1(path, &spec)
        } else {
            match stage2(&spec)? {}
        }
    };
    Some(match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("airlock sandbox: {e:#}");
            70
        }
    })
}

fn stage1(spec_path: &str, spec: &SandboxSpec) -> Result<i32> {
    let uid = nix::unistd::getuid();
    let gid = nix::unistd::getgid();
    let mut flags = CloneFlags::CLONE_NEWUSER
        | CloneFlags::CLONE_NEWNS
        | CloneFlags::CLONE_NEWPID
        | CloneFlags::CLONE_NEWIPC
        | CloneFlags::CLONE_NEWUTS;
    if !spec.network {
        flags |= CloneFlags::CLONE_NEWNET;
    }
    unshare(flags).context(
        "could not create user namespaces (some distributions restrict them, e.g. Ubuntu's \
         kernel.apparmor_restrict_unprivileged_userns); use --sandbox docker",
    )?;
    fs::write("/proc/self/setgroups", "deny")?;
    fs::write("/proc/self/uid_map", format!("0 {uid} 1"))?;
    fs::write("/proc/self/gid_map", format!("0 {gid} 1"))?;
    // Survive the runner's polite stop; the shim handles it.
    let flag = Arc::new(AtomicBool::new(false));
    for sig in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT, signal_hook::consts::SIGHUP] {
        signal_hook::flag::register(sig, flag.clone())?;
    }
    let status = std::process::Command::new(std::env::current_exe()?).arg(STAGE2).arg(spec_path).status()?;
    use std::os::unix::process::ExitStatusExt;
    Ok(status.code().unwrap_or_else(|| 128 + status.signal().unwrap_or(0)))
}

fn none() -> Option<&'static str> {
    None
}

/// Make a bind mount read-only, keeping the flags the kernel locks for
/// mounts inherited into a user namespace.
fn remount_ro(target: &Path) -> Result<()> {
    let f = statvfs(target)?.flags();
    let mut ms = MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY;
    for (fs_flag, ms_flag) in [
        (FsFlags::ST_NOSUID, MsFlags::MS_NOSUID),
        (FsFlags::ST_NODEV, MsFlags::MS_NODEV),
        (FsFlags::ST_NOEXEC, MsFlags::MS_NOEXEC),
        (FsFlags::ST_NOATIME, MsFlags::MS_NOATIME),
        (FsFlags::ST_NODIRATIME, MsFlags::MS_NODIRATIME),
        (FsFlags::ST_RELATIME, MsFlags::MS_RELATIME),
    ] {
        if f.contains(fs_flag) {
            ms |= ms_flag;
        }
    }
    mount(none(), target, none(), ms, none())
        .with_context(|| format!("remount {} read-only", target.display()))
}

/// Mount points at or below `top`, outermost first, from mountinfo.
fn mounts_under(top: &Path) -> Result<Vec<PathBuf>> {
    let info = fs::read_to_string("/proc/self/mountinfo")?;
    let mut out: Vec<PathBuf> = info
        .lines()
        .filter_map(|l| l.split(' ').nth(4))
        .map(|m| PathBuf::from(unescape_mountinfo(m)))
        .filter(|m| m.starts_with(top))
        .collect();
    out.sort_by_key(|m| m.components().count());
    out.dedup();
    Ok(out)
}

/// mountinfo escapes space, tab, newline and backslash as `\ooo`.
fn unescape_mountinfo(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            let oct: String = chars.by_ref().take(3).collect();
            match u8::from_str_radix(&oct, 8) {
                Ok(b) => out.push(b as char),
                Err(_) => {
                    out.push('\\');
                    out.push_str(&oct);
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn inside(root: &Path, p: &Path) -> PathBuf {
    root.join(p.strip_prefix("/").unwrap_or(p))
}

/// Bind `src` at `dst` under `root`; symlinks are recreated. The bind is
/// recursive: inside a user namespace the kernel refuses to bind a tree
/// whose sub-mounts would be dropped. For a read-only bind every mount in
/// the new tree is remounted read-only.
fn bind(root: &Path, src: &Path, dst: &Path, ro: bool) -> Result<()> {
    let Ok(meta) = fs::symlink_metadata(src) else { return Ok(()) };
    let target = inside(root, dst);
    if fs::symlink_metadata(&target).is_ok() && meta.file_type().is_symlink() {
        // Already visible, e.g. inside a directory bound earlier.
        return Ok(());
    }
    if meta.file_type().is_symlink() {
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        std::os::unix::fs::symlink(fs::read_link(src)?, &target)?;
        return Ok(());
    }
    if meta.is_dir() {
        fs::create_dir_all(&target)?;
    } else {
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&target, b"")?;
    }
    mount(Some(src), &target, none(), MsFlags::MS_BIND | MsFlags::MS_REC, none())
        .with_context(|| format!("bind {}", src.display()))?;
    if ro {
        for m in mounts_under(&target)? {
            remount_ro(&m)?;
        }
    }
    Ok(())
}

fn stage2(spec: &SandboxSpec) -> Result<Infallible> {
    let root = &spec.rootfs;
    mount(none(), "/", none(), MsFlags::MS_REC | MsFlags::MS_PRIVATE, none())?;
    fs::create_dir_all(root)?;
    mount(
        Some("tmpfs"),
        root,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some("mode=0755,size=16m"),
    )?;
    for d in SYSTEM_DIRS {
        bind(root, Path::new(d), Path::new(d), true)?;
    }
    // Before the runtime binds: a runtime under /tmp must stay visible.
    let nosuid_nodev = MsFlags::MS_NOSUID | MsFlags::MS_NODEV;
    let tmp = root.join("tmp");
    fs::create_dir_all(&tmp)?;
    mount(Some("tmpfs"), &tmp, Some("tmpfs"), nosuid_nodev, Some("mode=1777,size=64m"))?;
    for d in &spec.runtime_dirs {
        bind(root, d, d, true)?;
    }
    bind(root, &spec.work, Path::new("/work"), false)?;
    bind(root, &spec.out, Path::new("/out"), false)?;
    bind(root, &spec.meta, Path::new("/meta"), false)?;
    bind(root, &spec.shim, Path::new("/airlock/shim.py"), true)?;
    for d in DEVICES {
        let p = PathBuf::from("/dev").join(d);
        bind(root, &p, &p, false)?;
    }
    let proc_dir = root.join("proc");
    fs::create_dir_all(&proc_dir)?;
    mount(Some("proc"), &proc_dir, Some("proc"), nosuid_nodev | MsFlags::MS_NOEXEC, none())
        .context("mount /proc (inside a container this needs systempaths=unconfined)")?;

    let old = root.join(".old");
    fs::create_dir_all(&old)?;
    nix::unistd::pivot_root(root, &old).context("pivot_root")?;
    std::env::set_current_dir("/")?;
    umount2("/.old", MntFlags::MNT_DETACH)?;
    fs::remove_dir("/.old")?;
    mount(none(), "/", none(), MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY | nosuid_nodev, none())?;
    nix::unistd::sethostname("airlock")?;

    nix::sys::prctl::set_no_new_privs()?;
    landlock_restrict(spec)?;
    drop_capabilities()?;

    let err = std::process::Command::new(&spec.python)
        .arg("/airlock/shim.py")
        .args(["--work", "/work", "--entry", &spec.entry, "--timeout", &spec.timeout_s.to_string()])
        .args(["--result", "/meta/result.json", "--out", "/out"])
        .args(["--memory-mb", &spec.memory_mb.to_string()])
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .current_dir("/work")
        .exec();
    Err(err).context("exec the shim")
}

/// Read-only access to the system and runtime, read-write to the job's
/// directories. Best effort: older kernels enforce part or none of it, and
/// the mount layout above is the primary boundary.
fn landlock_restrict(spec: &SandboxSpec) -> Result<()> {
    use landlock::{
        Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus, ABI,
    };
    let abi = ABI::V3;
    let mut rs = Ruleset::default().handle_access(AccessFs::from_all(abi))?.create()?;
    let ro: Vec<PathBuf> = SYSTEM_DIRS
        .iter()
        .map(PathBuf::from)
        .chain(spec.runtime_dirs.iter().cloned())
        .chain(["/airlock", "/proc"].map(PathBuf::from))
        .collect();
    for p in ro.iter().filter(|p| p.exists()) {
        rs = rs.add_rule(PathBeneath::new(PathFd::new(p)?, AccessFs::from_read(abi)))?;
    }
    for p in ["/work", "/out", "/meta", "/tmp"] {
        rs = rs.add_rule(PathBeneath::new(PathFd::new(p)?, AccessFs::from_all(abi)))?;
    }
    for d in DEVICES {
        let p = PathBuf::from("/dev").join(d);
        if p.exists() {
            rs = rs.add_rule(PathBeneath::new(PathFd::new(&p)?, AccessFs::from_file(abi)))?;
        }
    }
    let status = rs.restrict_self()?;
    if status.ruleset == RulesetStatus::NotEnforced {
        eprintln!("airlock sandbox: Landlock is not available on this kernel; relying on mounts only");
    }
    Ok(())
}

fn drop_capabilities() -> Result<()> {
    use caps::CapSet;
    for c in caps::all() {
        caps::drop(None, CapSet::Bounding, c)?;
    }
    caps::clear(None, CapSet::Ambient)?;
    caps::clear(None, CapSet::Inheritable)?;
    caps::clear(None, CapSet::Effective)?;
    caps::clear(None, CapSet::Permitted)?;
    Ok(())
}
