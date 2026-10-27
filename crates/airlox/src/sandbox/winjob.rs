//! Windows Job Objects for the process sandbox, and the runner's own
//! privilege check.
//!
//! Each job's shim starts suspended, joins a fresh Job Object and only then
//! runs, so nothing it starts (a simulator such as `tara.exe` and its
//! children) can escape the job. The Job Object caps committed memory for
//! the whole tree, keeps it off the clipboard, desktop and other processes'
//! windows, and kills every process in it when the runner closes the handle,
//! whether the job finished, overran or the runner itself went away.
//!
//! The only module allowed `unsafe`: every block is a Win32 call, with its
//! reasoning beside it.
#![allow(unsafe_code)]

use std::mem::{size_of, zeroed};

use anyhow::{bail, Result};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, LUID};
use windows_sys::Win32::Security::{
    CheckTokenMembership, CreateWellKnownSid, GetTokenInformation, IsWellKnownSid, LookupPrivilegeValueW,
    TokenElevation, TokenElevationType, TokenElevationTypeLimited, TokenPrivileges, TokenUser,
    WinBuiltinAdministratorsSid, WinLocalSystemSid, SECURITY_MAX_SID_SIZE, TOKEN_ELEVATION,
    TOKEN_ELEVATION_TYPE, TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectAssociateCompletionPortInformation,
    JobObjectBasicUIRestrictions, JobObjectExtendedLimitInformation, QueryInformationJobObject,
    SetInformationJobObject, TerminateJobObject, JOBOBJECT_ASSOCIATE_COMPLETION_PORT,
    JOBOBJECT_BASIC_UI_RESTRICTIONS, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_JOB_MEMORY,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_UILIMIT_DESKTOP, JOB_OBJECT_UILIMIT_DISPLAYSETTINGS,
    JOB_OBJECT_UILIMIT_EXITWINDOWS, JOB_OBJECT_UILIMIT_GLOBALATOMS, JOB_OBJECT_UILIMIT_HANDLES,
    JOB_OBJECT_UILIMIT_READCLIPBOARD, JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS, JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcessToken, OpenThread, ResumeThread, CREATE_NO_WINDOW, CREATE_SUSPENDED,
    THREAD_SUSPEND_RESUME,
};
use windows_sys::Win32::System::IO::{CreateIoCompletionPort, GetQueuedCompletionStatus, OVERLAPPED};

/// Creation flags for a process that will join a job before it runs.
pub const SUSPENDED: u32 = CREATE_SUSPENDED | CREATE_NO_WINDOW;
/// Creation flags for a console helper that must not open a window (the
/// runner may be a service, with no console of its own).
pub const NO_WINDOW: u32 = CREATE_NO_WINDOW;

/// Exit code the job's processes get when the runner stops them.
const STOPPED: u32 = 0xA1;

/// Job notifications (winnt.h): a process, or the job as a whole, tried to
/// commit more memory than its limit allows.
const JOB_OBJECT_MSG_PROCESS_MEMORY_LIMIT: u32 = 9;
const JOB_OBJECT_MSG_JOB_MEMORY_LIMIT: u32 = 10;

fn last_error(what: &str) -> anyhow::Error {
    anyhow::anyhow!("{what}: {}", std::io::Error::last_os_error())
}

/// An owned handle, closed on drop.
struct Handle(HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: the handle was returned open by the API that created it
        // and is closed exactly once.
        unsafe { CloseHandle(self.0) };
    }
}

/// A Job Object holding one job's process tree. Dropping it kills
/// everything still in it.
pub struct WinJob {
    handle: Handle,
    /// Where Windows reports the job's events, such as hitting its memory cap.
    port: Handle,
}

// SAFETY: a job handle may be used from any thread.
unsafe impl Send for WinJob {}
unsafe impl Sync for WinJob {}

impl WinJob {
    /// A fresh, unnamed job: kill on close, no crash dialogs, committed
    /// memory capped at `memory_mb` for all its processes together.
    pub fn new(memory_mb: u32) -> Result<Self> {
        // SAFETY: no security attributes, no name.
        let h = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if h.is_null() {
            return Err(last_error("CreateJobObjectW"));
        }
        let handle = Handle(h);
        // SAFETY: a new completion port, not tied to any file.
        let port = unsafe { CreateIoCompletionPort(INVALID_HANDLE_VALUE, std::ptr::null_mut(), 0, 1) };
        if port.is_null() {
            return Err(last_error("CreateIoCompletionPort"));
        }
        let job = WinJob { handle, port: Handle(port) };
        let notify = JOBOBJECT_ASSOCIATE_COMPLETION_PORT {
            CompletionKey: std::ptr::null_mut(),
            CompletionPort: job.port.0,
        };
        job.set(JobObjectAssociateCompletionPortInformation, &notify, "job notifications")?;
        // SAFETY: plain-data struct, all zeroes is valid.
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_JOB_MEMORY
            | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
        limits.JobMemoryLimit = memory_mb as usize * 1024 * 1024;
        job.set(JobObjectExtendedLimitInformation, &limits, "job limits")?;
        let ui = JOBOBJECT_BASIC_UI_RESTRICTIONS {
            UIRestrictionsClass: JOB_OBJECT_UILIMIT_DESKTOP
                | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
                | JOB_OBJECT_UILIMIT_EXITWINDOWS
                | JOB_OBJECT_UILIMIT_GLOBALATOMS
                | JOB_OBJECT_UILIMIT_HANDLES
                | JOB_OBJECT_UILIMIT_READCLIPBOARD
                | JOB_OBJECT_UILIMIT_WRITECLIPBOARD
                | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS,
        };
        job.set(JobObjectBasicUIRestrictions, &ui, "job UI restrictions")?;
        Ok(job)
    }

    fn set<T>(&self, class: i32, info: &T, what: &str) -> Result<()> {
        // SAFETY: `info` is the structure `class` names, of the size given.
        let ok = unsafe {
            SetInformationJobObject(self.handle.0, class, (info as *const T).cast(), size_of::<T>() as u32)
        };
        if ok == 0 {
            return Err(last_error(what));
        }
        Ok(())
    }

    /// Put a process started with [`SUSPENDED`] into the job, then let it run.
    pub fn adopt(&self, process: HANDLE, pid: u32) -> Result<()> {
        // SAFETY: both handles are open; the process has not run yet.
        if unsafe { AssignProcessToJobObject(self.handle.0, process) } == 0 {
            return Err(last_error("AssignProcessToJobObject"));
        }
        resume(pid)
    }

    /// Kill every process in the job now.
    pub fn terminate(&self) {
        // SAFETY: the handle is open.
        unsafe { TerminateJobObject(self.handle.0, STOPPED) };
    }

    /// The most committed memory the job's processes held at once, in KiB.
    pub fn peak_kb(&self) -> u64 {
        // SAFETY: plain-data struct, all zeroes is valid; the size matches.
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
        let ok = unsafe {
            QueryInformationJobObject(
                self.handle.0,
                JobObjectExtendedLimitInformation,
                (&mut info as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return 0;
        }
        (info.PeakJobMemoryUsed / 1024) as u64
    }

    /// Windows refused one of the job's allocations because of its memory
    /// cap, by the notifications queued so far.
    pub fn hit_memory_limit(&self) -> bool {
        let mut hit = false;
        loop {
            let (mut message, mut key, mut overlapped) = (0u32, 0usize, std::ptr::null_mut::<OVERLAPPED>());
            // SAFETY: the port is open; all out-pointers are valid; a zero
            // timeout returns at once when nothing is queued.
            let got =
                unsafe { GetQueuedCompletionStatus(self.port.0, &mut message, &mut key, &mut overlapped, 0) };
            if got == 0 {
                return hit;
            }
            hit |= matches!(message, JOB_OBJECT_MSG_JOB_MEMORY_LIMIT | JOB_OBJECT_MSG_PROCESS_MEMORY_LIMIT);
        }
    }
}

/// Where an open file really is (links and junctions resolved), as a
/// `\\?\` path like [`std::fs::canonicalize`] returns.
pub fn final_path(f: &std::fs::File) -> Option<std::path::PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFinalPathNameByHandleW, FILE_NAME_NORMALIZED, VOLUME_NAME_DOS,
    };
    let mut buf = vec![0u16; 1024];
    loop {
        // SAFETY: the handle is open for the life of `f`; the buffer's
        // length is passed in u16 units.
        let n = unsafe {
            GetFinalPathNameByHandleW(
                f.as_raw_handle() as HANDLE,
                buf.as_mut_ptr(),
                buf.len() as u32,
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
            )
        } as usize;
        if n == 0 {
            return None;
        }
        // Too small: `n` is the size needed, including the terminator.
        if n >= buf.len() {
            buf.resize(n + 1, 0);
            continue;
        }
        return Some(std::ffi::OsString::from_wide(&buf[..n]).into());
    }
}

/// Resume every thread of a suspended process (a new process has one).
fn resume(pid: u32) -> Result<()> {
    // SAFETY: a snapshot of all threads; closed by `Handle`.
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snap == INVALID_HANDLE_VALUE {
        return Err(last_error("CreateToolhelp32Snapshot"));
    }
    let snap = Handle(snap);
    // SAFETY: plain-data struct; dwSize is set as the API requires.
    let mut entry: THREADENTRY32 = unsafe { zeroed() };
    entry.dwSize = size_of::<THREADENTRY32>() as u32;
    let mut resumed = 0;
    // SAFETY: `entry` is a valid THREADENTRY32 for the snapshot walk.
    let mut more = unsafe { Thread32First(snap.0, &mut entry) } != 0;
    while more {
        if entry.th32OwnerProcessID == pid {
            // SAFETY: opening a thread by id; closed by `Handle`.
            let t = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) };
            if !t.is_null() {
                let t = Handle(t);
                // SAFETY: the handle has THREAD_SUSPEND_RESUME access.
                if unsafe { ResumeThread(t.0) } != u32::MAX {
                    resumed += 1;
                }
            }
        }
        // SAFETY: as above.
        more = unsafe { Thread32Next(snap.0, &mut entry) } != 0;
    }
    if resumed == 0 {
        bail!("could not resume process {pid}");
    }
    Ok(())
}

/// Privileges that let a process take over the machine (impersonating a
/// SYSTEM token, reading or replacing any file, debugging any process).
/// Service accounts hold SeImpersonate by default.
const DANGEROUS_PRIVILEGES: &[&str] = &[
    "SeImpersonatePrivilege",
    "SeAssignPrimaryTokenPrivilege",
    "SeTcbPrivilege",
    "SeCreateTokenPrivilege",
    "SeDebugPrivilege",
    "SeBackupPrivilege",
    "SeRestorePrivilege",
    "SeTakeOwnershipPrivilege",
    "SeLoadDriverPrivilege",
];

/// `GetTokenInformation` into an 8-byte-aligned buffer; `None` if it fails.
fn token_info(token: HANDLE, class: i32) -> Option<Vec<u64>> {
    let mut len = 0u32;
    // SAFETY: a size query (null buffer, zero length) only writes `len`.
    unsafe { GetTokenInformation(token, class, std::ptr::null_mut(), 0, &mut len) };
    if len == 0 {
        return None;
    }
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: the buffer holds `len` bytes, aligned for any token structure.
    let ok = unsafe { GetTokenInformation(token, class, buf.as_mut_ptr().cast(), len, &mut len) };
    (ok != 0).then_some(buf)
}

/// Why this process must not run jobs, if it is privileged: SYSTEM, an
/// administrator (elevated or not), or an account holding a privilege that
/// leads to SYSTEM. Fails closed: a token it cannot read counts.
pub fn privileged() -> Option<&'static str> {
    const UNCHECKED: &str = "a user whose token cannot be checked";
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: the pseudo handle of this process; the token is closed by `Handle`.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Some(UNCHECKED);
    }
    let token = Handle(token);
    let Some(user) = token_info(token.0, TokenUser) else { return Some(UNCHECKED) };
    // SAFETY: the buffer starts with a TOKEN_USER whose SID points into it.
    let sid = unsafe { (*(user.as_ptr() as *const TOKEN_USER)).User.Sid };
    // SAFETY: the SID is valid while `user` lives.
    if unsafe { IsWellKnownSid(sid, WinLocalSystemSid) } != 0 {
        return Some("SYSTEM");
    }
    let Some(elevation) = token_info(token.0, TokenElevation) else { return Some(UNCHECKED) };
    // SAFETY: the buffer holds a TOKEN_ELEVATION.
    if unsafe { (*(elevation.as_ptr() as *const TOKEN_ELEVATION)).TokenIsElevated } != 0 {
        return Some("an elevated administrator");
    }
    // An administrator's ordinary, unelevated token: Administrators is
    // deny-only in it, so the membership check below misses it, but UAC is
    // not a security boundary and a job could still elevate.
    let Some(kind) = token_info(token.0, TokenElevationType) else { return Some(UNCHECKED) };
    // SAFETY: the buffer holds a TOKEN_ELEVATION_TYPE.
    if unsafe { *(kind.as_ptr() as *const TOKEN_ELEVATION_TYPE) } == TokenElevationTypeLimited {
        return Some("an administrator (even unelevated: a job could elevate)");
    }
    let mut sid = [0u64; (SECURITY_MAX_SID_SIZE as usize).div_ceil(8)];
    let mut sid_len = SECURITY_MAX_SID_SIZE;
    // SAFETY: the buffer holds any SID; its size is passed.
    let made = unsafe {
        CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            std::ptr::null_mut(),
            sid.as_mut_ptr().cast(),
            &mut sid_len,
        )
    };
    let mut member = 0;
    // SAFETY: a null token checks the caller's effective token; the SID is valid.
    if made == 0
        || unsafe { CheckTokenMembership(std::ptr::null_mut(), sid.as_mut_ptr().cast(), &mut member) } == 0
    {
        return Some(UNCHECKED);
    }
    if member != 0 {
        return Some("an administrator");
    }
    let Some(privs) = token_info(token.0, TokenPrivileges) else { return Some(UNCHECKED) };
    // SAFETY: the buffer holds a TOKEN_PRIVILEGES with `PrivilegeCount`
    // entries; a privilege the token lacks is not listed at all.
    let held = unsafe {
        let tp = privs.as_ptr() as *const TOKEN_PRIVILEGES;
        std::slice::from_raw_parts((*tp).Privileges.as_ptr(), (*tp).PrivilegeCount as usize)
    };
    for name in DANGEROUS_PRIVILEGES {
        let wide: Vec<u16> = name.encode_utf16().chain([0]).collect();
        let mut luid = LUID { LowPart: 0, HighPart: 0 };
        // SAFETY: a NUL-terminated name; `luid` is written on success.
        if unsafe { LookupPrivilegeValueW(std::ptr::null(), wide.as_ptr(), &mut luid) } == 0 {
            continue;
        }
        if held.iter().any(|p| p.Luid.LowPart == luid.LowPart && p.Luid.HighPart == luid.HighPart) {
            return Some(match *name {
                "SeImpersonatePrivilege" => "an account holding SeImpersonatePrivilege (it can reach SYSTEM)",
                _ => "an account holding a privilege that can reach SYSTEM or any file",
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::os::windows::io::AsRawHandle;
    use std::os::windows::process::CommandExt;
    use std::time::{Duration, Instant};

    /// `cmd` running a 30 s `ping` in a fresh job: a parent and a child.
    fn sleeper() -> (WinJob, std::process::Child) {
        let job = WinJob::new(256).unwrap();
        let child = std::process::Command::new("cmd")
            .args(["/c", "ping -n 30 127.0.0.1 >NUL"])
            .creation_flags(SUSPENDED)
            .spawn()
            .unwrap();
        job.adopt(child.as_raw_handle(), child.id()).unwrap();
        (job, child)
    }

    #[test]
    fn terminate_ends_the_tree() {
        let (job, mut child) = sleeper();
        std::thread::sleep(Duration::from_millis(300));
        assert!(child.try_wait().unwrap().is_none(), "resumed and running");
        job.terminate();
        assert_eq!(child.wait().unwrap().code(), Some(STOPPED as i32));
        assert!(!job.hit_memory_limit(), "a small job never reaches its cap");
    }

    #[test]
    fn an_allocation_over_the_cap_is_reported() {
        let job = WinJob::new(256).unwrap();
        let mut child = std::process::Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", "$b = [byte[]]::new(1GB)"])
            .creation_flags(SUSPENDED)
            .spawn()
            .unwrap();
        job.adopt(child.as_raw_handle(), child.id()).unwrap();
        assert!(!child.wait().unwrap().success(), "the allocation fails");
        assert!(job.hit_memory_limit());
    }

    #[test]
    fn closing_the_job_kills_it() {
        let (job, mut child) = sleeper();
        std::thread::sleep(Duration::from_millis(300));
        let start = Instant::now();
        drop(job);
        child.wait().unwrap();
        assert!(start.elapsed() < Duration::from_secs(10), "killed, not run to the end");
    }

    #[test]
    fn privilege_check_runs() {
        // Whatever this test runs as, the token calls succeed and answer.
        let who = privileged();
        assert_ne!(who, Some("a user whose token cannot be checked"));
    }
}
