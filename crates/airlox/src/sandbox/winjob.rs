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
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::{
    CheckTokenMembership, CreateWellKnownSid, GetTokenInformation, IsWellKnownSid, TokenElevation, TokenUser,
    WinBuiltinAdministratorsSid, WinLocalSystemSid, SECURITY_MAX_SID_SIZE, TOKEN_ELEVATION, TOKEN_QUERY,
    TOKEN_USER,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectBasicUIRestrictions,
    JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
    TerminateJobObject, JOBOBJECT_BASIC_UI_RESTRICTIONS, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_JOB_MEMORY,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_UILIMIT_DESKTOP, JOB_OBJECT_UILIMIT_DISPLAYSETTINGS,
    JOB_OBJECT_UILIMIT_EXITWINDOWS, JOB_OBJECT_UILIMIT_GLOBALATOMS, JOB_OBJECT_UILIMIT_HANDLES,
    JOB_OBJECT_UILIMIT_READCLIPBOARD, JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS, JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcessToken, OpenThread, ResumeThread, CREATE_NO_WINDOW, CREATE_SUSPENDED,
    THREAD_SUSPEND_RESUME,
};

/// Creation flags for a process that will join a job before it runs.
pub const SUSPENDED: u32 = CREATE_SUSPENDED | CREATE_NO_WINDOW;
/// Creation flags for a console helper that must not open a window (the
/// runner may be a service, with no console of its own).
pub const NO_WINDOW: u32 = CREATE_NO_WINDOW;

/// Exit code the job's processes get when the runner stops them.
const STOPPED: u32 = 0xA1;

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
    memory_limit: usize,
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
        let job = WinJob { handle: Handle(h), memory_limit: memory_mb as usize * 1024 * 1024 };
        // SAFETY: plain-data struct, all zeroes is valid.
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_JOB_MEMORY
            | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
        limits.JobMemoryLimit = job.memory_limit;
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

    /// The job came within 5% of its memory cap, so an allocation failure
    /// (and the job's exit) was most likely the cap.
    pub fn hit_memory_limit(&self) -> bool {
        self.peak_kb() * 1024 >= (self.memory_limit as u64) / 100 * 95
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

/// Why this process must not run jobs, if it is privileged: elevated, a
/// member of Administrators, or SYSTEM.
pub fn privileged() -> Option<&'static str> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: the pseudo handle of this process; the token is closed by `Handle`.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Some("a user whose token cannot be checked");
    }
    let token = Handle(token);
    let mut user = [0u8; 256];
    let mut len = 0u32;
    // SAFETY: the buffer is large enough for TOKEN_USER plus a SID and its
    // length is passed; the result is read only on success.
    let ok = unsafe {
        GetTokenInformation(token.0, TokenUser, user.as_mut_ptr().cast(), user.len() as u32, &mut len)
    };
    if ok != 0 {
        // SAFETY: on success the buffer starts with a TOKEN_USER (read
        // unaligned: the byte buffer has no alignment guarantee).
        let tu: TOKEN_USER = unsafe { std::ptr::read_unaligned(user.as_ptr().cast()) };
        // SAFETY: the SID points into `user`, which is still alive.
        if unsafe { IsWellKnownSid(tu.User.Sid, WinLocalSystemSid) } != 0 {
            return Some("SYSTEM");
        }
    }
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    // SAFETY: the buffer is a TOKEN_ELEVATION of the size given.
    let ok = unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
    };
    if ok != 0 && elevation.TokenIsElevated != 0 {
        return Some("an elevated administrator");
    }
    let mut sid = [0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut sid_len = sid.len() as u32;
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
    if made != 0
        && unsafe { CheckTokenMembership(std::ptr::null_mut(), sid.as_mut_ptr().cast(), &mut member) } != 0
        && member != 0
    {
        return Some("an administrator");
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
