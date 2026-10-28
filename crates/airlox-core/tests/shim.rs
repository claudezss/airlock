//! Runs the embedded job shim with the host's python3. Skipped if absent.

use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use airlox_core::shim::{ShimResult, SHIM_PY};

fn have_python() -> bool {
    Command::new("python3").arg("--version").output().map(|o| o.status.success()).unwrap_or(false)
}

struct Job {
    _dir: tempfile::TempDir,
    root: PathBuf,
}

impl Job {
    fn new(code: &str) -> Self {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().canonicalize().unwrap();
        std::fs::create_dir(root.join("work")).unwrap();
        std::fs::write(root.join("work/job.py"), code.replace("{ROOT}", root.to_str().unwrap())).unwrap();
        std::fs::write(root.join("work/helper.py"), "VALUE = 41\n").unwrap();
        std::fs::write(root.join("shim.py"), SHIM_PY).unwrap();
        Job { _dir: d, root }
    }

    fn cmd(&self, entry: &str, timeout: &str, extra: &[&str]) -> Command {
        let mut c = Command::new("python3");
        c.arg(self.root.join("shim.py"))
            .args([
                "--work",
                self.root.join("work").to_str().unwrap(),
                "--entry",
                entry,
                "--timeout",
                timeout,
            ])
            .args(["--result", self.root.join("meta/result.json").to_str().unwrap()])
            .args(extra);
        c
    }

    fn run(&self, entry: &str, timeout: &str, extra: &[&str]) -> ShimResult {
        assert!(self.cmd(entry, timeout, extra).status().unwrap().success());
        self.result()
    }

    fn spawn(&self, entry: &str, timeout: &str) -> Child {
        self.cmd(entry, timeout, &[]).spawn().unwrap()
    }

    fn result(&self) -> ShimResult {
        serde_json::from_slice(&std::fs::read(self.root.join("meta/result.json")).unwrap()).unwrap()
    }

    fn read(&self, name: &str) -> String {
        std::fs::read_to_string(self.root.join("meta").join(name)).unwrap_or_default()
    }

    fn exists(&self, rel: &str) -> bool {
        self.root.join(rel).exists()
    }
}

fn wait_for(p: &Path, max: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < max {
        if p.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// A child that sleeps then writes a marker file; used to detect survivors.
const SPAWN_SURVIVOR: &str = r#"
import subprocess, sys
subprocess.Popen([sys.executable, "-c",
    "import time, pathlib; time.sleep(1.5); pathlib.Path('{ROOT}/SURVIVED').write_text('x')"],
    start_new_session=NEW_SESSION)
"#;

#[test]
fn runs_job_and_captures_output() {
    if !have_python() {
        return;
    }
    let j = Job::new(
        "import os, sys, helper\nprint(helper.VALUE + 1)\n\
         print(sorted(k for k in os.environ if k.startswith('AWS')), file=sys.stderr)\n\
         print(os.environ['PATH'], sys.flags.dont_write_bytecode, os.environ['TMPDIR'].startswith(os.getcwd()), file=sys.stderr)\n\
         sys.exit(3)\n",
    );
    std::env::set_var("AWS_SECRET_ACCESS_KEY", "should-not-leak");
    let r = j.run("job.py", "10", &[]);
    assert_eq!(r.exit_code, Some(3));
    assert!(!r.timed_out && !r.cancelled);
    assert_eq!(j.read("stdout.txt").trim(), "42");
    let err = j.read("stderr.txt");
    let mut lines = err.lines();
    assert_eq!(lines.next(), Some("[]"), "host environment leaked into the job");
    let info = lines.next().unwrap();
    assert!(!info.contains(".cargo"), "host PATH leaked: {info}");
    assert!(info.ends_with(" 1 True"), "-B not applied or TMPDIR not per-job: {info}");
}

#[test]
fn out_dir_is_passed_to_the_job() {
    if !have_python() {
        return;
    }
    let j = Job::new("import os\nopen(os.path.join(os.environ['AIRLOX_OUT'], 'r.txt'), 'w').write('ok')\n");
    let out = j.root.join("out");
    std::fs::create_dir(&out).unwrap();
    let r = j.run("job.py", "10", &["--out", out.to_str().unwrap()]);
    assert_eq!(r.exit_code, Some(0), "{}", j.read("stderr.txt"));
    assert_eq!(std::fs::read_to_string(out.join("r.txt")).unwrap(), "ok");
}

#[test]
fn output_is_unbuffered_when_killed() {
    if !have_python() {
        return;
    }
    let j = Job::new("import time\nprint('before timeout')\ntime.sleep(30)\n");
    let r = j.run("job.py", "1", &[]);
    assert!(r.timed_out);
    assert_eq!(j.read("stdout.txt").trim(), "before timeout");
}

#[test]
fn kills_on_timeout() {
    if !have_python() {
        return;
    }
    let j = Job::new(&(SPAWN_SURVIVOR.replace("NEW_SESSION", "False") + "import time\ntime.sleep(60)\n"));
    let started = Instant::now();
    let r = j.run("job.py", "1", &[]);
    assert!(r.timed_out);
    assert_eq!(r.exit_code, None);
    assert!(started.elapsed() < Duration::from_secs(10));
    std::thread::sleep(Duration::from_secs(2));
    assert!(!j.exists("SURVIVED"), "child outlived the timeout");
}

#[test]
fn kills_children_after_normal_exit() {
    if !have_python() {
        return;
    }
    let j = Job::new(&SPAWN_SURVIVOR.replace("NEW_SESSION", "False"));
    let r = j.run("job.py", "10", &[]);
    assert_eq!(r.exit_code, Some(0));
    std::thread::sleep(Duration::from_secs(2));
    assert!(!j.exists("SURVIVED"), "orphan outlived a normal exit");
}

/// setsid escapes the process group; only a subreaper (Linux) can catch it.
#[cfg(target_os = "linux")]
#[test]
fn kills_setsid_children_on_linux() {
    if !have_python() {
        return;
    }
    let j = Job::new(&SPAWN_SURVIVOR.replace("NEW_SESSION", "True"));
    let r = j.run("job.py", "10", &[]);
    assert_eq!(r.exit_code, Some(0));
    std::thread::sleep(Duration::from_secs(2));
    assert!(!j.exists("SURVIVED"), "setsid child outlived the job");
}

#[test]
fn sigterm_cancels_job_and_writes_result() {
    if !have_python() {
        return;
    }
    let j = Job::new(
        &(SPAWN_SURVIVOR.replace("NEW_SESSION", "False")
            + "import pathlib, time\npathlib.Path('{ROOT}/STARTED').write_text('x')\ntime.sleep(60)\n"),
    );
    let mut child = j.spawn("job.py", "60");
    assert!(wait_for(&j.root.join("STARTED"), Duration::from_secs(10)));
    let status = Command::new("kill").args(["-TERM", &child.id().to_string()]).status().unwrap();
    assert!(status.success());
    assert!(child.wait().unwrap().success());
    let r = j.result();
    assert!(r.cancelled);
    assert_eq!(r.exit_code, None);
    std::thread::sleep(Duration::from_secs(2));
    assert!(!j.exists("SURVIVED"), "job outlived cancellation");
}

#[test]
fn caps_output_size() {
    if !have_python() {
        return;
    }
    let j = Job::new("import sys\nsys.stdout.write('x' * (5 * 1024 * 1024))\n");
    // Python's unbuffered write returns a short count at the limit instead of
    // raising, so the exit code is not meaningful here; the size cap is.
    j.run("job.py", "10", &["--fsize-mb", "1"]);
    let len = std::fs::metadata(j.root.join("meta/stdout.txt")).unwrap().len();
    assert!(len <= 1024 * 1024, "stdout grew to {len} bytes");
}

#[test]
fn rejects_bad_entry() {
    if !have_python() {
        return;
    }
    let j = Job::new("print(1)\n");
    let r = j.run("../job.py", "5", &[]);
    assert!(r.error.is_some());
    assert_eq!(r.exit_code, None);
}

impl Job {
    /// A shell job's command: the script sits in `meta`, outside the work dir.
    fn shell_cmd(&self, script: &str, cwd: Option<&str>, timeout: &str) -> Command {
        std::fs::create_dir_all(self.root.join("meta")).unwrap();
        let path = self.root.join("meta/job.sh");
        std::fs::write(&path, script).unwrap();
        let mut c = Command::new("python3");
        c.arg(self.root.join("shim.py"))
            .args(["--work", self.root.join("work").to_str().unwrap()])
            .args(["--shell", "sh", "--script", path.to_str().unwrap(), "--timeout", timeout])
            .args(["--result", self.root.join("meta/result.json").to_str().unwrap()]);
        if let Some(cwd) = cwd {
            c.args(["--cwd", cwd]);
        }
        c
    }

    fn run_shell(&self, script: &str, cwd: Option<&str>, timeout: &str) -> ShimResult {
        assert!(self.shell_cmd(script, cwd, timeout).status().unwrap().success());
        self.result()
    }
}

#[cfg(unix)]
#[test]
fn shell_job_runs_with_e_in_the_work_dir() {
    if !have_python() {
        return;
    }
    let j = Job::new("");
    let r = j.run_shell(
        "echo \"in $(basename \"$PWD\")\"; echo \"$HOME\" >&2\nls helper.py\nfalse\necho not-reached\n",
        None,
        "10",
    );
    // `sh -e` stops at the first failing command, and its status is the job's.
    assert_eq!(r.exit_code, Some(1), "{}", j.read("stderr.txt"));
    assert_eq!(j.read("stdout.txt"), "in work\nhelper.py\n");
    assert!(j.read("stderr.txt").trim_end().ends_with("/work"), "{}", j.read("stderr.txt"));
    assert!(!j.exists("work/job.sh"), "the script must not be written into the work dir");
}

#[cfg(unix)]
#[test]
fn shell_job_gets_the_sandbox_path_and_a_scrubbed_environment() {
    if !have_python() {
        return;
    }
    let j = Job::new("");
    // What the shim itself runs with is what the sandbox gave it.
    let sandbox_path = format!("{}:/sandbox/tools", std::env::var("PATH").unwrap_or_default());
    let mut c = j.shell_cmd("echo \"$PATH\"; env | grep -c AWS || true; echo \"$TMPDIR\"", None, "10");
    assert!(c.env("PATH", &sandbox_path).env("AWS_SECRET_ACCESS_KEY", "should-not-leak").status().unwrap().success());
    let r = j.result();
    assert_eq!(r.exit_code, Some(0), "{}", j.read("stderr.txt"));
    let out = j.read("stdout.txt");
    let mut lines = out.lines();
    // (A version manager's python3 shim may add to it before the shim runs.)
    assert!(lines.next().unwrap().ends_with(":/sandbox/tools"), "PATH is the sandbox's own");
    assert_eq!(lines.next(), Some("0"));
    assert!(lines.next().unwrap().ends_with("/work/.airlox-tmp"));
}

#[cfg(unix)]
#[test]
fn cwd_is_relative_to_the_work_dir_for_shell_and_python_jobs() {
    if !have_python() {
        return;
    }
    let j = Job::new(
        "import os, sys\nprint(os.path.basename(os.getcwd()))\n\
         print(sys.path[0] == os.path.dirname(os.path.abspath(__file__)))\n",
    );
    std::fs::create_dir_all(j.root.join("work/services/api")).unwrap();
    let r = j.run_shell("pwd", Some("services/api"), "10");
    assert_eq!(r.exit_code, Some(0));
    assert!(j.read("stdout.txt").trim_end().ends_with("/work/services/api"));
    // A Python job's entry stays in the work dir; the job starts below it.
    let r = j.run("job.py", "10", &["--cwd", "services/api"]);
    assert_eq!(r.exit_code, Some(0), "{}", j.read("stderr.txt"));
    assert_eq!(j.read("stdout.txt"), "api\nTrue\n");
}

#[cfg(unix)]
#[test]
fn a_bad_cwd_is_a_clear_error_and_nothing_runs() {
    if !have_python() {
        return;
    }
    let j = Job::new("");
    std::os::unix::fs::symlink("/", j.root.join("work/rootlink")).unwrap();
    for (cwd, why) in [
        ("missing/dir", "does not exist"),
        ("../x", "not a relative path"),
        ("/etc", "not a relative path"),
        ("a//b", "not a relative path"),
        ("rootlink/etc", "outside the work dir"),
    ] {
        let r = j.run_shell("touch RAN", Some(cwd), "10");
        let e = r.error.unwrap_or_default();
        assert!(e.contains(why), "{cwd}: {e}");
        assert_eq!(r.exit_code, None);
    }
    assert!(!j.exists("work/RAN"));
}

#[cfg(unix)]
#[test]
fn a_shell_job_that_overruns_is_killed_with_its_children() {
    if !have_python() {
        return;
    }
    let j = Job::new("");
    let started = Instant::now();
    let r = j.run_shell("(sleep 1.5; touch ../SURVIVED) &\nsleep 60", None, "1");
    assert!(r.timed_out);
    assert!(started.elapsed() < Duration::from_secs(10));
    std::thread::sleep(Duration::from_secs(2));
    assert!(!j.exists("SURVIVED"), "a background process outlived the timeout");
}

#[test]
fn the_shim_needs_exactly_one_kind_of_job() {
    if !have_python() {
        return;
    }
    let j = Job::new("print(1)\n");
    let both = j.cmd("job.py", "5", &["--shell", "sh", "--script", "x"]).output().unwrap();
    assert!(!both.status.success());
    let neither = Command::new("python3")
        .arg(j.root.join("shim.py"))
        .args(["--work", "w", "--timeout", "5", "--result", "r.json"])
        .output()
        .unwrap();
    assert!(!neither.status.success());
}

#[test]
fn tmpdir_starts_empty_for_every_job() {
    if !have_python() {
        return;
    }
    let j = Job::new(
        "import os\nprint(os.listdir(os.environ['TMPDIR']))\n\
         open(os.path.join(os.environ['TMPDIR'], 'junk'), 'w').write('x')\n",
    );
    j.run("job.py", "10", &[]);
    assert_eq!(j.read("stdout.txt").trim(), "[]");
    j.run("job.py", "10", &[]);
    assert_eq!(j.read("stdout.txt").trim(), "[]", "TMPDIR kept the last job's files");
}
