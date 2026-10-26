//! Runs the embedded job shim with the host's python3. Skipped if absent.

use std::path::Path;
use std::process::Command;

use airlock_core::shim::{ShimResult, SHIM_PY};

fn python() -> Option<&'static str> {
    Command::new("python3").arg("--version").output().ok().filter(|o| o.status.success()).map(|_| "python3")
}

fn run(work: &Path, entry: &str, timeout: &str) -> (ShimResult, String, String) {
    let meta = work.parent().unwrap().join("meta");
    let shim = work.parent().unwrap().join("shim.py");
    std::fs::write(&shim, SHIM_PY).unwrap();
    let status = Command::new(python().unwrap())
        .arg(&shim)
        .args(["--work", work.to_str().unwrap(), "--entry", entry, "--timeout", timeout])
        .args(["--result", meta.join("result.json").to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success());
    let r: ShimResult = serde_json::from_slice(&std::fs::read(meta.join("result.json")).unwrap()).unwrap();
    let out = std::fs::read_to_string(meta.join("stdout.txt")).unwrap_or_default();
    let err = std::fs::read_to_string(meta.join("stderr.txt")).unwrap_or_default();
    (r, out, err)
}

fn setup(code: &str) -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    let work = d.path().join("work");
    std::fs::create_dir(&work).unwrap();
    std::fs::write(work.join("job.py"), code).unwrap();
    std::fs::write(work.join("helper.py"), "VALUE = 41\n").unwrap();
    d
}

#[test]
fn runs_job_and_captures_output() {
    if python().is_none() {
        eprintln!("python3 not found; skipping");
        return;
    }
    let d = setup("import os, sys, helper\nprint(helper.VALUE + 1)\nprint(sorted(k for k in os.environ if k.startswith('AWS')), file=sys.stderr)\nsys.exit(3)\n");
    std::env::set_var("AWS_SECRET_ACCESS_KEY", "should-not-leak");
    let (r, out, err) = run(&d.path().join("work"), "job.py", "10");
    assert_eq!(r.exit_code, Some(3));
    assert!(!r.timed_out);
    assert_eq!(out.trim(), "42");
    assert_eq!(err.trim(), "[]", "host environment leaked into the job");
}

#[test]
fn kills_on_timeout() {
    if python().is_none() {
        return;
    }
    let d = setup("import subprocess, sys, time\nsubprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\ntime.sleep(60)\n");
    let started = std::time::Instant::now();
    let (r, _, _) = run(&d.path().join("work"), "job.py", "1");
    assert!(r.timed_out);
    assert_eq!(r.exit_code, None);
    assert!(started.elapsed().as_secs() < 10);
}

#[test]
fn rejects_bad_entry() {
    if python().is_none() {
        return;
    }
    let d = setup("print(1)\n");
    let (r, _, _) = run(&d.path().join("work"), "../job.py", "5");
    assert!(r.error.is_some());
    assert_eq!(r.exit_code, None);
}
