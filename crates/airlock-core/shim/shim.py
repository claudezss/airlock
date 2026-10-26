#!/usr/bin/env python3
"""Airlock job shim (v1).

Runs one job entry file inside a sandbox and records what happened. Standard
library only, so it works in any python3.8+ image.

    python3 shim.py --work DIR --entry FILE --timeout SECONDS --result PATH
                    [--fsize-mb N] [--memory-mb N] [--nproc N]

Writes PATH (result.json) plus stdout.txt and stderr.txt beside it. Always
exits 0 when it managed to write result.json; the job's own outcome is inside.

Containment guarantees:
- The job runs in its own process group. That group is killed when the job
  exits, on timeout, and when the shim gets SIGTERM, SIGINT or SIGHUP.
- On Linux the shim is a child subreaper, so descendants that call setsid()
  are reparented to it and killed too. On other systems a setsid() escape is
  only contained by the sandbox (container or pod); the local backend on
  macOS is not a security boundary.
- Every file the job writes, including stdout and stderr, is capped by
  RLIMIT_FSIZE. Optional RLIMIT_AS and RLIMIT_NPROC limits are applied when
  given. The meta directory holding PATH must not be writable by the job.
"""

import argparse
import json
import os
import signal
import subprocess
import sys
import tempfile
import time

try:
    import resource
except ImportError:  # Windows
    resource = None

SHIM_VERSION = 1
IS_LINUX = sys.platform.startswith("linux")
IS_WINDOWS = os.name == "nt"
PR_SET_CHILD_SUBREAPER = 36


def become_subreaper():
    if not IS_LINUX:
        return False
    try:
        import ctypes

        libc = ctypes.CDLL(None, use_errno=True)
        return libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) == 0
    except Exception:
        return False


def linux_descendants(root):
    out, stack = [], [root]
    while stack:
        pid = stack.pop()
        try:
            tids = os.listdir("/proc/%d/task" % pid)
        except OSError:
            continue
        for tid in tids:
            try:
                with open("/proc/%d/task/%s/children" % (pid, tid)) as f:
                    kids = [int(k) for k in f.read().split()]
            except OSError:
                continue
            out.extend(kids)
            stack.extend(kids)
    return out


def reap_all():
    if IS_WINDOWS:
        return
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if pid == 0:
            return


def kill_job(proc, subreaper):
    """Kill the job's process group and, on Linux, every descendant."""
    if proc is None:
        return
    if IS_WINDOWS:
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    if subreaper:
        for _ in range(100):
            kids = linux_descendants(os.getpid())
            if not kids:
                break
            for k in kids:
                try:
                    os.kill(k, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
            time.sleep(0.01)
            reap_all()


def peak_rss_kb():
    if resource is None:
        return 0
    ru = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    # Linux reports kilobytes, macOS reports bytes.
    return ru // 1024 if sys.platform == "darwin" else ru


def make_preexec(fsize_mb, memory_mb, nproc):
    if resource is None:
        return None

    def preexec():
        def setlim(which, value):
            try:
                resource.setrlimit(which, (value, value))
            except (ValueError, OSError):
                pass

        setlim(resource.RLIMIT_CORE, 0)
        setlim(resource.RLIMIT_FSIZE, fsize_mb * 1024 * 1024)
        if memory_mb:
            setlim(resource.RLIMIT_AS, memory_mb * 1024 * 1024)
        if nproc:
            setlim(resource.RLIMIT_NPROC, nproc)

    return preexec


def write_result(path, obj):
    meta_dir = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(prefix=".result-", dir=meta_dir)
    with os.fdopen(fd, "w") as f:
        json.dump(obj, f, sort_keys=True)
    os.replace(tmp, path)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--work", required=True)
    ap.add_argument("--entry", required=True)
    ap.add_argument("--timeout", type=float, required=True)
    ap.add_argument("--result", required=True)
    ap.add_argument("--python", default=sys.executable)
    ap.add_argument("--fsize-mb", type=int, default=1024)
    ap.add_argument("--memory-mb", type=int, default=0, help="RLIMIT_AS; prefer cgroups")
    ap.add_argument("--nproc", type=int, default=0, help="RLIMIT_NPROC; needs a dedicated uid")
    a = ap.parse_args(argv)

    work = os.path.abspath(a.work)
    result = os.path.abspath(a.result)
    meta_dir = os.path.dirname(result)
    os.makedirs(meta_dir, exist_ok=True)
    python = os.path.abspath(a.python)
    out = {
        "shim_version": SHIM_VERSION,
        "exit_code": None,
        "signal": None,
        "timed_out": False,
        "cancelled": False,
        "wall_ms": 0,
        "peak_rss_kb": 0,
        "error": None,
    }

    entry = os.path.join(work, a.entry)
    if os.sep in a.entry or "/" in a.entry or a.entry.startswith(".") or not os.path.isfile(entry):
        out["error"] = "entry file missing or invalid"
        return write_result(result, out)

    subreaper = become_subreaper()
    state = {"proc": None}

    def on_signal(signum, _frame):
        out["cancelled"] = True
        kill_job(state["proc"], subreaper)

    for sig in ("SIGTERM", "SIGINT", "SIGHUP"):
        if hasattr(signal, sig):
            signal.signal(getattr(signal, sig), on_signal)

    tmpdir = os.path.join(work, ".airlock-tmp")
    os.makedirs(tmpdir, exist_ok=True)
    env = {
        "PATH": os.pathsep.join([os.path.dirname(python), "/usr/local/bin", "/usr/bin", "/bin"]),
        "LANG": "C.UTF-8",
        "HOME": work,
        "TMPDIR": tmpdir,
        "MPLBACKEND": "Agg",
    }
    if IS_WINDOWS:
        env["SYSTEMROOT"] = os.environ.get("SYSTEMROOT", r"C:\Windows")
        env["PATH"] = os.path.dirname(python)

    popen_kw = {}
    if IS_WINDOWS:
        popen_kw["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        popen_kw["start_new_session"] = True
        popen_kw["preexec_fn"] = make_preexec(a.fsize_mb, a.memory_mb, a.nproc)

    with open(os.path.join(meta_dir, "stdout.txt"), "wb") as so, open(
        os.path.join(meta_dir, "stderr.txt"), "wb"
    ) as se:
        start = time.monotonic()
        try:
            # -E -s: ignore PYTHON* variables and user site-packages; the work dir
            # stays importable. -u: unbuffered, so output survives a kill.
            # -B: no .pyc files. -X utf8: UTF-8 I/O regardless of locale.
            proc = subprocess.Popen(
                [python, "-E", "-s", "-u", "-B", "-X", "utf8", a.entry],
                cwd=work,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=so,
                stderr=se,
                **popen_kw
            )
        except OSError as e:
            out["error"] = "could not start python: %s" % e
            return write_result(result, out)
        state["proc"] = proc
        if out["cancelled"]:
            kill_job(proc, subreaper)
        try:
            proc.wait(timeout=a.timeout)
        except subprocess.TimeoutExpired:
            out["timed_out"] = True
            kill_job(proc, subreaper)
            proc.wait()
        out["wall_ms"] = int((time.monotonic() - start) * 1000)
        # Whatever happened, nothing the job started may outlive it.
        kill_job(proc, subreaper)
        reap_all()

    rc = proc.returncode
    if out["timed_out"] or out["cancelled"]:
        pass
    elif rc is not None and rc < 0:
        out["signal"] = -rc
    else:
        out["exit_code"] = rc
    out["peak_rss_kb"] = int(peak_rss_kb())
    return write_result(result, out)


if __name__ == "__main__":
    sys.exit(main())
