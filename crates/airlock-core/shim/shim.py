#!/usr/bin/env python3
"""Airlock job shim (v1).

Runs one job entry file inside a sandbox and records what happened. It uses
only the standard library so it works in any python3.8+ image.

    python3 shim.py --work DIR --entry FILE --timeout SECONDS --result PATH

Writes PATH (result.json) plus PATH's siblings stdout.txt and stderr.txt.
Always exits 0 when it managed to write result.json; the job's own exit code
is inside the file.
"""

import argparse
import json
import os
import resource
import signal
import subprocess
import sys
import time

SHIM_VERSION = 1
KEEP_ENV = ("PATH", "LANG", "LC_ALL", "TZ")


def peak_rss_kb():
    ru = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    # Linux reports kilobytes, macOS reports bytes.
    return ru // 1024 if sys.platform == "darwin" else ru


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--work", required=True)
    ap.add_argument("--entry", required=True)
    ap.add_argument("--timeout", type=float, required=True)
    ap.add_argument("--result", required=True)
    ap.add_argument("--python", default=sys.executable)
    a = ap.parse_args(argv)

    meta_dir = os.path.dirname(os.path.abspath(a.result))
    os.makedirs(meta_dir, exist_ok=True)
    out = {
        "shim_version": SHIM_VERSION,
        "exit_code": None,
        "signal": None,
        "timed_out": False,
        "wall_ms": 0,
        "peak_rss_kb": 0,
        "error": None,
    }

    entry = os.path.join(a.work, a.entry)
    if os.path.sep in a.entry or a.entry.startswith(".") or not os.path.isfile(entry):
        out["error"] = "entry file missing or invalid"
        return write(a.result, out)

    env = {k: os.environ[k] for k in KEEP_ENV if k in os.environ}
    env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
    env.setdefault("LANG", "C.UTF-8")
    env.update(
        HOME=a.work,
        TMPDIR=os.environ.get("TMPDIR", "/tmp"),
        PYTHONDONTWRITEBYTECODE="1",
        PYTHONUNBUFFERED="1",
        PYTHONIOENCODING="utf-8",
        MPLBACKEND="Agg",
    )

    with open(os.path.join(meta_dir, "stdout.txt"), "wb") as so, open(
        os.path.join(meta_dir, "stderr.txt"), "wb"
    ) as se:
        start = time.monotonic()
        try:
            proc = subprocess.Popen(
                [a.python, "-E", "-s", a.entry],
                cwd=a.work,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=so,
                stderr=se,
                start_new_session=True,
            )
        except OSError as e:
            out["error"] = "could not start python: %s" % e
            return write(a.result, out)
        try:
            proc.wait(timeout=a.timeout)
        except subprocess.TimeoutExpired:
            out["timed_out"] = True
            kill_group(proc)
            proc.wait()
        out["wall_ms"] = int((time.monotonic() - start) * 1000)

    rc = proc.returncode
    if rc is not None and rc < 0:
        out["signal"] = -rc
    elif not out["timed_out"]:
        out["exit_code"] = rc
    out["peak_rss_kb"] = int(peak_rss_kb())
    return write(a.result, out)


def kill_group(proc):
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        try:
            proc.kill()
        except ProcessLookupError:
            pass


def write(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, sort_keys=True)
    os.replace(tmp, path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
