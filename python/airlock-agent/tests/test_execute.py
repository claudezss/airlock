"""Execute mode end to end: the SDK, the relay and a real `airlock` runner."""

import io
import os
import sys
import time
import zipfile

import pytest

from airlock import NoRunnerAvailable, Session

LIMITS = {
    "runtime": "python3.12",
    "timeout_s": 20,
    "memory_mb": 512,
    "network": False,
    "packages": [],
    "return_out": True,
    "approve_runners": True,
}

SUMMARIZE = """
import csv, json, os, struct, zlib
rows = list(csv.DictReader(open("dataset/orders.csv")))
total = sum(int(r["total"]) for r in rows)
print(f"{len(rows)} orders, total {total}")
out = os.environ["AIRLOCK_OUT"]
json.dump({"orders": len(rows), "total": total}, open(os.path.join(out, "summary.json"), "w"))
def chunk(t, d):
    return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d))
raw = b"".join(b"\\x00" + bytes((200, 10, 10)) * 4 for _ in range(4))
png = (b"\\x89PNG\\r\\n\\x1a\\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 4, 4, 8, 2, 0, 0, 0))
       + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))
open(os.path.join(out, "chart.png"), "wb").write(png)
"""


def dataset() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("dataset/orders.csv", "region,total\neast,10\nwest,32\n")
    return buf.getvalue()


def wait_runner(s, name, pred=lambda r: True, timeout=90.0, proc=None):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if proc is not None and proc.proc.poll() is not None:
            raise AssertionError(f"runner exited:\n{proc.output()}")
        for r in s.runners():
            if r.name == name and pred(r):
                return r
        time.sleep(0.2)
    raise AssertionError(f"runner {name} never appeared")


@pytest.fixture
def execute(relay, caches, start_runner):
    owner = Session.create(relay.url, mode="execute", job_limits=LIMITS, cache_dir=caches("owner"))
    agent = Session.join(owner.invites["sender"], display_name="planner-agent", cache_dir=caches("agent"))
    runner = start_runner(owner.invites["runner"], "runner-01", "--labels", "cpu")
    try:
        wait_runner(owner, "runner-01", lambda r: r.online, proc=runner)
    except AssertionError:
        raise AssertionError("runner did not come online:\n" + runner.output())
    return owner, agent, runner


def test_unapproved_runners_get_nothing_then_summarize_runs(execute):
    owner, agent, runner = execute
    [r] = agent.runners()
    assert (r.name, r.labels, r.approved, r.online) == ("runner-01", ["cpu"], False, True)
    with pytest.raises(NoRunnerAvailable):
        agent.run_python("print(1)")

    owner.approve_runner("runner-01")
    assert wait_runner(agent, "runner-01", lambda r: r.approved)
    data = agent.send_file(dataset(), name="dataset.zip")
    job = agent.run_python(SUMMARIZE, filename="summarize.py", files=[data], runner="runner-01")
    res = job.wait(timeout=60)
    assert res.signed and res.status == "completed", (res, runner.output())
    assert res.ok and res.stdout.strip() == "2 orders, total 42"
    assert {f.name for f in res.out_files} == {"chart.png", "out.zip"}
    assert res.out_file("chart.png").data.startswith(b"\x89PNG")
    z = zipfile.ZipFile(io.BytesIO(res.out_file("out.zip").data))
    assert z.read("summary.json") == b'{"orders": 2, "total": 42}'
    assert job.state()["state"] == "done"
    # The owner sees the same verified result.
    assert owner.items() and any(i.kind == "result" for i in owner.items())


def test_refusals_timeouts_and_cancels(execute):
    owner, agent, runner = execute
    owner.approve_runner("runner-01")
    wait_runner(agent, "runner-01", lambda r: r.approved)

    # Not in the allowlist: the runner refuses without running anything.
    res = agent.run_python("import scipy", requirements=["scipy"]).wait(timeout=30)
    assert res.status == "refused" and "scipy not in allowlist" in res.reason, res

    # A label the runner lacks never reaches it.
    with pytest.raises(NoRunnerAvailable):
        agent.run_python("print(1)", labels=["gpu"])

    res = agent.run_python("while True:\n    pass\n", timeout=1).wait(timeout=30)
    assert res.status == "timed_out" and res.exit_code is None, res

    res = agent.run_python("import sys\nprint('boom', file=sys.stderr)\nsys.exit(3)").wait(timeout=30)
    assert (res.status, res.exit_code, res.stderr.strip()) == ("completed", 3, "boom")

    job = agent.run_python("import time\nprint('started', flush=True)\ntime.sleep(60)\n", timeout=20)
    wait_until = time.monotonic() + 20
    while job.state()["state"] != "running" and time.monotonic() < wait_until:
        time.sleep(0.1)
    time.sleep(0.5)
    job.cancel()
    res = job.wait(timeout=30)
    assert res.status == "cancelled", (res, runner.output())


def test_rejected_runner_stops(execute):
    owner, agent, runner = execute
    owner.reject_runner("runner-01")
    runner.proc.wait(timeout=30)
    assert runner.proc.returncode != 0
    assert "rejected" in runner.output()


PROBE = """
import os, socket
def attempt(label, fn):
    try:
        fn()
        print(label, "allowed")
    except Exception as e:
        print(label, "denied", type(e).__name__)
attempt("network", lambda: socket.create_connection(("1.1.1.1", 53), timeout=2))
attempt("write-usr", lambda: open("/usr/airlock-probe", "w"))
attempt("read-home", lambda: os.listdir(os.path.expanduser("~" + os.environ.get("RUNNER_USER", "tester"))))
attempt("write-out", lambda: open(os.path.join(os.environ["AIRLOCK_OUT"], "ok.txt"), "w").write("ok"))
pids = [p for p in os.listdir("/proc") if p.isdigit()]
print("pids", len(pids))
print("cwd", os.getcwd())
"""


@pytest.mark.skipif(
    not (sys.platform.startswith("linux") or os.environ.get("AIRLOCK_TEST_SANDBOX") == "docker"),
    reason="the local backend only sandboxes on Linux",
)
def test_sandbox_confines_the_job(execute):
    owner, agent, runner = execute
    owner.approve_runner("runner-01")
    wait_runner(agent, "runner-01", lambda r: r.approved)
    res = agent.run_python(PROBE).wait(timeout=60)
    assert res.ok, (res, runner.output())
    lines = dict(line.split(" ", 1) for line in res.stdout.strip().splitlines())
    assert lines["network"].startswith("denied"), res.stdout
    assert lines["write-usr"].startswith("denied"), res.stdout
    assert lines["read-home"].startswith("denied"), res.stdout
    assert lines["write-out"] == "allowed", res.stdout
    assert int(lines["pids"]) <= 3, res.stdout
    assert lines["cwd"] == "/work", res.stdout
