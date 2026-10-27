"""The process sandbox end to end: an operator's interpreter, progress
reports, one job at a time, and the network gap it cannot close."""

import json
import platform
import sys
import time

import pytest

from airlox import RunnerBusy, RunnerFailed, Session

from test_execute import LIMITS, wait_runner

# The interpreter running these tests is the one the runner gets.
PROCESS_LIMITS = dict(LIMITS, runtime=f"python3.{sys.version_info.minor}", timeout_s=60)

LOGGING_JOB = """
import os, time
os.makedirs("logs", exist_ok=True)
with open("logs/run.log", "w") as f:
    for i in range(6):
        f.write(f"step {i}\\n")
        f.flush()
        time.sleep(0.7)
print("AIRLOX_INVITE" in os.environ)
"""


def start_process_runner(owner, start_runner, name, *extra):
    return start_runner(
        owner.invites["runner"], name, "--sandbox", "process", "--python", sys.executable, *extra
    )


def test_process_runner_reports_progress_and_refuses_while_busy(relay, caches, start_runner):
    owner = Session.create(relay.url, mode="execute", job_limits=PROCESS_LIMITS, cache_dir=caches("owner"))
    agent = Session.join(owner.invites["sender"], cache_dir=caches("agent"))
    runner = start_process_runner(
        owner, start_runner, "proc-01", "--accept-network-gap", "--progress-interval", "1s"
    )
    r = wait_runner(owner, "proc-01", lambda r: r.online, proc=runner)
    assert (r.sandbox, r.network_unblocked, r.python) == ("process", True, platform.python_version())
    assert r.version and not r.busy
    owner.approve_runner("proc-01")
    agent.wait_for_runner("proc-01", approved=True)

    job = agent.run_python(LOGGING_JOB, runner="proc-01", progress_file="logs/run.log")
    until = time.monotonic() + 20
    while job.state()["state"] != "running" and time.monotonic() < until:
        time.sleep(0.1)
    assert agent._runner("proc-01").busy
    # Busy: refused at once, not queued.
    with pytest.raises(RunnerBusy):
        agent.run_python("print(1)", runner="proc-01")

    seen = []
    res = job.wait(timeout=60, on_progress=seen.append)
    # The runner's own environment (its invite) never reaches the job.
    assert (res.status, res.exit_code, res.stdout.strip()) == ("completed", 0, "False"), (res, runner.output())
    assert seen, runner.output()
    assert all(p.runner == r.participant_pub for p in seen)
    assert [p.elapsed_ms for p in seen] == sorted(p.elapsed_ms for p in seen)
    assert any(p.tail and "step" in p.tail for p in seen)
    assert job.progress()[: len(seen)] == seen
    assert not agent._runner("proc-01").busy


def test_process_runner_refuses_a_no_network_session_unless_accepted(relay, caches, start_runner):
    owner = Session.create(relay.url, mode="execute", job_limits=PROCESS_LIMITS, cache_dir=caches("owner"))
    runner = start_process_runner(owner, start_runner, "proc-02")
    with pytest.raises(RunnerFailed, match="--accept-network-gap"):
        owner.wait_for_runner("proc-02", timeout=60)
    runner.proc.wait(timeout=30)
    assert runner.proc.returncode != 0


def test_process_runner_names_missing_packages(relay, caches, start_runner):
    limits = dict(PROCESS_LIMITS, network=True, packages=["surely-not-installed-pkg"])
    owner = Session.create(relay.url, mode="execute", job_limits=limits, cache_dir=caches("owner"))
    start_process_runner(owner, start_runner, "proc-03")
    with pytest.raises(RunnerFailed, match="surely-not-installed-pkg"):
        owner.wait_for_runner("proc-03", timeout=60)


ANSWER_JOB = """
import json, os
print("answer-saved-marker")
json.dump({"answer": 42, "items": ["a", "b"]}, open(os.path.join(os.environ["AIRLOX_OUT"], "answer.json"), "w"))
"""


def test_a_result_saved_before_a_crash_is_posted_after_restart(relay, caches, start_runner):
    owner = Session.create(relay.url, mode="execute", job_limits=PROCESS_LIMITS, cache_dir=caches("owner"))
    agent = Session.join(owner.invites["sender"], cache_dir=caches("agent"))
    runner = start_process_runner(owner, start_runner, "proc-04", "--accept-network-gap", "--exit-before-posting")
    wait_runner(owner, "proc-04", lambda r: r.online, proc=runner)
    owner.approve_runner("proc-04")
    agent.wait_for_runner("proc-04", approved=True)

    job = agent.run_python(ANSWER_JOB, runner="proc-04")
    # The answer is in the runner's outbox, but nothing reached the relay.
    runner.proc.wait(timeout=60)
    assert runner.proc.returncode == 3, runner.output()
    agent.sync()
    assert job.result() is None, runner.output()

    # Same name, same cache: the same runner, which posts the saved answer.
    # (Its log replaces the first run's.)
    again = start_process_runner(owner, start_runner, "proc-04", "--accept-network-gap")
    res = job.wait(timeout=60)
    assert (res.status, res.exit_code) == ("completed", 0), (res, again.output())
    assert "answer-saved-marker" in res.stdout
    assert res.signed
    assert json.loads(res.read("answer.json")) == {"answer": 42, "items": ["a", "b"]}
    results = [i for i in agent.items() if i.kind == "result" and i.meta.get("job", {}).get("id") == job.id]
    assert len(results) == 1, (results, again.output())
