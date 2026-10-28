"""The process sandbox end to end: an operator's interpreter, progress
reports, one job at a time, and the network gap it cannot close."""

import json
import os
import platform
import subprocess
import sys
import time

import pytest

from airlox import RunnerBusy, RunnerFailed, Session

from test_execute import LIMITS, wait_runner


def _windows_admin() -> bool:
    """An administrator account, elevated or not: the runner refuses it."""
    if os.name != "nt":
        return False
    groups = subprocess.run(["whoami", "/groups"], capture_output=True, text=True, errors="replace").stdout
    return "S-1-5-32-544" in groups


pytestmark = pytest.mark.skipif(
    _windows_admin(), reason="the runner refuses administrator accounts; run as a standard user"
)

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


def _installed(name: str) -> str:
    from importlib import metadata

    return metadata.version(name)


def test_python_pins_are_checked_and_results_report_the_environment(relay, caches, start_runner):
    pytest_version = _installed("pytest")
    limits = dict(PROCESS_LIMITS, network=True, packages=[f"pytest=={pytest_version}", "httpx>=0.1,<999"])
    owner = Session.create(relay.url, mode="execute", job_limits=limits, cache_dir=caches("owner"))
    assert owner.manifest["job_limits"]["packages"] == [f"pytest=={pytest_version}", "httpx>=0.1,<999"]
    agent = Session.join(owner.invites["sender"], cache_dir=caches("agent"))
    runner = start_process_runner(owner, start_runner, "proc-05")
    wait_runner(owner, "proc-05", lambda r: r.online, proc=runner)
    owner.approve_runner("proc-05")
    agent.wait_for_runner("proc-05", approved=True)

    # Jobs name the package; the version is the session's.
    res = agent.run_python("import pytest; print(pytest.__version__)", runner="proc-05",
                           requirements=["pytest"]).wait(timeout=60)
    assert (res.status, res.stdout.strip()) == ("completed", pytest_version), (res, runner.output())
    env = res.env
    assert env["interpreter"] == "--python" and env["sandbox"] == "process", env
    assert env["python"] == platform.python_version()
    assert env["packages"] == {"pytest": pytest_version, "httpx": _installed("httpx")}
    assert env["airlox"]
    # Nothing about where the interpreter or the work folder is.
    assert os.path.dirname(sys.executable) not in json.dumps(env)
    refused = agent.run_python("print(1)", runner="proc-05", requirements=[f"pytest=={pytest_version}"])
    res = refused.wait(timeout=60)
    assert res.status == "refused" and "requirements name packages only" in res.reason, res


def test_a_python_with_the_wrong_version_of_a_pinned_package_does_not_join(relay, caches, start_runner):
    limits = dict(PROCESS_LIMITS, network=True, packages=["pytest==0.0.1"])
    owner = Session.create(relay.url, mode="execute", job_limits=limits, cache_dir=caches("owner"))
    start_process_runner(owner, start_runner, "proc-06")
    want = f"--python has pytest {_installed('pytest')}, but the session pins pytest==0.0.1"
    with pytest.raises(RunnerFailed, match=want.replace(".", r"\.")):
        owner.wait_for_runner("proc-06", timeout=60)


PATH_JOB = """
import os, sys
print("cwd", os.getcwd())
print("out", os.environ["AIRLOX_OUT"])
print("repr", repr(os.getcwd()))
print("tb", os.getcwd(), file=sys.stderr)
open(os.path.join(os.environ["AIRLOX_OUT"], "where.txt"), "w").write(os.getcwd())
"""


def test_jobs_work_under_the_work_root_and_their_output_does_not_name_it(relay, caches, start_runner, tmp_path):
    root = tmp_path / "neutral-work-root"
    owner = Session.create(relay.url, mode="execute", job_limits=PROCESS_LIMITS, cache_dir=caches("owner"))
    agent = Session.join(owner.invites["sender"], cache_dir=caches("agent"))
    runner = start_process_runner(
        owner, start_runner, "proc-07", "--accept-network-gap", "--work-root", str(root)
    )
    wait_runner(owner, "proc-07", lambda r: r.online, proc=runner)
    owner.approve_runner("proc-07")
    agent.wait_for_runner("proc-07", approved=True)

    res = agent.run_python(PATH_JOB, runner="proc-07").wait(timeout=60)
    assert res.ok, (res, runner.output())
    lines = res.stdout.splitlines()
    assert lines[0] == "cwd $WORK" and lines[1] == "out $AIRLOX_OUT", res.stdout
    assert lines[2] == "repr '$WORK'", res.stdout
    assert res.stderr.strip() == "tb $WORK", res.stderr
    for real in (str(root), os.path.realpath(root), "airlox-jobs"):
        assert real not in res.stdout + res.stderr, (real, res.stdout)
    # What the job wrote is returned as it is: the folder was under the root.
    where = res.read("where.txt").decode()
    assert os.path.realpath(where).startswith(os.path.realpath(root)), where
    assert os.path.basename(os.path.dirname(os.path.dirname(where))).startswith("airlox-jobs-"), where
    # The runner cleaned up after the job.
    time.sleep(0.5)
    assert not os.path.exists(where)
