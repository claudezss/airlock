"""The process sandbox end to end: an operator's interpreter, progress
reports, one job at a time, and the network gap it cannot close."""

import json
import os
import platform
import subprocess
import sys
import time

import pytest

import io
import zipfile

from airlox import PolicyError, Runner, RunnerBusy, RunnerFailed, Session, TreeRefused

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


SHELL_LIMITS = dict(PROCESS_LIMITS, kinds=["python", "shell"], workspace=True)
posix_only = pytest.mark.skipif(os.name == "nt", reason="a Windows runner offers shell jobs only with --shell pwsh")


@posix_only
def test_shell_jobs_run_with_a_kept_workspace(relay, caches, start_runner):
    owner = Session.create(relay.url, mode="execute", job_limits=SHELL_LIMITS, cache_dir=caches("owner"))
    agent = Session.join(owner.invites["sender"], cache_dir=caches("agent"))
    runner = start_process_runner(owner, start_runner, "proc-05", "--accept-network-gap", "--workspace")
    r = wait_runner(owner, "proc-05", lambda r: r.online, proc=runner)
    assert (r.kinds, r.shell) == (["python", "shell"], "sh")
    owner.approve_runner("proc-05")
    agent.wait_for_runner("proc-05", approved=True)

    # What the browser and the CLI send: kind and subkind say shell, and `sh -e` stops at the first failure.
    job = agent.run_shell("echo out; echo err >&2; false; echo not-reached", runner="proc-05")
    assert job.meta["kind"] == "shell" and job.meta["filename"] == "job.sh"
    res = job.wait(timeout=60)
    assert (res.status, res.exit_code) == ("completed", 1), (res, runner.output())
    assert (res.stdout.strip(), res.stderr.strip()) == ("out", "err")
    assert res.env["shell"] == "sh" and "shell" in res.env["kinds"], res.env
    # Output chunks are not heartbeats.
    heartbeats = [i for i in agent._items.values() if i.kind == "progress" and not i.meta.get("stream")]
    assert len(job.progress()) == len(heartbeats)

    # The workspace outlives a job; `fresh` empties it; `cwd` starts a job in a folder of it.
    ok = agent.run_shell("mkdir -p build && echo kept > build/f.txt", runner="proc-05", fresh=True).wait(timeout=60)
    assert ok.ok, (ok, runner.output())
    res = agent.run_shell("cat f.txt", runner="proc-05", cwd="build").wait(timeout=60)
    assert res.ok and res.stdout.strip() == "kept", (res, runner.output())
    res = agent.run_shell("ls build", runner="proc-05", fresh=True).wait(timeout=60)
    assert res.status == "completed" and res.exit_code != 0, res

    # A Python job still works in the same session.
    res = agent.run_python("print(6 * 7)", runner="proc-05").wait(timeout=60)
    assert res.ok and res.stdout.strip() == "42", (res, runner.output())


def _git_repo(root):
    root.mkdir()
    (root / "sub").mkdir()
    (root / "a.txt").write_text("one\n")
    (root / "sub" / "b.txt").write_text("two\n")
    (root / "big.bin").write_bytes(os.urandom(200_000))
    (root / ".gitignore").write_text("node_modules/\n")
    git = lambda *a: subprocess.run(["git", "-C", str(root), *a], check=True, capture_output=True)
    git("init", "-q")
    git("add", "-A")
    git("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init")


def _sent_tree(agent, job):
    """The files in the zip a job sent as its tree, and whether it was a delta."""
    agent.sync()
    body = agent._items[job.meta["tree"]["id"]].body
    with zipfile.ZipFile(io.BytesIO(body)) as z:
        desc = json.loads(z.read(".airlox/tree.json"))
        return sorted(n for n in z.namelist() if not n.startswith(".airlox/")), desc.get("delta", False)


@posix_only
def test_trees_go_whole_then_as_deltas_and_output_streams(relay, caches, start_runner, runner_cache, tmp_path):
    repo = tmp_path / "repo"
    _git_repo(repo)
    owner = Session.create(relay.url, mode="execute", job_limits=SHELL_LIMITS, cache_dir=caches("owner"))
    agent = Session.join(owner.invites["sender"], cache_dir=caches("agent"))
    runner = start_process_runner(owner, start_runner, "proc-08", "--accept-network-gap", "--workspace")
    wait_runner(owner, "proc-08", lambda r: r.online, proc=runner)
    owner.approve_runner("proc-08")
    agent.wait_for_runner("proc-08", approved=True)

    # Untracked files go along, ignored ones do not, and credentials are refused.
    (repo / "node_modules").mkdir()
    (repo / "node_modules" / "dep.js").write_text("x")
    (repo / ".env").write_text("SECRET=1")
    with pytest.raises(TreeRefused, match=r"\.env"):
        agent.run_shell("true", tree=repo)
    (repo / "new.txt").write_text("new\n")

    # The first tree goes whole; the job starts where the tree was built from.
    job = agent.run_shell("pwd | sed 's|.*/||'; cat b.txt ../new.txt", tree=repo / "sub", tree_exclude=[".env"])
    res = job.wait(timeout=60)
    assert res.ok and res.stdout == "sub\ntwo\nnew\n", (res, runner.output())
    assert _sent_tree(agent, job) == ([".gitignore", "a.txt", "big.bin", "new.txt", "sub/b.txt"], False)
    assert res.env["tree"]["count"] == 5 and res.env["tree"]["changed"] == []

    # Then only what changed; a file the job edits is reported and sent again.
    (repo / "a.txt").write_text("uno\n")
    job = agent.run_shell("cat a.txt; echo edited > sub/b.txt", tree=repo, tree_exclude=[".env"])
    res = job.wait(timeout=60)
    assert res.ok and res.stdout == "uno\n", (res, runner.output())
    assert _sent_tree(agent, job) == (["a.txt"], True)
    assert res.env["tree"]["changed"] == ["sub/b.txt"]
    job = agent.run_shell("cat sub/b.txt", tree=repo, tree_exclude=[".env"])
    assert job.wait(timeout=60).stdout == "two\n"
    assert _sent_tree(agent, job) == (["sub/b.txt"], True)

    # A workspace that is not as this client left it: refused, then sent whole.
    [work] = (runner_cache / "workspaces" / owner.session_id).glob("*/work")
    (work / "big.bin").write_bytes(b"tampered")
    job = agent.run_shell("wc -c < big.bin", tree=repo, tree_exclude=[".env"])
    first = job.id
    res = job.wait(timeout=60)
    assert res.ok and res.stdout.strip() == "200000", (res, runner.output())
    assert job.id != first and _sent_tree(agent, job)[1] is False

    # Output arrives while the job runs, each stream in order.
    seen = []
    job = agent.run_shell("echo one; sleep 2.5; echo two >&2; sleep 1.5; echo three", runner="proc-08")
    res = job.wait(timeout=60, on_output=seen.append)
    assert res.ok, (res, runner.output())
    assert "".join(c.data for c in seen if c.stream == "stdout").startswith("one\n"), seen
    assert [c.data for c in seen if c.stream == "stderr"] == ["two\n"], seen
    assert job.output("stderr") == "two\n"


def test_shell_jobs_are_refused_before_they_leave_the_sender(relay, caches):
    # A session that names no kinds allows Python only.
    owner = Session.create(relay.url, mode="execute", job_limits=PROCESS_LIMITS, cache_dir=caches("owner"))
    with pytest.raises(PolicyError, match="does not allow shell jobs"):
        owner.run_shell("echo hi")

    owner = Session.create(relay.url, mode="execute", job_limits=SHELL_LIMITS, cache_dir=caches("owner2"))
    with pytest.raises(ValueError, match="64 KiB"):
        owner.run_shell("x" * (64 * 1024 + 1))
    # A runner that did not declare shell is not asked to run it.
    py_only = Runner(participant_pub="k", name="py-only", labels=[], host="h", sandbox="docker", network_unblocked=False,
                     approved=True, rejected=False, online=True, kinds=["python"])
    owner.runners = lambda: [py_only]
    with pytest.raises(PolicyError, match="py-only does not run shell jobs"):
        owner.run_shell("echo hi", runner="py-only")
