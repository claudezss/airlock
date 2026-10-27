"""Remote CI: a coding agent runs its project's tests on a runner it does not own.

    python examples/remote-tests/run.py [relay-url]    # default: starts a local relay

- The owner (Python SDK) creates an execute session, starts a runner labelled
  `ci` and approves it. In real use the runner is a build box in another
  team's lab, joined with `airlox runner join`.
- The coding agent only has a shell and the sender link, so it uses the
  `airlox` CLI the way skills/airlox/SKILL.md teaches: zip the project, run
  run_tests.py on any `ci` runner, read the exit code and the report.
- The first run fails (project/stats.py has a bug), the agent fixes the code
  and runs again, then tells the session the suite passes.
"""

import json
import os
import pathlib
import shutil
import subprocess
import sys
import zipfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from _local import binary, main, quiet, wait_for_runner  # noqa: E402

from airlox import Session  # noqa: E402

HERE = pathlib.Path(__file__).resolve().parent
LIMITS = {"runtime": "python3.12", "timeout_s": 60, "memory_mb": 512, "network": False,
          "packages": [], "return_out": True, "approve_runners": True}
FIX = ("    return s[mid]  # the bug the agent will find: wrong for even lengths\n",
       "    return s[mid] if len(s) % 2 else (s[mid - 1] + s[mid]) / 2\n")
RUN = "$ airlox run --label ci --input project.zip --json run_tests.py"


def zip_project(src: pathlib.Path, dest: pathlib.Path) -> None:
    with zipfile.ZipFile(dest, "w") as z:
        for f in sorted(src.rglob("*.py")):
            z.write(f, pathlib.Path("project") / f.relative_to(src))


def agent_cli(*args, invite: str, cache: pathlib.Path) -> subprocess.CompletedProcess:
    """`airlox …` as the coding agent runs it: invite in the environment, not argv."""
    env = dict(os.environ, AIRLOX_INVITE=invite, AIRLOX_NAME="coding-agent", AIRLOX_CACHE_DIR=str(cache))
    return subprocess.run([binary("AIRLOX_BIN", "airlox"), *map(str, args)], env=env, capture_output=True,
                          text=True, timeout=300)


def run_suite(workdir: pathlib.Path, invite: str, cache: pathlib.Path, attempt: int, step=quiet) -> dict:
    archive = workdir / "project.zip"
    zip_project(workdir / "project", archive)
    p = agent_cli("run", "--label", "ci", "--input", archive, "--json", HERE / "run_tests.py",
                  invite=invite, cache=cache)
    res = json.loads(p.stdout)
    # Small text files the job wrote come inline; --out-dir would save them all.
    report = json.loads(next(f["text"] for f in res["out_text"] if f["name"] == "report.json"))
    failed = ", ".join(t.rsplit(".", 1)[-1] for t in report["failed"])
    step("coding-agent", f"Gets the signed result: exit {p.returncode}", 'out_text → "report.json"',
         out=f"{report['ran']} tests, failed: {failed}" if failed else f"{report['ran']} tests, all passed")
    return {"exit_code": p.returncode, "signed": res["signed"], "runner": res["runner_name"], "report": report}


def scenario(relay: str, start_runner, workdir: pathlib.Path, step=quiet) -> dict:
    cache = workdir / "cache"
    step("team-lead", "Creates an execute session", 'Session.create(relay, mode="execute", job_limits=LIMITS)')
    owner = Session.create(relay, mode="execute", job_limits=LIMITS, display_name="team-lead",
                           cache_dir=cache / "owner")
    step("ci-box", "Joins as a runner on the shared build box",
         "$ airlox runner join --name ci-box --labels ci", observe=owner.invites["observer"])
    start_runner(owner.invites["runner"], "ci-box", "--labels", "ci",
                 "--description", "Shared CI box, Python 3.12, no network")
    wait_for_runner(owner, "ci-box")
    step("team-lead", "Approves the runner it expects", 'owner.approve_runner("ci-box")')
    owner.approve_runner("ci-box")
    wait_for_runner(owner, "ci-box", approved=True)

    # The agent's checkout: a copy of the project it is about to change.
    shutil.copytree(HERE / "project", workdir / "project")
    sender = owner.invites["sender"]
    step("coding-agent", "Runs its test suite on any ci runner, from the shell", RUN)
    first = run_suite(workdir, sender, cache / "agent", 1, step)

    stats = workdir / "project" / "stats.py"
    stats.write_text(stats.read_text().replace(*FIX))
    step("coding-agent", "Fixes median() and runs the suite again", RUN)
    second = run_suite(workdir, sender, cache / "agent", 2, step)

    step("coding-agent", "Reports back to the session", '$ airlox send text "stats: 3 tests pass on ci-box …"')
    agent_cli("send", "text", f"stats: {second['report']['ran']} tests pass on ci-box after fixing median()",
              invite=sender, cache=cache / "agent")
    owner.sync()
    jobs = [i for i in owner.items() if i.kind == "job"]
    results = [i for i in owner.items() if i.kind == "result"]
    last = [i.text for i in owner.items() if i.kind == "text"][-1]
    owner.close()
    return {"first": first, "second": second, "jobs_seen_by_owner": len(jobs),
            "results_seen_by_owner": len(results), "last_message": last}


if __name__ == "__main__":
    main(scenario)
