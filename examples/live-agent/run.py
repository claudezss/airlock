"""Live agent: a real coding agent picks up a task through Airlox.

    python examples/live-agent/run.py [relay-url]           # Claude Code: `claude` signed in
    AIRLOX_AGENT=codex python examples/live-agent/run.py    # or Codex: `codex` signed in

- A data team (Python SDK) owns an execute session with one approved runner,
  `analysis-box`. It posts a CSV and a question.
- The agent runs headless (`claude -p` or `codex exec`) with the `airlox mcp` server joined
  through the sender link. Nothing else is scripted: the model reads the
  session, writes Python, runs it on the runner with `run_python` and posts
  its answer with `send_text`.
- The data team checks the answer against its own computation, and that it
  came from a job the runner signed.

Set AIRLOX_AGENT_MODEL to pick the model (default: Claude Code's). The run
calls the model, so it costs tokens: the test suite runs it only when
AIRLOX_LIVE_AGENT=1.
"""

import csv
import io
import json
import os
import pathlib
import re
import subprocess
import sys
import zipfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from _local import binary, main, quiet, wait_for_runner  # noqa: E402

from airlox import Session  # noqa: E402

LIMITS = {"runtime": "python3.12", "timeout_s": 60, "memory_mb": 512, "network": False,
          "packages": [], "return_out": True, "approve_runners": True}
SALES = [("2026-09-01", "east", 120), ("2026-09-01", "west", 340), ("2026-09-02", "north", 75),
         ("2026-09-02", "east", 60), ("2026-09-03", "south", 210), ("2026-09-03", "west", 15),
         ("2026-09-04", "north", 125), ("2026-09-04", "south", 90)]
TASK = ("sales.zip holds sales/2026-09.csv (date, region, amount). Compute the total amount per region "
        "by running Python on the runner analysis-box; don't compute it yourself. Reply with exactly one "
        'message of the form ANSWER {"east": 180, ...} with every region.')
PROMPT = """You are an analysis agent. The airlox MCP tools are already joined to an Airlox session as a \
sender. The data team in that session will post a task and a data file: do that task, using only the \
airlox tools. Read the session with list_items (wait_s=30 if it is empty), pass the data file's item \
id in `files` when you call run_python (ZIPs are unpacked in the job's working directory), and post \
your reply with send_text. Then stop."""


def sales_zip() -> bytes:
    buf = io.StringIO()
    csv.writer(buf).writerows([("date", "region", "amount"), *SALES])
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        z.writestr("sales/2026-09.csv", buf.getvalue())
    return out.getvalue()


TOOLS = ["list_items", "session_info", "list_runners", "run_python", "get_result", "send_text"]


def describe(tool: str, args: dict) -> str:
    """A tool call as the narration shows it."""
    if tool == "run_python":
        code = args.get("code", "").strip().splitlines()
        rest = {k: v for k, v in args.items() if k != "code"}
        return f"run_python({', '.join(f'{k}={v!r}' for k, v in rest.items())}, code=\n" + "\n".join(
            "    " + line for line in code[:8]) + ("\n    …" if len(code) > 8 else "") + ")"
    return f"{tool}({', '.join(f'{k}={v!r}' for k, v in args.items())})"


def events(agent: str, line: str):
    """(tool, args) for each airlox tool call and (None, text) for each
    message in one line of the agent's JSON event stream."""
    try:
        ev = json.loads(line)
    except ValueError:
        return
    if agent == "codex":
        item = ev.get("item") or {}
        if ev.get("type") == "item.started" and item.get("type") == "mcp_tool_call":
            yield item["tool"], item.get("arguments") or {}
        elif ev.get("type") == "item.completed" and item.get("type") == "agent_message":
            yield None, item["text"]
    elif ev.get("type") == "assistant":
        for block in ev["message"].get("content", []):
            if block.get("type") == "tool_use" and block["name"].startswith("mcp__airlox__"):
                yield block["name"].removeprefix("mcp__airlox__"), block.get("input") or {}
            elif block.get("type") == "text" and block["text"].strip():
                yield None, block["text"]


def run_agent(agent: str, invite: str, workdir: pathlib.Path, step=quiet):
    """Run the coding agent headless and narrate its tool calls. Returns its
    exit code and the tail of its output. The invite goes in the environment,
    which the agent passes on to `airlox mcp`, never on a command line other
    users could read in `ps`."""
    airlox = binary("AIRLOX_BIN", "airlox")
    mcp_args = ["mcp", "--allow-dir", str(workdir), "--as", agent, "--cache-dir",
                str(workdir.parent / "cache" / agent), "--description", "Answers data questions on the runner"]
    model = os.environ.get("AIRLOX_AGENT_MODEL")
    env = {k: v for k, v in os.environ.items() if k != "CLAUDECODE"}  # may run inside Claude Code
    env["AIRLOX_INVITE"] = invite
    if agent == "codex":
        args = ["codex", "exec", "--json", "--skip-git-repo-check", "--ephemeral", "--sandbox", "read-only",
                "-c", f"mcp_servers.airlox.command={json.dumps(airlox)}",
                "-c", f"mcp_servers.airlox.args={json.dumps(mcp_args)}",
                "-c", 'mcp_servers.airlox.env_vars=["AIRLOX_INVITE"]',
                "-c", f"mcp_servers.airlox.enabled_tools={json.dumps(TOOLS)}",
                "-c", 'mcp_servers.airlox.default_tools_approval_mode="approve"']
        args += ["-m", model] if model else []
        args.append(PROMPT)
    else:
        config = workdir.parent / "claude-mcp.json"
        config.write_text(json.dumps({"mcpServers": {"airlox": {"command": airlox, "args": mcp_args}}}))
        args = ["claude", "-p", PROMPT, "--mcp-config", str(config), "--strict-mcp-config",
                "--allowedTools", ",".join(f"mcp__airlox__{t}" for t in TOOLS),
                "--no-session-persistence", "--output-format", "stream-json", "--verbose"]
        args += ["--model", model] if model else []
    stderr = workdir.parent / f"{agent}.stderr"
    with stderr.open("w") as err:
        proc = subprocess.Popen(args, cwd=workdir, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=err, text=True)
        tail = []
        for line in proc.stdout:
            tail = (tail + [line])[-20:]
            for tool, detail in events(agent, line):
                if tool:
                    step(agent, f"calls {tool}", describe(tool, detail))
                else:
                    step(agent, "says", out=detail)
        code = proc.wait(timeout=600)
    return code, "".join(tail)[-2000:] + stderr.read_text()[-2000:]


def scenario(relay: str, start_runner, workdir: pathlib.Path, step=quiet) -> dict:
    workdir.mkdir(parents=True, exist_ok=True)
    cache = workdir.parent / "cache"
    agent = os.environ.get("AIRLOX_AGENT", "claude")
    step("data-team", "Creates an execute session", 'Session.create(relay, mode="execute", job_limits=LIMITS)')
    team = Session.create(relay, mode="execute", job_limits=LIMITS, display_name="data-team",
                          cache_dir=cache / "team")
    step("analysis-box", "Joins as a runner; the data team approves it",
         '$ airlox runner join --name analysis-box\nteam.approve_runner("analysis-box")', observe=team.invites["observer"])
    start_runner(team.invites["runner"], "analysis-box", "--description", "Python 3.12, no network")
    wait_for_runner(team, "analysis-box")
    team.approve_runner("analysis-box")
    wait_for_runner(team, "analysis-box", approved=True)

    step("data-team", "Posts the data and the question", 'data = send_file("sales.zip")\nsend_text("Total amount per region … run it on analysis-box")')
    data = team.send_file(sales_zip(), name="sales.zip")
    team.send_text(TASK, refs=[data])

    command = "codex exec" if agent == "codex" else "claude -p"
    step("data-team", f"Starts a real {agent} agent with the airlox MCP server and the sender link",
         f'$ AIRLOX_INVITE=<sender link> {command} "Do the task the data team posts …"')
    agent_exit, agent_output = run_agent(agent, team.invites["sender"], workdir, step)
    team.sync()
    items = team.items()
    by_agent = [i for i in items if i.author_name == agent]
    jobs = [i for i in by_agent if i.kind == "job"]
    results = [i for i in items if i.kind == "result" and i.meta["job"]["id"] in {j.id for j in jobs}]
    replies = [i.text for i in by_agent if i.kind == "text"]
    match = re.search(r"ANSWER\s*(\{.*\})", replies[-1] if replies else "", re.S)

    expected = {}
    for _, region, amount in SALES:
        expected[region] = expected.get(region, 0) + amount
    answer = json.loads(match.group(1)) if match else None
    step("data-team", "Checks the answer and the runner's signature", "answer == totals computed locally",
         out=f"{'match' if answer == expected else 'MISMATCH'} · {len(results)} signed result(s) from analysis-box")
    team.close()
    return {
        "agent": agent,
        "agent_exit": agent_exit,
        "jobs_by_agent": len(jobs),
        "signed_results": [r.meta.get("exit_code") for r in results],
        "reply": replies[-1] if replies else None,
        "answer": answer,
        "expected": expected,
        "agent_output": agent_output if agent_exit or not match else "",
    }


if __name__ == "__main__":
    main(scenario)
