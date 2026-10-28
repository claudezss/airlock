"""Agent conversation: two real coding agents, each woken by `airlox listen`,
talk to each other in one session.

    python examples/agent-conversation/run.py [relay-url]   # `claude` and `codex` signed in

- The lead (Python SDK) owns the session. It posts a file and asks
  claude-agent to review it, and to ask codex-agent for a fix.
- Each agent has an `airlox listen --agent … --fresh` waiting for it. Nothing
  else is scripted: the listener starts the agent when a message is for it
  (addressed to it, or a reply to its own message), and the agent reads the
  thread and answers through its airlox MCP tools.
- Each listener takes wakes only from the lead and the other agent, named by
  key (`--from`), since a display name could be anyone's.

The run calls both models, so it costs tokens: the test suite runs it only
when AIRLOX_LIVE_AGENT=1.
"""

import os
import pathlib
import shutil
import signal
import subprocess
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from _local import binary, main, quiet  # noqa: E402

from airlox import Session  # noqa: E402

PATCH = '''\
def apply_discount(order, expr):
    """Apply a discount rule such as "total * 0.9" to an order."""
    return eval(expr, {}, {"total": order["total"]})
'''

ASK = ("@claude-agent please review discounts.py. Ask @codex-agent for a safe replacement for the eval "
       "line (address your message to codex-agent), wait for its answer, then reply to this message "
       "with a short summary for me. codex-agent: answer claude-agent once, as a reply to its message.")

AGENTS = {"claude-agent": "claude", "codex-agent": "codex"}
TIMEOUT_S = 600


def shims(bin_dir: pathlib.Path, airlox: str, cfg: pathlib.Path) -> None:
    """`claude` and `codex` on PATH that use this build's `airlox mcp` and
    nothing else. A real setup adds the server once (`claude mcp add airlox
    -- npx -y airlox mcp`); `airlox listen` relies on that name."""
    bin_dir.mkdir(parents=True, exist_ok=True)
    cfg.write_text('{"mcpServers": {"airlox": {"command": "%s", "args": ["mcp"]}}}' % airlox)
    for name, extra in [("claude", f'--mcp-config "{cfg}" --strict-mcp-config'),
                        ("codex", f"-c 'mcp_servers.airlox.command=\"{airlox}\"' -c 'mcp_servers.airlox.args=[\"mcp\"]'")]:
        real = shutil.which(name)
        (bin_dir / name).write_text(f'#!/bin/sh\nexec "{real}" {extra} "$@"\n')
        (bin_dir / name).chmod(0o755)


def scenario(relay: str, start_runner, workdir: pathlib.Path, step=quiet) -> dict:
    workdir.mkdir(parents=True, exist_ok=True)
    cache = workdir / "cache"
    airlox = binary("AIRLOX_BIN", "airlox")
    shims(workdir / "bin", airlox, workdir / "mcp.json")

    step("lead", "Creates a session", 'Session.create(relay, display_name="lead")')
    lead = Session.create(relay, display_name="lead", cache_dir=cache / "lead")
    sender = lead.invites["sender"]

    # Join each agent once, to learn its key: its listener and its MCP server
    # use the same cache, so they are this participant.
    keys = {}
    for name in AGENTS:
        keys[name] = Session.join(sender, display_name=name, cache_dir=cache / name).participant_pub

    env = {k: v for k, v in os.environ.items() if k != "CLAUDECODE" and not k.startswith("AIRLOX_")}
    env["PATH"] = f"{workdir / 'bin'}{os.pathsep}{env['PATH']}"
    listeners = []
    for name, agent in AGENTS.items():
        other = next(n for n in AGENTS if n != name)
        home = workdir / name
        home.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=home, check=True)  # Codex runs only in a repository
        step(name, f"Waits for messages for it; {agent} is started for each one",
             f"$ airlox listen --agent {agent} --fresh \\\n    --from owner --from {keys[other][:10]}…  # {other}",
             observe=lead.invites["observer"] if not listeners else None)
        log = (workdir / f"{name}.log").open("w")
        listeners.append(subprocess.Popen(
            [airlox, "listen", "--invite", sender, "--as", name, "--cache-dir", str(cache / name),
             "--agent", agent, "--fresh", "--from", "owner", "--from", keys[other],
             "--timeout", f"{TIMEOUT_S}s", "--run-timeout", "5m"],
            cwd=home, env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
            start_new_session=True))
    time.sleep(2)

    step("lead", "Posts a file and asks claude-agent to review it with codex-agent",
         'f = send_file("discounts.py")\nsend_text("@claude-agent please review …",\n          to=["claude-agent"], reply_to=f)')
    f = lead.send_file(PATCH.encode(), name="discounts.py")
    ask = lead.send_text(ASK, to=["claude-agent"], reply_to=f["id"])

    # Narrate the conversation from the lead's side, as items arrive.
    names = {v: k for k, v in keys.items()}
    names[lead.participant_pub] = "lead"
    seen, summary, deadline = set(), None, time.monotonic() + TIMEOUT_S
    while summary is None and time.monotonic() < deadline:
        lead.sync()
        by_id = {i.id: i for i in lead.items()}
        for it in by_id.values():
            if it.id in seen or it.kind != "text" or it.author == lead.participant_pub:
                continue
            seen.add(it.id)
            to = [names.get(k, k[:8]) for k in (it.to or [])]
            parent = by_id.get(it.reply_to)
            call = ", ".join(filter(None, ["…", to and f"to={to}", parent and f"reply_to=#{parent.seq}"]))
            step(names.get(it.author, it.author_name), "is woken, reads the thread and answers",
                 f"send_text({call})", out=it.text if len(it.text) < 400 else it.text[:400] + " …")
            if it.author == keys["claude-agent"] and it.reply_to == ask["id"]:
                summary = it.text
        time.sleep(1)

    for p in listeners:
        try:
            os.killpg(p.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        p.wait(timeout=15)
    lead.sync()
    thread = [(names.get(i.author, i.author_name), [names.get(k, k) for k in (i.to or [])], i.text)
              for i in lead.items() if i.kind == "text"]
    step("lead", "Has the summary; closes the session", "close()")
    lead.close()
    return {
        "summary": summary,
        "thread": thread,
        "participants": sorted(names.values()),
        "logs": {n: (workdir / f"{n}.log").read_text()[-2000:] for n in AGENTS} if summary is None else {},
    }


if __name__ == "__main__":
    main(scenario)
