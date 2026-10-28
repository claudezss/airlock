# airlox

Python SDK for [Airlox](https://github.com/claudezss/airlox): secure,
short-lived sessions where code and LLM agents share messages, files and
runnable Python. Everything is end-to-end encrypted and signed; the relay only
sees ciphertext.

```bash
pip install airlox
```

```python
from airlox import Session

s = Session.join("https://relay.example/s/ax_…#v=1&r=send&k=…&rk=…", display_name="build-agent")
s.send_text("Build finished.")
s.send_file("report.md")
for item in s.stream():
    if not item.mine:
        print(item.author_role, item.kind, item.text or item.name)
```

`item.mine` is true for items this session wrote, so a bot can skip its own.

In an execute session, `s.run_python(...)` sends code to an approved runner
and `job.wait()` returns its output and any files it wrote. Wait for the
runner first: `s.wait_for_runner("ci-box", approved=True)` returns once it is
online and this session has seen the owner's signed approval, and raises
`RunnerFailed` at once if the runner could not start its sandbox.

If the session allows shell jobs (`job_limits={..., "kinds": ["python", "shell"]}`),
`s.run_shell("make test", runner="ci-box")` runs a script with the runner's own
tools, as `airlox run -- make test` does. Runners say which kinds they take in
`Runner.kinds` and `Runner.shell`; `cwd=` and `fresh=True` are for sessions
with `"workspace": True`.

`tree=` sends a working tree along, as `airlox run --tree` does:

```python
job = s.run_shell("pytest -x", runner="ci-box", tree=".", tree_exclude=["*.sqlite"])
result = job.wait(timeout=None, on_output=lambda c: print(c.data, end=""))
```

The tree is the repository's tracked and untracked files (ignored ones left
out), and files named like credentials (`.env`, `*.pem`) are refused unless
`tree_allow=` names them. The job starts in the directory you gave, within
the tree. In a session with workspaces, later jobs to the same runner send
only the files that changed. `on_output` sees output as it streams;
`job.chunks()` and `job.output("stderr")` read it so far. Runners started
with `--concurrency N` take N jobs at once: `Runner.jobs`, `Runner.slots`
and `Runner.busy` (every slot taken).

Creating a session returns its owner. **Save the owner invite
(`session.invites["owner"]`) somewhere private right away**, such as a file
only you can read (mode 0600, outside any repository): it is the only way to
approve runners, revoke a role or close the session later, and `Session.join`
with it reopens the session as owner. Anyone who has it controls the session,
so don't print it or pass it to agents; hand out the `sender`, `observer` and
`runner` invites instead. The CLI does the same with
`airlox session create --owner-invite-file FILE`.

```python
import os

owner = Session.create("https://airlox.app", mode="execute", job_limits={...})
fd = os.open("owner.link", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w") as f:
    f.write(owner.invites["owner"])
```

Package allowlist entries in `job_limits` may pin versions with a PEP 440
specifier, such as `"cugrid==0.1.0"` or `"numpy>=1.26,<3"`. Every result says
where the job ran, signed by the runner: `res.env` holds the Python version,
the installed version of each allowlisted package, the sandbox and where the
interpreter came from.

The wheels also install the `airlox` command: the command-line client, the
runner and a local MCP server for agents.

```bash
uvx airlox session create --json
uvx airlox mcp --allow-dir ~/airlox-work
```

See the [repository](https://github.com/claudezss/airlox) for the relay, the
runner and the protocol.

<!-- mcp-name: io.github.claudezss/airlox -->
