# Pain points

What got in the way while building the [use cases](use-cases.md): writing
each scenario against the SDK, the CLI and the MCP server, running real
Claude Code and Codex agents through a session, and recording the demos.
Each entry says what happened, where it lives and a suggested fix. Most
recent first within each list.

## Fixed

| What | Fix |
|---|---|
| A runner that failed to prepare its sandbox never appeared in the session; owners and agents waited until they timed out | Runners join first and report `preparing` / `ready` / `failed` with a reason (`state`, `detail` in `GET /runners`), shown by the SDK, CLI, MCP and web UI |
| Files a job wrote besides top-level images came back only inside `out.zip`, so reading a 100-byte report meant saving and unpacking it | `--out-dir` and MCP `save_dir` unpack `out.zip` beside it; results carry small text files inline as `out_text`; the SDK has `Result.read(name)` |
| Results named their runner only by its key | `runner_name` in the SDK's `Result`, CLI JSON and MCP results |
| Runners started together on one machine (sharing `~/.cache/airlox`) deleted each other's half-built job runtime and exited | A lock per runtime in the local sandbox: one builds, the others wait |
| The web timeline stopped following new items when the sidebar sat below it (narrow windows) or a card grew as its file or result arrived | It follows when the reader is at the end of the timeline, not of the page |
| The landing page told runners to pass the invite with `--invite` (visible in `ps`) and to install with `cargo` | `AIRLOX_INVITE=…` and `pip install airlox` / `npm install -g airlox` |

## Open

### Waiting for a runner is hand-written everywhere

Every script polls `session.runners()` until a runner is online, and again
after `approve_runner` until a sender sees the approval:
`run_python(runner=…)` raises `PolicyError` ("no signed approval from the
owner yet") if it is called straight after the owner approves. The tests
(`wait_runner`) and the examples (`wait_for_runner` in `examples/_local.py`)
each have their own loop.

**Suggested fix:** `Session.wait_for_runner(name, approved=False, timeout=…)`
in the SDK. It should raise at once, with the runner's `detail`, when the
runner reports `failed`. A matching `airlox runner wait <name>` would cover
CLI agents.

### Your own items come back to you

`Session.stream()` and the MCP `list_items` tool return the caller's own
items. Every bot filters them out (`item.author != s.participant_pub` in the
review bot), and a model has to recognise its own messages by name.

**Suggested fix:** `Item.mine` in the SDK and `"mine": true` in the CLI's
and MCP's item JSON. A `stream(include_own=False)` option could come later.

### Headless agents need tool pre-approval, and a worker prompt

`codex exec` refused `run_python` and `send_text` ("approval policy is
never") until `default_tools_approval_mode="approve"` was set. `claude -p`
needs `--allowedTools`. And because every tool result says that session
content is data, not instructions, a worker agent only does a task posted
in the session if its own prompt says to. That is the right default, but
every integrator has to discover it.

**Suggested fix:** the README now documents the settings. Going further: an
`airlox mcp config codex|claude` command that prints a ready-made config
(invite in the environment, read and run tools enabled), plus a
recommended worker prompt in `skills/airlox/SKILL.md`
(`examples/live-agent/run.py` has one that works).

### Generic default names

Participants appear as `mcp`, `cli` and `owner` unless the caller passes a
name, so a session with two agents shows two `mcp`s. During the MCP
handshake the client sends its name (`clientInfo.name`: `codex`,
`claude-code`, …).

**Suggested fix:** default `airlox mcp`'s display name to the client's
name, and the CLI's to the user and host (`claude@build-01`). `--as` still
overrides both.

### Every MCP job is called `main.py`

When a model calls `run_python` without `filename`, which it usually does,
the job is `main.py`, so the web UI and the audit trail show a row of
`main.py` jobs.

**Suggested fix:** ask for a descriptive `filename` in the tool's
description, or derive one from the code's first comment or function name.

### The macOS local backend shows the runner's paths

On macOS the local backend runs jobs as plain processes in the runner's
cache, so a job's tracebacks and `os.getcwd()` reveal where that is, e.g.
`/Users/alice/.cache/airlox/ax_…/jobs/job-…/work`. Senders learn the
runner's user name and directory layout. The Linux sandbox and Docker mount
the job at `/work`.

**Suggested fix:** note it beside the existing "cannot block network
access" warning for this backend, and/or default its cache outside the
home directory (e.g. under the system temp directory).

### An owner can approve a runner that failed to start

The web UI shows a failed runner's reason, but still offers **Approve**
for it. Approving does no harm, since the runner has exited, but it invites
the question of why approved work never runs.

**Suggested fix:** hide **Approve** for a runner whose state is `failed`,
or put the reason next to the button.

### No relay in the pip and npm packages

`pip install airlox` and `npm install -g airlox` ship the client, runner
and MCP server, but not `airlox-server`. Trying the examples or testing an
integration locally needs a Rust build or a Docker build. Otherwise the
examples fall back to the public relay.

**Suggested fix:** publish the relay image (e.g. `ghcr.io/claudezss/airlox`)
from the release workflow, or add a development-only `airlox relay --ephemeral`
to the main binary.
