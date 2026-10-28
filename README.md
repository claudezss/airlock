<p align="center">
  <a href="https://airlox.app"><img src="docs/assets/logo.svg" width="96" height="96" alt="Airlox logo"></a>
</p>

<h1 align="center">Airlox</h1>

<p align="center">
  End-to-end encrypted, short-lived sessions where AI agents exchange messages,
  files and runnable code.
</p>

<p align="center">
  <a href="https://airlox.app"><strong>airlox.app</strong></a> ·
  <a href="docs/use-cases.md">Use cases</a> ·
  <a href="docs/DESIGN.md">Design</a> ·
  <a href="docs/protocol.md">Protocol</a> ·
  <a href="docs/deploy.md">Self-hosting</a>
</p>

<p align="center">
  <a href="#license"><img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue" alt="License: MIT OR Apache-2.0"></a>
  <img src="https://img.shields.io/badge/python-3.9%2B-blue" alt="Python 3.9+">
  <img src="https://img.shields.io/badge/rust-1.88-orange" alt="Rust 1.88">
</p>

---

Airlox gives two or more agents (or an agent and a person) a private, temporary
place to work together. One party creates a session and hands out invite
links; each link carries the keys for one role. Participants share text,
Markdown, Python, ZIP archives and images, and in execute sessions they can
send Python to a runner on someone else's machine and receive its output and
files back. The relay in the middle only ever sees ciphertext.

## Features

- **End-to-end encryption.** Every item is encrypted with AES-256-GCM under its
  own key and signed with Ed25519. Keys travel only in the invite link's
  fragment, which browsers never send to the server.
- **Roles, not accounts.** Owner, sender, observer and runner invites grant
  exactly what each participant may do. A participant proves its role with a
  certificate signed by that role's key, and the role keys are fixed in the
  session manifest the owner signed. Every client verifies both.
- **Transit, not storage.** Sessions expire, or last until closed if you ask
  for that, and files leave the relay once every recipient has stored them. There is no database, and the relay keeps
  nothing after a session ends.
- **Remote execution without an LLM on the other side.** A headless runner
  executes signed Python jobs in a Docker sandbox (no network, read-only root,
  dropped capabilities, resource limits) or, on Linux, a namespace and
  Landlock sandbox, and posts back a signed result with any files the job
  wrote.
- **Owner approval.** Execute sessions can require the owner to approve each
  runner before it receives work.
- **One protocol core.** Cryptography, wire formats and input validation live
  in a single Rust crate, used natively by the relay and runner, by Python
  through PyO3 and by the browser through WebAssembly, and checked against
  shared conformance vectors.

## How it works

```
 agent (SDK) ─┐                                   ┌─ runner (airlox runner join)
              │   HTTPS + server-sent events      │
 browser UI ──┼───────────▶   relay   ◀───────────┤
              │   ciphertext and signatures only  │
 agent (SDK) ─┘            (airlox.app)           └─ agent (SDK)
```

1. The owner creates a session. Its signed manifest fixes the mode, lifetime,
   allowed content types and, for execute sessions, the job limits.
2. The owner shares invite links of the form
   `https://airlox.app/s/<session>#…`, with the session key and a role key
   after the `#`.
3. Participants join with a certificate for their role, then post encrypted,
   signed items. Every participant verifies every item locally; the relay
   checks signatures and limits but cannot read content.
4. In an execute session a sender targets a runner by name or label. The
   runner verifies the job, runs it in its sandbox and returns a signed result
   bound to that job.

The full design is in [docs/DESIGN.md](docs/DESIGN.md) and the wire format in
[docs/protocol.md](docs/protocol.md).

## Getting started

### Install

The `airlox` binary is the command-line client, the runner and the MCP
server. Any of these puts it on your `PATH`:

```bash
npm install -g airlox        # or run it with npx -y airlox …
pip install airlox           # with the Python SDK; or run it with uvx airlox …
```

There are prebuilt binaries for macOS (arm64, x64), Linux (arm64, x64; static,
so any distribution) and Windows (x64), also on the
[releases page](https://github.com/claudezss/airlox/releases), each with
`SHA256SUMS`. On Windows, runners use Docker or the process sandbox
([docs/windows-runner.md](docs/windows-runner.md)). Elsewhere (and wherever pip finds no wheel, such
as Alpine, so installs the SDK without the command), build it with
`cargo install --git https://github.com/claudezss/airlox airlox`.

### A machine for your agent

Give a coding agent a job slot on hardware you own (the GPU box, the build
server behind the firewall) instead of an SSH login. On the agent's side:

```bash
airlox machine add gpu-box --image ghcr.io/me/ci:latest
```

It prints one command to run on the machine, waits for that runner to join,
and approves exactly it:

```bash
airlox runner join --code 7-guitar-orbit --name gpu-box --sandbox docker --image ghcr.io/me/ci:latest --workspace
```

Then, from any checkout, as often as you like:

```bash
airlox run --on gpu-box --tree -- pytest -x tests/
```

```text
gpu-box · job 7Qk… · pytest -x tests/ · tree 412 files, 3.1 MB (18 changed)
============================= test session starts ==============================
collected 212 items
…
── completed · exit 1 · 41.2 s · peak 318 MB · signed by runner gpu-box
```

The job is a shell command run with the image's tools (or, with `--sandbox
local`, the machine's own), sandboxed, without network unless you add the
machine with `--network`. `--tree` sends the working tree as it is right now,
uncommitted and untracked files included and ignored ones left out (it
refuses files named like credentials, such as `.env` or `*.pem`, unless
`--tree-allow` names them; `--tree-exclude` and `.airloxignore` leave files
out), and the job starts in your current directory within it. The runner
keeps a workspace per sender, syncing each tree into it, so `node_modules`,
`target/` and `.venv` survive and the second run of the afternoon is fast
(`--fresh` starts over). Output streams as it happens; the signed result is
the authority. `airlox run --shell ci.sh` sends a script, and `airlox run
file.py` still sends Python.

A hosted agent (Claude Code on the web, Codex cloud) gets the machine's
sender invite in `AIRLOX_INVITE` (`airlox machine invite gpu-box`, or
`--code` for a one-time code) and runs `airlox run --tree -- pytest`. `airlox
run --no-wait` hands back a job id; `airlox result --wait 2h -- <job>` or
`airlox listen --once` picks it up later, and `airlox job ls` lists jobs.
`airlox machine ls` shows each machine's runners, kinds, image and last job;
`airlox machine approve` adds a second box to a pool (`--on pool/gpu` targets
a label); `airlox machine rm` closes it. On the machine, `airlox runner serve`
restarts the runner after failures, and `airlox runner install-service --code
…` installs it as a systemd user unit or a launchd agent.

Machines are sessions underneath (below), with their invites kept under
`~/.cache/airlox/machines/`. A machine is a job slot, not a login: jobs run
in the sandbox with the limits the session signed, and the sender invite can
do nothing else. For a trusted local agent and a machine you can already SSH
into, SSH is fine.

### From the command line

```bash
airlox session create --json                 # prints invite links per role
export AIRLOX_INVITE='<sender link>'
airlox send text "Build finished."
airlox send file report.md
AIRLOX_INVITE='<owner link>' airlox watch    # print items as they arrive
airlox send text "Review parser.py?" --to coder          # address it; --reply-to <item> links an answer
airlox listen --once --json                  # block until something concerns you, print it, exit
airlox listen --agent codex --resume <id> --from owner   # or wake an agent per batch (--fresh for a new conversation; claude, --exec)
airlox delivery                              # who has fetched your items
```

Every command takes the invite from `AIRLOX_INVITE` (or `--invite`, which is
visible to other local users in `ps`) and prints JSON with `--json`. See
`airlox --help`.

### From an AI agent

Coding agents with a shell (Claude Code, Codex, Cursor, Gemini CLI) use the
CLI; [skills/airlox/SKILL.md](skills/airlox/SKILL.md) teaches them how. Add
it to your agent's skills, or point the agent at it.

Agents talking to agents wake only for what concerns them: messages
addressed to them (`--to`), replies to their own items (job results
included), and the owner's messages to everyone (a message without `--to`
wakes only its replied-to author, unless the owner sent it). Claude Code runs
`airlox listen --once` in the background and is woken when it exits; Codex
and other headless agents are started per batch by `airlox listen --agent
codex|claude --resume <id>` (or `--fresh`; one is required, so the folder's
most recent conversation is never woken by accident) or `--exec`, which pass
only item ids, never message text. The woken agent reads them with its
`airlox` MCP server, which joins as the listener (`listen` hands it
`AIRLOX_INVITE`, `AIRLOX_NAME`, `AIRLOX_CACHE_DIR` and `AIRLOX_DESCRIPTION`
from its own flags or environment), and only the airlox read and reply tools
are pre-approved for it. Codex's shell tool is told to drop `AIRLOX_*`, so
the invite stays out of what the agent runs; headless Claude Code cannot run
Bash unasked. Codex runs only in a git repository. `--agent` requires
`--from`, since a woken agent acts on what the sender asks: `--from owner`
lets only the owner wake it, and a participant key is just as safe. A display
name or `role:` is not: anyone with an invite picks their own name, and a role
is shared by everyone who joined with that link (`listen` warns about names).
Without `--from` anyone can wake an `--exec` command too, so agents can talk
to each other; give it `--from owner` unless every participant is trusted.
`--run-timeout` (default 30m) kills a command that hangs, with everything it
started (its own process group on Linux and macOS; on Windows only the
command itself), and Ctrl-C to `listen` stops it too. `--pending-timeout`
(default 60s) skips an item that cannot be fetched, and wakes for it if it
arrives later (not across a restart). A reply chain of more than 8 agent
posts in a row with no person in between
stops waking anyone (`--max-hops`); participant kinds are self-declared, so
this is a safety net against accidental loops, not a security boundary.
Clients 0.1.0 and 0.1.1 reject messages with `to`, results with `env` and
version-pinned packages: upgrade them to use these.

Chat apps and IDEs use the MCP server, which runs locally so session keys
never leave your machine. It reads and writes files only inside the
directories it is allowed (`--allow-dir`; default: its working directory;
never `/`, your home directory or a parent of it), never overwrites a file,
and never shows the owner invite to the model (`--owner-invite-dir` saves it
for you, in a folder its tools cannot read).

```bash
claude mcp add airlox -- npx -y airlox mcp    # Claude Code
codex mcp add airlox -- npx -y airlox mcp     # Codex
```

```json
{ "mcpServers": { "airlox": { "command": "npx", "args": ["-y", "airlox", "mcp", "--allow-dir", "/path/to/workdir"] } } }
```

The server joins sessions under the name the MCP client gives itself
(`claude-code`, `codex`, …) unless you pass `--as`.

Headless agents (`claude -p`, `codex exec`) cannot answer approval prompts,
so tools that send or run anything are refused unless allowed up front.
`airlox mcp config claude` and `airlox mcp config codex` print a ready
config: the invite comes from `AIRLOX_INVITE`, and only a worker's tools
(read, send, run Python) are allowed, on files in the one folder you give
it: a folder for this work, not your project. `airlox mcp prompt` prints a
prompt for an agent that does the work posted in a session:

```bash
mkdir -p ~/airlox-work && airlox mcp config codex --allow-dir ~/airlox-work >> ~/.codex/config.toml
AIRLOX_INVITE='<sender link>' codex exec "$(airlox mcp prompt)"
```

`uvx airlox mcp` works the same way. For Claude Desktop, download
`airlox-<version>.mcpb` from the
[releases page](https://github.com/claudezss/airlox/releases) and open it:
it asks for the working folder and, optionally, a folder to save owner links
to. The server is also listed in the
[MCP registry](https://registry.modelcontextprotocol.io) as
`io.github.claudezss/airlox`.

The tools let the agent create or join sessions, send messages and files,
read items, approve runners and run Python.

### From Python

```python
from airlox import Session

owner = Session.create("https://airlox.app")
print(owner.invites["sender"])       # give this link to the other agent

# On the other side:
agent = Session.join(invite_url, display_name="build-agent",
                     description="Builds and tests the Rust workspace; send it diffs")
agent.send_text("Build finished.")
agent.send_file("report.md")

for item in owner.stream(timeout=60):
    print(item.author_name, item.kind, item.text or item.name)
```

The same invite links open in a browser at [airlox.app](https://airlox.app).

### Run code on another machine

Create an execute session and start a runner with its runner invite:

```python
owner = Session.create(
    "https://airlox.app",
    mode="execute",
    job_limits={"runtime": "python3.12", "timeout_s": 120, "memory_mb": 2048,
                "network": False, "packages": ["pandas", "matplotlib"],
                "return_out": True, "approve_runners": True},
)
print(owner.invites["runner"])
```

```bash
airlox runner join --invite '<runner invite>' --name runner-01 --labels cpu --sandbox docker \
    --description "8 cores, 32 GB RAM, in the build lab"
```

Copying a link to another machine is awkward. Instead, make a one-time code
such as `7-guitar-orbit`, valid for 10 minutes: click **Send to another
machine** next to any invite in the web UI, or with the owner invite run

```bash
airlox session code runner             # prints the code; --wait waits until it is used
```

(`owner.transfer_code("runner").code` in Python). The relay holds the invite
sealed under the code's two words, which its operator could recover by trying
every pair, so a code trusts the relay as the link itself does not. On the
other machine:

```bash
airlox runner join --code 7-guitar-orbit --name runner-01 --sandbox docker
airlox receive 7-guitar-orbit           # or just print the invite link
```

You can also type the code in a browser at `/receive`.

For a long-lived runner, `airlox session create --profile host-runner`
starts from a session that never expires, with 30-minute jobs, 4096 MB of job
memory, items as large as the relay allows (up to 100 MB) and runner approval
on. Flags you give override it, and `create` prints the limits the session
ended up with.

Allowlist entries may pin versions with a PEP 440 specifier, so every runner
uses the one you tested against: `--package 'cugrid==0.1.0'` or
`"packages": ["numpy>=1.26,<3"]` (quote it in a shell). The runner installs
that version, or, given its own interpreter (`--python`), refuses to join if
the interpreter has another ("--python has cugrid 0.2.1, but the session pins
cugrid==0.1.0"). Jobs still name the package alone in `requirements`.

Approve the runner, then send it work:

```python
owner.approve_runner("runner-01")

data = agent.send_file("dataset.zip")
job = agent.run_python(open("summarize.py").read(), filename="summarize.py",
                       files=[data], runner="runner-01")
res = job.wait()
print(res.status, res.exit_code, res.stdout)
chart = res.read("chart.png")            # files the job wrote to $AIRLOX_OUT
summary = res.read("summary.json")       # by path, whether or not it came zipped
```

Every result carries `env`, signed by the runner and not written by the job:
the Python version, the installed version of each allowlisted package, the
sandbox, the airlox version and where the interpreter came from (`uv-runtime`,
`--python` or `docker:<image>`), without any file system path. `airlox run`
prints it on one line, `--json` and the MCP server include it, and the SDK has
it as `res.env`.

A job that runs as a plain process (`--sandbox process`, or `local` outside
Linux) works in a temporary folder, and on Windows that is under
`C:\Users\<name>\AppData\Local\Temp`, so a traceback printed by the job
would name the account. `airlox runner join --work-root C:\airlox-work` (or
`AIRLOX_WORK_ROOT`) puts the jobs' folders in a directory you choose instead.
Whichever you use, the runner replaces the job's work folder in its stdout,
stderr, failure reason and progress tail with `$WORK`, its output folder with
`$AIRLOX_OUT`, the job's own folder with `$JOB`, its runtime and cache folders
(the venv, the Python install behind it) with `$RUNTIME` and your home folder
with `~` before it signs the result; files the job writes are returned as
written.

The runner builds its job image once (`python:3.12-slim` plus the session's
package allowlist) and refuses any job not signed by a sender or the owner.
`--sandbox local` runs jobs with `uv` instead of Docker: sandboxed with
namespaces and Landlock on Linux, and as a plain process on macOS, which is
only suitable for trusted code. On Windows, `--sandbox process` runs jobs
with an interpreter you provide, each in a Job Object that caps its memory
and ends everything it started, also as a Windows service; see
[docs/windows-runner.md](docs/windows-runner.md). Runners take one job at a
time (a busy one refuses new jobs with `runner_busy`), post progress while
long jobs run, and finish jobs across dropped connections. A complete
example is in
[examples/summarize](examples/summarize), and
[docs/use-cases.md](docs/use-cases.md) walks through four more: a code
review handoff over MCP, remote CI from the CLI, fan-out across a runner
pool, and a real Claude Code or Codex agent doing work on a runner.

## Self-hosting

A session's relay is simply the host in its invite links, so anyone can run
their own. The relay is one static binary that needs a single writable
directory. It is published as a linux/amd64 image: `:latest` follows `main`,
and from 0.1.1 on each release is also tagged with its version (`0.1.1`,
without the `v`). On another architecture (arm64), build it yourself from the
`Dockerfile`, as below:

```bash
docker run -p 8080:8080 -v airlox-data:/data ghcr.io/claudezss/airlox-server:latest
```

It listens on port 8080 and keeps sessions in `/data`. To try it out, or to
test an integration against a local relay, add `--ephemeral` after the image
name: nothing then survives a restart.

To build it yourself instead:

```bash
docker build -t airlox-server . && docker run -p 8080:8080 -v airlox-data:/data airlox-server
```

or, from a checkout:

```bash
make web && cargo run --release -p airlox-server -- --data ./data
```

Limits such as session lifetime, item and session size, transfer, session
counts and the disk watermark are flags and `AIRLOX_*` environment variables;
see `airlox-server --help`. `--ephemeral` keeps nothing across restarts.
`GET /v1/health` answers `200` while the relay serves, for load balancer and
Kubernetes liveness and readiness probes.
[docs/deploy.md](docs/deploy.md) describes the production setup behind
airlox.app: Caddy for HTTPS and automatic deploys from CI.
[docs/kubernetes.md](docs/kubernetes.md) runs it in a cluster
([`deploy/kubernetes/`](deploy/kubernetes/airlox-relay.yaml)), with plain
http between pods when the session's owner allows it
(`--insecure-http-host`).

## Security model

- The relay stores and forwards ciphertext. It cannot read items, forge
  them, or impersonate a participant.
- Whoever holds an invite link holds that role. Share links only over a
  channel you trust.
- A transfer code (Send to another machine) parks the invite on the relay,
  encrypted under the code's two words. Each code takes three wrong guesses
  before it is cancelled, and each address gets ten wrong guesses across all
  codes, so outsiders have only a small chance of guessing a code. The relay
  itself could guess the words, so use the link itself if you don't trust
  the relay operator.
- The browser UI is served by the relay, so browser users trust the relay
  operator to serve unmodified code. Agents using a relay they do not operate
  should use the Python SDK, which verifies everything locally.
- Jobs run with no network by default and within the session's time and
  memory limits. The Docker sandbox is the recommended runner for untrusted
  senders.

Please report vulnerabilities privately through
[GitHub security advisories](https://github.com/claudezss/airlox/security/advisories/new).

## Repository layout

| Path | Contents |
|---|---|
| `crates/airlox-core` | Protocol types, canonical JSON, cryptography, certificates, item envelopes, policy, validators and the job shim |
| `crates/airlox-core/vectors` | Conformance vectors every implementation must pass |
| `crates/airlox-server` | The relay, with the web UI embedded |
| `crates/airlox` | The `airlox` binary: command-line client, MCP server, and the runner with its Docker and local sandboxes |
| `bindings/python` | PyO3 bindings, built into the `airlox` wheel as `airlox._core` |
| `bindings/wasm` | WebAssembly bindings used by the web UI |
| `python/airlox` | The Python SDK |
| `web` | The browser UI |
| `skills/airlox` | Agent skill that teaches coding agents the CLI |
| `packaging` | The npm packages, the MCPB bundle and the MCP registry entry, staged around the release binaries |
| `deploy` | Docker Compose, Caddy and Droplet scripts for the hosted relay |
| `examples` | End-to-end examples, run as tests by `test_use_cases.py` ([docs/use-cases.md](docs/use-cases.md)) |

## Development

Requirements: `rustup` (the toolchain is pinned in `rust-toolchain.toml`),
`uv`, `maturin`, `wasm-bindgen-cli` 0.2.100 and Node 20 or later.

```bash
uv tool install maturin==1.8.6
```

```bash
cargo install wasm-bindgen-cli --version 0.2.100 --locked
```

```bash
make check
```

`make check` runs rustfmt, Clippy with warnings as errors (native and
WebAssembly), the Rust tests, the Python binding and SDK tests (including
execute mode against a real runner, and the Docker scenario when a Docker
daemon is available) and the WebAssembly tests in Node. Release steps are in
[docs/releasing.md](docs/releasing.md).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT), at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.
