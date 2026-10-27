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
`SHA256SUMS`. On Windows it is the command-line client and the MCP server;
runners need macOS or Linux. Elsewhere (and wherever pip finds no wheel, such
as Alpine, so installs the SDK without the command), build it with
`cargo install --git https://github.com/claudezss/airlox airlox`.

### From the command line

```bash
airlox session create --json                 # prints invite links per role
export AIRLOX_INVITE='<sender link>'
airlox send text "Build finished."
airlox send file report.md
AIRLOX_INVITE='<owner link>' airlox watch    # print items as they arrive
```

Every command takes the invite from `AIRLOX_INVITE` (or `--invite`, which is
visible to other local users in `ps`) and prints JSON with `--json`. See
`airlox --help`.

### From an AI agent

Coding agents with a shell (Claude Code, Codex, Cursor, Gemini CLI) use the
CLI; [skills/airlox/SKILL.md](skills/airlox/SKILL.md) teaches them how. Add
it to your agent's skills, or point the agent at it.

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
    job_limits={"runtime": "python3.12", "timeout_s": 120, "memory_mb": 512,
                "network": False, "packages": ["pandas", "matplotlib"],
                "return_out": True, "approve_runners": True},
)
print(owner.invites["runner"])
```

```bash
airlox runner join --invite '<runner invite>' --name runner-01 --labels cpu --sandbox docker \
    --description "8 cores, 32 GB RAM, in the build lab"
```

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

The runner builds its job image once (`python:3.12-slim` plus the session's
package allowlist) and refuses any job not signed by a sender or the owner.
`--sandbox local` runs jobs with `uv` instead of Docker: sandboxed with
namespaces and Landlock on Linux, and as a plain process on macOS, which is
only suitable for trusted code. A complete example is in
[examples/summarize](examples/summarize), and
[docs/use-cases.md](docs/use-cases.md) walks through four more: a code
review handoff over MCP, remote CI from the CLI, fan-out across a runner
pool, and a real Claude Code or Codex agent doing work on a runner.

## Self-hosting

A session's relay is simply the host in its invite links, so anyone can run
their own. The relay is one static binary that needs a single writable
directory. It is published as an image: `:latest` follows `main`
(linux/amd64), and from 0.1.1 on each release is also tagged with its version
(`0.1.1`, without the `v`) for amd64 and arm64:

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
[docs/deploy.md](docs/deploy.md) describes the production setup behind
airlox.app: Caddy for HTTPS and automatic deploys from CI.

## Security model

- The relay stores and forwards ciphertext. It cannot read items, forge
  them, or impersonate a participant.
- Whoever holds an invite link holds that role. Share links only over a
  channel you trust.
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
