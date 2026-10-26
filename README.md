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
- **Short-lived by design.** Sessions expire, and files leave the relay once
  every recipient has stored them. There is no database, and the relay keeps
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
server:

```bash
cargo install --git https://github.com/claudezss/airlox airlox
```

The Python SDK:

```bash
pip install airlox
```

### From the command line

```bash
airlox session create --json                 # prints invite links per role
airlox send text --invite "$SENDER" "Build finished."
airlox send file --invite "$SENDER" report.md
airlox watch --invite "$OWNER"               # print items as they arrive
```

Every command takes `--invite` (or `AIRLOX_INVITE`) and `--json`. See
`airlox --help`.

### From an AI agent

Coding agents with a shell (Claude Code, Codex, Cursor, Gemini CLI) use the
CLI; [skills/airlox/SKILL.md](skills/airlox/SKILL.md) teaches them how. Add
it to your agent's skills, or point the agent at it.

Chat apps and IDEs use the MCP server, which runs locally so session keys
never leave your machine. It reads and writes files only inside the
directories it is allowed (`--allow-dir`, default: its working directory).

```bash
claude mcp add airlox -- airlox mcp           # Claude Code
codex mcp add airlox -- airlox mcp            # Codex
```

```json
{ "mcpServers": { "airlox": { "command": "airlox", "args": ["mcp", "--allow-dir", "/path/to/workdir"] } } }
```

The tools let the agent create or join sessions, send messages and files,
read items, approve runners and run Python.

### From Python

```python
from airlox import Session

owner = Session.create("https://airlox.app")
print(owner.invites["sender"])       # give this link to the other agent

# On the other side:
agent = Session.join(invite_url, display_name="build-agent")
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
airlox runner join --invite '<runner invite>' --name runner-01 --labels cpu --sandbox docker
```

Approve the runner, then send it work:

```python
owner.approve_runner("runner-01")

data = agent.send_file("dataset.zip")
job = agent.run_python(open("summarize.py").read(), filename="summarize.py",
                       files=[data], runner="runner-01")
res = job.wait()
print(res.status, res.exit_code, res.stdout)
chart = res.out_file("chart.png").data   # files the job wrote to $AIRLOX_OUT
```

The runner builds its job image once (`python:3.12-slim` plus the session's
package allowlist) and refuses any job not signed by a sender or the owner.
`--sandbox local` runs jobs with `uv` instead of Docker: sandboxed with
namespaces and Landlock on Linux, and as a plain process on macOS, which is
only suitable for trusted code. A complete example is in
[examples/summarize](examples/summarize).

## Self-hosting

A session's relay is simply the host in its invite links, so anyone can run
their own. The relay is one static binary that needs a single writable
directory:

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
| `deploy` | Docker Compose, Caddy and Droplet scripts for the hosted relay |
| `examples` | End-to-end examples |

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
