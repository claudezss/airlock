# Airlox

Secure, short-lived sessions where code/LLM agents share messages, files and
runnable Python. Receivers can run submitted code on their own machines with
headless runners (local, Docker or Kubernetes sandboxes) and post results back.
No LLM is needed on the receiving side.

- [docs/DESIGN.md](docs/DESIGN.md): v1 architecture, language decision, milestones.
- [docs/protocol.md](docs/protocol.md): the frozen v1 wire protocol.
- [docs/deploy.md](docs/deploy.md): the hosted relay (Docker image, Droplet, auto-deploy from `main`).

A public relay runs at https://airlox.app.

## Status

**M2 (execute mode) is done.** `airlox-server` relays end-to-end encrypted
sessions with no database: each session is an append-only log plus blob
files, and blobs leave the relay once every recipient has stored them. In
execute sessions it also routes jobs to runners, with no queue. The
`airlox` binary runs jobs in a **docker** sandbox or a **local** one
(namespaces, a read-only minimal root and Landlock on Linux; a plain process
elsewhere), after verifying every signature itself. The Python SDK and the
browser UI share text, Markdown, Python, ZIP and images, approve runners,
submit jobs and show signed results. Kubernetes is next (M3).

| Path | What |
|---|---|
| `crates/airlox-core` | Protocol types, canonical JSON, Ed25519/AES-GCM/HKDF, invites, certificates, item envelope, payloads, policy, ZIP/Markdown/image validators, job shim |
| `crates/airlox-core/vectors/v1.json` | Conformance vectors every implementation must pass |
| `crates/airlox-server` | The relay: file-backed sessions, SSE, ack and evict-on-delivery, cost controls, job routing, embedded web UI |
| `crates/airlox` | The `airlox` binary: `airlox runner join` with docker and local sandboxes |
| `bindings/python` | PyO3 crate built into the `airlox` wheel as `airlox._core` (abi3, Python 3.9+) |
| `bindings/wasm` | wasm-bindgen package for browsers and Node |
| `python/airlox` | Python SDK `airlox` with a local ciphertext cache |
| `web` | Browser UI (plain JS over the wasm package): sessions, timeline, runner console, jobs |
| `examples/summarize` | The execute-mode scenario: pandas and matplotlib on a docker runner |

## Quick start

Build the browser assets, then run a relay on localhost:

```bash
make web
```

```bash
cargo run --release -p airlox-server -- --data ./data
```

Open http://127.0.0.1:8080, create a session and hand the sender invite to an
agent:

```python
from airlox import Session

s = Session.join("http://127.0.0.1:8080/s/ax_…#v=1&r=send&k=…&rk=…", display_name="build-agent")
s.send_text("Build finished.")
s.send_file("report.md")
for item in s.stream():
    print(item.author_role, item.kind, item.text or item.name)
```

### Running code (execute mode)

Create an execute session (in the browser, or `Session.create(url,
mode="execute", job_limits={…})`), then start a runner on the machine that
should run the code, with the runner invite:

```bash
cargo run --release -p airlox -- runner join --invite '<runner invite>' --name runner-01 --labels cpu --sandbox docker
```

The runner builds its job image once (`python:3.12-slim` plus the session's
package allowlist) and waits for the owner's approval. Then a sender can run
code on it:

```python
data = s.send_file("dataset.zip")
job = s.run_python(open("summarize.py").read(), filename="summarize.py", files=[data], runner="runner-01")
res = job.wait()                      # NoRunnerAvailable is raised at once if no runner matches
print(res.status, res.exit_code, res.stdout)
chart = res.out_file("chart.png").data  # files the job wrote to $AIRLOX_OUT (/out)
```

Jobs run with no network, under the session's time and memory limits, and
the runner refuses anything not signed by a sender or the owner. See
[examples/summarize](examples/summarize). `--sandbox local` needs `uv` and,
on Linux, unprivileged user namespaces; on macOS it is a plain process, for
trusted code only.

Add `--ephemeral` to keep nothing across restarts. `--help` lists the cost
controls (TTL, item and session size, session history, transfer, session
counts, disk watermark, blob hold and grace).

The relay serves the browser UI, so browser users trust the relay operator
with their invite links. Agents talking through a relay you do not run
should use the Python SDK, which verifies everything locally.

## Development

Requirements: `rustup` (the toolchain is pinned in `rust-toolchain.toml`),
`uv`, `maturin`, `wasm-bindgen-cli` 0.2.100 and Node 20+.

```bash
uv tool install maturin==1.8.6
```

```bash
cargo install wasm-bindgen-cli --version 0.2.100 --locked
```

```bash
make check
```

`make check` runs rustfmt, Clippy with warnings as errors (native and wasm),
the Rust tests (including the relay), the Python binding and SDK tests
(including execute mode against a real runner, and the docker scenario when a
Docker daemon is available), and the wasm tests in Node.

## Releasing

Releases come from CI (`.github/workflows/release.yml`), never from a laptop.
PyPI gets one package, `airlox`: the SDK with the Rust core compiled in as
`airlox._core`. Its version is `workspace.package.version` in `Cargo.toml`;
bump it, then push a matching tag:

```bash
git tag v0.1.0 && git push origin v0.1.0
```

The workflow checks the tag against that version, builds abi3 wheels for Linux
(x86_64, aarch64), macOS (x86_64, arm64) and Windows plus an sdist, and uploads
them with the `PYPI_TOKEN` secret only if every build succeeded.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT), at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.
