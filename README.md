# Airlock

Secure, short-lived sessions where code/LLM agents share messages, files and
runnable Python. Receivers can run submitted code on their own machines with
headless runners (local, Docker or Kubernetes sandboxes) and post results back.
No LLM is needed on the receiving side.

- [docs/DESIGN.md](docs/DESIGN.md): v1 architecture, language decision, milestones.
- [docs/protocol.md](docs/protocol.md): the frozen v1 wire protocol.

## Status

**M1 (relay mode) is done.** `airlock-server` relays end-to-end encrypted
sessions with no database: each session is an append-only log plus blob
files, and blobs leave the relay once every recipient has stored them. The
Python SDK and a minimal browser timeline exchange text, Markdown, Python,
ZIP and images through it. Execute mode and runners are next (M2).

| Path | What |
|---|---|
| `crates/airlock-core` | Protocol types, canonical JSON, Ed25519/AES-GCM/HKDF, invites, certificates, item envelope, payloads, policy, ZIP/Markdown/image validators, job shim |
| `crates/airlock-core/vectors/v1.json` | Conformance vectors every implementation must pass |
| `crates/airlock-server` | The relay: file-backed sessions, SSE, ack and evict-on-delivery, cost controls, embedded web UI |
| `bindings/python` | PyO3 module `airlock_core` (abi3 wheel, Python 3.9+) |
| `bindings/wasm` | wasm-bindgen package for browsers and Node |
| `python/airlock-agent` | Python SDK `airlock` with a local ciphertext cache |
| `web` | Browser timeline (plain JS over the wasm package) |

## Quick start

Build the browser assets, then run a relay on localhost:

```bash
make web
```

```bash
cargo run --release -p airlock-server -- --data ./data
```

Open http://127.0.0.1:8080, create a session and hand the sender invite to an
agent:

```python
from airlock import Session

s = Session.join("http://127.0.0.1:8080/s/ak_…#v=1&r=send&k=…&rk=…", display_name="build-agent")
s.send_text("Build finished.")
s.send_file("report.md")
for item in s.stream():
    print(item.author_role, item.kind, item.text or item.name)
```

Add `--ephemeral` to keep nothing across restarts. `--help` lists the cost
controls (TTL, item and session size, transfer, session counts, disk
watermark, blob hold and grace).

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
the Rust tests (including the relay), the Python binding and SDK tests, and
the wasm tests in Node.
