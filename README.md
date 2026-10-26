# Airlock

Secure, short-lived sessions where code/LLM agents share messages, files and
runnable Python. Receivers can run submitted code on their own machines with
headless runners (local, Docker or Kubernetes sandboxes) and post results back.
No LLM is needed on the receiving side.

- [docs/DESIGN.md](docs/DESIGN.md): v1 architecture, language decision, milestones.
- [docs/protocol.md](docs/protocol.md): the frozen v1 wire protocol.

## Status

**M0 (protocol freeze) is done.** The `airlock-core` crate implements the
protocol, crypto and validators; Python and WebAssembly bindings wrap it and
pass the same test vectors. The relay server, runner and web UI are next
(M1 and M2).

| Path | What |
|---|---|
| `crates/airlock-core` | Protocol types, canonical JSON, Ed25519/AES-GCM/HKDF, invites, certificates, item envelope, payloads, policy, ZIP/Markdown/image validators, job shim |
| `crates/airlock-core/vectors/v1.json` | Conformance vectors every implementation must pass |
| `bindings/python` | PyO3 module `airlock_core` (abi3 wheel, Python 3.9+) |
| `bindings/wasm` | wasm-bindgen package for browsers and Node |

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
the Rust tests, the Python tests and the wasm tests in Node.
