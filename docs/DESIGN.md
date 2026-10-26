# Airlock — v1 design

Secure, short-lived sessions in which code/LLM agents exchange messages, files and
runnable Python. In **Relay** mode the other side only reads. In **Execute** mode
headless **runners** on the receiver's own machines run submitted Python in a
sandbox and post results back. No LLM is required on the receiving side.

This document fixes the architecture, the implementation languages and the
protocol for v1. The UI reference is the "Airlock — agent sessions" design
canvas (landing, live session, new session, runner console).

---

## 1. Goals and non-goals

**v1 goals**

- Sessions with two modes (Relay, Execute), an expiry timer, an allowed-type
  list and per-job limits (timeout, memory, network, package allowlist).
- Four content types: Python (`.py`), Markdown (`.md`), ZIP (`.zip`), images
  (`.png .jpg .webp`), plus plain text messages.
- Roles via invite links: **owner**, **sender**, **runner**, **observer**.
- End-to-end encryption: the server stores ciphertext and sizes only. Every item
  is signed; a runner executes only jobs signed by a sender-role participant.
- Runners join by hand, are approved by the owner, carry a name and labels, and
  are addressed per job by name, label, or "any idle". No queueing: if no
  matching approved runner is online, the job fails immediately.
- Three sandbox backends for the runner: **local**, **docker**, **kubernetes**.
- Agent access through a Python SDK, a CLI, an MCP tool server and plain HTTPS.
- A web UI for humans to open sessions, hand out invites, watch the timeline,
  approve runners and inspect jobs.
- **Lightweight to host, with cost pushed to users**: one process and one
  data directory. No database server, no object store, no queue. Clients do
  the expensive work (crypto, validation, history, execution); the relay is a
  short-lived transit buffer that deletes each file once it is delivered.
  Hard server-side caps keep disk and bandwidth bounded (§7).

**Non-goals for v1**

- Languages other than Python in jobs.
- Persistent user accounts / billing. The owner is whoever holds the owner link.
- Server-side queueing or autoscaling of runners.
- Multi-region, federation, or anything beyond one relay deployment.
- GPU scheduling beyond "label matches".

---

## 2. Language decision

### Recommendation

| Component | Language | Stack |
|---|---|---|
| `airlock-core`: protocol, crypto, validators, job shim | **Rust** | `ed25519-dalek`, `aes-gcm`, `hkdf`, `sha2`, `serde` + canonical JSON; bindings via **PyO3** (Python wheel) and **wasm-bindgen** (browser) |
| Relay server (API, SSE, storage, purge) | **Rust** | `axum` + `tokio`, `tower` middleware; storage is plain files (append-only session logs + blob files), **no database** |
| `airlock` binary: runner, CLI | **Rust** | `tokio`, `reqwest` (SSE), `bollard` (Docker), `kube` (Kubernetes), `nix` + Landlock + seccomp for the local backend |
| SDK and MCP server (`pip install airlock-agent`) | **Python 3.12+** | thin orchestration over the `airlock-core` wheel; `httpx`, `mcp`; the wheel also bundles the `airlock` binary |
| Web UI (static SPA served by the server) | **TypeScript** | Vite + React, `airlock-core` wasm for all crypto, markdown-it + DOMPurify, zip.js |

Rust owns everything that touches keys, signatures, sandboxes or the wire.
Python is a thin convenience layer for agents and the MCP ecosystem. TypeScript
is confined to the browser, and even there the crypto is the Rust core compiled
to WebAssembly.

### Why Rust for core, server and runner

1. **One crypto and protocol implementation, everywhere.** The same crate
   signs and encrypts in the SDK (through PyO3), verifies and decrypts in the
   runner, verifies certificates in the server, and runs in the browser
   (through wasm). There is no second implementation to drift. This is the
   single most important property of an end-to-end encrypted system.
2. **Resource footprint of the relay.** The server's job is to hold many idle
   SSE connections and shuffle ciphertext. On tokio an idle connection costs a
   few KB and the whole process runs in tens of MB of RSS. That is the
   difference between a public relay on the smallest instance tier and one
   that needs a worker pool. Blobs stream from the request body straight to a
   file on disk without being buffered in memory.
3. **Runner distribution.** A static musl binary drops onto a CI box, a GPU
   server or a `FROM scratch` image with no Python on the host. The same
   binary is also bundled inside the Python wheel, so both
   `pip install airlock-agent` and `curl | sh` work.
4. **A real local sandbox.** From Rust the runner reaches Linux user
   namespaces, Landlock, seccomp and cgroups v2 directly, so the local backend
   can enforce no-network and filesystem confinement on Linux instead of
   shelling out to `bwrap` and hoping it exists.
5. **Memory safety at the trust boundary.** The runner and server parse
   attacker-controlled bytes (zip manifests, headers, certificates). Rust
   removes the memory-corruption class entirely and `cargo-deny` keeps the
   dependency tree auditable.

### Costs, and how the plan absorbs them

- **Format churn is expensive in Rust.** Mitigation: milestone M0 freezes the
  protocol as a written spec with test vectors *before* server or runner work
  starts (§12). Everything downstream codes against fixed vectors.
- **Build matrix.** PyO3 wheels (macOS arm64/x86_64, Linux glibc/musl,
  Windows) plus a wasm bundle plus static runner binaries. Mitigation:
  `maturin-action` and `cargo-zigbuild` in CI from day one; the matrix is set
  up in M0 while the code is still tiny.
- **Not one language.** Agents expect a Python SDK and the MCP SDK is most
  mature in Python, so Python stays for that layer. It is intentionally thin:
  HTTP calls plus ergonomic wrappers around core types.
- **Thinner examples for `bollard` and `kube`.** Both are production-grade;
  the backend surface we use is small (create, copy in, start, wait, logs,
  copy out, remove).

### Alternatives considered

| Option | Pros | Why not |
|---|---|---|
| Python for server, runner and SDK; TS browser crypto | Fastest iteration; one language for all server-side code | Two crypto implementations (Python + browser); runner needs Python on every receiver; relay memory per connection is an order of magnitude higher; local backend stays weak |
| Go for server + runner, Python SDK | Static binaries, good concurrency, simple toolchain | Still two or three crypto implementations (Go, Python, browser); no wasm/PyO3 story as clean as Rust's; weaker sandboxing primitives |
| Rust runner + core, Python server | Keeps the server easy to change | The server also verifies certificates and streams blobs; keeping it in Rust means one binary family, one deploy image, and the lowest-footprint relay |

---

---

## 3. System overview

```
                 ┌───────────────────────── relay server ─────────────────────────┐
                 │  axum/tokio  ·  one data dir: per-session log + blob files       │
                 │  no database · in-memory index rebuilt from the logs on start   │
                 │  holds: manifests, participants, item envelopes, ciphertext,    │
                 │         job states, audit trail (hashes)                        │
                 └────▲──────────────▲────────────────────▲─────────────────▲──────┘
                      │ HTTPS+SSE    │ HTTPS+SSE          │ HTTPS+SSE       │ HTTPS+SSE
          ┌───────────┴───┐  ┌───────┴────────┐  ┌────────┴────────┐  ┌─────┴──────┐
          │ sender agent  │  │ owner / human  │  │ runner (no LLM) │  │ observer   │
          │ Python SDK /  │  │ web UI (TS)    │  │ airlock runner  │  │ web / SDK  │
          │ CLI / MCP     │  │                │  │ join …          │  │ read-only  │
          └───────────────┘  └────────────────┘  └────────┬────────┘  └────────────┘
                                                          │ backend
                                           ┌──────────────┼──────────────┐
                                           │ local        │ docker       │ kubernetes
                                           │ subprocess   │ container    │ pod per job
                                           │ + rlimits    │ per job      │
                                           └──────────────┴──────────────┘
```

Everything that matters is decided at the edges. The server never holds the
session key, never sees plaintext, and never executes code.

---

## 4. Identity, keys and roles

All asymmetric keys are **Ed25519** (signing) and **X25519** (only if we later
need per-recipient wrapping; v1 does not). Symmetric encryption is
**AES-256-GCM**; key derivation is **HKDF-SHA256**. All of them are implemented once in the
`airlock-core` crate (RustCrypto `ed25519-dalek`, `aes-gcm`, `hkdf`, `sha2`)
and reach Python through PyO3 and the browser through wasm; no second
implementation exists.

### Session creation (owner, client-side)

1. Generate a 32-byte owner seed; the owner keypair `O` uses it directly.
2. Derive session key `K` and one **role keypair** per role (`R_send`,
   `R_run`, `R_view`) from the owner seed with HKDF.
3. `session_id = "ak_" + base32(sha256(O.pub))[:12]`.
4. Build the **manifest** (plaintext, signed by `O`):

   ```json
   {
     "v": 1, "session_id": "ak_7f3e…", "owner_pub": "…",
     "roles": {"sender": "R_send.pub", "runner": "R_run.pub", "observer": "R_view.pub"},
     "mode": "execute", "expires_at": "…", "allowed_types": ["text","py","md","zip","image"],
     "max_item_bytes": 26214400,
     "job_limits": {"runtime": "python3.12", "timeout_s": 30, "memory_mb": 512,
                    "network": false, "packages": ["pandas","numpy","matplotlib"],
                    "return_out": true, "approve_runners": true}
   }
   ```

   The manifest is policy, not secret. The server reads it to enforce expiry,
   sizes and types; the session *name* is encrypted as the first item.
5. `POST /v1/sessions` with the manifest and the owner's signature.

### Invite links

```
https://<host>/s/<session_id>#v=1&r=<send|run|view>&k=<K>&rk=<role private seed>
https://<host>/s/<session_id>#v=1&r=owner&ok=<owner seed>
```

The fragment never reaches the server. Holding an invite = holding `K` (read
everything) + the role's private key (mint a certificate for that role). This
matches the design copy: "each link carries its role and the session key".
`K` and the role seeds are derived from the owner seed with HKDF, so the owner
link carries only the owner seed. The normative format is in
[protocol.md](protocol.md).

### Joining (any participant)

1. Generate a participant keypair `P`.
2. Self-issue a **role certificate**: `cert = Sign(R_role.priv, {session_id,
   role, P.pub, issued_at})`.
3. `POST /v1/sessions/:id/participants` with `P.pub`, `cert`, and a
   signed join record (display name, kind: `sdk|web|runner`, runner metadata).
4. The server verifies `cert` against the manifest's role public key and issues
   a short-lived bearer token bound to `P.pub`. Every later write is also
   signed by `P`, so the token is a convenience, not the trust anchor.

The same certificate is what other participants verify end-to-end: a runner
checks `cert` chains to `roles.sender` in the owner-signed manifest before it
runs anything. Server verification is defense in depth, not the source of truth.

### Runner approval

A runner joins with role `runner` and sits in `awaiting_approval`. The owner
posts a signed `runner.approve` event naming `P.pub`. Senders only target
runners whose approval event verifies against `owner_pub`; the server only
dispatches to approved runners. Reject = signed `runner.reject`; the server
drops the connection.

### Revocation

v1: the owner revokes a role server-side (`POST …/roles/:role/revoke`), which
stops admission and invalidates tokens for that role. Because the role private
key is in the invite, true cryptographic revocation requires rotating `K` and
reissuing invites; v1 exposes that as "Close & purge". Per-role key rotation
without closing the session is a v2 item.

---

## 5. Items: the wire format

Every message, file, job and result is an **item**. The server stores the
plaintext **header**, the **ciphertext**, and the **signature**.

```
header (canonical JSON, plaintext):
  { "v":1, "id": ulid, "session_id", "author": P.pub fingerprint,
    "kind": "text|file|job|result|event", "subkind": "md|py|zip|image|null",
    "size": plaintext bytes, "created_at_ms", "refs": [item ids] }

blob: nonce(12) || AES-256-GCM( key = HKDF(K, salt=session_id, info="airlock/v1/item-key\0"+id),
                                 aad = canonical(header) )

sig: Ed25519( P.priv, ctx "item", canonical(header) || sha256(blob) )
```

- **Per-item keys** derived from `K` mean a leaked item key exposes one item.
- **AAD = header** binds kind/size/author to the ciphertext, so the server
  cannot relabel a job as a message.
- Max plaintext per item is set in the manifest (default 25 MB). Larger uploads
  are rejected by the server by `size`; chunking is a v2 item.
- Payloads by kind:
  - `text`: UTF-8 string.
  - `file`: `{name, mime, bytes}`; `subkind` fixes which viewer applies.
  - `job`: `{code, filename, runtime, timeout_s, files: [item refs],
    requirements: [...], target: {runner: participant_pub} | {labels: [...]} | any}`.
  - `result`: `{job: item ref, exit_code, status, wall_ms, peak_mem_mb, stdout,
    stderr, out_files: [{name, size, item: item ref}], code_sha256,
    input_sha256}`. Files from `/out` are uploaded as separate `file` items
    first (images as `image`, everything else bundled into one `zip`), then
    referenced.
  - An item ref is `{id, blob_sha256}`, so a reference cannot be redirected
    to a different item with the same id. Exact formats: [protocol.md](protocol.md).
  - `event`: `runner.approve`, `runner.reject`, `session.close`, `job.cancel`.

### Content handling rules (client/runner side, since the server is blind)

- **Markdown**: rendered with HTML stripped (markdown-it with `html: false`
  plus DOMPurify). Raw toggle shows original bytes.
- **Images**: re-encoded on the *sending* side (Pillow in the SDK, canvas in
  the browser) to strip metadata. Receivers still treat them as untrusted.
- **ZIP**: manifest listed before download. The runner's unpacker rejects
  absolute paths, `..`, symlinks, hardlinks, > N entries, and compression
  ratios above a bomb threshold; it extracts only into the job work dir.
- **Python**: displayed as code in Relay mode; only `job` items run, never
  `file` items with a `.py` suffix.

---

## 6. Runner

`airlock runner join --invite $RUNNER_INVITE --name runner-01 --labels cpu,py3.12
--sandbox docker|local|k8s [--no-network] [--memory 512m]`

The runner is a subcommand of the static `airlock` binary: a long-running
tokio process with **no LLM and no shell for anyone else**. Loop:

1. Join (§4), register `{name, labels, host, sandbox, limits}`, open the SSE
   stream `GET /v1/sessions/:id/runners/me/stream`.
2. On `job.assigned`: fetch the job item and referenced files, **verify** the
   author's certificate chains to the sender role and the signature matches,
   **check** the job against the manifest limits (timeout ≤, memory ≤, every
   requirement ∈ allowlist, runtime supported). Any failure → post a `result`
   with a refusal reason, never run.
3. Decrypt into a fresh temp dir: `/work` (code + unpacked inputs) and `/out`
   (empty).
4. Hand to the **backend** (below). Enforce the timeout from the runner side
   too; kill on expiry.
5. Collect stdout/stderr (capped, e.g. 1 MB each, with truncation flags),
   exit code, wall time, peak memory, and `/out`. Upload out files as items,
   post the signed `result`. Delete the temp dir.
6. Heartbeat every 10 s with `idle|busy:<job_id>`; the server fails a job whose
   runner misses 3 heartbeats.

Concurrency: one job at a time per runner in v1 (`--concurrency N` later).

### Backend interface

```rust
#[async_trait]
pub trait Sandbox: Send + Sync {
    async fn prepare(&self, spec: &RuntimeSpec) -> Result<()>;        // build/pull once
    async fn run(&self, job: &PreparedJob) -> Result<RawResult>;      // one job
    async fn cleanup(&self, job: &PreparedJob) -> Result<()>;
}
```

`PreparedJob` = `{work_dir, out_dir, entry_file, timeout_s, memory_mb, cpu,
network: bool, env}`. `RawResult` = `{exit_code, stdout_path, stderr_path,
wall_ms, peak_mem_mb, out_dir}`.

All backends execute the same tiny **job shim**, a dependency-free Python
script embedded in `airlock-core` and copied into the sandbox: it sets
`cwd=/work`, scrubs the environment, runs `python -E -s entry.py`, enforces the
wall clock, measures peak RSS and writes a `result.json`. The shim stays in
Python because it must run inside an image that has only Python; it is ~150
lines and is covered by the core test suite. One shim → identical behaviour
across backends.

### Packages vs. "network off"

Jobs run with no network, yet the manifest allows a package allowlist. The
runner resolves this by building a **runtime environment once, with network,
at `prepare()` time**, keyed by `sha256(runtime + sorted(allowlist))`:

- local → a `uv venv` with the allowlist installed (the runner shells out to
  `uv`, which it downloads on first use if absent);
- docker → an image `airlock-rt:<hash>` built `FROM python:3.12-slim` with the
  allowlist pip-installed;
- k8s → the same image pushed to a registry the cluster can pull from
  (`--image-repo`), or a pre-built image name passed by the operator.

A job's `requirements` must be a subset of the allowlist; nothing is installed
at job time. This is what makes "scipy not in allowlist → exit 1 in 0.40 s"
in the design possible.

### Backends

| | local | docker | kubernetes |
|---|---|---|---|
| Isolation | **Linux:** user + mount + net + pid namespaces, Landlock filesystem rules (ro venv, rw `/work` and `/out`), seccomp allowlist, cgroups v2 memory/cpu/pids limits, no network namespace interfaces → `network: false` is enforced. **macOS/Windows:** process only (rlimits, fresh temp dir, scrubbed env, process-group kill); network cannot be blocked, the runner reports `network: host` and the UI shows a warning badge. | Container per job: `--network none`, `--memory`, `--cpus`, `--pids-limit`, `--read-only` rootfs, `--tmpfs /tmp`, `--cap-drop ALL`, `--security-opt no-new-privileges`, non-root user, bind-mount `/work` (rw) and `/out` (rw). Optional `--runtime runsc` (gVisor). | Pod per job (not `Job`, simpler cleanup): restricted `securityContext`, resource requests/limits, `automountServiceAccountToken: false`, emptyDir for `/work` and `/out`, deny-all `NetworkPolicy` label, optional `runtimeClassName: gvisor`. |
| Input delivery | copy into temp dir | bind mount | runner pod streams a tar into the job pod via the exec API (`kubectl cp` semantics) before signalling start; no shared PVC needed |
| Output | read temp dir | read bind mount | exec `tar -C /out` back; logs via the logs API |
| Who runs it | developer laptop, trusted CI | default for receivers | runner deployed as a `Deployment` in-cluster with a ServiceAccount allowed to create/exec/delete pods in one namespace |
| Intended trust | code from yourself | code from another agent | code from another agent, at scale |

The local backend on Linux is a real sandbox and acceptable for untrusted
code from another agent. On macOS and Windows it is for development and
trusted pairs only: the shim kills the job's process group, but a job that
calls `setsid()` can outlive it there, and network cannot be blocked. The CLI
prints a one-line warning when it is selected in a session whose manifest says
`network: false`.

### Job routing ("no queue")

Submission is synchronous with respect to assignment:

1. Sender `POST /v1/sessions/:id/jobs` (the job item + target).
2. Server computes candidates = approved ∧ online ∧ idle ∧ target match.
3. None → `409 no_runner_available`; the job item is stored with
   `status: failed, reason: not_available` so the timeline shows it (as in the
   design: "failed · runner-03 not available · not queued").
4. Otherwise the server picks one (name match, else first idle by join time),
   marks it `busy` **atomically**, and emits `job.assigned` on that runner's
   stream. If the runner does not `POST …/jobs/:id/claim` within 5 s, the job
   fails with `runner_unresponsive` and the runner is marked offline.

Cancel: sender or owner posts `job.cancel`; the server forwards it; the runner
kills the sandbox and posts a `result` with `exit_code: null, cancelled: true`.

---

## 7. Relay server

### Responsibilities

- Session lifecycle: create, read manifest, close & purge, timed expiry.
- Admission: verify role certificates, issue tokens, enforce role rights.
- Items: accept header + ciphertext + signature; enforce `size ≤ max`,
  `subkind ∈ allowed_types`, author role may post that kind (observers: none;
  runners: `result` and `file`, execute mode only; senders: text, file, job,
  event; owner: everything). Exact rules: [protocol.md](protocol.md) §8.
- Jobs: routing (§6), status, heartbeats.
- Streams: `GET /v1/sessions/:id/stream` (SSE) for the timeline, per-runner
  assignment streams.
- Audit log: append-only `{ts, actor, action, item_id, sha256}`; exportable as
  JSONL before purge.
- Purge: deleting the session directory at `expires_at` or on close. The
  audit trail goes with it unless the owner exported it first.
- Cost limits: the server-side caps in "Cost controls" below.

### API (v1)

```
POST   /v1/sessions                          create (manifest + owner sig)
GET    /v1/sessions/:id                      manifest, state, counts
POST   /v1/sessions/:id/close                owner; purge now
POST   /v1/sessions/:id/participants         join with cert → token
GET    /v1/sessions/:id/participants
POST   /v1/sessions/:id/items                header + ciphertext + sig  (multipart)
GET    /v1/sessions/:id/items?after=<id>     headers
GET    /v1/sessions/:id/items/:item/blob     ciphertext (410 once evicted)
POST   /v1/sessions/:id/items/:item/ack      recipient stored it locally
POST   /v1/sessions/:id/items/:item/want     ask holders to re-seed an evicted blob
PUT    /v1/sessions/:id/items/:item/blob     re-seed: accepted only if SHA-256 matches the signed envelope
GET    /v1/sessions/:id/stream               SSE: item.created, job.*, runner.*, session.*
                                             blob.evicted, blob.wanted
                                             (event id = log seq; resume with Last-Event-ID)
POST   /v1/sessions/:id/jobs                 job item + target  → assigned | 409
POST   /v1/sessions/:id/jobs/:job/cancel
GET    /v1/sessions/:id/jobs/:job
GET    /v1/sessions/:id/runners
GET    /v1/sessions/:id/runners/me/stream    SSE (runner): job.assigned, job.cancel
POST   /v1/sessions/:id/runners/me/heartbeat
POST   /v1/sessions/:id/jobs/:job/claim      runner
POST   /v1/sessions/:id/roles/:role/revoke   owner
GET    /v1/sessions/:id/audit.jsonl          owner / observer
```

### Cost model: clients do the heavy lifting

The relay keeps only what cannot live anywhere else: the session's small
metadata, a rendezvous point, and a brief buffer for files in transit.
Everything else runs on the participants' machines.

| Work | Where it runs | Server cost |
|---|---|---|
| Encryption, signing, verification | Clients (Rust core, Python wheel, wasm) | none |
| ZIP, image and Markdown validation; image re-encoding | Clients and runners | none |
| Code execution | Runners on the receiver's machines | none |
| Timeline history and files | Client-side cache (browser IndexedDB, SDK cache dir) | none |
| File delivery | Relay buffer, deleted after delivery (below); direct peer-to-peer in v2 | short-lived disk, one upload plus one download per recipient |
| Metadata, routing, SSE | Relay, in memory plus an append-only log | small |
| Heavy or long-lived use | The user's own relay (self-hosting, §7 Deployment) | none for the hosted relay |

#### Transit buffer: delete on delivery

A blob stays on the relay only until its recipients have it.

- **Recipients** of an item are the participants admitted when it was posted
  (runners: approved), excluding the author.
- A client **acks** an item after it has verified the blob and stored it in
  its local cache (`POST …/items/:item/ack`). A runner acks a job and its
  input files once they are in the job's work dir; the sender acks result
  output files.
- The relay **evicts** the blob when every recipient has acked and
  `AIRLOCK_BLOB_GRACE` has passed, or when `AIRLOCK_BLOB_HOLD` has passed
  since upload, whichever comes first. It emits `blob.evicted`.
- **Envelopes stay** in the log for the whole session. The timeline remains
  complete and every reference still verifies; only the ciphertext is gone
  from the relay.
- **Re-seeding.** A participant that joins late, or opens the session on a
  new device, posts `want`. Any client still holding the blob in its cache
  re-uploads it with `PUT …/blob`. The relay accepts the upload from anyone,
  because the envelope already pins the blob's SHA-256 under the author's
  signature, so a re-seed cannot alter content. If no holder is online, the
  UI shows the file as "delivered and removed from the relay".
- This needs no protocol change: blob location and lifetime are relay
  behaviour, and integrity already rests on the signed blob hash.

#### Direct transfer (v2)

When sender and recipient are both online, files can skip the relay
entirely: the relay only carries WebRTC signaling (offer, answer, ICE
candidates) over the existing SSE stream and a small POST endpoint. Public
STUN handles most NATs. There is deliberately no TURN server, because relaying
traffic is exactly the cost being avoided; peers that cannot connect directly
fall back to the transit buffer. Browsers have WebRTC built in; the Rust
runner and the Python SDK would use `webrtc-rs`. The received blob is checked
against the signed hash exactly as one from the relay.

### Storage: no database

Sessions are short-lived, independent of each other and append-only, and the
server never queries across them. That fits a directory per session far
better than a database server plus an object store:

```
$AIRLOCK_DATA/
  LOCK                         flock'd by the running server; a second server on the same dir refuses to start
  sessions/<session_id>/
    manifest.json              signed manifest, canonical JSON, exactly as received
    log.jsonl                  append-only events, one canonical JSON object per line:
                                 {seq, ts_ms, type: join | item | ack | evict | reseed | job_state | approve | reject | revoke | close, ...}
    blobs/<item_id>            ciphertext, exactly as uploaded; deleted on eviction
```

- **In-memory index.** Each session keeps its participants, item envelopes,
  job states and runner presence in memory, rebuilt from `log.jsonl` at
  startup. An envelope is a few hundred bytes, so even thousands of items cost
  little RAM. Ciphertext is never held in memory: uploads stream to disk and
  downloads stream from disk.
- **Write order.** Stream the blob to `blobs/.<id>.tmp`, fsync, rename to
  `blobs/<id>`, then append the log line and fsync it, then broadcast on SSE.
  A crash can leave only an orphaned blob with no log line; startup deletes
  those. A log line never points at a missing blob.
- **Concurrency.** One process owns the data dir (`LOCK`). Each session has
  its own async mutex, so writers to different sessions never contend. Job
  routing ("mark one runner busy atomically") is a check-and-set under that
  mutex.
- **Eviction timers** are rebuilt from the log at startup: an item whose
  hold has passed, or whose recipients have all acked, is evicted
  immediately.
- **What is not persisted.** Runner presence, heartbeats and SSE
  subscriptions live in memory only. After a restart, runners and clients
  reconnect and re-subscribe from their last seen `seq`.
- **Purge.** Each session arms a timer for `expires_at`; startup also sweeps
  expired sessions. Purging renames the directory to `.trash/<id>` and deletes
  it in the background, so purge is instant and needs no cron job.
- **Audit export.** It is `log.jsonl` itself, which already holds only
  envelopes, hashes and events, never ciphertext.
- **SSE fan-out** is an in-process broadcast per session
  (`tokio::sync::broadcast`).

Storage sits behind two small traits, `SessionLog` and `BlobStore`. v1 ships
only the filesystem implementations. An object-store `BlobStore` can be added
later without changing the API.

### Cost controls

Server configuration, so none of it changes the frozen protocol. The server
refuses a manifest or an upload that exceeds a limit.

| Setting | Default | Effect |
|---|---|---|
| `AIRLOCK_MAX_TTL` | 24 h | Rejects manifests that live longer, although the protocol allows 30 days. The web UI defaults to 1 h. |
| `AIRLOCK_MAX_ITEM_BYTES` | 25 MiB | A manifest's `max_item_bytes` may not exceed it. |
| `AIRLOCK_BLOB_HOLD` | 1 h | Longest a blob stays on the relay after upload, delivered or not. |
| `AIRLOCK_BLOB_GRACE` | 5 min | How long a blob stays after its last recipient acked, for late joiners. |
| `AIRLOCK_MAX_SESSION_BYTES` | 200 MiB | Ciphertext a session may have held on the relay at once; uploads past it get `413`. |
| `AIRLOCK_MAX_SESSION_TRANSFER` | 1 GiB | Total bytes uploaded plus downloaded per session, the bandwidth cap; past it, `429`. |
| `AIRLOCK_MAX_ITEMS` | 5 000 | Items per session. |
| `AIRLOCK_IDLE_TTL` | 2 h | Purges a session early after this long with no new items or joins. |
| `AIRLOCK_MAX_SESSIONS_PER_IP` | 20 | Active sessions per creator IP. |
| `AIRLOCK_MAX_SESSIONS` | 1 000 | Active sessions in total. |
| `AIRLOCK_DISK_HIGH_WATERMARK` | 90 % | Above this volume usage, new sessions and uploads get `507`. |

The worst case disk use is therefore bounded by
`MAX_SESSIONS × MAX_SESSION_BYTES`, and the realistic case is far lower:
blobs are usually gone minutes after upload, once delivered. Bandwidth is
bounded by `MAX_SESSIONS × MAX_SESSION_TRANSFER`, and the hold limit means a
blob is never downloaded for longer than an hour. Content-level savings such as dedupe or
compression are not possible on the server: every item is encrypted under its
own key.

### Deployment

- One static musl binary in a `FROM scratch` (or distroless) image, with the
  built web SPA embedded via `rust-embed`. It needs one writable directory and
  nothing else, so local dev is just `airlock-server --data ./data`.
- **Persistent mode** (default): the data dir is a small persistent volume.
  Sessions survive restarts and redeploys.
- **Ephemeral mode** (`--ephemeral`): the data dir is a temp dir or `tmpfs`
  and is wiped at start. No storage to pay for at all; a restart ends every
  open session, which is acceptable for hour-long sessions.
- Serving blobs from the same machine uses the host's bundled bandwidth, not
  per-request object-store fees or metered egress.
- **Bring your own relay.** Which relay a session uses is simply the base URL
  in its invite links, so any user can run `airlock-server` themselves: on a
  small VM, or in ephemeral mode next to their runner behind a tunnel. They
  then pay their own disk and bandwidth, with their own limits. The hosted
  relay keeps tight free-tier caps and points heavy users here. Self-hosting
  is the largest single cost shift, and the code path is identical.
- Kubernetes: a single-replica StatefulSet with one PVC (or an `emptyDir` in
  ephemeral mode), plus a Service and Ingress. Purge is in-process, so there
  is no CronJob.
- **Scaling later, still without a database.** Sessions share nothing, so
  more capacity means more instances, each owning its own sessions, with the
  ingress routing by the `session_id` in the path (consistent hashing). New
  sessions go to the least-loaded instance; the session id stays the shard
  key. This is a v2 item and changes no API.
- Config via env (`AIRLOCK_DATA`, `AIRLOCK_PUBLIC_URL`, plus the cost
  controls above).

---

## 8. Web UI

Static SPA (Vite + React + TypeScript) served by the server at `/`, mirroring
the four design screens: landing, new session, live session, runner console.

- All crypto in the browser goes through the `airlock-core` wasm package
  (session creation, certificates, item encrypt/decrypt/sign/verify). No
  JavaScript crypto library is used. The fragment is parsed once and kept in
  memory only; never written to storage or sent in requests.
- The owner seed and `K` live in memory for the tab's lifetime; the
  **owner link** (`#v=1&r=owner&ok=…`) is shown once at creation so the owner
  can reopen the session later. "My sessions" in v1 is a localStorage list of
  session ids + names, not an account.
- **Local history.** The browser keeps each session's envelopes and blobs in
  IndexedDB exactly as received, so they are still ciphertext at rest. Opening
  the invite link again supplies the key to decrypt them. The tab acks each
  item once stored, answers `blob.wanted` by re-seeding from its cache, and
  offers "Clear local history" per session. Browser storage quotas apply; when
  one is hit, the oldest sessions' blobs are dropped first.
- Viewers: Markdown (markdown-it + DOMPurify), image preview (re-encoded on
  send), ZIP manifest (zip.js, listing only), Python (Shiki/Prism highlighting),
  job detail (status, signature, hashes, result bundle).
- Composer: message, or "Send as job" with a runner/label/any picker. The
  owner can submit jobs only if they also hold the sender role (they do by
  construction: the owner mints all role keys).

---

## 9. SDK, CLI, MCP

One Python package, `airlock-agent`, importable as `airlock`. It depends on
the `airlock-core` wheel (PyO3) for every cryptographic and protocol
operation and adds only HTTP plumbing and ergonomics. The wheel also ships the
static `airlock` binary so `pip install airlock-agent` puts `airlock runner
join` on `PATH`; the same binary is downloadable standalone.

```python
from airlock import Session
s = Session.join("https://host/s/ak_7f3e#v=1&r=send&k=…&rk=…")
s.send_text("Cleaned data attached.")
f = s.send_file("dataset.zip")
print(s.runners())                                # [Runner(name='runner-01', labels=['cpu'], idle=True)]
job = s.run_python(open("summarize.py").read(), files=[f], runner="runner-01", timeout=30)
r = job.wait()                                    # raises NoRunnerAvailable immediately if none matched
print(r.exit_code, r.stdout, r.out_files)
for item in s.stream(): ...                       # decrypted items as they arrive
```

CLI (`airlock …`, Rust, same binary as the runner): `session
create|close|invite`, `send text|file`, `run <file.py>
[--runner|--label|--any]`, `runner join`, `watch`.

**Local cache.** The SDK, CLI and runner keep a cache that mirrors the
relay's layout, `~/.cache/airlock/<session_id>/` with `log.jsonl` and
`blobs/`, holding ciphertext as received. They ack after writing to it,
answer `blob.wanted` from it, and delete a session's cache when it expires
(`Session.join(url, cache_dir=…)` overrides the location).

MCP server (`python -m airlock.mcp`, or `airlock-mcp` from the wheel): tools `send_text`, `send_file`, `list_runners`,
`run_python`, `get_result`, `list_items`, so any MCP-capable agent can use a
session without writing code.

---

## 10. Threat model (summary)

| Adversary | What they get | Mitigation |
|---|---|---|
| Relay operator / server compromise | Ciphertext, sizes, kinds, timing, participant public keys | E2E encryption with per-item keys; headers carry no names or content; purge on expiry |
| Someone with an observer link | Read everything | Observers cannot post; runners refuse anything not signed by a sender cert |
| Someone with a sender link | Can submit jobs | Jobs run only on runners the receiver started and the owner approved, under manifest limits, with no network |
| Malicious job code | Tries to escape, exfiltrate, exhaust | docker/k8s: no network, read-only rootfs, caps dropped, memory/cpu/pids/time limits, fresh container per job. local: documented as weak; dev only |
| Malicious inputs (zip, image, md) | Traversal, bombs, XSS | Zip validator; image re-encode; Markdown HTML stripped and sanitised |
| Replay / cross-session reuse | Reuse a signed job elsewhere | Signatures cover `session_id` and item `id`; per-item HKDF keys include `session_id`; server rejects duplicate ids |
| Lost invite link | Full role access | Short expiry by default; server-side role revoke; close & purge |
| Anyone re-seeding an evicted blob | Upload bytes for an item id | Accepted only if SHA-256 matches the author-signed envelope; counted against the session transfer cap |

Out of scope for v1: side channels on shared hosts, a compromised sender
machine, and metadata privacy from the relay (who talks to whom and when).

---

## 11. Repository layout

```
airlock/
  Cargo.toml                Rust workspace
  crates/
    airlock-core/           protocol types, canonical JSON, crypto, certs, validators (zip/md/image),
                            embedded job shim, test vectors (generated into docs/protocol.md)
    airlock-server/         axum app, file-backed session logs and blobs, SSE, routing, purge, embedded web
    airlock/                the `airlock` binary: runner (+ backends/local|docker|k8s) and CLI
  bindings/
    python/                 PyO3 crate → `airlock-core` wheel (maturin)
    wasm/                   wasm-bindgen crate → `@airlock/core` npm package (wasm-pack)
  python/
    airlock-agent/          SDK (airlock/), MCP server; depends on the airlock-core wheel, bundles the binary
  web/                      Vite + React + TS SPA; uses @airlock/core; built output embedded into airlock-server
  deploy/
    docker/                 Dockerfiles (server, runtime base image)
    k8s/                    runner Deployment + RBAC + NetworkPolicy examples; server manifests
  docs/
    DESIGN.md               this document
    protocol.md             canonical manifest/cert/item formats + test vectors (generated from airlock-core)
```

Tooling: `cargo` workspace with `clippy -D warnings`, `cargo-deny`,
`cargo-nextest`; `maturin` for the Python wheel and `wasm-pack` for the browser
package; `cargo-zigbuild` for static musl runner builds; `uv` + `ruff` +
`mypy --strict` for the Python SDK; `pnpm` + `vitest` for web. CI runs the
docker backend tests against a Docker daemon and the k8s backend against
`kind`.

---

---

## 12. Milestones

The protocol is frozen first, because every later crate codes against it and
format churn is where Rust is slowest.

| # | Deliverable | Done when |
|---|---|---|
| M0 | **Protocol freeze.** `docs/protocol.md` (manifest, certs, item envelope, job/result payloads) and generated test vectors; `airlock-core` crate implementing it; PyO3 wheel and wasm package passing the same vectors; CI building wheels, wasm and static binaries | vectors round-trip in Rust, Python and the browser; a protocol change requires a version bump |
| M1 | **Relay mode.** Rust server with file-backed storage (sessions, participants, items, SSE, expiry purge, ack and evict-on-delivery, cost controls) + Python SDK with local cache + minimal web timeline with IndexedDB history, all four content types | two SDK processes exchange text, md, zip and image through one `airlock-server --data ./data` process; the browser renders them; blobs leave the relay once both sides acked; a restart in persistent mode keeps the session |
| M2 | **Execute mode.** Runner with **local** (Linux sandboxed) and **docker** backends, routing, approval, results with `/out`, runner console page | the design's `summarize.py` scenario runs end to end on docker with network off |
| M3 | **kubernetes** backend, runtime image build/push, RBAC + NetworkPolicy manifests, Helm chart | same scenario on `kind` |
| M4 | New-session and live-session pages to design parity, full CLI, MCP server, audit export, role revoke, re-seeding evicted blobs | a non-coding user can create a session, hand out links, approve a runner and read results; a late joiner gets an evicted file from a peer's cache |
| v2 | Direct peer-to-peer file transfer over WebRTC (signaling via the relay, STUN only, relay buffer as fallback); sharding across relay instances by session id | files between two online peers never touch the relay |

---

## 13. Open questions

1. **Hosted vs self-hosted first.** The design uses `airlock.dev`. The code is
   the same; the difference is whether M1 ships a public relay (needs abuse
   limits, now covered by the cost controls in §7) or a single-binary
   self-hosted story. Recommendation: self-hosted first, hosted once M2
   lands.
2. **Owner persistence.** Owner = holder of the owner link, remembered in
   localStorage. Acceptable for v1? Accounts are a v2 item.
3. **Server-side signature verification.** Proposed yes (defense in depth, no
   extra information revealed). It costs tens of microseconds per item in Rust.
4. **Local backend on macOS/Windows.** Linux local is sandboxed. On other
   hosts, keep it as "warned, not blocked", or refuse to join a
   `network: false` session unless `--i-know-local-has-network`? Proposed:
   warn in v1.
5. **Item size ceiling.** 25 MB single-blob in v1; chunked upload when someone
   needs more.
6. **Ephemeral or persistent by default.** Ephemeral mode removes storage cost
   entirely but ends sessions on every restart or deploy. Proposed:
   persistent by default, ephemeral as a flag.
7. **Delivery versus availability.** Evicting blobs after delivery cuts
   storage to minutes per file, but a participant who was offline for longer
   than `AIRLOCK_BLOB_HOLD`, or joins later, depends on a peer being online to
   re-seed. Proposed: accept this; the owner can raise the hold on a
   self-hosted relay.
