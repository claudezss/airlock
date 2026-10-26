# Airlock wire protocol v1

Status: **frozen** at M0. Any change to a byte on the wire requires bumping
`v` and adding `vectors/v2.json`. The reference implementation is the
`airlock-core` crate; the conformance suite is
[`crates/airlock-core/vectors/v1.json`](../crates/airlock-core/vectors/v1.json).
Every implementation (Rust, Python binding, wasm binding) must reproduce every
derived value in that file from its `inputs` and pass every verification step.

## 1. Conventions

- **Binary in text** is base64url without padding (RFC 4648 §5).
- **Canonical JSON** is used for everything signed or used as AEAD associated
  data: UTF-8, no insignificant whitespace, object keys sorted by byte order,
  ASCII-only keys, integers only and within ±(2^53 − 1) (floats are an
  error), strings escaped only where JSON requires (`"`, `\`, control
  characters; U+2028 and `/` stay raw). `null` fields are written, not
  omitted.
- **Signed structures travel as canonical JSON.** A receiver parses the
  bytes, re-serializes canonically and rejects the input unless the two are
  identical. Whitespace, key order, alternate escapes, missing `null` fields
  and unknown fields are therefore all rejected before any signature check.
- **Timestamps** are integer Unix milliseconds (`*_ms`). The core never reads
  a clock; callers supply times.
- **Signatures** are Ed25519 (strict verification) over
  `"airlock/v1/" || context || 0x00 || message`. Contexts: `manifest`,
  `cert`, `join`, `item`.
- **Hashes** are SHA-256. **KDF** is HKDF-SHA256. **AEAD** is AES-256-GCM
  with a 12-byte random nonce and 16-byte tag.

## 2. Session secrets

The owner generates a 32-byte **owner seed**. Everything else derives from it:

| Value | Derivation |
|---|---|
| owner keypair | Ed25519 key from seed = owner seed |
| session key `K` | `HKDF(salt="airlock/v1", ikm=owner_seed, info="session-key", L=32)` |
| role seed for R ∈ {sender, runner, observer} | `HKDF(salt="airlock/v1", ikm=owner_seed, info="role:" + R, L=32)` |
| role keypair | Ed25519 key from seed = role seed |
| session id | `"ak_" + base32_lower(SHA-256(owner_pub)[0..16])` (26 characters, 128 bits) |

`base32_lower` is RFC 4648 base32 with the alphabet `a-z2-7`, no padding.
Rotating `K` therefore means a new owner seed, i.e. a new session. Member
links pin the manifest only through the session id, which is why it carries
128 bits: forging a different owner key with the same id is infeasible.

## 3. Manifest

```json
{
  "manifest": {
    "v": 1,
    "session_id": "ak_kzdvvj2umnduyauf35o36k6kw4",
    "owner_pub": "<b64 32>",
    "roles": { "sender": "<b64>", "runner": "<b64>", "observer": "<b64>" },
    "mode": "relay" | "execute",
    "created_at_ms": 1761400000000,
    "expires_at_ms": 1761403600000,
    "allowed_types": ["text", "py", "md", "zip", "image"],
    "max_item_bytes": 26214400,
    "job_limits": null | {
      "runtime": "python3.12", "timeout_s": 30, "memory_mb": 512,
      "network": false, "packages": ["numpy", "pandas"],
      "return_out": true, "approve_runners": true
    }
  },
  "sig": "<owner signature, context manifest, over canonical(manifest)>"
}
```

Validity rules (all enforced by `Manifest::validate`):

- `session_id` equals the derivation from `owner_pub`; `v == 1`.
- `0 < expires_at_ms − created_at_ms ≤ 30 days`.
- `allowed_types` is non-empty and has no duplicates.
- `0 < max_item_bytes ≤ 1 GiB`.
- The four public keys are pairwise distinct.
- `mode == relay` ⇔ `job_limits == null`. Execute mode requires `py` in
  `allowed_types`, `runtime` of the form `python3.<minor>`,
  `1 ≤ timeout_s ≤ 3600`, `32 ≤ memory_mb ≤ 65536`, and every package already
  PEP 503-normalized.

The manifest is plaintext policy. The server reads it to enforce expiry,
sizes, kinds and roles. The session *name* is not in it; clients post it as
the first text item.

## 4. Invite links

```text
owner:  {base}/s/{session_id}#v=1&r=owner&ok={owner_seed}
member: {base}/s/{session_id}#v=1&r={send|run|view}&k={K}&rk={role_seed}
```

- `base` is `https://host[:port][/path]` without query, fragment, userinfo or
  trailing `/`. `http://` is accepted only for `localhost`, `*.localhost`,
  `127.0.0.1` and `[::1]`.
- The fragment never reaches the server.
- Parsers reject: missing or non-`1` `v`, duplicate keys, an owner link
  carrying `k`/`rk`, a member link carrying `ok`, and an owner seed whose
  derived session id differs from the path. Unknown keys are ignored.
- After fetching the manifest, a client checks that the role keypair derived
  from the invite matches `manifest.roles[role]` (or `owner_pub`).

## 5. Role certificates and joining

Each participant generates its own Ed25519 keypair and certifies it with the
role key from its invite (the owner uses the owner key):

```json
{
  "cert": { "v": 1, "session_id": "…", "role": "owner|sender|runner|observer",
            "participant_pub": "<b64>", "issued_at_ms": 0 },
  "sig": "<role key signature, context cert, over canonical(cert)>"
}
```

A certificate is valid iff `session_id` matches and the signature verifies
under `manifest.role_key(role)`. A sender role key cannot mint a runner
certificate because the runner role key differs.

The join request is signed by the participant key the certificate names:

```json
{
  "join": {
    "v": 1, "session_id": "…", "cert": { … },
    "display_name": "runner-01",
    "kind": "sdk|cli|web|runner",
    "runner": null | { "name": "runner-01", "labels": ["cpu"], "host": "build-box",
                       "sandbox": "local|docker|kubernetes", "network_unblocked": false },
    "created_at_ms": 0
  },
  "sig": "<participant signature, context join, over canonical(join)>"
}
```

`kind == runner`, `runner != null` and `cert.role == runner` must all hold or
all fail. Runner names and labels match `[a-z0-9][a-z0-9._-]{0,62}`; at most
16 labels. `display_name` is 1–64 non-control characters.

## 6. Items

Every message, file, job, result and event is an item: a plaintext
**header**, the author's **signature**, and an encrypted **blob**.

```json
{
  "header": {
    "v": 1,
    "id": "<22-char base64url of 16 random bytes>",
    "session_id": "…",
    "author": "<participant public key>",
    "kind": "text|file|job|result|event",
    "subkind": null | "py|md|zip|image",
    "size": 31,
    "created_at_ms": 0,
    "refs": [{"id": "<item id>", "blob_sha256": "<b64 SHA-256 of that item's blob>"}, …]
  },
  "sig": "<author signature, context item>"
}
```

```text
item_key = HKDF(salt = session_id, ikm = K, info = "airlock/v1/item-key" || 0x00 || id, L = 32)
blob     = nonce(12) || AES-256-GCM(item_key, nonce, payload, aad = canonical(header))
sig      = Ed25519(author, "item", canonical(header) || SHA-256(blob))
```

- `subkind` rules: `text`, `result`, `event` → `null`; `file` → one of
  `py|md|zip|image`; `job` → `py`.
- `size` is the plaintext payload length; `len(blob) == size + 28`.
- `id` must decode (strict base64url) to exactly 16 bytes.
- `refs` holds at most 64 **item references**. A reference is
  `{id, blob_sha256}`; it matches an item only if both the id and the hash of
  that item's blob agree. Anyone holding `K` (observers included) can seal a
  different item under an existing id, so references never name an item by id
  alone, and receivers fetch referenced items and check the hash.
- Item ids are unique per session. The server rejects duplicates; a client
  that sees two items with the same id treats the later one as a conflict and
  ignores it.
- Because the header is the AAD, re-labelling a header (even re-signed by a
  different author) makes decryption fail. Because the signature covers the
  blob hash, the server can check authorship without the key.

## 7. Payloads

```text
payload = u32_be(len(meta)) || meta || body
```

`meta` is canonical JSON tagged by `type`; receivers reject non-canonical
meta. Only `file` carries a non-empty `body`.

| type | meta fields |
|---|---|
| `text` | `text` |
| `file` | `name` (bare file name, ≤ 255 bytes), `mime` |
| `job` | `filename`, `code`, `runtime`, `timeout_s`, `memory_mb` (nullable), `files` (item references), `requirements` (package names), `target` |
| `result` | `job` (item reference), `exit_code` (nullable), `status`, `reason` (nullable), `wall_ms`, `peak_mem_mb`, `stdout`, `stderr`, `stdout_truncated`, `stderr_truncated`, `out_files` [`{name, size, item}`] where `item` is an item reference, `code_sha256`, `input_sha256` (lowercase hex) |
| `event` | tagged by `event`: `runner_approve {participant_pub}`, `runner_reject {participant_pub, reason}`, `job_cancel {job}` (item reference), `session_close` |

`target` is `{"type":"runner","participant_pub":…,"name":…}` (one runner,
pinned by its participant key; `name` is for display),
`{"type":"labels","labels":[…]}` or `{"type":"any"}`. `status` is one of
`completed`, `refused`, `timed_out`, `cancelled`, `failed`.

File names follow the component rules of §9 and additionally may not start
with `.`; at most 255 bytes.

File type rules (checked after decryption):

| subkind | extension | mime | content |
|---|---|---|---|
| `py` | `.py` | `text/x-python` | UTF-8 |
| `md` | `.md`, `.markdown` | `text/markdown` | UTF-8, no NUL |
| `zip` | `.zip` | `application/zip` | `PK\x03\x04` or `PK\x05\x06` magic; passes every §9 inspection rule |
| `image` | `.png` / `.jpg` `.jpeg` / `.webp` | `image/png` / `image/jpeg` / `image/webp` | magic bytes match the mime |

## 8. Policy

An author's role always comes from a role certificate that verifies against
the manifest **and** whose `participant_pub` equals the item's `author`.
Never from relay metadata or caller input.

**Server-enforceable** (header only):

| role | may post kinds |
|---|---|
| owner | all |
| sender | text, file, job, event |
| runner | result, file |
| observer | none |

Plus: runners may post only in execute mode; `size ≤ max_item_bytes`;
`created_at_ms` within the session lifetime; `text` needs `text` allowed;
`file` needs its subkind allowed; `job` needs execute mode and `py` allowed;
`result` needs execute mode.

**Client and runner** (after decryption): payload type equals header kind;
file rules from §7; events other than `job_cancel` come from the owner only;
a `job_cancel` is honored only from the owner or the sender who authored the
job. Results must satisfy: `stdout` and `stderr` ≤ 1 MiB each; hashes are 64
lowercase hex characters; at most 64 `out_files`, each with a valid file name
and item reference; `reason` ≤ 4096 characters and present for `refused` and
`failed`; `completed` has an `exit_code`, `refused`/`timed_out`/`cancelled`
have none. A result is accepted for a job only if its `job` reference matches
the job item, and, for a `runner` target, only if its author is that runner's
participant key. Clients accept the first valid result per job.
A runner additionally refuses a job unless: entry file is a bare `.py` name;
code ≤ 1 MiB; `runtime` equals the manifest runtime;
`1 ≤ timeout_s ≤ limit`; `memory_mb` (if set) `≤ limit`; at most 32 `files`,
each fetched and matched against its reference; every requirement,
PEP 503-normalized, is in `packages`; the target is well-formed. Runners also
verify the author's certificate chains to the sender (or owner) role, that a
`runner_approve` event for themselves is signed by an owner-role participant,
and keep a per-session set of job ids so a relayed duplicate never runs twice.

## 9. ZIP handling

Inspection reads only the central directory. Path components must be
non-empty, not `.` or `..`, contain no `/`, `\`, `:` (drive letters, NTFS
streams), NUL, control or invisible formatting characters (bidi overrides,
zero-width characters and the like), not end in `.` or space, and not be a
Windows device name (`CON`, `PRN`, `AUX`, `NUL`, `COM0-9`, `LPT0-9`, with any
extension). Also rejected: more than 10 000 entries; absolute paths; paths
over 512 bytes or depth 32; duplicates after Unicode NFC normalization and
lowercasing; symlinks (unix mode `0o120000`); encrypted entries; compression
other than stored or deflate; an entry over 512 MiB; a total over 1 GiB; a
compression ratio above 100 for any entry over 1 MiB, or for the archive as a
whole (total declared size / archive size) once the total exceeds 1 MiB.

Extraction writes only into an existing, **empty** directory that nothing
else writes to (a fresh per-job work dir), so no pre-existing symlink can
redirect a write. Every created directory is checked to resolve inside the
destination, files are created with `create_new`, and extraction fails if any
entry inflates beyond its declared size. Runners also cap total extracted
bytes per job.

## 10. Images

Images are decoded with limits: at most 16 384 px per side, and both the
decoded buffer and its 8-bit RGBA size must fit a 128 MiB budget. The budget
is checked from the header before any pixel buffer is allocated, so peak
memory stays near three times the budget. EXIF orientation is applied, and the
pixels are re-encoded in the same format (PNG; JPEG at quality 90; lossless
WebP). Re-encoding drops all metadata.
Senders sanitize before upload; receivers still treat images as untrusted.

## 11. Job shim

All sandbox backends run the embedded `shim.py`:

```text
python3 shim.py --work DIR --entry FILE --timeout SECONDS --result PATH
                [--fsize-mb N] [--memory-mb N] [--nproc N]
```

- **Environment.** Only a fixed `PATH` (the interpreter's directory plus
  `/usr/local/bin:/usr/bin:/bin`), `LANG=C.UTF-8`, `HOME` (the work dir),
  `TMPDIR` (a directory inside the work dir) and `MPLBACKEND=Agg` reach the
  job. It runs as `python -E -s -u -B -X utf8 FILE`: the work dir is
  importable, `PYTHON*` variables and user site-packages are ignored, output
  is unbuffered so it survives a kill, and no `.pyc` files are written.
- **Containment.** The job runs in its own process group. That group is
  killed when the job exits, on timeout, and when the shim receives SIGTERM,
  SIGINT or SIGHUP; the result then records `cancelled: true`. On Linux the
  shim is a child subreaper and also kills every descendant, including ones
  that called `setsid()`. On other systems only the sandbox (container or pod)
  contains a `setsid()` escape, so the macOS local backend is not a security
  boundary.
- **Limits.** `RLIMIT_FSIZE` (default 1024 MiB) caps every file the job
  writes, including `stdout.txt` and `stderr.txt`. `RLIMIT_CORE` is 0.
  `RLIMIT_AS` and `RLIMIT_NPROC` are applied when given; real memory and
  process limits come from cgroups in the docker and kubernetes backends.
- **Output.** `PATH` receives `{shim_version, exit_code, signal, timed_out,
  cancelled, wall_ms, peak_rss_kb, error}`, written atomically through a
  randomly named temporary file. `stdout.txt` and `stderr.txt` sit beside it.
  The directory holding `PATH` must not be writable by the job.
