# Airlox wire protocol v1

Status: **frozen** at M0. Any change to a byte on the wire requires bumping
`v` and adding `vectors/v2.json`. The reference implementation is the
`airlox-core` crate; the conformance suite is
[`crates/airlox-core/vectors/v1.json`](../crates/airlox-core/vectors/v1.json).
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
  `"airlox/v1/" || context || 0x00 || message`. Contexts: `manifest`,
  `cert`, `join`, `item`.
- **Hashes** are SHA-256. **KDF** is HKDF-SHA256. **AEAD** is AES-256-GCM
  with a 12-byte random nonce and 16-byte tag.

## 2. Session secrets

The owner generates a 32-byte **owner seed**. Everything else derives from it:

| Value | Derivation |
|---|---|
| owner keypair | Ed25519 key from seed = owner seed |
| session key `K` | `HKDF(salt="airlox/v1", ikm=owner_seed, info="session-key", L=32)` |
| role seed for R ∈ {sender, runner, observer} | `HKDF(salt="airlox/v1", ikm=owner_seed, info="role:" + R, L=32)` |
| role keypair | Ed25519 key from seed = role seed |
| session id | `"ax_" + base32_lower(SHA-256(owner_pub)[0..16])` (26 characters, 128 bits) |

`base32_lower` is RFC 4648 base32 with the alphabet `a-z2-7`, no padding.
Rotating `K` therefore means a new owner seed, i.e. a new session. Member
links pin the manifest only through the session id, which is why it carries
128 bits: forging a different owner key with the same id is infeasible.

## 3. Manifest

```json
{
  "manifest": {
    "v": 1,
    "session_id": "ax_kzdvvj2umnduyauf35o36k6kw4",
    "owner_pub": "<b64 32>",
    "roles": { "sender": "<b64>", "runner": "<b64>", "observer": "<b64>" },
    "mode": "relay" | "execute",
    "created_at_ms": 1761400000000,
    "expires_at_ms": 1761403600000 | null,
    "allowed_types": ["text", "py", "md", "zip", "image"],
    "max_item_bytes": 26214400,
    "job_limits": null | {
      "runtime": "python3.12", "timeout_s": 30, "memory_mb": 512,
      "network": false, "packages": ["numpy", "pandas"],
      "return_out": true, "approve_runners": true
    },
    "insecure_http_host": "airlox-relay.ns.svc"
  },
  "sig": "<owner signature, context manifest, over canonical(manifest)>"
}
```

Validity rules (all enforced by `Manifest::validate`):

- `session_id` equals the derivation from `owner_pub`; `v == 1`.
- `0 < expires_at_ms − created_at_ms ≤ 30 days`, or `expires_at_ms` is
  `null` (present, not omitted): the session never expires and lasts until it
  is closed. A relay may refuse such sessions (`400 ttl`) or purge them after
  a long idle period. In session params, `ttl_ms` is likewise required and
  `null` for no expiry.
- `allowed_types` is non-empty and has no duplicates.
- `0 < max_item_bytes ≤ 1 GiB`.
- The four public keys are pairwise distinct.
- `mode == relay` ⇔ `job_limits == null`. Execute mode requires `py` in
  `allowed_types`, `runtime` of the form `python3.<minor>`,
  `1 ≤ timeout_s ≤ 86400`, `32 ≤ memory_mb ≤ 65536`, and every `packages`
  entry already in canonical form (below). Clients normalize what the owner
  typed (and drop repeats) when they build the manifest, so `pyPowerGEM` is
  signed as `pypowergem`.
- A `packages` entry is a PEP 503-normalized name, optionally followed by a
  PEP 440 version specifier: `cugrid`, `cugrid==0.1.0`, `numpy>=1.26,<3`. The
  specifier is one or more comma-separated clauses, each an operator
  (`==`, `!=`, `>=`, `<=`, `>`, `<`, `~=`, `===`) and a version, written
  lowercase without spaces; `==` and `!=` may end in `.*`, and a `+local`
  version goes only with `==`, `!=` and `===`. Extras, environment markers
  and URLs are not accepted. An entry is at most 256 bytes, a specifier has
  at most 8 clauses, and a name appears in one entry only. Clients put the
  entry in this form when they build the manifest (`CuGrid >= 0.1.0.dev0`
  is signed as `cugrid>=0.1.0.dev0`). An allowlist of bare names is signed
  as before. A verifier older than this rule rejects a manifest that pins a
  version, as a package name that is not valid. A job's `requirements` name
  packages only (the name part of an entry); the version is the session's.
- `insecure_http_host` is optional and left out (not `null`) when unset, so
  manifests without it are unchanged. When present it is a lowercase DNS name
  or IPv4 address, without scheme, port or path, and not a loopback name: the
  one relay host participants may reach over plain `http://` (§4).

The manifest is plaintext policy. The server reads it to enforce expiry,
sizes, kinds and roles. The session *name* is not in it; clients post it as
the first text item.

## 4. Invite links

```text
owner:  {base}/s/{session_id}#v=1&r=owner&ok={owner_seed}
member: {base}/s/{session_id}#v=1&r={send|run|view}&k={K}&rk={role_seed}
```

- `base` is `https://host[:port][/path]` or `http://host[:port][/path]`,
  without query, fragment, userinfo or trailing `/`. Parsers accept either
  scheme; whether `http://` may be used is decided against the manifest
  below, since the link alone cannot vouch for it.
- The fragment never reaches the server.
- Parsers reject: missing or non-`1` `v`, duplicate keys, an owner link
  carrying `k`/`rk`, a member link carrying `ok`, and an owner seed whose
  derived session id differs from the path. Unknown keys are ignored.
- After fetching the manifest, a client checks that the role keypair derived
  from the invite matches `manifest.roles[role]` (or `owner_pub`), and that
  `base` is `https://`, or `http://` to `localhost`, `*.localhost`,
  `127.0.0.1` or `[::1]`, or `http://` to exactly the host the signed
  manifest names in `insecure_http_host`. Only then does it join or send a
  token. Fetching the manifest itself reveals only the session id. Creators
  run the same check on the owner link before registering a session.
- Over plain `http://`, content stays end-to-end encrypted, but bearer tokens
  and transfer codes (whose two words are 16 bits) cross the network in the
  clear, and a token is the participant toward the relay: the owner's can
  close the session, revoke roles and approve runners; a runner's can claim
  jobs. `insecure_http_host` is for a network the owner trusts, such as a
  cluster's service network. Clients refuse to claim a transfer code over
  plain http to another machine unless told to.
- `base` must be ASCII without `\` or `%`: HTTP clients read `\` as `/` and
  decode escapes, so the host they connect to must be the host checked.
  `insecure_http_host` is a lowercase DNS name or dotted-quad IPv4 address;
  hosts URL parsers read as IPv4 (a numeric last label) must be four decimal
  octets, not loopback, link-local, unspecified, broadcast or multicast.

### 4.1 Transfer codes

A one-time code such as `7-guitar-orbit` carries an invite link to another
machine, so nobody has to copy the link across by hand.

```text
code   = {nameplate}-{w1}-{w2}            w1, w2 from transfer::WORDS (256 words)
secret = "{w1}-{w2}"
key    = HKDF-SHA256(ikm = secret, salt = none, info = "airlox transfer v1 key")
claim  = HKDF-SHA256(ikm = secret, salt = none, info = "airlox transfer v1 claim")
box    = nonce(12) || AES-256-GCM(key, nonce, invite_link, aad = "airlox transfer v1")
```

- The sender posts `{claim_hash: hex(sha256(claim)), box: b64url(box)}` to
  `POST /v1/drops` (§12) and shows `{nameplate}-{secret}` with the nameplate
  the relay assigns.
- The receiver posts `{claim: b64url(claim)}` to `POST /v1/drops/{nameplate}/claim`
  and opens the box. The relay hands it out once.
- Codes are lowercased, and spaces or underscores read as `-`.
- The secret has 16 bits. Against outsiders the relay's limits protect it:
  three wrong claims burn a drop, a drop lives for minutes, and one address
  gets ten wrong claims per TTL over all drops (unknown numbers included).
  So an outsider gets a handful of guesses in 65,536 overall, not three per
  open code, and can cancel only a few codes. Many addresses (say, IPv6
  ranges) can still guess more and cancel more codes; a cancelled code tells
  its sender to make a new one. The relay itself can try every secret
  against `claim_hash`, so a transfer code trusts the relay with the invite
  in a way the link's fragment does not.

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
    "description": "A100 80 GB, CUDA 12; data team",   // optional
    "kind": "sdk|cli|web|runner",
    "runner": null | { "name": "runner-01", "labels": ["cpu"], "host": "build-box",
                       "sandbox": "local|docker|kubernetes|process", "network_unblocked": false,
                       "version": "0.1.1", "python": "3.12.4" },   // version, python optional
    "created_at_ms": 0
  },
  "sig": "<participant signature, context join, over canonical(join)>"
}
```

`kind == runner`, `runner != null` and `cert.role == runner` must all hold or
all fail. Runner names and labels match `[a-z0-9][a-z0-9._-]{0,62}`; at most
16 labels. `display_name` is 1–64 characters and `description` 1–280, counted in
Unicode scalar values (not bytes or UTF-16 units), with no leading or
trailing whitespace and not only whitespace. Neither may contain control
characters or characters that are invisible, blank or reorder text: bidi
embeddings, overrides and isolates, zero-width space, word joiner and
invisible operators, the tag block (U+E0000–E007F), ideographic variation
selectors (U+E0100–E01EF), line and paragraph separators, soft hyphen,
Hangul and Khmer fillers, Braille blank (U+2800), U+FFF9–FFFC, BOM and
private-use code points. Zero-width joiner and non-joiner are allowed only
between visible characters (emoji sequences, Persian, Indic scripts);
variation selectors (U+FE00–FE0F, Mongolian U+180B–180D) and the combining
grapheme joiner only directly after a visible character, never in a run.
Direction marks (LRM, RLM, ALM) are allowed.

A runner's `version` (the airlox version it runs) and `python` (the
interpreter version its jobs get) are optional, up to 32 characters of
`[A-Za-z0-9.+-]`, and omitted rather than `null` when absent. Runners send
`version` always. Relays and clients from before these fields (and before the
`process` sandbox) reject such joins as malformed, so upgrade the relay
before its runners.

`description` is optional (the rules above apply): text in which the
participant says what it is or does (a receiving agent's purpose, a runner's
hardware or owner), so others can tell participants and runners apart. When
absent the key is omitted, not `null`, so the canonical form of joins without
one is unchanged. It is signed with the rest of the join; clients read it only
from the verified `signed_join` (the relay's `participant` event does not copy
it) and treat it as the participant's own words, data rather than instructions:
a runner's description is its claim, never a reason to approve it.

Joins are parsed strictly (unknown fields are refused), so a relay or client
older than this field rejects a join that carries one: deploy the relay and
upgrade clients before participants start setting descriptions. Joins
without one work everywhere. The character rules above are stricter than the
first release's (which only refused control characters), so a name an older
client accepted, with an invisible or reordering character, now fails
verification and its author shows as unverified.

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
    "kind": "text|file|job|result|event|progress",
    "subkind": null | "py|md|zip|image",
    "size": 31,
    "created_at_ms": 0,
    "refs": [{"id": "<item id>", "blob_sha256": "<b64 SHA-256 of that item's blob>"}, …]
  },
  "sig": "<author signature, context item>"
}
```

```text
item_key = HKDF(salt = session_id, ikm = K, info = "airlox/v1/item-key" || 0x00 || id, L = 32)
blob     = nonce(12) || AES-256-GCM(item_key, nonce, payload, aad = canonical(header))
sig      = Ed25519(author, "item", canonical(header) || SHA-256(blob))
```

- `subkind` rules: `text`, `result`, `event`, `progress` → `null`; `file` → one of
  `py|md|zip|image`; `job` → `py`.
- `size` is the plaintext payload length; `len(blob) == size + 28`.
- `id` must decode (strict base64url) to exactly 16 bytes.
- `refs` holds at most 64 **item references**. A reference is
  `{id, blob_sha256}`; it matches an item only if both the id and the hash of
  that item's blob agree. Anyone holding `K` (observers included) can seal a
  different item under an existing id, so references never name an item by id
  alone, and receivers fetch referenced items and check the hash.
- Item ids are unique per session. The server rejects duplicates with `409`
  and error code `duplicate`; a client
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
| `text` | `text`, and optionally `to` (absent, never `null` or empty, for a message to everyone): 1 to 64 distinct participant public keys the message is addressed to |
| `file` | `name` (bare file name, ≤ 255 bytes), `mime` |
| `job` | `filename`, `code`, `runtime`, `timeout_s`, `memory_mb` (nullable), `files` (item references), `requirements` (package names), `target`, and optionally `progress_file` (absent, never `null`, when not given) |
| `result` | `job` (item reference), `exit_code` (nullable), `status`, `reason` (nullable), `wall_ms`, `peak_mem_mb`, `stdout`, `stderr`, `stdout_truncated`, `stderr_truncated`, `out_files` [`{name, size, item}`] where `item` is an item reference, `code_sha256`, `input_sha256` (lowercase hex), and optionally `env` (absent, never `null`, when not reported) |
| `event` | tagged by `event`: `runner_approve {participant_pub}`, `runner_reject {participant_pub, reason}`, `job_cancel {job}` (item reference), `session_close` |
| `progress` | `job` (item reference), `elapsed_ms`, `tail` (nullable), `tail_truncated` |

A `progress` item is a runner's signed note that a job is still running:
the time since it started and, if the job named a `progress_file` (a
relative `/`-separated path in its work dir, such as a simulator's log), the
end of that file as text (at most 64 KiB, starting at a line).
`progress_file` follows the component rules of §9, no component may start
with `.`, at most 8 components and 255 bytes.

A result's `env` says where the job ran, as its runner measured it once for
the runtime (not per job), so a sender can check it without trusting the
job's own output: `{"python": "3.12.4", "packages": {"cugrid": "0.1.0"},
"airlox": "0.1.2", "sandbox": "process", "interpreter": "--python"}`.
`packages` maps the normalized name of each allowlisted package to the
version installed, `airlox` is the runner's version, `sandbox` is the same
kind as in the runner's join request, and `interpreter` says where the
interpreter came from: `uv-runtime` (built by the runner from the
allowlist), `--python` (the operator's own), or `docker:<image>`. It holds no
file system paths. `python` and `airlox` are 1 to 32 printable characters,
`interpreter` 1 to 128, each version 1 to 64, and at most 256 packages are
listed.
A runner reports it on a job that ran; a `refused` result has none. A runner
shortens the digest of a digest-pinned image (`repo@sha256:` plus 12 hex
digits), cuts `interpreter` to fit, and leaves out a package whose version it
could not read; if the result would still fail these checks it omits `env`.

Before signing a result, a runner replaces the absolute path of the job's
work directory in `stdout`, `stderr` and `reason` with `$WORK`, of its out
directory with `$AIRLOX_OUT`, of the job's own directory with `$JOB`, of its
own runtime and cache directories with `$RUNTIME` and of the user's home
directory with `~` (the same goes for a progress item's `tail`), so an
account name in a path does not travel with the result. Files the job wrote
are returned as they are.

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

**Replies and addressing.** A `text` or `file` item whose `refs` is
non-empty replies to the item its first reference names; a `result` answers
its `job` the same way. `to` says whose attention a message needs: clients
use it, with replies, to decide which agents to wake (an item addressed to
the reader, a reply to one of the reader's items whoever else it names, or
the owner's message to everyone: a message without `to` wakes every listener
when the owner sent it and otherwise only the author of the item it replies
to). `to` is advice, not access control: every participant can read every
item. A listener may limit who can wake it to chosen authors (`airlox listen
--from`; only `owner` and a key cannot be imitated, since display names are
self-chosen and a role is shared by everyone holding that invite), and stops waking for a long run of posts from non-web
participants, counted up the reply chain or, for an addressed message that
replies to nothing, over the text items just before it since a web participant
last posted. A participant's `kind` is self-declared, so that count is a
safety net against accidental loops, not a security boundary.

**Compatibility.** Clients 0.1.0 and 0.1.1 reject text items that carry `to`,
job results that carry `env`, and manifests whose allowlist pins package
versions (`name==1.2.3`); there is no
protocol flag: use 0.1.2 or later in a session that uses them.

## 8. Policy

An author's role always comes from a role certificate that verifies against
the manifest **and** whose `participant_pub` equals the item's `author`.
Never from relay metadata or caller input.

**Server-enforceable** (header only):

| role | may post kinds |
|---|---|
| owner | all |
| sender | text, file, job, event |
| runner | result, file, progress |
| observer | none |

Plus: runners may post only in execute mode; `size ≤ max_item_bytes`;
`created_at_ms` within the session lifetime; `text` needs `text` allowed;
`file` needs its subkind allowed; `job` needs execute mode and `py` allowed;
`result` and `progress` need execute mode.

**Client and runner** (after decryption): payload type equals header kind;
file rules from §7; a text's `to`, when present, holds 1 to 64 distinct keys;
events other than `job_cancel` come from the owner only;
a `job_cancel` is honored only from the owner or the sender who authored the
job. Results must satisfy: `stdout` and `stderr` ≤ 1 MiB each; hashes are 64
lowercase hex characters; at most 64 `out_files`, each with a valid file name
and item reference; `reason` ≤ 4096 characters and present for `refused` and
`failed`; `completed` has an `exit_code`, `refused`/`timed_out`/`cancelled`
have none. A result is accepted for a job only if its `job` reference matches
the job item, and, for a `runner` target, only if its author is that runner's
participant key. Clients accept the first valid result per job. Progress
items follow the same binding (their `job` reference matches, a `runner`
target's key authored them, the runner is approved) and carry a `tail` of at
most 64 KiB.
A runner additionally refuses a job unless: entry file is a bare `.py` name;
code ≤ 1 MiB; `runtime` equals the manifest runtime;
`1 ≤ timeout_s ≤ limit`; `memory_mb` (if set) `≤ limit`; at most 32 `files`,
each fetched and matched against its reference; every requirement,
PEP 503-normalized, names the package of an entry in `packages`; the target
is well-formed. Runners also
verify the author's certificate chains to the sender (or owner) role, that a
`runner_approve` event for themselves is signed by an owner-role participant,
and keep a per-session record of job ids, written before a job runs, so a
relayed duplicate never runs twice, also across restarts. A job a runner
started but never answered (it stopped while the job ran) gets a `failed`
result when the runner starts again; it does not run again. A runner keeps a
finished job's answer (its sealed out files and result) on disk until the
relay has it, so a result is not lost if the runner stops before posting it;
after a restart it posts the saved items instead of a `failed` result. They
are the same sealed items, so a resend the relay already has is a
`409 duplicate`, which counts as delivered.
Runners install the manifest's `packages` from wheels only (`--only-binary
:all:`) when they join, before approval, each with its version specifier: a
source distribution's build script would otherwise run outside the sandbox. A
runner that is given its own interpreter installs nothing; it checks that
each package is installed at a version its entry allows and does not join
if one is missing or outside its specifier.

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
compression ratio above 500 for any entry over 1 MiB, or for the archive as a
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
                [--out DIR] [--fsize-mb N] [--memory-mb N] [--nproc N]
                [--pass-env NAME ...]
```

- **Environment.** Only a fixed `PATH` (the interpreter's directory plus
  `/usr/local/bin:/usr/bin:/bin`), `LANG=C.UTF-8`, `HOME` (the work dir),
  `TMPDIR` (a directory inside the work dir), `MPLBACKEND=Agg` and, with
  `--out`, `AIRLOX_OUT` (the output directory: `/out` in containers) reach
  the job. It runs as `python -E -s -u -B -X utf8 FILE`: the work dir is
  importable, `PYTHON*` variables and user site-packages are ignored, output
  is unbuffered so it survives a kill, and no `.pyc` files are written. On
  Windows the job also gets `SYSTEMROOT`, `TEMP` and `TMP` (the same
  directory as `TMPDIR`) and `USERPROFILE` (the work dir), and `PATH` is the
  interpreter's directory plus the system directories. Each `--pass-env NAME`
  copies that variable from the shim's own environment (a `PATH` is appended
  to the job's; `AIRLOX_*` names are never copied).
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

## 12. Relay HTTP binding

This section fixes how clients talk to `airlox-server` in relay mode. The
relay sees only what is listed here: signed manifests, signed join requests,
item envelopes and ciphertext blobs. Execute-mode endpoints (jobs, runners)
are in §13 and change nothing here except that `POST /items` refuses `job`
items, which go through `POST /jobs`.

**Conventions.** All paths are under `/v1`. JSON request bodies for create
and join are the canonical JSON strings defined above, sent as-is and capped
at 256 KiB. Authenticated calls carry `Authorization: Bearer <token>`. The
token is returned by join, never appears in a URL, and the relay stores only
its SHA-256. A token is valid until its participant leaves or the session
ends. Errors are `{"error": <code>, "message": <text>}`. A request body that
sends nothing for 30 seconds is answered with `408`.

| Method and path | Auth | Body | Success |
|---|---|---|---|
| `GET /v1/health` | none | none | `200 {"ok": true, "protocol": 1, "max_item_bytes": 104857600}`; clients default a new session's `max_item_bytes` to it |
| `POST /v1/sessions` | none | signed manifest | `201 {"session_id", "expires_at_ms"}` |
| `GET /v1/sessions/{id}` | none | none | `200 {"signed_manifest"}` |
| `POST /v1/sessions/{id}/participants` | none | signed join request | `201 {"token", "participant_pub", "role", "seq"}` |
| `POST /v1/sessions/{id}/leave` | bearer | none | `204`; the token stops working |
| `GET /v1/sessions/{id}/participants` | bearer | none | `200 {"participants": [participant…]}`, excluding those who left |
| `GET /v1/sessions/{id}/events?after=N` | bearer | none | `200 {"events": [event…]}` with `seq > N`; omit `after` for all |
| `GET /v1/sessions/{id}/stream` | bearer | none | SSE, see below |
| `POST /v1/sessions/{id}/items` | bearer | upload frame | `201 {"id", "seq"}`; `409 duplicate` if the item id exists |
| `GET /v1/sessions/{id}/items/{item}/blob` | bearer | none | `200` ciphertext, or `410 evicted` |
| `POST /v1/sessions/{id}/items/{item}/ack` | bearer, recipient | none | `204` |
| `GET /v1/sessions/{id}/delivery` | bearer | none | `200 {"items": {id: {"seq", "delivered": [participant_pub…], "waiting": [participant_pub…]}}}` for the caller's own most recent 500 items: who acked each one, and which live recipients the relay still holds it for. Ack means stored, not read |
| `POST /v1/sessions/{id}/items/{item}/want` | bearer, never received it | none | `202 {"open": true}`; `409 present` if the blob is on the relay |
| `PUT /v1/sessions/{id}/items/{item}/blob` | bearer, while wanted | ciphertext | `204`; `409 present` or `409 not_wanted` |
| `POST /v1/sessions/{id}/roles/{role}/revoke` | bearer, owner | none | `204`; `role` is `sender`, `observer` or `runner` |
| `GET /v1/sessions/{id}/audit.jsonl` | bearer, owner or observer | none | `200` JSON lines, see below |
| `POST /v1/sessions/{id}/close` | bearer, owner | none | `204`; the session is purged |

**Create.** The relay verifies the manifest signature, requires
`created_at_ms` within 5 minutes of its clock, and applies its own caps on
TTL, item size and session count. The session id is derived from the owner
key, so a second create with the same key is `409`. A session that was closed
or purged before its expiry cannot be created again until that expiry
(`410 closed`): its signed manifest is public, and re-creating it would revive
old invites.

**Join.** The relay runs the join verification of §5. Runners are refused in
relay-mode sessions. Each participant key joins once: signed joins are
published to every participant in `participant` events, so a second join with
the same key is `409` rather than a fresh token for whoever replayed it. A
participant who loses its token joins again with a new key; the old
participant stays in the log. A participant that is done calls `leave`, so
the relay stops waiting for its acks.

**Upload frame.** The item body is a single binary stream:

```
u32_be(len(envelope)) || envelope (canonical JSON, at most 64 KiB) || blob
```

The relay requires the envelope's `header.author` to be the authenticated
participant, runs the header policy of §8 with that participant's
certificate, streams the blob to disk while hashing it, and accepts the item
only if the blob length equals the header's ciphertext length and the
signature verifies over the received SHA-256. The recipients are every other
participant joined and not departed at that moment. An item whose header
`size` exceeds the manifest's `max_item_bytes` is `413`, decided from the
envelope before any blob byte is read.

**Events.** Every accepted change is one line in the session log, and each
public event carries that line's `seq`. Events are `{"seq", "kind", "data"}`:

| kind | data |
|---|---|
| `participant` | `{participant_pub, role, display_name, kind, runner, signed_join}` |
| `item` | `{envelope, blob_len, blob_present}` |
| `left` | `{participant_pub}`: no longer a recipient; its token is revoked |
| `evicted` | `{item}`: the blob left the relay; the envelope stays |
| `want` | `{item, by}`: participant `by` asks holders to upload the evicted blob again |
| `reseeded` | `{item, by}`: participant `by` uploaded it; it is on the relay again |
| `revoked` | `{role, participants}`: the owner revoked `role`; those participants' tokens are revoked |
| `closed` | `{reason}`: the last event of a session |

Clients must verify each `signed_join` themselves (§5) and take a
participant's key, role, display name and certificate from the verified join,
never from the event's unsigned copies of those fields. Every event is
durable before it is sent, so a sequence number is never reused.

**Stream.** `GET /stream` is Server-Sent Events with `id: <seq>`,
`event: <kind>` and `data: <event data JSON>`. It first replays every event
after `Last-Event-ID` (or all events when the header is absent), then streams
live ones. It ends after `closed`, after a `left`, `revoked` or (for a
runner) `runner … rejected` event that names the stream's own participant,
on server shutdown, or when the client
falls too far behind; clients reconnect with `Last-Event-ID`. A participant
may hold 4 streams at once; a fifth is `429`. Browsers use
`fetch` rather than `EventSource` so the token stays in a header.

**Delivery and eviction.** A recipient acks an item only after it has stored
the ciphertext locally. The relay deletes a blob once every recipient has
acked and a short grace period has passed, or when the hold limit expires,
whichever comes first. A recipient that leaves stops counting. The owner's
signed `event` items up to 16 KiB (runner approvals and rejections, close)
are never evicted, so a participant that joins later can always verify which
runners the owner approved. After that
`GET …/blob` is `410 evicted`, and clients show the item as delivered but
unavailable until it is re-seeded. A download that fails for any other
reason (network, `429`, `5xx`) is retried; clients must not record the item
as received or ack it until its blob is stored.

**Re-seeding.** A participant that never received an evicted blob (a late
joiner, or a new device, which joins with a new key) posts `want`. The relay
refuses it from a participant that acked the item and from a runner not yet
approved (`403`), keeps it open for 10 minutes, allows 16 open wants and
1024 distinct items per participant, and logs it and emits a `want` event.
Asking again for an open want only refreshes it in memory, with no log line
or event, except once every 10 minutes, when it is logged and announced
again for holders whose earlier upload was refused. At most 256 `want` log lines per participant and 2048 per session are
kept; past that, `429`. A want stays open while a re-seed upload is in
progress (the upload may fail); `409 present` means the blob is on the relay
to download. Clients ask again, about every 5 minutes, for items still
evicted, and a holder waits a random moment (up to 2 s) before answering.
Any participant holding the ciphertext answers with `PUT …/blob` and the
raw ciphertext. The relay takes it only while a want from another
participant is open and the blob is absent, and only if its length and
SHA-256 match the author-signed envelope, so a re-seed cannot alter content.
Up to 3 holders may upload one blob at once (a fourth gets `409 uploading`)
and the first to finish wins; a participant may have 4 re-seeds in flight
(`429`), and each must finish within 30 s plus 128 KiB/s of its size. An
upload that lost, or whose wanters all left or lapsed meanwhile, is `409
present` or `409 not_wanted` and is not charged to the transfer limit.
The first accepted upload closes the item's wants and emits `reseeded`; the askers become the blob's recipients, and it is evicted once
they have acked (after the grace period) or after a short hold of at most 10
minutes. Re-seeded bytes count against the session's transfer and storage
limits. Clients answer only for items they have verified, and must take the
item id of a `want` as a lookup in their own verified history, never as a
file name.

**Revocation.** The owner revokes a role: every participant holding it
departs at once (as with `leave`: a runner's active job fails with
`runner_revoked`, and jobs a revoked sender has queued or running fail with
`author_revoked`), and any later join with that role is `403 revoked`, also
after a restart. Revoking twice is a no-op. The owner role cannot be revoked.
A revoked participant still holds the session key from its invite, so what
it already copied stays readable to it; only closing the session ends access
to the rest. Clients treat `401` from `events` or `stream` as the session
having ended for them.

**Audit export.** `GET …/audit.jsonl` returns one JSON object per log
record, oldest first: `{"seq", "ts_ms", "action", "actor"?, …}`, where
`action` is `create` (with `signed_manifest`), `join` (with `role` and
`signed_join`), `item` (with `item`, `kind`, `blob_len`, `blob_sha256` and the
signed `envelope`), `ack`, `leave`, `evict`, `want`, `reseed`,
`runner_approve`, `runner_reject`, `job` (with `state`, `runner`, `reason`),
`revoke` (with `role` and the `participants` cut off) or `close`. `actor` is a
participant key. With the signed joins and envelopes, and `blob_sha256` (the
digest each author signed), anyone can check every item line against its
author without the relay. Only those lines are signed: the rest (acks,
evictions, approvals as the relay recorded them, revocations, job states) are
the relay's word, and the relay could leave lines out, so the export is a
record to check items against, not a tamper-evident log. The export never
contains ciphertext, bearer-token hashes or the creator's address hash. It is
purged with the session. The relay builds two exports at a time; more are
`429`.

**Error codes.**

| Status | `error` | Meaning |
|---|---|---|
| 400 | `invalid`, `signature`, `body`, `clock`, `ttl`, `item_size` | malformed or unverifiable input |
| 401 | `unauthorized` | missing or unknown bearer token |
| 403 | `forbidden`, `revoked` | role, author or content policy not allowed; a join with a revoked role's invite |
| 404 | `not_found` | no such session or item |
| 408 | `timeout` | request body stalled or upload too slow |
| 409 | `conflict`, `duplicate`, `present`, `not_wanted`, `uploading`, `runner_busy` | duplicate session or participant key; a duplicate item id (`duplicate`), or one still being uploaded (`uploading`: retry); a want or re-seed for a blob the relay has; a re-seed nobody asked for; enough re-seeds of that blob already in flight; a job whose matching runner is busy |
| 410 | `closed`, `evicted` | session closed (or closed and not re-creatable), or blob already delivered |
| 413 | `too_large`, `storage_wait`, `session_full` | body, envelope or item limit; the session's storage is full until deliveries free some (`storage_wait`: retry); the session history limit (`session_full`) |
| 429 | `limit`, `session_full` | relay, address, participant, stream, want or re-seed limit, or two audit exports already being built (`limit`: retry later); the session's item or transfer limit (`session_full`: it will not lift). `progress` items also get `session_full` once a session has used nine tenths of its item or history limit, which is kept for results |
| 507 | `storage_full` | relay disk above its high watermark |

**Address limits.** The per-address session limit counts IPv4 addresses
individually and IPv6 addresses per /64. Behind a reverse proxy
(`--trust-proxy`), the address is the last `X-Forwarded-For` entry, the one
the proxy appended; earlier entries are client-controlled and ignored.

### Transfer codes (§4.1)

Held in memory only, for `--drop-ttl` (default 10 minutes); a restart forgets
them. Nameplates are drawn at random from `1..=max(100, 4 × drops held)`. A
finished drop (claimed, burned, cancelled or expired) keeps its nameplate for
another TTL, so a stale code gets `410` rather than reaching a newer drop.
Only open drops count toward the limits.

| Request | Body / auth | Answer |
| --- | --- | --- |
| `POST /v1/drops` | `{claim_hash, box}`; `box` at most 4096 bytes decoded | `201 {nameplate, token, expires_at_ms, ttl_ms}`; `429` over `--max-drops` or `--max-drops-per-ip` open drops |
| `POST /v1/drops/{n}/claim` | `{claim}` | `200 {box}` once; `403` wrong claim; `410` with `error` `used`, `burned` (third wrong claim), `cancelled` or `expired`; `404` unknown; `429` once the address has ten wrong claims this TTL |
| `GET /v1/drops/{n}` | `Authorization: Bearer {token}` | `{state: waiting \| picked_up \| burned \| cancelled \| expired, picked_up_at_ms, expires_at_ms}` |
| `DELETE /v1/drops/{n}` | `Authorization: Bearer {token}` | `204`; the code stops working (`410 cancelled`) |

## 13. Execute HTTP binding

Execute-mode sessions add the endpoints below. All of them need a bearer
token; all of them answer `403` in a relay-mode session. The relay cannot
read jobs or results, so everything it does here is routing; the signed
items stay the source of truth.

| Method and path | Auth | Body | Success |
|---|---|---|---|
| `POST /v1/sessions/{id}/jobs` | sender or owner | `Airlox-Target` header + upload frame of a `job` item | `201 {"id", "seq", "state": "assigned", "runner"}` |
| `GET /v1/sessions/{id}/jobs/{job}` | any | none | `200 {"job", "state", "runner", "reason"}` |
| `POST /v1/sessions/{id}/jobs/{job}/claim` | the assigned runner | none | `204` |
| `POST /v1/sessions/{id}/jobs/{job}/cancel` | owner, or the job's sender | none | `202 {"job", "state", "runner", "reason"}` |
| `GET /v1/sessions/{id}/runners` | any | none | `200 {"runners": [runner…], "approval_required"}`; each runner has `busy` (it has an active job) |
| `POST /v1/sessions/{id}/runners/{participant_pub}/approve` | owner | none | `204` |
| `POST /v1/sessions/{id}/runners/{participant_pub}/reject` | owner | none | `204` |
| `GET /v1/sessions/{id}/runners/me/stream` | runner | none | SSE, see below |
| `POST /v1/sessions/{id}/runners/me/heartbeat` | runner | `{"job": id or null, "state", "detail"}` (all optional) | `200 {"approved", "job"}` |

**Approval.** When the manifest's `approve_runners` is true, a runner gets
no jobs, and is not a recipient of new items, until the owner approves it.
The owner does two things: posts a signed `runner_approve` event item (what
runners and senders verify, §8) and calls `…/approve` (what the relay
routes on). Rejecting is the same with `runner_reject` and `…/reject`; the
relay then revokes the runner's token like `leave`, fails its active job
with `runner_rejected` and ends its streams. When `approve_runners` is false
every runner is eligible as soon as it joins.

**Setup.** A runner joins before it prepares its sandbox and reports how
that goes in heartbeats: `"state": "preparing"`, then `"ready"`, or
`"failed"` with a `detail` of at most 300 characters saying why, before it
exits. The relay keeps the last state reported (in memory, like presence)
and lists it as `state` and `detail` in `GET /runners`, `null` for runners
that never report one. They are the runner's own unsigned words: clients
show them, never act on them.

**Submitting.** A sender seals a `job` item and posts its upload frame to
`POST /jobs` with `Airlox-Target` set to the job's `target` JSON (§7). The
relay routes on this copy; the runner refuses a job whose signed target does
not match it. Candidates are runners that are eligible, online, idle and
match the target (a `runner` target matches only that key; `labels` needs
every label; `any` matches all). The earliest joined candidate gets the job.
There is no queue: with no candidate the job item is still stored and its
state becomes `failed`. If a runner that would have matched is online but
busy with another job (runners take one job at a time) the reason is
`runner_busy` and the answer `409 runner_busy`; otherwise the reason is
`not_available` and the answer `409 no_runner_available`.

**Job states** (relay view): `assigned` → `running` (claimed) → `done`
(the assigned runner posted a `result` item whose `refs` include the job),
or `failed` with a reason:

| reason | when |
|---|---|
| `not_available` | no candidate at submission |
| `runner_busy` | no idle candidate at submission, but a matching one was busy |
| `runner_unresponsive` | not claimed within the claim timeout (default 5 s); the runner is offline until its next heartbeat |
| `runner_lost` | an assigned job's runner sent no heartbeat within the runner timeout (default 30 s); a running job's within the job reconnect grace (default 15 min, at least the runner timeout); or a heartbeat reported a different job |
| `runner_left`, `runner_rejected`, `runner_revoked` | its runner left, was rejected, or its role was revoked |
| `author_revoked` | the sender who submitted it had its role revoked |
| `cancelled` | cancelled before it was claimed |

Every change is a `job` event `{job, state, runner, reason}` on the session
stream. Approvals and rejections are `runner` events
`{participant_pub, status: "approved" | "rejected"}`. Both are relay
metadata, unsigned: clients decide what happened from signed items.

**Runner stream.** `GET /runners/me/stream` is SSE without event ids:
`job_assigned {job, envelope}`, `job_cancel {job}` and `rejected {}` (the
stream then ends; it also ends when the runner's role is revoked or the
session closes). On connect it repeats the runner's active assignment, so a
runner that reconnects does not lose it. A runner is **online** while it
holds this stream and has sent a heartbeat within the runner timeout;
heartbeats go every 10 seconds. At most 2 streams per runner.

**Reconnecting.** A runner that loses its connection goes offline after the
runner timeout, but its running job stays `running` for the job reconnect
grace: the job keeps running on the runner, which reconnects with backoff and
posts the result when the relay answers. A runner that reports, in a
heartbeat, a job the relay already failed as `runner_lost` gets it back as
`running`, and such a job's result from its runner still makes it `done`.
A runner that restarts names the job it still owes an answer for in its
setup heartbeats (`preparing`, `ready`), so that job stays `running` until
the answer arrives.
While a job runs, its runner may post signed `progress` items (§7) whose
`refs` include it.

**Claiming and results.** A runner claims an assignment right away, then
verifies and runs it, then posts its output files and the `result` item
through `POST /items`. A claim for a job that has failed or was reassigned is
`409`, and the runner drops the job. The relay takes items from a runner only
while it is eligible (approved when approval is required, not rejected, not
left or revoked, checked again when an upload commits),
a `result` only if its `refs` include a job assigned to that runner, and a
`progress` item only if its `refs` include a job that runner is running (or
that the relay failed as `runner_lost`).

Clients accept a result for a job only if, besides the §8 rules, its author
holds the runner role and, when the session requires approval, has a
verified `runner_approve` event from an owner-role participant and no
`runner_reject`. A rejection is final: a later or replayed approval does not
undo it. Runners apply the same rule to themselves. A runner records a job
id as handled before it runs the job, so a job runs at most once per runner.

**Cancelling.** `…/cancel` fails an unclaimed job at once. For a running job
the relay forwards `job_cancel` to the runner, which kills the job and posts a
`cancelled` result. The relay remembers the request and repeats it when the
runner's stream reconnects. Clients also post a signed `job_cancel` event item as the
record of who asked.

**Runner list.** Each entry is `{participant_pub, runner, approved, rejected,
online, job, signed_join}`, where `runner` is the runner info from the join.
Clients verify `signed_join` and the owner's signed approvals themselves.
