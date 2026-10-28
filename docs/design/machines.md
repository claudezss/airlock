# Machines: a job slot on your own hardware, for any agent

Status: implemented (M-A to M-D) in 0.2; M-E (delta trees, beyond `job ls`)
remains. Where the implementation differs: a sender invite cannot be rotated
in place, because revoking a role is permanent and its invite is derived from
the owner seed, so there is no `machine invite --rotate` (`machine rm` and
`machine add` start over); and runners declare their `kinds` and shell in their
signed join (a breaking change to the join), so `machine ls` shows them as
soon as a runner joins. Originally a
proposal. Builds on [DESIGN.md](../DESIGN.md) §6 (runner) and
[protocol.md](../protocol.md) §7, §11 and §13. Nothing here changes the
cryptography, the roles or the relay's blindness; it changes what a job may
be, how its output arrives, what the runner keeps between jobs, and how a
person pairs a machine in the first place.

## 1. Why

A coding agent routinely sits on the wrong machine. A hosted agent (Claude
Code on the web, Codex cloud, Copilot's coding agent) runs in a sandbox with
HTTPS-only egress and cannot reach the GPU box, the staging database or the
licensed toolchain. A local agent on a laptop cannot reach the build server
behind the corporate firewall. Today the answers are an SSH key (a login, with
everything a login can do, reusable from anywhere, until someone notices) or
a cloud sandbox (their machine, not yours).

Airlox already has the right primitive: a signed job, run in a sandbox with
declared limits on a machine the receiver owns, answered with a signed
result, over outbound HTTPS from both ends. Five things stop it being what an
agent reaches for every day:

| today | needed |
|---|---|
| Jobs are Python files | `npm test`, `pytest`, `cargo test`, `make` |
| Output arrives when the job ends | Output as it happens; a 20-minute suite with a blank screen is unusable |
| Inputs are files the agent names one by one | The working tree as it is right now, uncommitted changes included |
| Every job starts from an empty directory | A warm checkout: dependencies installed once, incremental builds |
| Pairing is session vocabulary: create, invites, roles, links | `airlox machine add gpu-box`, one command on each side |

Against SSH the claim is specific, not general: the agent gets a job slot,
not a login, and it works from hosted agents and through NAT, where SSH does
not reach. For a trusted local agent and a machine you can already SSH into,
SSH is fine, and this document does not pretend otherwise.

## 2. Goals and non-goals

Goals:

- An agent with only a shell and an invite runs its project's test command
  on a machine it does not own and reads the output as it streams.
- Repeated runs are fast: the second `airlox run` of the afternoon does not
  reinstall `node_modules`.
- A person pairs a machine in under a minute with no file copying and no
  understanding of sessions, roles or manifests.
- Everything a job can do stays bounded by the sandbox and the signed
  manifest, as now. No change to the threat model's shape.

Non-goals:

- Interactive sessions, port forwarding, editing files in place on the
  machine. Those are SSH's; a job is a process with a start and an end.
- Hiding credentials from a job. A job that can run code on a machine can
  print anything that machine gives it. Access to anything sensitive is a
  question of what the runner is given and who approves the job
  (per-job approval is a separate proposal), never of filtering output.
- Concurrency above one job per runner in the first milestones (§14).

## 3. The flow this designs for

On the machine, once:

```bash
airlox runner join --code 7-guitar-orbit --name gpu-box --labels gpu,cuda12 --sandbox docker --image ghcr.io/me/ci:latest
```

On the agent's side, once:

```bash
airlox machine add gpu-box          # prints the code and the command above, waits for the join, approves it
```

Then, from any checkout, as often as wanted:

```bash
airlox run --on gpu-box --tree -- pytest -x tests/
```

```text
gpu-box · job 7Qk… · pytest -x tests/ · tree 412 files, 3.1 MB (18 changed)
============================= test session starts ==============================
collected 212 items
tests/test_median.py ....F
…
exit 1 · 41.2 s · peak 318 MB · out: report.json (2.1 KB)
```

A hosted agent does the same with the machine's sender invite in
`AIRLOX_INVITE` (`airlox machine invite gpu-box` prints it, or a code for it)
and `airlox run --tree -- pytest`.

## 4. Shell jobs

### Manifest

`job_limits` gains `kinds`, a non-empty list drawn from `python`, `shell`:

```json
"job_limits": {
  "kinds": ["python", "shell"],
  "runtime": "python3.12", "timeout_s": 1800, "memory_mb": 4096,
  "network": false, "packages": [], "return_out": true, "approve_runners": true,
  "workspace": true
}
```

`kinds` absent means `["python"]`, so every existing manifest keeps its
meaning. `runtime` and `packages` apply to `python` jobs only; a manifest with
`kinds: ["shell"]` still carries a valid `runtime` (clients default it) so
older verifiers that happen to accept the manifest read something sensible.
The `host-runner` profile sets `kinds: ["python", "shell"]`.

### Job payload

```json
{ "type": "job", "kind": "shell", "filename": "job.sh", "code": "pytest -x tests/\n",
  "cwd": "", "timeout_s": 1800, "memory_mb": null, "files": [], "tree": null,
  "requirements": [], "target": {"type": "labels", "labels": ["gpu"]} }
```

- `kind` is `python` (absent means `python`) or `shell`. A `shell` job's
  `code` is a script of at most 64 KiB run by the runner's POSIX shell as
  `sh -e -c "$code"` (Windows runners: `pwsh -NoProfile -Command`), with
  `cwd` a relative path inside the work dir (component rules of §9; empty
  for the work dir). `filename` is kept for display and for `code_sha256`,
  which is unchanged: SHA-256 of `code`.
- `airlox run -- <argv…>` joins the arguments with shell quoting into one
  line; `airlox run --shell script.sh` sends a file's contents. Both print the
  script when not `--json`.
- The item header's `subkind` for a `job` becomes `py` or `sh`. The relay
  learns the kind of a job, as it learns `py` today, and nothing else.

### Runner side

The shim already runs an entry under a scrubbed environment with limits,
output capture and process-group kill. It gains `--shell`: the entry is
executed by `sh -e` instead of `python -E -s`. `PATH` for a shell job is the
sandbox's own (the image's, or the host's system directories under the local
sandbox); `HOME` and `TMPDIR` stay inside the work dir, so tool caches
(`~/.npm`, `~/.cache/pip`, `~/.cargo`) land in the workspace (§7) and warm up
over time.

A shell job needs a toolchain, which the allowlist cannot express. Runners
that offer `shell` say where it runs:

- docker: `--image <ref>` names the operator's image; the runner pins it by
  digest at prepare time and reports `docker:<repo>@sha256:…` in the result's
  `env.interpreter`. Without `--image` the runner refuses `shell` jobs and
  says so in its setup heartbeat.
- local (Linux): the host's `/usr`, `/bin`, `/etc` already bind read-only
  into the sandbox root; `shell` jobs see the host's tools, contained by the
  same namespaces and Landlock rules as Python jobs.
- process, and local on macOS or Windows: the host's tools, with the same
  warnings as today (no network isolation, process-group containment only).

`env` gains `kinds` (what this runner accepts) and `shell` (`sh`, `pwsh`),
measured once per runtime like the rest of it. The runner refuses, with
`reason: kind_not_supported`, a job of a kind it does not run or the session
does not allow; `airlox machine ls` and the web UI show each runner's kinds.

What a `shell` job can do is exactly what a `python` job can already do by
calling `subprocess`. The kind changes which tools exist in the sandbox, not
what the sandbox permits.

## 5. Streaming output

The `progress` item (§7) already carries `elapsed_ms` and the tail of a named
file. It gains output chunks:

```json
{ "type": "progress", "job": {"id": "…", "blob_sha256": "…"}, "elapsed_ms": 4120,
  "stream": "stdout", "offset": 0, "data": "collected 212 items\n…", "tail": null, "tail_truncated": false }
```

- `stream` is `stdout` or `stderr`; `offset` is the byte position of `data`
  in that stream; `data` is at most 64 KiB and cut at a UTF-8 boundary. A
  chunk without `stream` is today's heartbeat-style progress item.
- The runner posts a chunk when 64 KiB are pending or every second while
  anything is, whichever first, and never more than `--progress-rate` items
  per minute (default 120); beyond that it coalesces. Both streams together
  are capped at `--stream-max-mb` (default 16); after that the runner posts
  a final chunk with `"truncated": true` and stops streaming. The signed
  `result` still carries the capped `stdout`/`stderr` and is the authority;
  chunks are display. A client that shows chunks and then the result shows
  the result's text, not a stitch of chunks.
- Chunks pass through the same `$WORK`/`~` path replacement as results, per
  chunk, so a path split across two chunks may escape it; the result is still
  clean.

`airlox run` prints chunks as they arrive on stderr (stdout chunks to its
stdout, stderr chunks to its stderr, so `airlox run -- make 2>/dev/null`
behaves) and the final summary line after the result; `--json` prints the
result only; `--stream-json` prints one object per chunk and then the
result. The MCP server's `run_python` gains a `run` tool with the same shape
and returns the result; chunks are available to MCP clients that support
progress notifications, else dropped. The web UI appends chunks to the job
card.

**Relay.** Every chunk is an item: encrypted, signed, routed like any other.
Two changes keep them from filling a session: the relay does not count
`progress` items toward the session history limit, and it drops a
`progress` item's blob once every recipient has fetched it or after the blob
hold, whichever first, and does not keep the envelope (today envelopes stay
after eviction). The header already says `kind: progress`, so this needs no
new information. Chunks from a runner nobody is listening to still cost
upload; `--progress-rate 0` turns streaming off for a runner.

## 6. The working tree

`airlox run --tree` sends the current checkout as the job's input:

- The file list is `git ls-files -co --exclude-standard` from the repository
  root (tracked and untracked files, ignored ones left out), zipped with the
  §9 rules, plus `.airlox/tree.json`: `{root_name, head, branch, dirty,
  files: [{path, sha256, mode}], count, bytes}`. Outside a git repository
  the list is every regular file under the current directory except `.git`,
  with a warning.
- `cwd` for the job is the current directory relative to the root, so
  `airlox run --tree -- pytest` from `services/api` runs there.
- Before sending, the CLI prints the count and size and the names of up to
  five of the largest files. It refuses, by default, a tree that contains a
  file matching a short built-in list of credential names (`.env`, `.env.*`,
  `*.pem`, `id_rsa*`, `*.keystore`, `.netrc`, `credentials.json`) unless
  `--tree-allow <glob>` names it, and `--tree-exclude <glob>` (repeatable,
  also read from `.airloxignore`) drops files. Untracked files are the usual
  home of secrets, which is why the default is to send them with a check
  rather than to leave them out: a test that needs a generated fixture
  should not fail because it was untracked.
- The tree counts toward `max_item_bytes` as one zip. Over the limit, the
  CLI names the largest files and suggests excludes; chunked upload stays a
  separate item (DESIGN.md §13.5).

The result's `env` is joined by `tree: {head, dirty, count, sha256}` from the
job, copied by the runner from `tree.json`, so an observer reading results
sees which tree each ran against without opening the job.

`--tree` can go with `--input`; inputs unpack after the tree and may overwrite
it. A `files` entry whose name is `tree.zip` and whose `tree.json` is present
is a tree; the job payload's `tree` field is its item reference, `null`
otherwise, so a runner knows which input to sync (§7) rather than unpack.

## 7. Workspaces

Today a job's work dir is created empty and deleted afterwards. With
`workspace: true` in the manifest and `--workspace` on the runner (the
`host-runner` profile and `airlox machine add` set both), the runner keeps
one directory per `(session, sender participant key)`:

```text
<cache-dir>/workspaces/<session_id>/<sender_pub>/
    work/                 the job's work dir, kept
    .airlox/placed.json   paths the last tree put there
```

- A job's `/work` is the workspace's `work/`. `/out` is still fresh per job.
- A tree input is synced, not unpacked: files whose `sha256` in `tree.json`
  matches what is on disk are left alone; others are written; paths listed
  in `placed.json` but absent from the new tree are deleted. Nothing else is
  touched. Since ignored paths (`node_modules/`, `target/`, `.venv/`) are
  never in a tree, they survive from job to job: that is the whole point.
  `--fresh` on `airlox run` asks for an empty workspace first.
- `HOME` is the work dir, so tool caches accumulate there too.
- Limits: `--workspace-max-mb` (default 10240) per workspace; a job that
  leaves the workspace over the limit gets `status: completed` and the next
  job from that sender is refused with `workspace_full` until it runs with
  `--fresh`. `--workspace-ttl` (default 14 days idle) removes unused ones;
  closing the session removes all of it. A runner restart keeps workspaces.
- Docker: the workspace is bind-mounted as `/work` rw in place of the
  per-job temp dir; the root stays read-only. Linux local: the pivoted root
  binds it the same way. Nothing changes in what the job may reach.
- Two jobs from one sender cannot share a workspace at once. A runner with
  several slots (§14) holds a lock per workspace: a second job from the same
  sender is refused with a signed `refused` result whose reason starts
  `runner_busy:`, as a runner with no free slot would be.

A job can leave something behind for the next job of the **same sender**.
That is the same trust domain as the job that planted it, and no more than a
local test run on a developer's machine already allows. Senders are isolated
from each other by directory and, in the sandbox, by the bind; the runner
operator's own files are as far from a workspace as they are from a temp
dir today.

Delta upload (sending only changed files) is a later milestone (§13): the
runner would post a signed `workspace` event with the `sha256` list it holds,
and the CLI would send only what differs. Full trees first; they are small
for most repositories once ignored paths are out.

## 8. Machines

A machine is a long-lived execute session with a name, kept on the agent's
side under `<cache-dir>/machines/<name>/`: the owner invite (mode 0600, in
a directory the MCP server's tools cannot read, like `--owner-invite-dir`),
a sender invite, and the runner's participant key once approved. The
`machine` commands are the session commands with the vocabulary removed:

| command | does |
|---|---|
| `airlox machine add <name> [--labels …] [--kinds …] [--timeout 30m] [--memory 4096] [--network]` | creates a `host-runner` session (never expires, approval on, workspace on), makes a transfer code for the runner invite, prints the `runner join` line to run on the machine, waits for the join, approves **that** runner, saves the machine |
| `airlox machine ls [--json]` | each machine: runners online, labels, kinds, sandbox, image digest, last job |
| `airlox machine invite <name> [--role sender\|observer] [--code]` | the invite for another agent (a hosted one, say), as a link or a one-time code |
| `airlox machine approve <name> [<runner>]` | approve a runner that joined later (a second box in a pool) |
| `airlox machine rm <name>` | closes the session; runners exit, workspaces are removed |
| `airlox run --on <name> …`, `airlox result --on <name> …` | use the machine's sender invite; `AIRLOX_INVITE` is not needed |

`--on` also accepts `name/label` (`--on pool/gpu`) and resolves to `--label`
inside that machine's session.

**Approving the right runner.** `machine add` must approve the runner that
claimed its code and no other, without the person comparing keys. The
claim (`POST /v1/drops/{nameplate}/claim`, §4.1) gains an optional
`participant_pub`, which `runner join --code` sets to the key it will join
with; the relay reports it to the code's creator (`session code --wait`
already streams how a code ended). `machine add` approves exactly that key
when it joins and leaves approval on for everyone else. This trusts the
relay to report the claimant honestly, which is the trust a code already
places in it (it could recover the invite); it does not trust the relay with
anything a link would not. A person who wants no such trust uses `--invite`
on the machine and `machine approve` by hand.

**Staying up.** `airlox runner serve` is `runner join` that restarts itself
on failure with backoff and logs to a file; `airlox runner install-service
--code …` writes and enables a `systemd --user` unit, a `launchd` agent or a
Windows service running `serve`, with the invite in a file only that user
can read. Runners already keep a finished job's answer until the relay has
it, so a restart in the middle of a job loses nothing that is not already
documented in §13 of the protocol.

The README and the skill lead with `machine`; sessions, roles and invites
remain the model underneath and the vocabulary for everything that is not a
machine (handoffs, observers, agent conversation).

## 9. Jobs that outlive the agent

Most of this exists. `airlox run --no-wait` prints the job id; `airlox
result <job> --wait 2h` blocks for it; a result replies to its job, and
`airlox listen --once` wakes for replies to the reader's own items, so an
agent that submitted a job and exited is woken by its result, across its own
restarts, because the identity cache makes the job still "mine". Changes:

- `airlox result --wait` streams chunks while it waits, like `run`.
- `airlox job ls [--on <name>] [--mine]` lists jobs with state, runner and
  age, from the relay's job states (§13) joined with the signed items.
- `run --no-wait` prints, in text mode, the `result` and `listen` lines that
  pick the job up later.

## 10. Relay changes, all together

1. `progress` items: excluded from the history limit; envelope and blob
   dropped after delivery or the blob hold.
2. Drop claims may carry `participant_pub`; the creator's `--wait` stream
   reports it.
3. `subkind: sh` for job items, and the `Airlox-Target` routing unchanged.
4. Nothing else. Trees are files; workspaces are the runner's; kinds live
   in the signed manifest and in signed results. The relay still reads
   headers and policy, never content.

## 11. Security

- **Sandbox is the boundary, as before.** `shell` adds no capability a
  Python job lacked. The operator chooses what the sandbox contains (image,
  host tools) and whether it has network; both were already the operator's
  choice. The CLI's existing warnings for sandboxes that cannot block
  network apply unchanged.
- **Network is the exfiltration path when it is on.** A machine joined to a
  staging database necessarily has `--network`; a malicious job on it can
  read what the sandbox can reach and send it anywhere, through the result
  or directly. That is true of SSH too, with a larger reach. The controls are
  what the runner is given and, for sensitive machines, a human approving
  each job before it runs (separate proposal); never output filtering, which
  this design does not attempt.
- **Trees carry whatever is in the checkout.** Hence the credential-name
  refusal, the size and count print, and `.airloxignore`. The list is a
  seat belt, not a scanner; the skill tells agents to read the printed
  summary before confirming.
- **Workspaces persist state within one sender's trust domain** (§7).
  `--fresh` and the TTL bound how long.
- **Machines keep an owner invite on disk**, in a directory the MCP server
  cannot read, as `--owner-invite-dir` does today. A sender invite handed
  to a hosted agent is a secret with a bounded blast radius: submit
  sandboxed jobs to approved runners until `machine rm`. There is no
  rotation in place: revoking a role is permanent (DESIGN.md §4, revocation)
  and the sender invite is derived from the owner seed, so a leaked sender
  invite is answered by `machine rm` and a new `machine add`.
- **Streaming reveals timing** of output to the relay (when chunks were
  posted and how large), as items always have. No plaintext.

## 12. Compatibility

Clients before this change reject manifests with `kinds` or `workspace`, job
payloads with `kind`, `cwd` or `tree`, progress items with `stream`, and
results whose `env` carries `kinds`, `shell` or `tree`: the canonical-JSON
rules refuse unknown fields. A session that uses any of this needs 0.2
clients throughout, as the `to`/`env` note in protocol §7 already says for
0.1.2. A `python` job without `--tree` in a manifest without `kinds` is
byte-for-byte what 0.1.x sends, so a 0.2 CLI against a 0.1.x runner keeps
working for what 0.1.x could do, and a 0.2 runner accepts 0.1.x jobs.

## 13. Milestones

| | ships | size |
|---|---|---|
| M-A | `kinds`, `shell` jobs, `--image`, `env.kinds/shell`, `airlox run -- …` | protocol + shim + runner + CLI; the largest piece of core work |
| M-B | streamed chunks in `progress`, `run`/`result` printing, relay retention rules, web UI append | runner + relay + two clients |
| M-C | `--tree` with checks, `cwd`, `env.tree`; workspaces with sync, limits, `--fresh` | CLI + runner; no protocol change beyond fields in M-A |
| M-D | `machine add/ls/invite/approve/rm`, `--on`, drop-claim `participant_pub`, `runner serve`, `install-service`; README and skill rewritten around it | CLI + relay (small) + docs |
| M-E | delta trees via signed `workspace` events; `job ls` | later, driven by use |

M-A through M-D are each one to two weeks for one person familiar with the
code. M-D is the one users see first and should not wait for M-E.

## 14. Open questions

1. **Windows shell jobs.** `pwsh` versus `cmd`; whether the process sandbox's
   Job Object limits are enough for arbitrary toolchains. Proposed: `pwsh`
   only, and a Windows runner reports `kinds: ["python"]` unless the operator
   passes `--shell pwsh`.
2. **Concurrency.** *Implemented.* One job per runner is a poor fit for a
   shared CI box. `--concurrency N` (1 to 16, default 1; `--max-jobs` is an
   alias) is the runner's `slots` in its signed join, and `machine add`
   puts it in the printed command. The relay sends a runner at most `slots`
   active jobs, preferring the least loaded runner, and `runner_busy`
   means "no free slot". A runner's workspace is a lock per sender, kept by
   the runner. Differences from the proposal: a second job from a sender
   whose workspace is in use is refused by the runner, not the relay (the
   relay cannot see content, only the author, and does not know whether a
   runner keeps workspaces), so the sender sees a `refused` result with a
   `runner_busy:` reason after it was routed; and the slots are fixed by
   the join, so a runner changes them by joining again under a new name.
   Memory and CPU limits are per job: size the host for all slots.
3. **Chunk cost on the hosted relay.** 120 items a minute per running job
   is cheap in bytes and not in requests. If it shows in the relay's
   footprint measurement, raise the coalescing floor to 2 s before touching
   the protocol.
4. **Should `machine add` default to `--network`?** CI against a database
   needs it; a GPU box for numerics does not. Proposed: off, and the printed
   summary says how to turn it on, because the default is what people keep.
5. **Trees and large binary fixtures.** Git LFS pointers come through as
   pointers. Proposed: document `--tree-exclude` and `--input` for them; do
   not resolve LFS.
6. **Whether `python` jobs should also default to a workspace.** They gain
   from warm caches too, but today's users expect a clean directory.
   Proposed: the manifest flag decides, and `host-runner` turns it on for
   both kinds.
