# Pain points

What got in the way while building the [use cases](use-cases.md): writing
each scenario against the SDK, the CLI and the MCP server, running real
Claude Code and Codex agents through a session, and recording the demos.
Each entry says what happened and what changed, most recent first.

## Fixed

| What | Fix |
|---|---|
| `airlox mcp` joined its `--invite` session only on `initialize`, which clients on the stateless MCP protocol (2026-07-28, e.g. Claude Code 2.1.3xx) never send: every tool said "no session yet" | It joins on `initialize`, on `server/discover`, or before the first tool that needs a session, and reads the client's name from either |
| Every script polled `runners()` until a runner was online, and again until a sender saw the owner's approval (`run_python(runner=…)` straight after approving raised `PolicyError`) | `Session.wait_for_runner(name, approved=True)` in the SDK (raises `RunnerFailed` for a runner that could not start, `PolicyError` for a rejected one) and `airlox runner wait <name> --approved` |
| Your own items came back to you, so bots filtered on `author == participant_pub` and models had to recognise their own messages | `Item.mine` in the SDK, `"mine"` in CLI and MCP item JSON |
| Headless agents (`codex exec`, `claude -p`) had their send and run tools refused, and every integrator had to work out the settings and a worker prompt | `airlox mcp config claude` or `codex` prints a config (invite from `AIRLOX_INVITE`, only a worker's tools, no prompts); `airlox mcp prompt` prints a worker prompt |
| Participants were called `mcp`, `cli` or `owner` unless named, so a session with two agents showed two `mcp`s | `airlox mcp` takes its name from the MCP client (`claude-code`, `codex`, …) unless `--as` is given |
| Every MCP job was called `main.py` | `run_python` asks for a descriptive `filename` |
| On macOS the local backend's jobs saw paths naming the user and the runner's cache | Unsandboxed jobs run under the system temp directory, and the runner's warning says they can read the user's files |
| The web UI offered **Approve** for a runner that had failed to start, and counted it as awaiting approval | It shows the reason instead; Reject stays |
| The relay was not in the pip or npm packages, so trying things locally needed a Rust or Docker build | Releases publish `ghcr.io/claudezss/airlox-server:<version>` for amd64 and arm64 (from the release after 0.1.0; `:latest` follows `main`), and the examples run it in Docker when no `airlox-server` is installed |
| A runner that failed to prepare its sandbox never appeared in the session; owners and agents waited until they timed out | Runners join first and report `preparing` / `ready` / `failed` with a reason (`state`, `detail` in `GET /runners`), shown by the SDK, CLI, MCP and web UI |
| Files a job wrote besides top-level images came back only inside `out.zip`, so reading a 100-byte report meant saving and unpacking it | `--out-dir` and MCP `save_dir` unpack `out.zip` beside it; results carry small text files inline as `out_text`; the SDK has `Result.read(name)` |
| Results named their runner only by its key | `runner_name` in the SDK's `Result`, CLI JSON and MCP results |
| Runners started together on one machine (sharing `~/.cache/airlox`) deleted each other's half-built job runtime and exited | A lock per runtime in the local sandbox: one builds, the others wait |
| The web timeline stopped following new items when the sidebar sat below it (narrow windows) or a card grew as its file or result arrived | It follows when the reader is at the end of the timeline, not of the page |
| The landing page told runners to pass the invite with `--invite` (visible in `ps`) and to install with `cargo` | `AIRLOX_INVITE=…` and `pip install airlox` / `npm install -g airlox` |

## Open

- The release image job (`release.yml`, `image`) has not run yet: it first
  runs on the next `vX.Y.Z` tag, and its arm64 half builds under QEMU.
- The live agent test (`AIRLOX_LIVE_AGENT=1`) calls a real model, so it can
  fail when the model answers in another shape; one Codex run of five did.
