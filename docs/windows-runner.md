# Running a runner on Windows

A Windows machine can run jobs with `--sandbox process`: each job is a plain
process using an interpreter you provide, contained in a Windows Job Object.
It is meant for tools that need the machine itself, such as a licensed
simulator, and for **senders you trust as much as the runner's operator**.
A job runs as the runner's own account. It can read whatever that account
can read (including the runner's saved invite and identity, so it can act as
the runner in the session), reach the network, and, using Windows facilities
such as WMI, start processes outside its Job Object.

`--sandbox docker` also works on Windows (Docker Desktop with Linux
containers), and is the one to use for code you don't trust.

## What the process sandbox does

- **Your interpreter, unchanged.** `--python C:\sim\venv\Scripts\python.exe`
  runs jobs with that venv. At startup the runner checks that it is the
  session's Python version and has every package in the session's allowlist,
  and stops with the missing names if not. It never installs anything into
  it. Without `--python` it builds a runtime with `uv`, as `--sandbox local`
  does.
- **Where packages come from.** At startup the runner logs where each
  allowlisted package resolves from. It warns when one is an editable install
  (jobs import that checkout, not a wheel) or when `import` would load a copy
  other than the installed one.
- **One Job Object per job.** The job's memory (the session's limit, or less
  with `--memory`) is capped for its whole process tree, so `tara.exe` and
  anything it starts count together. Every process in it is killed when the
  job ends, times out, is cancelled, or the runner itself stops or crashes:
  nothing a job starts outlives it. Jobs get no clipboard, desktop or
  display-settings access, and a crash ends the job instead of opening a
  dialog.
- **Memory is counted as commit.** That runs well above what Task Manager
  shows: importing numpy and a compiled extension can take more than 512 MB.
  At startup the runner imports the allowlisted packages once, in a Job
  Object with the job's cap, and warns when that alone comes near the cap.
  Sessions created from the CLI, the MCP server or the web UI default to
  2048 MB.
- **A fresh work folder per job**, deleted afterwards. By default it is under
  the system temp directory, which on Windows is under your profile
  (`C:\Users\<name>\AppData\Local\Temp`) and so shows your account name in
  any traceback the job prints. `--work-root C:\airlox-work` (or
  `AIRLOX_WORK_ROOT`) puts the folders in a directory you choose; the runner
  creates it, so the account it runs as needs write access to its parent. Either
  way, the runner replaces the folder's path in the job's stdout, stderr and
  progress tail with `$WORK` (and `$AIRLOX_OUT` for the output folder, `$RUNTIME`
  for its runtime and cache, `~` for your profile) before it signs the result.
- **A scrubbed environment.** A job sees only `PATH` (its interpreter and
  the Windows system folders), `SYSTEMROOT`, `TEMP`/`TMP` inside its work
  folder, `HOME` and `USERPROFILE` (the work folder), `LANG`, `MPLBACKEND`,
  `AIRLOX_OUT`, the machine's own variables (`WINDIR`, `COMSPEC`,
  `PATHEXT`, `OS`, `SystemDrive`, `NUMBER_OF_PROCESSORS`,
  `PROCESSOR_*`, `ProgramData`, `ALLUSERSPROFILE`, `PUBLIC`,
  `ProgramFiles*`, `CommonProgramFiles*`), and what you pass with
  `--pass-env`. Pass anything a tool needs beyond that, such as a license
  server (`LM_LICENSE_FILE`) or `APPDATA`, by name. The runner's own
  variables, its invite among them, never reach a job, and no `AIRLOX_*`
  variable is ever passed.
- **Not as an administrator.** The runner refuses to start as SYSTEM, as an
  administrator (elevated or not: UAC is not a security boundary, so an
  unelevated administrator's job could still elevate), or as an account that
  holds a privilege leading to SYSTEM, such as `SeImpersonatePrivilege`.
  Run it as a standard user, or as the Windows service below. The same holds
  for running the tests of the process sandbox.
- **No network isolation.** It cannot block the network, says so when it
  joins (`runner list` shows "cannot block network"), and refuses a session
  whose manifest says `network: false` unless you start it with
  `--accept-network-gap`.

## Running it

```powershell
airlox runner join --invite-file C:\airlox\invite-runner.txt --name tara-01 `
    --labels tara --sandbox process --python C:\sim\venv\Scripts\python.exe `
    --pass-env LM_LICENSE_FILE --accept-network-gap
```

`--invite-file` keeps the invite out of the command line and the
environment; `--code 7-guitar-orbit` works for the first start and saves the
invite for later ones. Write the file with

```powershell
Set-Content C:\airlox\invite-runner.txt -NoNewline -Encoding ascii -Value '<runner invite>'
```

and keep it readable only by the account the runner runs as.

If the relay is reachable only through a tunnel or port-forward, add
`--relay http://127.0.0.1:8080`: the runner connects there instead of the
host in the invite. It takes https anywhere, or plain http to this machine
only, and only this flag redirects the runner (`AIRLOX_RELAY` only chooses
where `--code` is claimed). The session's keys still come only from the
invite, and the relay never sees them.

### Sessions for a long-lived runner

A runner serves one session and stops, cleanly, when that session ends. For
a runner that should keep working (a service), create the session without an
expiry, on a relay that allows that (the default; `--max-ttl`):

```powershell
airlox session create --profile host-runner --job-timeout 6h --package numpy
```

A relay purges a session that sees no activity (joins, items, downloads) for
`--idle-ttl-unexpiring`, 3 days by default; jobs and their progress count,
and a session is never idle while a runner or participant holds a stream to
it, so a runner that stays connected keeps its session. The idle clock starts
when the last stream closes, and after a relay restart runners get
`--job-reconnect-grace` (15 minutes) to reconnect before it counts.
To move a runner to a new session, put the new runner invite in its invite
file (for the service, `%ProgramData%\airlox\<service>\invite-runner.txt`,
from an elevated prompt) and start it again (`sc.exe start <service>`).

`--profile host-runner` stands for `--execute --ttl never --job-timeout 30m
--job-memory 4096 --kinds python,shell --workspace`, with items as large as
the relay allows (up to 100 MB) and runner approval on. Any flag you give wins, and `create` prints the
limits the session got.

Items are capped per session when it is created: by default at the largest
item the relay allows, up to 100 MB (25 MB for relays that do not say), or
at what you pass (`--max-item-mb`, or `max_item_bytes=` in the SDK's
`Session.create`). MB here means 1024 × 1024 bytes.

### Long jobs and dropped connections

Session job timeouts go up to 24 hours (`airlox session create
--job-timeout 6h`). If the connection to the relay drops, a running job
keeps running; the runner reconnects with backoff and posts the result when
the relay answers again. The relay keeps the job `running` for its
`--job-reconnect-grace` (15 minutes by default); after that it reports the
job as `runner_lost`, but takes the job back if the runner returns, and a
result posted later still counts.

A job runs at most once. A finished job's answer (its sealed out files and
result) stays in the runner's cache until the relay has accepted it. While
the relay is unreachable the runner keeps retrying it, for up to a day, and
after a restart it picks the saved answer up again: if the runner stops after
a job finished but before posting, it posts that job's real signed result
when it starts again, once. Only a job that was still running when the
runner stopped is lost: the Job Object ends the job with the runner, and on
startup the runner posts a signed `failed` result for it (it was not
finished, and is not run again).

### Progress

A job can name a log file: `run_python(..., progress_file="logs/tara.log")`
in the SDK, `airlox run --progress-file logs/tara.log` on the command line.
The path is relative, and looked up in the job's work folder and then in its
out folder (`$AIRLOX_OUT`, where a tool may write its log, such as TARA's
`taralog.txt` in a run folder). While the job runs, the runner posts a signed
progress item every `--progress-interval` (60 s by default; at most every
5 minutes after the first hour) with the elapsed time and the end of that
file (`--progress-tail`, 4 KiB by default), so a sender can tell a long run
from a hung one. When a session is nearly full, the relay pauses progress so
that results still fit:

```python
job = agent.run_python(code, runner="tara-01", progress_file="logs/tara.log")
res = job.wait(timeout=None, on_progress=lambda p: print(p.elapsed_ms, p.tail))
```

### One job at a time

A runner runs one job at a time unless started with `--concurrency N` (up to
16). While every slot is taken, `runners()` shows `busy`, and a new job for it
is refused at once with `runner_busy` (`RunnerBusy` in the SDK) rather than
queued.

## As a Windows service

From an elevated prompt:

```powershell
airlox runner service install --code 7-guitar-orbit --name tara-01 --labels tara `
    --sandbox process --python C:\sim\venv\Scripts\python.exe --accept-network-gap
```

This:

- copies `airlox.exe` to `%ProgramFiles%\airlox\`, where only
  administrators can change it;
- creates the service `airlox-runner-tara-01`, which starts with Windows and
  is restarted after a crash or failed start (after 10 s, 30 s, then every
  minute). A session that ends stops it cleanly;
- runs it as its own virtual account, `NT SERVICE\airlox-runner-tara-01`,
  which is neither an administrator nor SYSTEM, with only the privilege
  every process needs (`sc.exe privs`: no `SeImpersonatePrivilege`);
- keeps the invite, the runner's identity, its cache and its logs in
  `%ProgramData%\airlox\airlox-runner-tara-01`, which it makes owned by
  Administrators and open only to that account, SYSTEM and administrators
  (whatever was there before). The invite comes from `--code`,
  `--invite-file` or `--invite` and is written there; the service reads it
  from that file, never from its command line;
- gives the account read access to the `--python` venv and the Python
  installation it is based on.

The service account is a member of Users and Authenticated Users, so its
jobs can already read everything those groups can, which on default
permissions is most folders on the machine. Deny it what jobs should not
see, such as other projects' data and build caches:

```powershell
icacls D:\decks /deny "NT SERVICE\airlox-runner-tara-01:(OI)(CI)R"
```

and grant it read access to anything jobs need that it cannot read yet
(the simulator's folder, its license file), for example
`icacls C:\sim /grant "NT SERVICE\airlox-runner-tara-01:(OI)(CI)RX"`.

Logs are in `...\cache\runner\logs\airlox-runner-tara-01.log`; they never
contain the invite or keys. Stop or start the service with
`sc.exe stop airlox-runner-tara-01` / `sc.exe start ...`, and remove it with:

```powershell
airlox runner service uninstall airlox-runner-tara-01          # keeps its data folder
airlox runner service uninstall airlox-runner-tara-01 --purge  # deletes it too
```
