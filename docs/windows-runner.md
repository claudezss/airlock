# Running a runner on Windows

A Windows machine can run jobs with `--sandbox process`: each job is a plain
process using an interpreter you provide, contained in a Windows Job Object.
It is meant for tools that need the machine itself, such as a licensed
simulator, and for **senders you trust**: a job can read whatever the
runner's account can read, and reach the network.

`--sandbox docker` also works on Windows (Docker Desktop with Linux
containers), and is the one to use for code you don't trust.

## What the process sandbox does

- **Your interpreter, unchanged.** `--python C:\sim\venv\Scripts\python.exe`
  runs jobs with that venv. At startup the runner checks that it is the
  session's Python version and has every package in the session's allowlist,
  and stops with the missing names if not. It never installs anything into
  it. Without `--python` it builds a runtime with `uv`, as `--sandbox local`
  does.
- **One Job Object per job.** The job's memory (the session's limit, or less
  with `--memory`) is capped for its whole process tree, so `tara.exe` and
  anything it starts count together. Every process in it is killed when the
  job ends, times out, is cancelled, or the runner itself stops or crashes:
  nothing a job starts outlives it. Jobs get no clipboard, desktop or
  display-settings access, and a crash ends the job instead of opening a
  dialog.
- **A fresh work folder per job**, under the system temp directory, deleted
  afterwards.
- **A scrubbed environment.** A job sees only `PATH` (its interpreter and
  the Windows system folders), `SYSTEMROOT`, `TEMP`/`TMP` inside its work
  folder, `HOME` and `USERPROFILE` (the work folder), `LANG`,
  `MPLBACKEND`, `AIRLOX_OUT`, and what you pass with `--pass-env`
  (a license server, say). Never the runner's invite or keys, and never an
  `AIRLOX_*` variable.
- **Not as an administrator.** The runner refuses to start elevated, as a
  member of Administrators, or as SYSTEM: jobs would get those rights.
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
invite for later ones.

If the relay is reachable only through a tunnel or port-forward, add
`--relay http://127.0.0.1:8080`: the runner connects there instead of the
host in the invite. The session's keys still come only from the invite, and
the relay never sees them.

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
While it runs, the runner posts a signed progress item every
`--progress-interval` (60 s by default) with the elapsed time and the end of
that file (`--progress-tail`, 4 KiB by default), so a sender can tell a long
run from a hung one:

```python
job = agent.run_python(code, runner="tara-01", progress_file="logs/tara.log")
res = job.wait(timeout=None, on_progress=lambda p: print(p.elapsed_ms, p.tail))
```

### One job at a time

A runner runs one job at a time (`--max-jobs 1`). While it is busy,
`runners()` shows `busy`, and a new job for it is refused at once with
`runner_busy` (`RunnerBusy` in the SDK) rather than queued.

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
  which is neither an administrator nor SYSTEM;
- keeps the invite, the runner's identity, its cache and its logs in
  `%ProgramData%\airlox\airlox-runner-tara-01`, which only that account,
  SYSTEM and administrators can open. The invite comes from `--code`,
  `--invite-file` or `--invite` and is written there; the service reads it
  from that file, never from its command line;
- gives the account read access to the `--python` venv and the Python
  installation it is based on.

Grant the service account read access to anything else jobs need (the
simulator's folder, its license file), for example
`icacls C:\sim /grant "NT SERVICE\airlox-runner-tara-01:(OI)(CI)RX"`.

Logs are in `...\cache\runner\logs\airlox-runner-tara-01.log`; they never
contain the invite or keys. Stop or start the service with
`sc.exe stop airlox-runner-tara-01` / `sc.exe start ...`, and remove it with:

```powershell
airlox runner service uninstall airlox-runner-tara-01          # keeps its data folder
airlox runner service uninstall airlox-runner-tara-01 --purge  # deletes it too
```
