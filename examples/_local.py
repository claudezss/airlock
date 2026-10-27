"""Shared plumbing for the examples: a local relay, runner processes and an
MCP client, so each example runs with one command and doubles as an
end-to-end test (python/airlox/tests/test_use_cases.py).

Binaries come from AIRLOX_BIN and AIRLOX_SERVER_BIN, else from PATH.
Runners use the local sandbox unless AIRLOX_SANDBOX says otherwise.
"""

import contextlib
import json
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import time

import httpx

from airlox import Session


def binary(env: str, name: str) -> str:
    path = os.environ.get(env) or shutil.which(name)
    if not path:
        sys.exit(f"{name} not found: put it on PATH or set {env}")
    return path


@contextlib.contextmanager
def local_relay(data: pathlib.Path):
    """An `airlox-server` on a free local port, for as long as the block runs."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    proc = subprocess.Popen([binary("AIRLOX_SERVER_BIN", "airlox-server"), "--data", str(data),
                             "--listen", f"127.0.0.1:{port}"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    url = f"http://127.0.0.1:{port}"
    try:
        for _ in range(200):
            try:
                if httpx.get(url + "/v1/health").status_code == 200:
                    break
            except httpx.TransportError:
                time.sleep(0.05)
        else:
            raise RuntimeError("relay did not start: " + proc.stderr.read().decode())
        yield url
    finally:
        proc.terminate()
        proc.wait(timeout=10)


class Runners:
    """Starts `airlox runner join` processes and stops them on exit. Called as
    ``start(invite, name, *flags)``, like the test suite's runner fixture."""

    def __init__(self, cache: pathlib.Path) -> None:
        self.cache = cache
        self.procs = []

    def __call__(self, invite: str, name: str, *flags: str) -> subprocess.Popen:
        cache = self.cache / name  # each its own, as on separate machines
        cache.mkdir(parents=True, exist_ok=True)
        if "--sandbox" not in flags:
            flags = ("--sandbox", os.environ.get("AIRLOX_SANDBOX", "local"), *flags)
        args = [binary("AIRLOX_BIN", "airlox"), "runner", "join", "--name", name,
                "--cache-dir", str(cache), *flags]
        log = (self.cache / f"{name}.log").open("w")
        proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=log, env=dict(os.environ, AIRLOX_INVITE=invite))
        self.procs.append(proc)
        return proc

    def __enter__(self) -> "Runners":
        return self

    def __exit__(self, exc_type, *exc) -> None:
        for p in self.procs:
            p.terminate()
        if exc_type is not None:  # show what the runners said
            for log in sorted(self.cache.glob("*.log")):
                print(f"--- {log.name}\n" + log.read_text()[-2000:], file=sys.stderr)
        for p in self.procs:
            try:
                p.wait(timeout=20)
            except subprocess.TimeoutExpired:
                p.kill()


def wait_for_runner(session: Session, name: str, approved: bool = False, timeout: float = 120.0):
    """Wait until runner ``name`` is online (and approved, if asked)."""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        for r in session.runners():
            if r.name == name and r.online and (r.approved or not approved):
                return r
        time.sleep(0.25)
    raise TimeoutError(f"runner {name} did not come online")


class McpTools:
    """`airlox mcp` driven through the official MCP Python SDK, as a chat app
    or IDE would. ``await tools.call(name, **args)`` returns the tool's JSON."""

    def __init__(self, session) -> None:
        self.session = session

    async def call(self, name: str, **args):
        r = await self.session.call_tool(name, args)
        text = r.content[0].text
        if r.is_error:
            raise RuntimeError(f"{name}: {text}")
        return json.loads(text)


@contextlib.asynccontextmanager
async def mcp_server(*flags: str, cwd: pathlib.Path, env: dict = None):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(command=binary("AIRLOX_BIN", "airlox"), args=["mcp", *flags], cwd=str(cwd),
                                   env={**os.environ, **(env or {})})
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        yield McpTools(session)


def quiet(*args, **kw) -> None:
    pass


def say(actor: str, text: str, code: str = None, *, out: str = None, observe: str = None) -> None:
    """A scenario's progress: who does what, and the call or command it uses.
    ``observe`` carries an observer link for watching the session in a
    browser (the demo recorder opens it); it is not printed."""
    lines = [f"[{actor}] {text}"] + [f"    {c}" for c in (code or "").splitlines()]
    lines += [f"    = {o}" for o in (out or "").splitlines()]
    print("\n".join(lines), file=sys.stderr, flush=True)


def main(scenario) -> None:
    """Run ``scenario(relay, start_runner, workdir, step)`` against the relay named
    on the command line, else a local `airlox-server` if there is one, else
    https://airlox.app, and print what it returns."""
    relay = sys.argv[1] if len(sys.argv) > 1 else None
    if relay is None and not (os.environ.get("AIRLOX_SERVER_BIN") or shutil.which("airlox-server")):
        relay = "https://airlox.app"
    with tempfile.TemporaryDirectory(prefix="airlox-example-") as tmp:
        tmp = pathlib.Path(tmp)
        print("relay:", relay or "local", file=sys.stderr)
        with contextlib.ExitStack() as stack:
            if relay is None:
                relay = stack.enter_context(local_relay(tmp / "relay"))
            runners = stack.enter_context(Runners(tmp / "runners"))
            result = scenario(relay, runners, tmp / "work", say)
        print(json.dumps(result, indent=2, default=str))
