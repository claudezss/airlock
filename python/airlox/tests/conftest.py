import os
import pathlib
import socket
import subprocess
import time

import httpx
import pytest

REPO = pathlib.Path(__file__).resolve().parents[3]


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Relay:
    def __init__(self, data: pathlib.Path, **flags) -> None:
        self.data = data
        self.flags = flags
        self.proc = None
        self.url = ""

    def start(self) -> "Relay":
        binary = os.environ.get("AIRLOX_SERVER_BIN", str(REPO / "target/debug/airlox-server"))
        port = _free_port()
        args = [binary, "--data", str(self.data), "--listen", f"127.0.0.1:{port}",
                "--sweep-interval", "50ms", "--blob-grace", "200ms"]
        for k, v in self.flags.items():
            args += [f"--{k.replace('_', '-')}", str(v)]
        self.proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        self.url = f"http://127.0.0.1:{port}"
        for _ in range(100):
            try:
                if httpx.get(self.url + "/v1/health").status_code == 200:
                    return self
            except httpx.TransportError:
                time.sleep(0.05)
        raise RuntimeError("relay did not start: " + self.proc.stderr.read().decode())

    def stop(self) -> None:
        if self.proc:
            self.proc.terminate()
            self.proc.wait(timeout=10)
            self.proc = None

    def restart(self) -> None:
        self.stop()
        self.start()


@pytest.fixture
def relay(tmp_path):
    r = Relay(tmp_path / "relay").start()
    yield r
    r.stop()


@pytest.fixture
def caches(tmp_path):
    def make(name):
        return tmp_path / "cache" / name
    return make


class RunnerProc:
    """An `airlox runner join` process."""

    def __init__(self, invite: str, name: str, cache: pathlib.Path, *extra: str) -> None:
        binary = os.environ.get("AIRLOX_BIN", str(REPO / "target/debug/airlox"))
        sandbox = os.environ.get("AIRLOX_TEST_SANDBOX", "local")
        self.log = cache / f"{name}.log"
        cache.mkdir(parents=True, exist_ok=True)
        if "--sandbox" not in extra:
            extra = ("--sandbox", sandbox, *extra)
        args = [binary, "runner", "join", "--name", name, "--cache-dir", str(cache), *extra]
        env = dict(os.environ, AIRLOX_INVITE=invite, RUST_LOG="airlox=debug")
        self.proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=self.log.open("w"), env=env)

    def output(self) -> str:
        return self.log.read_text()

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                self.proc.kill()


@pytest.fixture(scope="session")
def runner_cache(tmp_path_factory):
    # Shared so the job runtime is built once per test run.
    return tmp_path_factory.mktemp("runner-cache")


@pytest.fixture
def start_runner(runner_cache):
    procs = []

    def start(invite, name="runner-01", *extra):
        p = RunnerProc(invite, name, runner_cache, *extra)
        procs.append(p)
        return p

    yield start
    for p in procs:
        p.stop()
