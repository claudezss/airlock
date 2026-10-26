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
        binary = os.environ.get("AIRLOCK_SERVER_BIN", str(REPO / "target/debug/airlock-server"))
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
