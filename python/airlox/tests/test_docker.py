"""The M2 scenario: summarize.py with pandas and matplotlib on the docker
backend, network off. Skipped without a Docker daemon. The first run builds
the job runtime image, which needs network and takes a minute or two."""

import io
import pathlib
import shutil
import subprocess
import time
import zipfile

import pytest

from airlox import Session

from test_execute import wait_runner

EXAMPLE = pathlib.Path(__file__).resolve().parents[3] / "examples/summarize/summarize.py"


def docker_ok() -> bool:
    return shutil.which("docker") is not None and subprocess.run(
        ["docker", "version"], capture_output=True
    ).returncode == 0


pytestmark = pytest.mark.skipif(not docker_ok(), reason="needs a Docker daemon")


def test_summarize_on_docker_with_network_off(relay, caches, start_runner):
    limits = {"runtime": "python3.12", "timeout_s": 60, "memory_mb": 512, "network": False,
              "packages": ["matplotlib", "pandas"], "return_out": True, "approve_runners": True}
    owner = Session.create(relay.url, mode="execute", job_limits=limits, cache_dir=caches("owner"))
    agent = Session.join(owner.invites["sender"], display_name="planner-agent", cache_dir=caches("agent"))
    runner = start_runner(owner.invites["runner"], "docker-01", "--sandbox", "docker")
    try:
        wait_runner(owner, "docker-01", lambda r: r.online, timeout=600, proc=runner)
    except AssertionError:
        raise AssertionError(runner.output())
    owner.approve_runner("docker-01")
    wait_runner(agent, "docker-01", lambda r: r.approved)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("dataset/orders.csv", "region,total\neast,120\nwest,340\neast,60\n")
    data = agent.send_file(buf.getvalue(), name="dataset.zip")
    t0 = time.monotonic()
    res = agent.run_file(EXAMPLE, files=[data], runner="docker-01", requirements=["pandas"]).wait(timeout=180)
    assert res.ok, (res, runner.output())
    assert "west" in res.stdout and "400" not in res.stdout.split("west")[0]
    assert "network: blocked" in res.stdout, res.stdout
    assert {f.name for f in res.out_files} == {"chart.png", "out.zip"}
    assert res.out_file("chart.png").data.startswith(b"\x89PNG")
    csv = zipfile.ZipFile(io.BytesIO(res.out_file("out.zip").data)).read("by_region.csv").decode()
    assert csv.splitlines()[1].startswith("west,1,340")
    print(f"summarize.py on docker: {res.wall_ms} ms in the sandbox, {time.monotonic() - t0:.1f} s end to end")

    # Container limits hold: no network, no writes outside /work, /out, /meta and /tmp.
    probe = (
        "import os\n"
        "try:\n    open('/usr/x', 'w')\n    print('rootfs: writable')\n"
        "except OSError:\n    print('rootfs: read-only')\n"
        "print('uid', os.getuid())\n"
    )
    res = agent.run_python(probe, runner="docker-01").wait(timeout=60)
    assert "rootfs: read-only" in res.stdout and "uid 0" not in res.stdout, res
