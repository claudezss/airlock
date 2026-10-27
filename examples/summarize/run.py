"""Drive the summarize scenario against a relay with one runner.

    airlox-server --data ./data &
    python examples/summarize/run.py http://127.0.0.1:8080
    # it prints a runner invite; start the runner with it:
    airlox runner join --invite '<runner invite>' --name runner-01 --sandbox docker
"""

import io
import pathlib
import sys
import zipfile

from airlox import Session

HERE = pathlib.Path(__file__).parent


def dataset() -> bytes:
    rows = ["region,total", "east,120", "west,340", "north,75", "east,60", "south,210", "west,15"]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("dataset/orders.csv", "\n".join(rows) + "\n")
    return buf.getvalue()


def main(relay: str) -> None:
    limits = {"runtime": "python3.12", "timeout_s": 120, "memory_mb": 512, "network": False,
              "packages": ["matplotlib", "pandas"], "return_out": True, "approve_runners": True}
    owner = Session.create(relay, mode="execute", job_limits=limits)
    print("runner invite:", owner.invites["runner"])
    agent = Session.join(owner.invites["sender"], display_name="planner-agent")
    print("waiting for runner-01 …")
    owner.wait_for_runner("runner-01", timeout=600)
    owner.approve_runner("runner-01")
    agent.wait_for_runner("runner-01", approved=True)
    data = agent.send_file(dataset(), name="dataset.zip")
    res = agent.run_file(HERE / "summarize.py", files=[data], runner="runner-01").wait(timeout=300)
    print(res.status, res.exit_code, f"{res.wall_ms} ms")
    print(res.stdout)
    for f in res.out_files:
        print("out:", f.name, f.size, "bytes")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080")
