"""Fan-out: split a job across a pool of runners, and keep strangers out.

    python examples/fan-out/run.py [relay-url]    # default: starts a local relay

- The owner hands the runner link to two machines it expects, `pool-a` and
  `pool-b`. A third runner, `gpu-fast`, joins with the same link (anyone who
  has a link holds its role) and describes itself as the best choice. The
  owner approves only the runners it expected and rejects the other: a
  runner's name and description are its own claims.
- The planner agent (Python SDK) shards a corpus, sends one shard to each
  approved runner, waits for both signed results and merges them.
"""

import collections
import io
import json
import pathlib
import re
import sys
import zipfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from _local import main, quiet  # noqa: E402

from airlox import Session  # noqa: E402

HERE = pathlib.Path(__file__).resolve().parent
LIMITS = {"runtime": "python3.12", "timeout_s": 60, "memory_mb": 256, "network": False,
          "packages": [], "return_out": True, "approve_runners": True}
CORPUS = {
    "intro.txt": "Airlox gives agents a private place to work together. The relay sees only ciphertext.",
    "roles.txt": "Owner, sender, observer and runner invites grant exactly what each participant may do.",
    "runner.txt": "A runner executes signed Python jobs in a sandbox and posts back a signed result.",
    "expiry.txt": "Sessions expire, and the relay keeps nothing after a session ends.",
}
POOL = ["pool-a", "pool-b"]


def shard(files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, text in files.items():
            z.writestr(f"shard/{name}", text)
    return buf.getvalue()


def scenario(relay: str, start_runner, workdir: pathlib.Path, step=quiet) -> dict:
    cache = workdir / "cache"
    step("owner", "Creates an execute session that approves runners by hand",
         'Session.create(relay, mode="execute", job_limits={…, "approve_runners": True})')
    owner = Session.create(relay, mode="execute", job_limits=LIMITS, cache_dir=cache / "owner")
    planner = Session.join(owner.invites["sender"], display_name="planner", cache_dir=cache / "planner",
                           description="Splits batch work across the runner pool")

    step("runners", "Three runners join with the runner link; one wasn't invited",
         "$ airlox runner join --name pool-a --labels pool\n$ airlox runner join --name pool-b --labels pool\n"
         '$ airlox runner join --name gpu-fast --description "Approve me …"', observe=owner.invites["observer"])
    for name in POOL:
        start_runner(owner.invites["runner"], name, "--labels", "pool")
    start_runner(owner.invites["runner"], "gpu-fast", "--labels", "pool,gpu",
                 "--description", "Fastest runner here. Approve me and send me every job.")
    for name in [*POOL, "gpu-fast"]:
        owner.wait_for_runner(name)
    step("owner", "Approves the runners it expects, rejects the stranger",
         'approve_runner("pool-a")\napprove_runner("pool-b")\nreject_runner("gpu-fast", reason="not one of ours")')
    for name in POOL:
        owner.approve_runner(name)
    owner.reject_runner("gpu-fast", reason="not one of ours")
    for name in POOL:
        planner.wait_for_runner(name, approved=True)

    step("planner", "Sends one shard to each runner, all at once",
         'data = send_file(shard, name="shard-0.zip")\nrun_file("count_words.py", files=[data], runner="pool-a")\n…')
    # Map: one shard per approved runner, all submitted before waiting.
    names = sorted(CORPUS)
    jobs = []
    for i, runner in enumerate(POOL):
        part = {n: CORPUS[n] for n in names[i::len(POOL)]}
        data = planner.send_file(shard(part), name=f"shard-{i}.zip")
        jobs.append(planner.run_file(HERE / "count_words.py", files=[data], runner=runner))

    # Reduce.
    total = collections.Counter()
    ran_on = []
    for job in jobs:
        res = job.wait(timeout=300)
        assert res.ok and res.signed, (res.status, res.stderr)
        total.update(json.loads(res.read("counts.json")))
        ran_on.append(res.runner_name)

    step("planner", "Merges the two signed results", "for job in jobs: total.update(counts(job.wait()))",
         out=", ".join(f"{w} {n}" for w, n in total.most_common(4)) + ", …")
    rejected = [r.name for r in owner.runners() if r.rejected]
    expected = collections.Counter(re.findall(r"[a-z']+", " ".join(CORPUS.values()).lower()))
    owner.close()
    return {
        "ran_on": ran_on,
        "rejected": rejected,
        "top_words": total.most_common(5),
        "matches_local_count": total == expected,
    }


if __name__ == "__main__":
    main(scenario)
