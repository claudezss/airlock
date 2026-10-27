"""Count words in this job's shard: every .txt under shard/. Runs on a runner."""

import collections
import json
import os
import pathlib
import re

counts = collections.Counter()
for f in sorted(pathlib.Path("shard").glob("*.txt")):
    counts.update(re.findall(r"[a-z']+", f.read_text().lower()))

with open(os.path.join(os.environ.get("AIRLOX_OUT", "/out"), "counts.json"), "w") as out:
    json.dump(counts, out)
print(f"{sum(counts.values())} words, {len(counts)} distinct")
