"""Run the unpacked project's unittest suite on the runner.

Writes report.json to $AIRLOX_OUT (it comes back in out.zip) and exits 1 if
any test failed, so `airlox run` exits the same way.
"""

import json
import os
import sys
import unittest

suite = unittest.defaultTestLoader.discover("project", top_level_dir="project")
result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(suite)

report = {
    "python": sys.version.split()[0],
    "ran": result.testsRun,
    "failed": [t.id() for t, _ in result.failures + result.errors],
}
with open(os.path.join(os.environ.get("AIRLOX_OUT", "/out"), "report.json"), "w") as f:
    json.dump(report, f, indent=2)
sys.exit(0 if result.wasSuccessful() else 1)
