"""Summarize orders by region: the M2 execute-mode scenario.

Runs on an Airlock runner. Inputs arrive in the work dir (dataset.zip is
unpacked there); files written to $AIRLOCK_OUT come back as out files.
"""

import os
import socket

import matplotlib.pyplot as plt
import pandas as pd

out = os.environ.get("AIRLOCK_OUT", "/out")

orders = pd.read_csv("dataset/orders.csv")
by_region = orders.groupby("region")["total"].agg(["count", "sum"]).sort_values("sum", ascending=False)
print(by_region.to_string())

ax = by_region["sum"].plot.bar(title="Revenue by region")
ax.set_ylabel("total")
plt.tight_layout()
plt.savefig(os.path.join(out, "chart.png"))
by_region.to_csv(os.path.join(out, "by_region.csv"))

# Sessions run with the network off; show that it really is.
try:
    socket.create_connection(("1.1.1.1", 53), timeout=2)
    print("network: reachable")
except OSError as e:
    print(f"network: blocked ({e.__class__.__name__})")
