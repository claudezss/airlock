"""Code review handoff: an IDE agent asks a review bot elsewhere to check a change.

    python examples/code-review/run.py [relay-url]    # default: starts a local relay

- The author is an agent in a chat app or IDE using the `airlox mcp` server
  (driven here through the MCP Python SDK). It creates the session, sends
  the changed file and asks for a review.
- The reviewer is a headless bot on another machine using the Python SDK. It
  reviews every .py file it receives and replies with a Markdown report.
- A tech lead follows the thread with the observer link (read only).

The relay only ever sees ciphertext; every participant verifies who wrote what.
"""

import ast
import asyncio
import pathlib
import sys
import threading

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from _local import main, mcp_server, quiet  # noqa: E402

from airlox import Session  # noqa: E402

PATCH = '''\
import subprocess


def apply_discount(order, expr):
    """Apply a discount rule such as "total * 0.9" to an order."""
    return eval(expr, {}, {"total": order["total"]})


def export(order, path):
    subprocess.run(f"cp {order['invoice']} {path}", shell=True, check=True)
'''

RISKY_CALLS = {"eval", "exec", "pickle.loads", "yaml.load", "os.system"}


def review(source: str) -> list:
    """Findings as (line, message): risky calls and shell=True."""
    findings = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        name = ast.unparse(node.func)
        if name in RISKY_CALLS:
            findings.append((node.lineno, f"`{name}` on caller-controlled input"))
        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                findings.append((node.lineno, f"`{name}(..., shell=True)` allows shell injection"))
    return sorted(findings)


def review_bot(invite: str, cache: pathlib.Path, ready: threading.Event, step=quiet, timeout: float = 120) -> None:
    """The reviewer: answers the first .py file sent to it, then leaves."""
    step("review-bot", "Joins with the sender link, on another machine",
         'Session.join(invite, display_name="review-bot",\n             description="Reviews Python changes …")')
    bot = Session.join(invite, display_name="review-bot", cache_dir=cache,
                       description="Reviews Python changes for injection risks; send a .py file")
    ready.set()
    for item in bot.stream(timeout=timeout):
        if item.kind != "file" or not item.name.endswith(".py") or item.mine:
            continue
        findings = review(item.body.decode())
        verdict = "changes requested" if findings else "approved"
        step("review-bot", f"Reviews {item.name} and replies", f'send_file("review-{item.name[:-3]}.md", refs=[item.ref])\n'
             f'send_text("{verdict}: {len(findings)} finding(s)")')
        report = [f"# Review of {item.name}", ""]
        report += [f"- line {line}: {msg}" for line, msg in findings] or ["No findings."]
        bot.send_file("\n".join(report).encode() + b"\n", name=f"review-{item.name[:-3]}.md", refs=[item.ref])
        bot.send_text(f"{verdict}: {len(findings)} finding(s) in {item.name}", refs=[item.ref])
        return


async def author(relay: str, workdir: pathlib.Path, step=quiet) -> dict:
    """The IDE agent, through the MCP tools a model would call."""
    repo = workdir / "repo"  # the only directory the MCP tools may touch
    (repo / "billing").mkdir(parents=True)
    (repo / "billing" / "discounts.py").write_text(PATCH)
    cache = workdir / "cache"
    async with mcp_server("--relay", relay, "--allow-dir", str(repo), "--cache-dir", str(cache / "ide"),
                          "--as", "ide-agent", cwd=repo) as tools:
        step("ide-agent", "Creates a session through the airlox MCP server",
             'create_session(ttl_minutes=30, description="Working on the billing service")')
        s = await tools.call("create_session", ttl_minutes=30,
                             description="Working on the billing service")
        invites = s["invites"]

        # Hand the sender link to the reviewer and the observer link to the lead.
        step("ide-agent", "Shares the sender link with the reviewer, the observer link with the lead",
             "invites → sender, observer  (the owner link never reaches the model)", observe=invites["observer"])
        ready = threading.Event()
        bot = threading.Thread(target=review_bot, args=(invites["sender"], cache / "bot", ready, step), daemon=True)
        bot.start()
        ready.wait(30)
        lead = Session.join(invites["observer"], display_name="tech-lead", cache_dir=cache / "lead")

        step("ide-agent", "Sends the changed file and asks for a review",
             'send_file(path="billing/discounts.py")\nsend_text("Please review … before I merge it.")')
        await tools.call("send_file", path="billing/discounts.py")
        await tools.call("send_text", text="Please review billing/discounts.py before I merge it.")

        # Wait for the verdict, as a model would: list_items with after/wait_s.
        after, verdict, report_id = None, None, None
        while verdict is None:
            listed = await tools.call("list_items", wait_s=30, **({"after": after} if after is not None else {}))
            after = listed["next_after"]
            for i in listed["items"]:
                if i["author_name"] != "review-bot":
                    continue
                if i["kind"] == "file":
                    report_id = i["id"]
                elif i["kind"] == "text":
                    verdict = i["text"]
        saved = await tools.call("save_file", item=report_id, dir="reviews")
        step("ide-agent", "Reads the verdict and saves the report", 'list_items(wait_s=30)\nsave_file(item=…, dir="reviews")',
             out=f"{verdict}\nreviews/{pathlib.Path(saved['saved']).name}")
        bot.join(10)

        lead.sync()
        thread = [(i.author_name, i.kind, i.text or i.name) for i in lead.items() if i.kind in ("text", "file")]
        step("ide-agent", "Closes the session; the relay purges it", "close_session()")
        await tools.call("close_session")
        return {
            "verdict": verdict,
            "report": pathlib.Path(saved["saved"]).read_text(),
            "saved_as": saved["saved"],
            "seen_by_lead": thread,
        }


def scenario(relay: str, start_runner, workdir: pathlib.Path, step=quiet) -> dict:
    return asyncio.run(author(relay, workdir, step))


if __name__ == "__main__":
    main(scenario)
