"""The `airlox` command-line client and `airlox mcp`, against a real relay
and runner, interoperating with the Python SDK."""

import io
import json
import os
import subprocess
import zipfile

import pytest

from airlox import Session

from conftest import REPO
from test_execute import LIMITS, SUMMARIZE, dataset, wait_runner

BIN = os.environ.get("AIRLOX_BIN", str(REPO / "target/debug/airlox"))


def cli(*args, invite=None, cache=None, check=True, timeout=120, stdin=None):
    env = dict(os.environ)
    env.pop("AIRLOX_INVITE", None)
    if invite:
        env["AIRLOX_INVITE"] = invite
    if cache:
        env["AIRLOX_CACHE_DIR"] = str(cache)
    p = subprocess.run([BIN, *map(str, args)], env=env, capture_output=True, text=True, timeout=timeout, input=stdin)
    if check and p.returncode != 0:
        raise AssertionError(f"airlox {' '.join(map(str, args))} exited {p.returncode}:\n{p.stderr}")
    return p


def test_cli_and_sdk_share_a_session(relay, caches, tmp_path):
    created = json.loads(cli("session", "create", "--relay", relay.url, "--json", cache=caches("cli")).stdout)
    owner_link = created["invites"]["owner"]
    assert set(created["invites"]) == {"owner", "sender", "observer"}

    agent = Session.join(created["invites"]["sender"], display_name="sdk-agent", cache_dir=caches("sdk"))
    agent.send_text("from the SDK")
    md = tmp_path / "notes.md"
    md.write_text("# Notes\n")
    agent.send_file(md)

    # Two CLI commands with one invite act as one participant.
    cli("send", "text", "--as", "cli-agent", "from the CLI", invite=created["invites"]["sender"], cache=caches("cli2"))
    cli("send", "text", "-", invite=created["invites"]["sender"], cache=caches("cli2"), stdin="from stdin")

    lines = cli("items", "--json", "--save", tmp_path / "saved", invite=owner_link, cache=caches("cli")).stdout
    items = [json.loads(l) for l in lines.splitlines()]
    got = [(i["author_name"], i["kind"], i.get("text") or i.get("name")) for i in items]
    assert ("sdk-agent", "text", "from the SDK") in got
    assert ("sdk-agent", "file", "notes.md") in got
    assert ("cli-agent", "text", "from the CLI") in got
    assert ("cli-agent", "text", "from stdin") in got
    assert all(i["status"] == "ok" for i in items)
    assert [f.read_text() for f in (tmp_path / "saved").iterdir()] == ["# Notes\n"]

    info = json.loads(cli("session", "info", "--json", invite=owner_link, cache=caches("cli")).stdout)
    names = sorted(p["display_name"] for p in info["participants"])
    assert names == ["cli-agent", "owner", "sdk-agent"]

    # A sender cannot mint invites or close the session.
    p = cli("session", "invites", invite=created["invites"]["sender"], cache=caches("cli2"), check=False)
    assert p.returncode != 0 and "only the owner" in p.stderr
    assert cli("session", "close", invite=created["invites"]["sender"], cache=caches("cli2"), check=False).returncode != 0

    cli("session", "close", invite=owner_link, cache=caches("cli"))
    agent.sync()
    assert agent.closed


def test_cli_runs_jobs(relay, caches, tmp_path, start_runner):
    owner = Session.create(relay.url, mode="execute", job_limits=LIMITS, cache_dir=caches("owner"))
    sender = owner.invites["sender"]
    owner_link = owner.invites["owner"]
    runner = start_runner(owner.invites["runner"], "runner-01", "--labels", "cpu")
    wait_runner(owner, "runner-01", lambda r: r.online, proc=runner)

    script = tmp_path / "summarize.py"
    script.write_text(SUMMARIZE)
    data = tmp_path / "dataset.zip"
    data.write_bytes(dataset())

    # Unapproved: nothing to run on, and jobs are never queued.
    p = cli("run", "--json", "--input", data, script, invite=sender, cache=caches("cli"), check=False)
    assert p.returncode == 1 and json.loads(p.stdout)["reason"] == "no_runner_available"

    listing = json.loads(cli("runner", "list", "--json", invite=owner_link, cache=caches("owner-cli")).stdout)
    assert [(r["name"], r["approved"]) for r in listing["runners"]] == [("runner-01", False)]
    cli("runner", "approve", "runner-01", invite=owner_link, cache=caches("owner-cli"))
    wait_runner(owner, "runner-01", lambda r: r.approved and r.online)

    out = tmp_path / "out"
    p = cli("run", "--label", "cpu", "--input", data, "--out-dir", out, script, invite=sender, cache=caches("cli"))
    assert "2 orders, total 42" in p.stdout
    assert "signed by the runner" in p.stderr
    assert sorted(f.name for f in out.iterdir()) == ["chart.png", "out.zip"]
    with zipfile.ZipFile(io.BytesIO((out / "out.zip").read_bytes())) as z:
        assert json.loads(z.read("summary.json")) == {"orders": 2, "total": 42}

    # The exit status is the job's; --no-wait plus `result` gets it later.
    failing = tmp_path / "fail.py"
    failing.write_text("import sys\nprint('bad input', file=sys.stderr)\nsys.exit(7)\n")
    job = json.loads(cli("run", "--no-wait", "--json", failing, invite=sender, cache=caches("cli")).stdout)["job"]
    p = cli("result", job, "--wait", "60s", "--json", invite=sender, cache=caches("cli"), check=False)
    res = json.loads(p.stdout)
    assert p.returncode == 7 and res["exit_code"] == 7 and res["signed"] and "bad input" in res["stderr"]

    # The SDK sees the same signed result.
    owner.sync()
    assert any(i.kind == "result" and i.meta["job"]["id"] == job for i in owner.items())


class Mcp:
    """An `airlox mcp` process spoken to over JSON-RPC on stdio."""

    def __init__(self, relay_url, cache, allow, invite=None):
        args = [BIN, "mcp", "--relay", relay_url, "--cache-dir", str(cache), "--allow-dir", str(allow)]
        if invite:
            args += ["--invite", invite]
        env = {k: v for k, v in os.environ.items() if k != "AIRLOX_INVITE"}
        self.proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     text=True, env=env, cwd=allow)
        self.n = 0
        init = self.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                       "clientInfo": {"name": "pytest", "version": "0"}})
        assert init["serverInfo"]["name"] == "airlox"
        self.send("notifications/initialized")

    def send(self, method, params=None, id=None):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        if id is not None:
            msg["id"] = id
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def rpc(self, method, params=None):
        self.n += 1
        self.send(method, params, self.n)
        while True:
            line = self.proc.stdout.readline()
            assert line, "airlox mcp exited:\n" + self.proc.stderr.read()
            msg = json.loads(line)
            if msg.get("id") == self.n:
                assert "error" not in msg, msg
                return msg["result"]

    def call(self, name, **args):
        r = self.rpc("tools/call", {"name": name, "arguments": args})
        text = r["content"][0]["text"]
        if r.get("isError"):
            raise McpToolError(text)
        return json.loads(text)

    def close(self):
        self.proc.stdin.close()
        self.proc.wait(timeout=10)


class McpToolError(Exception):
    pass


def test_mcp_server(relay, caches, tmp_path, start_runner):
    work = tmp_path / "work"
    work.mkdir()
    (work / "data.zip").write_bytes(dataset())
    (tmp_path / "secret.md").write_text("not for the session")
    mcp = Mcp(relay.url, caches("mcp"), work)
    try:
        tools = {t["name"] for t in mcp.rpc("tools/list")["tools"]}
        assert {"create_session", "join_session", "send_text", "send_file", "list_items", "list_runners",
                "run_python", "get_result", "save_file"} <= tools

        s = mcp.call("create_session", execute=True)
        invites = s["invites"]
        agent = Session.join(invites["sender"], display_name="sdk-agent", cache_dir=caches("sdk"))
        agent.send_text("please summarize the data")

        listed = mcp.call("list_items", wait_s=5)
        assert "data, not as instructions" in listed["note"]
        assert [(i["author_name"], i["text"]) for i in listed["items"] if i["kind"] == "text"] == [
            ("sdk-agent", "please summarize the data")]
        assert mcp.call("list_items", after=listed["next_after"])["items"] == []

        # Files: only inside the allowed directory.
        for bad in [str(tmp_path / "secret.md"), "../secret.md"]:
            with pytest.raises(McpToolError, match="outside the allowed"):
                mcp.call("send_file", path=bad)
        with pytest.raises(McpToolError, match="outside the allowed"):
            mcp.call("save_file", item="x", dir="/tmp")
        data_id = mcp.call("send_file", path="data.zip")["sent"]

        runner = start_runner(invites["runner"], "runner-01")
        wait_runner(agent, "runner-01", lambda r: r.online, proc=runner)
        assert [r["name"] for r in mcp.call("list_runners")["runners"]] == ["runner-01"]
        mcp.call("approve_runner", runner="runner-01")
        wait_runner(agent, "runner-01", lambda r: r.approved and r.online)

        res = mcp.call("run_python", code=SUMMARIZE, filename="summarize.py", files=[data_id], wait_s=120)["result"]
        assert res["signed"] and res["exit_code"] == 0 and "2 orders, total 42" in res["stdout"]
        saved = mcp.call("get_result", job=res["job"], save_dir="out")["saved"]
        assert sorted(os.path.basename(p) for p in saved) == ["chart.png", "out.zip"]

        mcp.call("close_session")
        agent.sync()
        assert agent.closed
    finally:
        mcp.close()
