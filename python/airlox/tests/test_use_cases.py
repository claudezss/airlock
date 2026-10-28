"""The use cases in examples/, run end to end against a real relay and
runners: they are the samples in docs/use-cases.md, so this keeps them working.

The live agent and agent conversation cases call real models and run only
with AIRLOX_LIVE_AGENT=1 (AIRLOX_AGENT=claude or codex picks the live agent;
the conversation needs both, signed in).
"""

import importlib.util
import json
import os
import shutil

import pytest

from conftest import REPO


def load(name):
    spec = importlib.util.spec_from_file_location(f"example_{name.replace('-', '_')}", REPO / "examples" / name / "run.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(autouse=True)
def binaries(monkeypatch):
    monkeypatch.setenv("AIRLOX_BIN", os.environ.get("AIRLOX_BIN", str(REPO / "target/debug/airlox")))
    monkeypatch.setenv("AIRLOX_SANDBOX", os.environ.get("AIRLOX_TEST_SANDBOX", "local"))


def test_code_review_over_mcp(relay, start_runner, tmp_path):
    pytest.importorskip("mcp")
    out = load("code-review").scenario(relay.url, start_runner, tmp_path)
    assert out["verdict"] == "changes requested: 2 finding(s) in discounts.py"
    assert "line 6: `eval`" in out["report"] and "shell=True" in out["report"]
    # Saved under a fresh name inside the allowed directory, never over a file.
    assert os.path.basename(out["saved_as"]).startswith("airlox-")
    assert out["saved_as"].startswith(str(tmp_path / "repo" / "reviews"))
    # The observer saw the whole thread, each item with its verified author.
    assert [(a, k) for a, k, _ in out["seen_by_lead"]] == [
        ("ide-agent", "file"), ("ide-agent", "text"), ("review-bot", "file"), ("review-bot", "text")]


def test_remote_tests_with_the_cli(relay, start_runner, tmp_path):
    out = load("remote-tests").scenario(relay.url, start_runner, tmp_path)
    first, second = out["first"], out["second"]
    assert first["exit_code"] == 1 and first["signed"] and first["runner"] == "ci-box"
    assert first["report"]["failed"] == ["tests.test_stats.StatsTest.test_median_even"]
    assert second["exit_code"] == 0 and second["report"] == {**second["report"], "ran": 3, "failed": []}
    assert out["jobs_seen_by_owner"] == out["results_seen_by_owner"] == 2
    assert out["last_message"].startswith("stats: 3 tests pass")


def test_fan_out_across_a_runner_pool(relay, start_runner, tmp_path):
    out = load("fan-out").scenario(relay.url, start_runner, tmp_path)
    assert out["ran_on"] == ["pool-a", "pool-b"]
    assert out["rejected"] == ["gpu-fast"]
    assert out["matches_local_count"]


@pytest.mark.skipif(not os.environ.get("AIRLOX_LIVE_AGENT"), reason="calls a real model; set AIRLOX_LIVE_AGENT=1")
def test_live_agent(relay, start_runner, tmp_path):
    agent = os.environ.get("AIRLOX_AGENT", "claude")
    if not shutil.which(agent):
        pytest.skip(f"{agent} is not installed")
    steps = []

    def step(actor, text, code=None, *, out=None, observe=None):
        steps.append("\n".join(filter(None, [f"[{actor}] {text}", code, out and f"= {out}"])))

    out = load("live-agent").scenario(relay.url, start_runner, tmp_path, step)
    # On failure, the whole run: every tool call the agent made and what it said.
    transcript = "\n".join(steps) + "\n" + json.dumps(out, indent=1)
    assert out["agent_exit"] == 0, transcript
    # The agent did the work on the runner, not in its head.
    assert out["jobs_by_agent"] >= 1 and 0 in out["signed_results"], transcript
    assert out["answer"] == out["expected"], transcript


@pytest.mark.skipif(not os.environ.get("AIRLOX_LIVE_AGENT"), reason="calls real models; set AIRLOX_LIVE_AGENT=1")
def test_agent_conversation(relay, start_runner, tmp_path):
    if not (shutil.which("claude") and shutil.which("codex")):
        pytest.skip("needs both claude and codex")
    out = load("agent-conversation").scenario(relay.url, start_runner, tmp_path)
    transcript = json.dumps(out, indent=1)
    # Each agent was woken by its listener and spoke as itself, one participant each.
    assert out["participants"] == ["claude-agent", "codex-agent", "lead"], transcript
    assert out["summary"], transcript
    # Claude asked Codex by address, and Codex answered Claude.
    assert any(who == "claude-agent" and "codex-agent" in to for who, to, _ in out["thread"]), transcript
    assert any(who == "codex-agent" and "claude-agent" in to for who, to, _ in out["thread"]), transcript
