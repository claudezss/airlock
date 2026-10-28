"""Record the use cases as GIFs for the landing page (web/demos/), each with
a still of its last frame.

    make web server runner
    .venv/bin/pip install playwright pillow    # uses your installed Chrome
    PATH="$PWD/target/debug:$PATH" .venv/bin/python examples/record_demos.py [name ...]

Each GIF is a real run against a local relay: on the left, what each
participant does (the scenario's steps, and for the live agent its actual
tool calls); on the right, the session's web UI opened with the observer
link, updating as items arrive. The live agent needs `codex` (or set
AIRLOX_AGENT=claude), the agent conversation both `claude` and `codex`; each
is recorded only when its agents are installed.
"""

import argparse
import contextlib
import hashlib
import html
import importlib.util
import io
import json
import os
import pathlib
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time

from PIL import Image
from playwright.sync_api import sync_playwright

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from _local import Runners, local_relay  # noqa: E402

W, H, LEFT = 1280, 720, 470
FPS = 6
MAX_STILL_S = 2.2  # a stretch with nothing changing (a runner building, a model thinking) is cut to this

DEMOS = {
    "code-review": ("Code review handoff", "IDE agent (MCP) → review bot (SDK)",
                    {"ide-agent": "accent", "review-bot": "link"}),
    "remote-tests": ("Remote CI", "Coding agent (CLI) → someone else's build box",
                     {"coding-agent": "accent", "ci-box": "ok", "team-lead": "soft"}),
    "fan-out": ("Fan-out", "Planner (SDK) → a pool of approved runners",
                {"planner": "accent", "runners": "ok", "owner": "soft"}),
    "live-agent": ("Live agent", "A real coding agent picks up a task and runs it on a runner",
                   {"codex": "link", "claude": "link", "analysis-box": "ok", "data-team": "accent"}),
    "agent-conversation": ("Agent conversation", "Claude Code and Codex, each woken by airlox listen",
                           {"lead": "accent", "claude-agent": "link", "codex-agent": "ok"}),
}
# Demos that call real models, and the agents each needs installed.
NEEDS = {"live-agent": lambda: [os.environ["AIRLOX_AGENT"]], "agent-conversation": lambda: ["claude", "codex"]}

PAGE = """<!doctype html><html><head><meta charset="utf-8"><style>
:root { --bg:#0f1113; --panel:#16191c; --raised:#1c2024; --line:#2a2f35; --text:#ecebe4; --muted:#a3a8ae;
  --soft:#c9b8f5; --accent:#f2a93b; --link:#78b8ff; --ok:#7fd99a; --mono: ui-monospace, "SF Mono", Menlo, monospace; }
* { box-sizing: border-box; }
body { margin:0; width:%(w)dpx; height:%(h)dpx; background:var(--bg); color:var(--text);
  font:14px/1.45 system-ui, -apple-system, sans-serif; display:flex; flex-direction:column; overflow:hidden; }
header { padding:18px 22px 14px; border-bottom:1px solid var(--line); }
.brand { display:flex; align-items:center; gap:8px; font-weight:700; color:var(--accent); font-size:13px;
  font-family:var(--mono); letter-spacing:.08em; text-transform:uppercase; }
h1 { margin:8px 0 2px; font-size:22px; letter-spacing:-.01em; }
.sub { color:var(--muted); font-size:13px; }
#steps { flex:1; overflow:hidden; padding:14px 18px; display:flex; flex-direction:column; gap:10px;
  justify-content:flex-start; }
.step { background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:10px 12px;
  opacity:.5; transition:none; flex:none; }
.step.now { opacity:1; border-color:#4a3b22; background:#1a1712; }
.who { font-family:var(--mono); font-size:12px; font-weight:600; }
.what { margin-left:6px; }
pre { margin:6px 0 0; font:12px/1.5 var(--mono); color:#d8d6d0; white-space:pre-wrap; word-break:break-word; }
pre.out { color:var(--ok); }
footer { padding:10px 22px; border-top:1px solid var(--line); color:var(--muted); font:12px var(--mono);
  display:flex; justify-content:space-between; }
.accent { color:var(--accent); } .link { color:var(--link); } .ok { color:var(--ok); } .soft { color:var(--soft); }
</style></head><body>
<header><div class="brand">Airlox · real run</div><h1>%(title)s</h1><div class="sub">%(sub)s</div></header>
<div id="steps"></div>
<footer><span>right: the live session, as an observer</span><span id="n"></span></footer>
<script>
function add(cls, who, what, code, out) {
  const box = document.getElementById("steps");
  for (const s of box.children) s.classList.remove("now");
  const d = document.createElement("div"); d.className = "step now";
  d.innerHTML = `<span class="who ${cls}">${who}</span><span class="what">${what}</span>` +
    (code ? `<pre>${code}</pre>` : "") + (out ? `<pre class="out">${out}</pre>` : "");
  box.appendChild(d);
  while (box.scrollHeight > box.clientHeight && box.children.length > 1) box.removeChild(box.firstChild);
  document.getElementById("n").textContent = "step " + (++window.count);
}
window.count = 0;
</script></body></html>"""

WAITING = """<!doctype html><body style="margin:0;background:#0f1113;color:#a3a8ae;font:15px system-ui;
display:flex;align-items:center;justify-content:center;height:100vh">the session opens here</body>"""


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), HERE / name / "run.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def dwell(code, out) -> float:
    lines = len((code or "").splitlines()) + len((out or "").splitlines())
    return min(1.6 + 0.3 * lines, 4.0)


def record(name: str, relay: str, tmp: pathlib.Path, out_dir: pathlib.Path, browser) -> pathlib.Path:
    title, sub, colors = DEMOS[name]
    events = queue.Queue()

    def step(actor, text, code=None, *, out=None, observe=None):
        events.put((actor, text, code, out, observe))
        time.sleep(dwell(code, out))

    narration = browser.new_page(viewport={"width": LEFT, "height": H})
    narration.set_content(PAGE % {"w": LEFT, "h": H, "title": html.escape(title), "sub": html.escape(sub)})
    ui = browser.new_page(viewport={"width": W - LEFT - 1, "height": H})
    ui.set_content(WAITING)

    result, error = {}, []

    def run():
        try:
            with Runners(tmp / "runners") as runners:
                result.update(load(name).scenario(relay, runners, tmp / "work", step))
        except BaseException as e:  # reported after recording
            error.append(e)

    frames = []  # (png bytes, seconds shown)
    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    last = time.monotonic()
    while worker.is_alive() or not events.empty():
        while not events.empty():
            actor, text, code, out, observe = events.get()
            e = lambda s: json.dumps(html.escape(s or ""))  # noqa: E731
            narration.evaluate(f"add({json.dumps(colors.get(actor, 'soft'))}, {e(actor)}, {e(text)}, {e(code)}, {e(out)})")
            if observe:
                ui.goto(observe)
        frame = Image.new("RGB", (W, H), (42, 47, 53))
        frame.paste(Image.open(io.BytesIO(narration.screenshot())), (0, 0))
        try:
            frame.paste(Image.open(io.BytesIO(ui.screenshot())), (LEFT + 1, 0))
        except Exception:  # mid-navigation: keep the previous right half
            if frames:
                frame.paste(Image.open(io.BytesIO(frames[-1][0])).crop((LEFT + 1, 0, W, H)), (LEFT + 1, 0))
        now = time.monotonic()
        if frames:
            frames[-1][1] += now - last
        buf = io.BytesIO()
        frame.save(buf, "PNG")
        frames.append([buf.getvalue(), 0.0])
        last = now
        time.sleep(max(0.0, 1 / FPS - (time.monotonic() - now)))
    frames[-1][1] = 4.0  # hold the end
    narration.close()
    ui.close()
    if error:
        raise error[0]
    return encode(name, frames, tmp, out_dir)


def encode(name, frames, tmp, out_dir) -> pathlib.Path:
    # Merge identical frames, cap still stretches, then one palette for the whole GIF.
    merged = []
    for png, secs in frames:
        digest = hashlib.sha256(Image.open(io.BytesIO(png)).tobytes()).digest()
        if merged and merged[-1][0] == digest:
            merged[-1][2] += secs
        else:
            merged.append([digest, png, secs])
    seq = tmp / f"{name}-frames"
    seq.mkdir()
    lines = []
    for i, (_, png, secs) in enumerate(merged):
        (seq / f"{i:05d}.png").write_bytes(png)
        hold = 4.0 if i == len(merged) - 1 else min(secs, MAX_STILL_S)
        lines += [f"file '{seq / f'{i:05d}.png'}'", f"duration {max(hold, 0.05):.3f}"]
    lines.append(f"file '{seq / f'{len(merged) - 1:05d}.png'}'")
    (seq / "list.txt").write_text("\n".join(lines) + "\n")
    # A still of the end, for readers who prefer reduced motion.
    Image.open(io.BytesIO(merged[-1][1])).save(out_dir / f"{name}.webp", quality=80)
    out = out_dir / f"{name}.gif"
    graph = ("[0:v]split[a][b];[a]palettegen=max_colors=96:stats_mode=diff[p];"
             "[b][p]paletteuse=dither=none:diff_mode=rectangle")
    subprocess.run(["ffmpeg", "-loglevel", "error", "-y", "-f", "concat", "-safe", "0", "-i", str(seq / "list.txt"),
                    "-filter_complex", graph, "-loop", "0", str(out)], check=True)
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("names", nargs="*", default=list(DEMOS))
    ap.add_argument("--out", type=pathlib.Path, default=HERE.parent / "web" / "demos")
    a = ap.parse_args()
    os.environ.setdefault("AIRLOX_AGENT", "codex")
    names = [n for n in a.names if all(shutil.which(x) for x in NEEDS.get(n, list)())]
    a.out.mkdir(parents=True, exist_ok=True)
    # Under /tmp: paths can show in the recordings (a traceback in job output).
    with tempfile.TemporaryDirectory(prefix="airlox-demos-", dir="/tmp") as tmp, sync_playwright() as p:
        tmp = pathlib.Path(tmp)
        browser = p.chromium.launch(channel="chrome")
        for name in names:
            with contextlib.ExitStack() as stack:
                relay = stack.enter_context(local_relay(tmp / name / "relay"))
                path = record(name, relay, tmp / name, a.out, browser)
            print(f"{path}  {path.stat().st_size / 1e6:.1f} MB", file=sys.stderr)
        browser.close()


if __name__ == "__main__":
    main()
