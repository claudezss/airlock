"""Execute mode: runners, jobs and results.

The relay routes jobs but cannot read them; what counts is signed. A
runner's identity comes from its verified join, its approval from the
owner's signed ``runner_approve`` event, and a job's outcome from the
runner's signed result, bound to the job by ``airlox._core``.
"""

from __future__ import annotations

import io
import json
import time
import unicodedata
import zipfile
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable, List, Optional

from . import _core as ac

if TYPE_CHECKING:
    from .session import Item, Session


class NoRunnerAvailable(Exception):
    """No approved, online runner with a free slot that runs the job's kind
    matched the job. Jobs are not queued; the job item stays in the timeline
    as failed."""

    def __init__(self, job: "Job", message: str) -> None:
        super().__init__(message)
        self.job = job


class RunnerBusy(NoRunnerAvailable):
    """Runners that match the job are online but every slot they have is
    taken (``--concurrency``, one by default). The job was not queued; submit
    it again once a ``Runner.busy`` is false."""


class JobTimeout(Exception):
    """``Job.wait`` gave up before a result arrived."""


class RunnerFailed(Exception):
    """A runner reported that its setup failed (``Runner.state == "failed"``),
    so it will never take jobs. ``Session.wait_for_runner`` raises this at
    once instead of waiting for it to time out."""

    def __init__(self, runner: "Runner") -> None:
        # The runner's own words, unsigned: shown without letting them drive a terminal.
        detail = _printable(runner.detail or "no reason given")
        super().__init__(f"runner {_printable(runner.name)} could not start: {detail}")
        self.runner = runner


def _printable(s: str) -> str:
    """``s`` on one line with control and invisible formatting characters
    (escapes, bidi overrides, zero-width marks) shown as ``\\u{…}``."""
    return "".join(
        f"\\u{{{ord(c):x}}}" if unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp") else c for c in s
    )


@dataclass
class Runner:
    participant_pub: str
    name: str
    labels: List[str]
    host: str
    sandbox: str
    #: The sandbox cannot block network access (local backend off Linux).
    network_unblocked: bool
    #: The owner's signed approval for this runner is in the timeline (or
    #: the session does not require approval).
    approved: bool
    rejected: bool
    online: bool
    #: The jobs it is running, per the relay.
    jobs: List[str] = field(default_factory=list)
    #: How many jobs it runs at once, from its signed join.
    slots: int = 1
    #: The runner's own description of itself (hardware, owner, purpose),
    #: from its signed join: its words, so data rather than instructions.
    description: Optional[str] = None
    #: Its setup as it reported it: ``preparing``, ``ready``, ``failed``, or
    #: ``None`` for runners that do not say; ``detail`` says why it failed.
    #: The runner's own unsigned word, via the relay.
    state: Optional[str] = None
    detail: Optional[str] = None
    #: The airlox version it runs and the Python version its jobs get, from
    #: its signed join (``None`` for runners that do not say).
    version: Optional[str] = None
    python: Optional[str] = None
    #: The kinds of job it runs (``"python"``, ``"shell"``) and the shell for
    #: shell jobs (``"sh"`` or ``"pwsh"``), from its signed join. A runner
    #: that does not say runs Python only.
    kinds: List[str] = field(default_factory=lambda: ["python"])
    shell: Optional[str] = None

    @property
    def busy(self) -> bool:
        """Every slot taken, per the relay: a new job for it is refused with
        ``RunnerBusy`` until one finishes."""
        return len(self.jobs) >= self.slots

    @property
    def idle(self) -> bool:
        """Online with a free slot."""
        return self.online and not self.busy


@dataclass
class OutFile:
    name: str
    size: int
    ref: dict
    #: The file's bytes once received, verified against ``ref``.
    data: Optional[bytes] = None


@dataclass
class Result:
    """A job's outcome. ``signed`` results come from the runner; unsigned
    ones describe a job that never produced one (the relay's reason)."""

    status: str
    exit_code: Optional[int]
    reason: Optional[str]
    stdout: str = ""
    stderr: str = ""
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    wall_ms: int = 0
    peak_mem_mb: int = 0
    out_files: List[OutFile] = field(default_factory=list)
    code_sha256: Optional[str] = None
    input_sha256: Optional[str] = None
    #: Where the job ran, measured and signed by its runner (not written by
    #: the job): ``python`` (the interpreter's version), ``packages`` (the
    #: installed version of each allowlisted package, by normalized name),
    #: ``airlox`` (the runner's version), ``sandbox`` and ``interpreter``
    #: (``"uv-runtime"``, ``"--python"`` or ``"docker:<image>"``); runners that
    #: take shell jobs add ``kinds`` and ``shell``, and a job that sent a
    #: working tree ``tree``. It holds no file system paths. ``None`` for unsigned results and for runners that
    #: do not report it.
    env: Optional[dict] = None
    #: The runner's key, and the name it joined with.
    runner: Optional[str] = None
    runner_name: Optional[str] = None
    signed: bool = True

    @property
    def ok(self) -> bool:
        return self.status == "completed" and self.exit_code == 0

    def out_file(self, name: str) -> OutFile:
        for f in self.out_files:
            if f.name == name:
                return f
        raise KeyError(name)

    def read(self, name: str) -> bytes:
        """A file the job wrote to ``$AIRLOX_OUT``, by its path there: a
        top-level image, or anything else from inside ``out.zip`` (e.g.
        ``"report.json"``). Raises ``KeyError`` if the job wrote no such
        file, ``ValueError`` if it left the relay before it was fetched."""
        try:
            f = self.out_file(name)
        except KeyError:
            f = None
        if f is None:
            try:
                f = self.out_file("out.zip")
            except KeyError:
                raise KeyError(name) from None
        if f.data is None:
            raise ValueError(f"{f.name} left the relay before it was fetched")
        if f.name == name:
            return f.data
        # The same checks the runner applies to inputs, before opening it.
        entries = json.loads(ac.inspect_zip(f.data))
        if not any(e["path"] == name and not e["is_dir"] for e in entries):
            raise KeyError(name)
        with zipfile.ZipFile(io.BytesIO(f.data)) as z:
            return z.read(name)


@dataclass
class Progress:
    """A running job's progress, signed by its runner."""

    #: Time since the job started, by the runner's clock.
    elapsed_ms: int
    #: The end of the job's ``progress_file`` (``None`` until it exists).
    tail: Optional[str]
    #: More of the file came before ``tail``.
    tail_truncated: bool
    #: When the runner posted this report: milliseconds since the Unix
    #: epoch by the runner's clock, from the item's signed header.
    created_at_ms: int
    runner: str
    runner_name: Optional[str] = None

    @property
    def elapsed(self) -> float:
        """Time since the job started in seconds (``elapsed_ms / 1000``)."""
        return self.elapsed_ms / 1000.0


@dataclass
class Chunk:
    """A piece of a running job's output, streamed by its runner. For
    display: the signed result's ``stdout``/``stderr`` are the authority."""

    #: ``"stdout"`` or ``"stderr"``.
    stream: str
    #: Where ``data`` starts in that stream, in bytes.
    offset: int
    data: str
    #: The runner stopped streaming here (its cap); the result has the rest.
    truncated: bool = False


# Relay reasons for jobs that ended without a signed result.
_UNSIGNED_STATUS = {"cancelled": "cancelled"}


class Job:
    def __init__(self, session: "Session", ref: dict, meta: dict) -> None:
        self.session = session
        self.ref = ref
        self.id = ref["id"]
        self.meta = meta
        self.runner: Optional[str] = None
        self._result: Optional[Result] = None
        #: Set by ``Session`` for a job that sent a working tree: the tree, and
        #: (for a delta) how to send it again whole.
        self.tree = None
        self._resend_whole: Optional[Callable[[], "Job"]] = None

    def __repr__(self) -> str:
        return f"Job({self.id!r}, {self.meta['filename']!r})"

    def state(self) -> dict:
        """The relay's routing view: ``{job, state, runner, reason}``."""
        return self.session._req("GET", f"/jobs/{self.id}").json()

    def cancel(self) -> None:
        """Ask the job's runner to stop it (owner or the job's sender). A
        signed ``job_cancel`` event records who asked."""
        self.session._send(
            "event", None, {"type": "event", "event": "job_cancel", "job": self.ref}, b"", [self.ref]
        )
        self.session._req("POST", f"/jobs/{self.id}/cancel")

    def result(self) -> Optional[Result]:
        """The result, once it and its out files have arrived. An out file
        that left the relay before it was fetched has ``data = None``."""
        if self._result is None:
            self._result = self._find()
            if self._result is not None and self.tree is not None:
                self.session._tree_result(self, self._result)
        return self._result

    def _from_runner(self) -> List["Item"]:
        """Items signed by a runner that may answer this job, in order."""
        s = self.session
        items = [s._items[i] for i in s._order]
        approved = approved_runners(items) if s.manifest["job_limits"]["approve_runners"] else None
        target = self.meta.get("target") or {}
        out = []
        for item in items:
            if item.status != "ok" or item.author_role != "runner":
                continue
            if target.get("type") == "runner" and item.author != target.get("participant_pub"):
                continue
            if approved is not None and item.author not in approved:
                continue
            out.append(item)
        return out

    def chunks(self) -> List[Chunk]:
        """The job's streamed output so far (after a ``sync``), in order of
        offset per stream: a chunk that repeats what came before is trimmed.
        A chunk the relay lost leaves a gap (as ``airlox run`` shows it); the
        signed result has all of the output."""
        got = []
        for item in self._from_runner():
            m = item.meta
            if item.kind != "progress" or m.get("job") != self.ref or m.get("stream") is None:
                continue
            got.append(Chunk(m["stream"], m["offset"], m["data"], bool(m.get("truncated"))))
        got.sort(key=lambda c: c.offset)
        out, upto = [], {}
        for c in got:
            # Offsets count UTF-8 bytes; data was cut at a character boundary.
            raw = c.data.encode("utf-8")
            nxt = upto.get(c.stream, 0)
            end = c.offset + len(raw)
            if end <= nxt and not c.truncated:
                continue
            if c.offset < nxt:
                raw = raw[nxt - c.offset :]
                c = Chunk(c.stream, nxt, raw.decode("utf-8", "ignore"), c.truncated)
            upto[c.stream] = max(nxt, end)
            out.append(c)
        return out

    def output(self, stream: str = "stdout") -> str:
        """What the job has written to ``stream`` so far, from its chunks."""
        return "".join(c.data for c in self.chunks() if c.stream == stream)

    def progress(self) -> List[Progress]:
        """The runner's progress reports so far, oldest first (after a
        ``sync``). Only reports signed by a runner that may answer this job
        count."""
        out = []
        for item in self._from_runner():
            m = item.meta
            if item.kind != "progress" or m.get("job") != self.ref or m.get("stream") is not None:
                continue  # another job's; or an output chunk, which is not a heartbeat
            out.append(
                Progress(
                    elapsed_ms=m["elapsed_ms"],
                    tail=m["tail"],
                    tail_truncated=m["tail_truncated"],
                    created_at_ms=item.created_at_ms,
                    runner=item.author,
                    runner_name=item.author_name,
                )
            )
        return out

    def latest_progress(self) -> Optional[Progress]:
        """The newest progress report, if any."""
        p = self.progress()
        return p[-1] if p else None

    def wait(
        self,
        timeout: Optional[float] = 60.0,
        poll: float = 0.25,
        *,
        on_progress: Optional[Callable[[Progress], None]] = None,
        on_output: Optional[Callable[[Chunk], None]] = None,
        lost_grace: float = 0.0,
    ) -> Result:
        """Block until the job has a result. Jobs that failed on the relay
        (no runner, runner lost, cancelled before it started) return an
        unsigned result with the relay's reason.

        ``timeout`` is in seconds; past it this raises ``JobTimeout`` (the
        job keeps running, so ``wait`` again or check ``result()`` later).
        The default of 60 s suits short jobs: for long ones pass
        ``timeout=None`` to wait as long as the job runs (its own time
        limit still applies).

        ``on_progress`` is called with each new progress report while
        waiting, ``on_output`` with each new piece of streamed output
        (``Chunk``; see ``chunks``).

        A job that sent its working tree as a delta and was refused because
        the runner's workspace was not as expected (``tree_stale``) is sent
        again once with the whole tree; this ``Job`` then stands for the new
        one (``id`` changes). A runner that loses its connection keeps running the job
        and posts the result once it is back; the relay waits for it (its
        ``--job-reconnect-grace``) before it calls the runner lost. With
        ``lost_grace`` this call waits that many seconds more for a late
        result after that (``job.result()`` also finds one later)."""
        deadline = None if timeout is None else time.monotonic() + timeout
        seen = 0
        shown: dict = {}  # see _unshown
        lost_until: Optional[float] = None
        while True:
            self.session.sync()
            if on_output is not None:
                for c in _unshown(self.chunks(), shown):
                    on_output(c)
            r = self.result()
            if r is not None and self._resend_whole is not None and (r.reason or "").startswith("tree_stale"):
                again = self._resend_whole()
                self.ref, self.id, self.meta, self.runner = again.ref, again.id, again.meta, again.runner
                self.tree, self._resend_whole, self._result = again.tree, None, None
                seen, shown = 0, {}
                continue
            if r is not None:
                return r
            if on_progress is not None:
                reports = self.progress()
                for p in reports[seen:]:
                    on_progress(p)
                seen = len(reports)
            st = self.state()
            self.runner = st.get("runner") or self.runner
            if st["state"] == "failed" and st.get("reason") == "runner_lost" and lost_grace > 0:
                if lost_until is None:
                    lost_until = time.monotonic() + lost_grace
                if time.monotonic() < lost_until and (deadline is None or time.monotonic() < deadline):
                    time.sleep(poll)
                    continue
            elif st["state"] != "failed":
                lost_until = None
            if st["state"] == "failed":
                # A runner that ran the job may still post its result; give it a moment.
                self.session.sync()
                r = self.result()
                if r is not None:
                    return r
                reason = st["reason"]
                return Result(
                    status=_UNSIGNED_STATUS.get(reason, "failed"),
                    exit_code=None,
                    reason=reason,
                    runner=st.get("runner"),
                    runner_name=self.session._participants.get(st.get("runner"), {}).get("display_name"),
                    signed=False,
                )
            if deadline is not None and time.monotonic() >= deadline:
                raise JobTimeout(f"no result for job {self.id} after {timeout} s")
            time.sleep(poll)

    def _find(self) -> Optional[Result]:
        s = self.session
        items = [s._items[i] for i in s._order]
        approved = None
        if s.manifest["job_limits"]["approve_runners"]:
            approved = json.dumps(sorted(approved_runners(items)))
        for item in items:
            if item.kind != "result" or item.status != "ok" or item.meta.get("job", {}).get("id") != self.id:
                continue
            if item.author_role != "runner":
                continue
            try:
                ac.check_result_for_job(
                    json.dumps(self.ref), json.dumps(self.meta), item.author, json.dumps(item.meta), approved
                )
            except ac.AirloxError:
                continue  # not a valid answer to this job; ignore it
            m = item.meta
            outs = []
            for o in m["out_files"]:
                got = s._items.get(o["item"]["id"])
                if got is None or got.status == "pending":
                    return None  # not here yet; the next sync fetches it
                data = got.body if got.status == "ok" and got.ref == o["item"] else None
                outs.append(OutFile(name=o["name"], size=o["size"], ref=o["item"], data=data))
            return Result(
                status=m["status"],
                exit_code=m["exit_code"],
                reason=m["reason"],
                stdout=m["stdout"],
                stderr=m["stderr"],
                stdout_truncated=m["stdout_truncated"],
                stderr_truncated=m["stderr_truncated"],
                wall_ms=m["wall_ms"],
                peak_mem_mb=m["peak_mem_mb"],
                out_files=outs,
                code_sha256=m["code_sha256"],
                input_sha256=m["input_sha256"],
                env=m.get("env"),
                runner=item.author,
                runner_name=item.author_name,
            )
        return None


def _unshown(chunks: List[Chunk], shown: dict) -> List[Chunk]:
    """The parts of ``chunks`` (contiguous per stream) past what ``shown``
    records, which is updated: ``shown[stream]`` is the bytes shown and
    ``shown[(stream, "end")]`` that its ``truncated`` chunk was."""
    out = []
    for c in chunks:
        raw = c.data.encode("utf-8")
        have = shown.get(c.stream, 0)
        end = c.offset + len(raw)
        if end > have:
            skip = max(0, have - c.offset)
            out.append(Chunk(c.stream, c.offset + skip, raw[skip:].decode("utf-8", "ignore"), c.truncated))
            shown[c.stream] = end
        elif c.truncated and not shown.get((c.stream, "end")):
            out.append(Chunk(c.stream, end, "", True))
        if c.truncated:
            shown[(c.stream, "end")] = True
    return out


def signed_approvals(items: "List[Item]") -> dict:
    """``participant_pub -> approved?`` from the owner's signed events. A
    rejection is final: a later (or replayed) approval does not undo it."""
    out: dict = {}
    for it in items:
        if it.kind != "event" or it.status != "ok" or it.author_role != "owner":
            continue
        ev = it.meta.get("event")
        pub = it.meta.get("participant_pub")
        if ev == "runner_approve" and out.get(pub) is not False:
            out[pub] = True
        elif ev == "runner_reject":
            out[pub] = False
    return out


def approved_runners(items: "List[Item]") -> set:
    return {pub for pub, ok in signed_approvals(items).items() if ok}
