"""Execute mode: runners, jobs and results.

The relay routes jobs but cannot read them; what counts is signed. A
runner's identity comes from its verified join, its approval from the
owner's signed ``runner_approve`` event, and a job's outcome from the
runner's signed result, bound to the job by ``airlock_core``.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, List, Optional

import airlock_core as ac

if TYPE_CHECKING:
    from .session import Item, Session


class NoRunnerAvailable(Exception):
    """No approved, online, idle runner matched the job. Jobs are not
    queued; the job item stays in the timeline as failed."""

    def __init__(self, job: "Job", message: str) -> None:
        super().__init__(message)
        self.job = job


class JobTimeout(Exception):
    """``Job.wait`` gave up before a result arrived."""


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
    #: The job it is running, per the relay.
    job: Optional[str]

    @property
    def idle(self) -> bool:
        return self.online and self.job is None


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
    runner: Optional[str] = None
    signed: bool = True

    @property
    def ok(self) -> bool:
        return self.status == "completed" and self.exit_code == 0

    def out_file(self, name: str) -> OutFile:
        for f in self.out_files:
            if f.name == name:
                return f
        raise KeyError(name)


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
        return self._result

    def wait(self, timeout: Optional[float] = 60.0, poll: float = 0.25) -> Result:
        """Block until the job has a result. Jobs that failed on the relay
        (no runner, runner lost, cancelled before it started) return an
        unsigned result with the relay's reason."""
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            self.session.sync()
            r = self.result()
            if r is not None:
                return r
            st = self.state()
            self.runner = st.get("runner") or self.runner
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
            except ac.AirlockError:
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
                runner=item.author,
            )
        return None


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
