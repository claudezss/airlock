"""Sessions: create, join, send, receive.

All cryptography and validation happens in ``airlox._core`` (Rust). This
module is HTTP plumbing, the local cache, and ergonomics.
"""

from __future__ import annotations

import json
import re
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Union

from . import _core as ac
import httpx

from .cache import Cache, default_root
from .execute import Job, NoRunnerAvailable, Runner, signed_approvals

DEFAULT_TYPES = ("text", "py", "md", "zip", "image")
FILE_TYPES = {
    ".py": ("py", "text/x-python"),
    ".md": ("md", "text/markdown"),
    ".markdown": ("md", "text/markdown"),
    ".zip": ("zip", "application/zip"),
    ".png": ("image", "image/png"),
    ".jpg": ("image", "image/jpeg"),
    ".jpeg": ("image", "image/jpeg"),
    ".webp": ("image", "image/webp"),
}


def _now_ms() -> int:
    return int(time.time() * 1000)


def _duration_ms(v: Union[int, float, str]) -> int:
    if isinstance(v, (int, float)):
        return int(v * 1000)
    m = re.fullmatch(r"\s*(\d+)\s*(ms|s|m|h|d)?\s*", v)
    if not m:
        raise ValueError(f"bad duration {v!r}")
    mult = {"ms": 1, "s": 1000, None: 1000, "m": 60_000, "h": 3_600_000, "d": 86_400_000}[m.group(2)]
    return int(m.group(1)) * mult


def _canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class RelayError(Exception):
    """The relay refused a request."""

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(f"{status} {code}: {message}")
        self.status = status
        self.code = code
        self.message = message


@dataclass
class Item:
    """A received or sent item, verified and decrypted."""

    seq: int
    id: str
    kind: str
    subkind: Optional[str]
    author: str
    author_role: Optional[str]
    author_name: Optional[str]
    created_at_ms: int
    ref: dict
    refs: List[dict] = field(default_factory=list)
    meta: Optional[dict] = None
    body: Optional[bytes] = None
    #: ``ok``; ``pending`` (the blob could not be fetched yet: a network
    #: error or a busy relay; retried on the next ``sync`` or ``stream``);
    #: ``evicted`` (removed from the relay before this client fetched it); or
    #: ``rejected`` (failed verification or policy, see ``error``).
    status: str = "ok"
    error: Optional[str] = None

    @property
    def available(self) -> bool:
        return self.status == "ok"

    @property
    def text(self) -> Optional[str]:
        return self.meta.get("text") if self.meta and self.kind == "text" else None

    @property
    def name(self) -> Optional[str]:
        return self.meta.get("name") if self.meta and self.kind == "file" else None

    @property
    def mime(self) -> Optional[str]:
        return self.meta.get("mime") if self.meta and self.kind == "file" else None


#: Largest believable gap between consecutive event sequence numbers.
MAX_SEQ_JUMP = 10_000

class Session:
    """A participant's view of one session."""

    def __init__(
        self,
        *,
        relay: str,
        session_id: str,
        signed_manifest: str,
        session_key: bytes,
        role: str,
        participant_seed: bytes,
        token: str,
        cache: Cache,
        owner_seed: Optional[bytes] = None,
        http: Optional[httpx.Client] = None,
    ) -> None:
        self.relay = relay.rstrip("/")
        self.session_id = session_id
        self.signed_manifest = signed_manifest
        self.manifest = json.loads(ac.verify_manifest(signed_manifest))
        self.role = role
        self.participant_pub = ac.public_key(participant_seed)
        self._key = session_key
        self._seed = participant_seed
        self._token = token
        self._owner_seed = owner_seed
        self._cache = cache
        self._http = http or httpx.Client(timeout=httpx.Timeout(30.0, connect=10.0))
        self._participants: Dict[str, dict] = {}
        self._items: Dict[str, Item] = {}
        self._order: List[str] = []
        self._envelopes: Dict[str, str] = {}
        self._evicted: set = set()
        self._unacked: set = set()
        self._last_seq = -1
        self.closed: Optional[str] = None
        cached = list(cache.events())
        self._evicted = {ev["data"]["item"] for ev in cached if ev["kind"] == "evicted"}
        for ev in cached:
            self._apply(ev, fetch=False, record=False)

    # construction -----------------------------------------------------
    @classmethod
    def create(
        cls,
        relay: str,
        *,
        mode: str = "relay",
        ttl: Union[int, float, str] = "1h",
        allowed_types: Iterable[str] = DEFAULT_TYPES,
        max_item_bytes: int = 25 * 1024 * 1024,
        job_limits: Optional[dict] = None,
        display_name: str = "owner",
        description: Optional[str] = None,
        cache_dir: Optional[Union[str, Path]] = None,
    ) -> "Session":
        """Create a session on ``relay`` and join it as the owner."""
        params = {
            "mode": mode,
            "created_at_ms": _now_ms(),
            "ttl_ms": _duration_ms(ttl),
            "allowed_types": list(allowed_types),
            "max_item_bytes": max_item_bytes,
            "job_limits": job_limits,
        }
        owner_seed, signed = ac.create_session(json.dumps(params))
        http = httpx.Client(timeout=httpx.Timeout(30.0, connect=10.0))
        _check(http.post(relay.rstrip("/") + "/v1/sessions", content=signed))
        url = ac.owner_invite(relay, owner_seed)
        return cls.join(url, display_name=display_name, description=description, cache_dir=cache_dir, _http=http)

    @classmethod
    def join(
        cls,
        invite_url: str,
        *,
        display_name: str = "agent",
        description: Optional[str] = None,
        cache_dir: Optional[Union[str, Path]] = None,
        _http: Optional[httpx.Client] = None,
    ) -> "Session":
        """Join with an invite link. Rejoins as the same participant if this
        cache already holds an identity for the session and role.

        ``description`` (up to 280 characters) tells the other participants
        what you are or do, e.g. ``"reviews Python for security issues"``.
        Like ``display_name`` it is signed and fixed at the first join.

        If the relay no longer has the session but this cache does, the
        session opens read-only with its local history and ``closed`` set.
        Two processes using one invite should use different ``cache_dir``s:
        a cache holds one identity per role."""
        info_json, session_key, role_seed = ac.parse_invite(invite_url)
        info = json.loads(info_json)
        relay, sid, role = info["base_url"], info["session_id"], info["role"]
        http = _http or httpx.Client(timeout=httpx.Timeout(30.0, connect=10.0))
        root = Path(cache_dir) if cache_dir else default_root()
        Cache.sweep_expired(root)
        cache = Cache(root, sid)
        identity = cache.load_identity(role)
        # The cached token belongs to the relay that issued it: an invite with
        # this session's keys but another relay (an altered link) must not
        # receive it.
        bound = (identity or {}).get("base_url")
        if bound and bound != relay.rstrip("/"):
            raise ValueError(
                f"this invite names relay {relay!r} but you joined session {sid} on {bound!r}; "
                "refusing to send your token to another relay (the link may have been altered)"
            )
        offline = False
        try:
            signed = _check(http.get(f"{relay}/v1/sessions/{sid}")).json()["signed_manifest"]
        except RelayError as e:
            signed = cache.load_manifest()
            if e.status != 404 or signed is None or identity is None:
                raise
            offline = True
        ac.check_invite(invite_url, signed)
        if not offline:
            cache.save_manifest(signed)
        if not identity:
            seed = ac.generate_seed()
            pub = ac.public_key(seed)
            cert = ac.issue_cert(role_seed, sid, role, pub, _now_ms())
            join = {
                "v": 1,
                "session_id": sid,
                "cert": json.loads(cert),
                "display_name": display_name,
                "description": (description or "").strip() or None,
                "kind": "sdk",
                "runner": None,
                "created_at_ms": _now_ms(),
            }
            signed_join = ac.sign_join(seed, json.dumps(join))
            resp = _check(http.post(f"{relay}/v1/sessions/{sid}/participants", content=signed_join)).json()
            identity = {"participant_seed": seed.hex(), "token": resp["token"], "role": role, "base_url": relay.rstrip("/")}
            cache.save_identity(role, identity)
        elif not bound:
            identity = {**identity, "base_url": relay.rstrip("/")}
            cache.save_identity(role, identity)
        session = cls(
            relay=relay,
            session_id=sid,
            signed_manifest=signed,
            session_key=session_key,
            role=role,
            participant_seed=bytes.fromhex(identity["participant_seed"]),
            token=identity["token"],
            cache=cache,
            owner_seed=role_seed if role == "owner" else None,
            http=http,
        )
        if offline and not session.closed:
            session.closed = "no longer on the relay"
        return session

    def disconnect(self) -> None:
        """Close this client's HTTP connections. The session itself is untouched."""
        self._http.close()

    def __enter__(self) -> "Session":
        return self

    def __exit__(self, *exc) -> None:
        self.disconnect()

    # owner ------------------------------------------------------------
    @property
    def invites(self) -> Dict[str, str]:
        """Invite links per role (owner only)."""
        if self._owner_seed is None:
            raise PermissionError("only the owner can mint invites")
        roles = ["sender", "observer"] + (["runner"] if self.manifest["mode"] == "execute" else [])
        out = {r: ac.member_invite(self.relay, self._owner_seed, r) for r in roles}
        out["owner"] = ac.owner_invite(self.relay, self._owner_seed)
        return out

    def close(self) -> None:
        """Close and purge the session on the relay (owner only)."""
        self._req("POST", "/close")
        self.closed = "closed by owner"

    def leave(self, *, delete_cache: bool = False) -> None:
        """Stop receiving: the relay no longer waits for this participant
        before deleting blobs, and its token stops working."""
        if not self.closed:
            try:
                self._req("POST", "/leave")
            except RelayError as e:
                if e.status not in (401, 404, 410):
                    raise
        self.closed = "left"
        if delete_cache:
            self._cache.delete()

    # sending ----------------------------------------------------------
    def send_text(self, text: str, *, refs: Iterable[dict] = ()) -> dict:
        """Send a message. Returns its item reference."""
        return self._send("text", None, {"type": "text", "text": text}, b"", refs)

    def send_file(
        self,
        src: Union[str, Path, bytes],
        *,
        name: Optional[str] = None,
        refs: Iterable[dict] = (),
    ) -> dict:
        """Send a .py, .md, .zip, .png, .jpg or .webp file. Images are
        re-encoded first to strip metadata. Returns the item reference."""
        if isinstance(src, (str, Path)):
            path = Path(src)
            data = path.read_bytes()
            name = name or path.name
        else:
            data = bytes(src)
            if not name:
                raise ValueError("name is required when sending bytes")
        ext = Path(name).suffix.lower()
        if ext not in FILE_TYPES:
            raise ValueError(f"unsupported file type {ext!r}; use {', '.join(sorted(FILE_TYPES))}")
        subkind, mime = FILE_TYPES[ext]
        if subkind == "image":
            mime, data = ac.sanitize_image(data)
        elif subkind == "zip":
            ac.inspect_zip(data)
        return self._send("file", subkind, {"type": "file", "name": name, "mime": mime}, data, refs)

    def _seal(self, kind: str, subkind: Optional[str], meta: dict, body: bytes, refs: Iterable[dict]):
        """Returns ``(item_id, envelope_json, blob, frame)``."""
        allowed = self.manifest["allowed_types"]
        needed = {"text": "text", "file": subkind, "job": "py"}.get(kind)
        if needed is not None and needed not in allowed:
            raise ac.PolicyError(f"{needed} is not allowed in this session (allowed: {', '.join(allowed)})")
        payload = ac.encode_payload(json.dumps(meta), body)
        if len(payload) > self.manifest["max_item_bytes"]:
            raise ac.PolicyError(f"item is {len(payload)} bytes; the session limit is {self.manifest['max_item_bytes']}")
        new = {
            "id": ac.new_item_id(),
            "session_id": self.session_id,
            "kind": kind,
            "subkind": subkind,
            "created_at_ms": _now_ms(),
            "refs": list(refs),
        }
        env, blob = ac.seal_item(self._key, self._seed, json.dumps(new), payload)
        frame = struct.pack(">I", len(env.encode())) + env.encode() + blob
        self._cache.write_blob(new["id"], blob)
        return new["id"], env, blob, frame

    def _send(self, kind: str, subkind: Optional[str], meta: dict, body: bytes, refs: Iterable[dict]) -> dict:
        _, env, blob, frame = self._seal(kind, subkind, meta, body, refs)
        self._req("POST", "/items", content=frame)
        return json.loads(ac.item_ref(env, blob))

    # execute mode -----------------------------------------------------
    def _require_execute(self) -> dict:
        if self.manifest["mode"] != "execute":
            raise ac.PolicyError("this session is in relay mode")
        return self.manifest["job_limits"]

    def runners(self) -> List[Runner]:
        """Runners in the session. Names and labels come from each runner's
        verified join; ``approved`` from the owner's signed approval."""
        self._require_execute()
        self.sync()
        listing = self._req("GET", "/runners").json()
        approvals = signed_approvals([self._items[i] for i in self._order])
        out = []
        for r in listing["runners"]:
            try:
                ac.verify_join(r["signed_join"], self.signed_manifest)
            except ac.AirloxError:
                continue
            join = json.loads(r["signed_join"])["join"]
            info = join["runner"]
            pub = join["cert"]["cert"]["participant_pub"]
            approved = approvals.get(pub, False) if listing["approval_required"] else not r["rejected"]
            out.append(
                Runner(
                    participant_pub=pub,
                    name=info["name"],
                    labels=info["labels"],
                    host=info["host"],
                    sandbox=info["sandbox"],
                    network_unblocked=info["network_unblocked"],
                    approved=approved and not r["rejected"],
                    rejected=r["rejected"] or approvals.get(pub) is False,
                    online=r["online"],
                    job=r["job"],
                    description=join.get("description"),
                )
            )
        return out

    def _runner(self, which: Union[Runner, str]) -> Runner:
        if isinstance(which, Runner):
            return which
        matches = [r for r in self.runners() if which in (r.name, r.participant_pub)]
        if len(matches) != 1:
            raise LookupError(f"{'no' if not matches else 'more than one'} runner matches {which!r}")
        return matches[0]

    def approve_runner(self, runner: Union[Runner, str]) -> Runner:
        """Let a runner take jobs (owner only): a signed ``runner_approve``
        event for runners and senders to verify, plus the relay's copy."""
        r = self._runner(runner)
        self._send("event", None, {"type": "event", "event": "runner_approve", "participant_pub": r.participant_pub}, b"", [])
        self._req("POST", f"/runners/{r.participant_pub}/approve")
        return r

    def reject_runner(self, runner: Union[Runner, str], reason: Optional[str] = None) -> None:
        """Turn a runner away (owner only); its token stops working."""
        r = self._runner(runner)
        meta = {"type": "event", "event": "runner_reject", "participant_pub": r.participant_pub, "reason": reason}
        self._send("event", None, meta, b"", [])
        self._req("POST", f"/runners/{r.participant_pub}/reject")

    def run_python(
        self,
        code: str,
        *,
        filename: str = "main.py",
        files: Iterable[dict] = (),
        runner: Optional[Union[Runner, str]] = None,
        labels: Optional[Iterable[str]] = None,
        timeout: Optional[int] = None,
        memory_mb: Optional[int] = None,
        requirements: Iterable[str] = (),
    ) -> Job:
        """Submit Python to a runner. ``files`` are item references from
        ``send_file`` (ZIPs are unpacked into the work dir). Target one
        ``runner`` (by name, key or ``Runner``), any runner with all of
        ``labels``, or any idle runner. Raises ``NoRunnerAvailable`` at once
        if nothing matches: jobs are never queued. Files the job writes to
        ``os.environ["AIRLOX_OUT"]`` (``/out`` in containers) come back as
        out files."""
        limits = self._require_execute()
        if runner is not None and labels is not None:
            raise ValueError("pass runner or labels, not both")
        if runner is not None:
            r = self._runner(runner)
            target = {"type": "runner", "participant_pub": r.participant_pub, "name": r.name}
        elif labels is not None:
            target = {"type": "labels", "labels": list(labels)}
        else:
            target = {"type": "any"}
        meta = {
            "type": "job",
            "filename": filename,
            "code": code,
            "runtime": limits["runtime"],
            "timeout_s": int(timeout if timeout is not None else limits["timeout_s"]),
            "memory_mb": memory_mb,
            "files": list(files),
            "requirements": list(requirements),
            "target": target,
        }
        _, env, blob, frame = self._seal("job", "py", meta, b"", [])
        job = Job(self, json.loads(ac.item_ref(env, blob)), meta)
        try:
            resp = self._req("POST", "/jobs", content=frame, headers={"Airlox-Target": json.dumps(target)})
        except RelayError as e:
            if e.code == "no_runner_available":
                raise NoRunnerAvailable(job, e.message) from None
            raise
        job.runner = resp.json().get("runner")
        return job

    def run_file(self, path: Union[str, Path], **kw) -> Job:
        """``run_python`` with a local ``.py`` file as the entry point."""
        p = Path(path)
        return self.run_python(p.read_text(), filename=p.name, **kw)

    # receiving --------------------------------------------------------
    def sync(self) -> List[Item]:
        """Fetch new events from the relay and retry pending downloads and
        acks. Returns items that became available."""
        if self.closed:
            return []
        out = self._retry()
        query = f"?after={self._last_seq}" if self._last_seq >= 0 else ""
        try:
            evs = self._req("GET", f"/events{query}").json()["events"]
        except RelayError as e:
            if e.status in (404, 410):
                self.closed = self.closed or "no longer on the relay"
                return out
            raise
        out += [i for i in (self._apply(e) for e in evs) if i is not None and i.status != "pending"]
        return out

    def items(self) -> List[Item]:
        """All items, oldest first: what the relay still has plus local history."""
        self.sync()
        return [self._items[i] for i in self._order]

    def participants(self) -> List[dict]:
        return list(self._participants.values())

    def stream(self, timeout: Optional[float] = None) -> Iterator[Item]:
        """Yield items as they arrive over SSE, reconnecting and resuming
        as needed. Ends when the session closes or ``timeout`` elapses."""
        deadline = None if timeout is None else time.monotonic() + timeout
        while not self.closed:
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                return
            headers = {"Authorization": f"Bearer {self._token}"}
            if self._last_seq >= 0:
                headers["Last-Event-ID"] = str(self._last_seq)
            read = 60.0 if remaining is None else max(0.1, min(60.0, remaining))
            yield from self._retry()
            try:
                with self._http.stream(
                    "GET",
                    self._url("/stream"),
                    headers=headers,
                    timeout=httpx.Timeout(read, connect=10.0),
                ) as r:
                    if r.status_code in (404, 410):
                        self.closed = self.closed or "no longer on the relay"
                        return
                    if r.status_code != 200:
                        r.read()
                        _check(r)
                    for ev in _sse_events(r.iter_lines()):
                        item = self._apply(ev)
                        if item is not None and item.status != "pending":
                            yield item
                        if self.closed:
                            return
                        if deadline is not None and time.monotonic() >= deadline:
                            return
            except httpx.TransportError:
                time.sleep(0.5)
                continue

    # internals --------------------------------------------------------
    def _url(self, path: str) -> str:
        return f"{self.relay}/v1/sessions/{self.session_id}{path}"

    def _req(self, method: str, path: str, **kw) -> httpx.Response:
        headers = kw.pop("headers", {})
        headers["Authorization"] = f"Bearer {self._token}"
        return _check(self._http.request(method, self._url(path), headers=headers, **kw))

    def _apply(self, ev: dict, *, fetch: bool = True, record: bool = True) -> Optional[Item]:
        seq = ev["seq"]
        # A wild jump would make every later event look old, and the cache
        # would keep it (as the Rust client does: drop it unrecorded).
        if seq > max(self._last_seq, 0) + MAX_SEQ_JUMP:
            return None
        if record and seq <= self._last_seq:
            return None
        kind, data = ev["kind"], ev["data"]
        item = None
        if kind == "participant":
            # Only fields from the verified signed join count; the relay's
            # copies of role and name are unsigned.
            try:
                ac.verify_join(data["signed_join"], self.signed_manifest)
                join = json.loads(data["signed_join"])["join"]
                cert = join["cert"]["cert"]
                self._participants[cert["participant_pub"]] = {
                    "participant_pub": cert["participant_pub"],
                    "role": cert["role"],
                    "display_name": join["display_name"],
                    "description": join.get("description"),
                    "kind": join["kind"],
                    "cert": ac.join_cert(data["signed_join"]),
                    "left": False,
                }
            except (ac.AirloxError, KeyError, ValueError):
                pass  # a relay cannot make us accept a forged participant
        elif kind == "item":
            item = self._receive(seq, data["envelope"], fetch)
        elif kind == "evicted":
            self._evicted.add(data["item"])
            pending = self._items.get(data["item"])
            if pending is not None and pending.status == "pending":
                pending.status = "evicted"
        elif kind == "left":
            p = self._participants.get(data.get("participant_pub"))
            if p is not None:
                p["left"] = True
        elif kind == "closed":
            self.closed = data.get("reason", "closed")
        if record:
            self._cache.append_event(ev)
        self._last_seq = max(self._last_seq, seq)
        return item

    def _retry(self) -> List[Item]:
        """Retry pending downloads and unsent acks."""
        out = []
        for item_id in [i for i in self._order if self._items[i].status == "pending"]:
            item = self._receive(self._items[item_id].seq, self._envelopes[item_id], True)
            if item is not None and item.status != "pending":
                out.append(item)
        for item_id in list(self._unacked):
            self._ack(item_id)
        return out

    def _ack(self, item_id: str) -> None:
        try:
            r = self._http.post(self._url(f"/items/{item_id}/ack"), headers={"Authorization": f"Bearer {self._token}"})
        except httpx.TransportError:
            self._unacked.add(item_id)
            return
        if r.status_code in (204, 404, 410):
            self._unacked.discard(item_id)
        elif r.status_code == 429 or r.status_code >= 500:
            self._unacked.add(item_id)
        else:
            self._unacked.discard(item_id)
            _check(r)

    def _receive(self, seq: int, envelope: str, fetch: bool) -> Optional[Item]:
        header = json.loads(envelope)["header"]
        item_id = header["id"]
        existing = self._items.get(item_id)
        if existing is not None and existing.status != "pending":
            return None
        self._envelopes[item_id] = envelope
        author = self._participants.get(header["author"])
        item = Item(
            seq=seq,
            id=item_id,
            kind=header["kind"],
            subkind=header["subkind"],
            author=header["author"],
            author_role=author["role"] if author else None,
            author_name=author["display_name"] if author else None,
            created_at_ms=header["created_at_ms"],
            refs=header["refs"],
            ref={"id": item_id, "blob_sha256": ""},
        )
        if item_id not in self._items:
            self._order.append(item_id)
        self._items[item_id] = item
        if author is None:
            item.status, item.error = "rejected", "author is not a verified participant"
            return item
        blob = self._cache.read_blob(item_id)
        fresh = False
        if blob is None:
            if item_id in self._evicted:
                item.status = "evicted"
                return item
            if not fetch:
                # Loaded from the cache without its blob: fetch on the next sync.
                item.status = "pending"
                return item
            try:
                r = self._http.get(
                    self._url(f"/items/{item_id}/blob"), headers={"Authorization": f"Bearer {self._token}"}
                )
            except httpx.TransportError:
                item.status = "pending"
                return item
            if r.status_code in (404, 410):
                item.status = "evicted"
                return item
            if r.status_code == 429 or r.status_code >= 500:
                item.status = "pending"
                return item
            blob = _check(r).content
            fresh = True
        try:
            role, meta, body = ac.open_checked(self.signed_manifest, author["cert"], self._key, envelope, blob)
        except ac.AirloxError as e:
            item.status, item.error = "rejected", str(e)
            return item
        item.author_role = role
        item.meta, item.body = json.loads(meta), body
        item.ref = json.loads(ac.item_ref(envelope, blob))
        if fresh:
            self._cache.write_blob(item_id, blob)
            if header["author"] != self.participant_pub:
                self._ack(item_id)
        return item


def _check(r: httpx.Response) -> httpx.Response:
    if r.status_code >= 400:
        try:
            body = r.json()
            code, message = body.get("error", "error"), body.get("message", "")
        except ValueError:
            code, message = "error", r.text
        raise RelayError(r.status_code, code, message)
    return r


def _sse_events(lines: Iterator[str]) -> Iterator[dict]:
    """Minimal SSE parser yielding ``{seq, kind, data}``."""
    event = data = ident = None
    for line in lines:
        if line == "":
            if data is not None and event is not None:
                yield {"seq": int(ident) if ident else -1, "kind": event, "data": json.loads(data)}
            event = data = ident = None
        elif line.startswith(":"):
            continue
        else:
            name, _, value = line.partition(":")
            value = value[1:] if value.startswith(" ") else value
            if name == "event":
                event = value
            elif name == "data":
                data = value if data is None else data + "\n" + value
            elif name == "id":
                ident = value
