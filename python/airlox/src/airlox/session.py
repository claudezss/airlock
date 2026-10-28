"""Sessions: create, join, send, receive.

All cryptography and validation happens in ``airlox._core`` (Rust). This
module is HTTP plumbing, the local cache, and ergonomics.
"""

from __future__ import annotations

import json
import logging
import random
import re
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Union

from . import _core as ac
import httpx

from .cache import Cache, default_root
from .execute import Job, NoRunnerAvailable, Runner, RunnerBusy, RunnerFailed, signed_approvals

log = logging.getLogger(__name__)

DEFAULT_TYPES = ("text", "py", "md", "zip", "image")
# The item limit for a relay that does not say what it allows, and the
# largest default a relay's answer can raise it to.
DEFAULT_MAX_ITEM_BYTES = 25 * 1024 * 1024
MAX_DEFAULT_ITEM_BYTES = 100 * 1024 * 1024
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


def _relay_max_item_bytes(http: httpx.Client, base: str) -> Optional[int]:
    """The largest item a session on this relay may allow, from
    ``/v1/health``; ``None`` if the relay does not say."""
    try:
        v = _check(http.get(base + "/v1/health", timeout=5.0)).json().get("max_item_bytes")
    except (httpx.HTTPError, RelayError, ValueError, AttributeError):
        return None
    # The relay is not trusted to pick a large limit: it caps the default only.
    return min(v, MAX_DEFAULT_ITEM_BYTES) if type(v) is int and v > 0 else None


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
    #: ``evicted`` (removed from the relay before this client fetched it; the
    #: client asks the participants holding it to upload it again, and fetches
    #: it if one does); or
    #: ``rejected`` (failed verification or policy, see ``error``).
    status: str = "ok"
    error: Optional[str] = None
    #: This session's participant wrote it (``author`` is ``participant_pub``).
    mine: bool = False

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

    @property
    def to(self) -> Optional[List[str]]:
        """The participant keys a message is addressed to; ``None`` for everyone."""
        to = self.meta.get("to") if self.meta and self.kind == "text" else None
        return list(to) if isinstance(to, list) else None

    @property
    def reply_to(self) -> Optional[str]:
        """The id of the item this one answers: a message's or file's first
        reference, a result's job."""
        if self.kind in ("text", "file", "result") and self.refs:
            return self.refs[0].get("id")
        return None


#: Largest believable gap between consecutive event sequence numbers.
MAX_SEQ_JUMP = 10_000
#: Ask again for an evicted blob nobody re-seeded after this long; the
#: relay drops a want after ten minutes.
REASK_S = 5 * 60.0


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
        #: Cursor of the batch ``wait_for_messages`` last returned, not yet marked handled.
        self._uncommitted: Optional[int] = None
        #: When (monotonic) each pending item was first seen so, and which were given up on.
        self._pending_since: Dict[int, float] = {}
        self._pending_skipped: set = set()
        self._envelopes: Dict[str, str] = {}
        self._evicted: set = set()
        self._wanted: Dict[str, float] = {}  # evicted items this client asked holders for → when
        self._asked: set = set()  # evicted items others asked for, which this cache may hold
        self._reseeded: set = set()  # evicted items back on the relay, to fetch
        self._unacked: set = set()
        self._last_seq = -1
        #: When this client last heard from the relay (ms since the epoch).
        self.synced_at_ms: Optional[int] = None
        self.closed: Optional[str] = None
        cached = list(cache.events())
        # Which blobs the relay lacks now, so replayed items without a cached
        # blob come out evicted rather than pending.
        for ev in cached:
            if ev["kind"] == "evicted":
                self._evicted.add(ev["data"]["item"])
            elif ev["kind"] == "reseeded":
                self._evicted.discard(ev["data"]["item"])
        for ev in cached:
            self._apply(ev, fetch=False, record=False)

    # construction -----------------------------------------------------
    @classmethod
    def create(
        cls,
        relay: str,
        *,
        mode: str = "relay",
        ttl: Union[int, float, str, None] = "1h",
        allowed_types: Iterable[str] = DEFAULT_TYPES,
        max_item_bytes: Optional[int] = None,
        job_limits: Optional[dict] = None,
        insecure_http_host: Optional[str] = None,
        display_name: str = "owner",
        description: Optional[str] = None,
        cache_dir: Optional[Union[str, Path]] = None,
    ) -> "Session":
        """Create a session on ``relay`` and join it as the owner. ``ttl`` is
        seconds or a duration such as ``"30m"`` (at most 30 days); ``None``
        or ``"never"`` makes a session that lasts until it is closed, if the
        relay allows it.

        ``max_item_bytes`` defaults to the largest item the relay allows, up
        to 100 MB (25 MB if the relay does not say). Package names in ``job_limits`` are PEP 503
        normalized (``"pyPowerGEM"`` becomes ``"pypowergem"``). An entry may also pin
        versions with a PEP 440 specifier (``"cugrid==0.1.0"``, ``"numpy>=1.26,<3"``): runners
        install that version, or, with ``--python``, refuse to join an interpreter that has
        another. Jobs still name the package alone in ``requirements``, and each result's
        ``env`` says which versions it ran with.

        **Save the owner invite.** ``session.invites["owner"]`` is the only way to approve
        runners, mint more invites, revoke a role or close the session later: it holds the
        owner key, and nothing else in the cache or on the relay can stand in for it. Write
        it to a private file (mode 0600, outside any repository) as soon as the session
        exists, like the CLI's ``--owner-invite-file``, and treat it as a secret: anyone
        with it controls the session. ``Session.join(invite)`` with it reopens the session
        as owner.

        ``insecure_http_host`` lets participants reach the relay over plain
        ``http://`` at that host, such as ``"airlox-relay.ns.svc"`` inside a
        cluster; it is recorded in the signed manifest. Content stays
        end-to-end encrypted, but bearer tokens cross that network in the
        clear."""
        http = httpx.Client(timeout=httpx.Timeout(30.0, connect=10.0))
        try:
            base = relay.rstrip("/")
            if max_item_bytes is None:
                max_item_bytes = _relay_max_item_bytes(http, base) or DEFAULT_MAX_ITEM_BYTES
            params = {
                "mode": mode,
                "created_at_ms": _now_ms(),
                "ttl_ms": None if ttl is None or ttl == "never" else _duration_ms(ttl),
                "allowed_types": list(allowed_types),
                "max_item_bytes": max_item_bytes,
                "job_limits": job_limits,
            }
            if insecure_http_host is not None:
                params["insecure_http_host"] = insecure_http_host.strip().lower()
            owner_seed, signed = ac.create_session(json.dumps(params))
            url = ac.owner_invite(relay, owner_seed)
            # Refuse a relay URL the session's own links could not use (plain
            # http to a host it does not name) before the session exists.
            ac.check_invite(url, signed)
            _check(http.post(base + "/v1/sessions", content=signed))
            return cls.join(url, display_name=display_name, description=description, cache_dir=cache_dir, _http=http)
        except BaseException:
            http.close()
            raise

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
                "display_name": display_name.strip(),
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

    def transfer_code(self, role: str, *, allow_owner: bool = False) -> "TransferCode":
        """Park ``role``'s invite on the relay under a one-time code such as
        ``7-guitar-orbit`` (owner only), like the web UI's "Send to another
        machine". Type it on the other machine with ``airlox runner join
        --code`` or ``airlox receive``, or pass it to :func:`receive_code`.
        The code works once and for a few minutes.

        The relay holds the invite sealed under the code's two words, which
        its operator could recover by trying all 65,536 pairs: a code trusts
        the relay in a way the link itself does not. A code for the
        ``owner`` invite hands over the session and needs ``allow_owner``."""
        if role == "owner" and not allow_owner:
            raise ValueError("a code for the owner invite hands over the session; pass allow_owner=True")
        invites = self.invites
        if role not in invites:
            raise ValueError(f"this session has no {role} invite")
        secret, claim_hash, sealed = ac.transfer_seal(invites[role])
        r = _check(self._http.post(self.relay + "/v1/drops", json={"claim_hash": claim_hash, "box": sealed})).json()
        return TransferCode(
            code=f"{r['nameplate']}-{secret}",
            role=role,
            relay=self.relay,
            expires_at_ms=r["expires_at_ms"],
            _nameplate=r["nameplate"],
            _token=r["token"],
            _http=self._http,
        )

    def close(self) -> None:
        """Close and purge the session on the relay (owner only)."""
        self._req("POST", "/close")
        self.closed = "closed by owner"

    def revoke(self, role: str) -> None:
        """Revoke a role (owner only): its participants are cut off and its
        invite admits no one. Whoever kept that invite still holds the session
        key, so what they already copied stays readable to them."""
        if self.role != "owner":
            raise PermissionError("only the owner can revoke a role")
        if role not in ("sender", "observer", "runner"):
            raise ValueError("revoke one of sender, observer or runner")
        self._req("POST", f"/roles/{role}/revoke")

    def audit(self) -> List[dict]:
        """The session's audit trail (owner or observer): one dict per
        record, oldest first, with the signed joins and item envelopes to
        check it against. It is purged with the session."""
        text = self._req("GET", "/audit.jsonl").text
        return [json.loads(line) for line in text.splitlines() if line]

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
    def send_text(
        self,
        text: str,
        *,
        to: Iterable[str] = (),
        reply_to: Union[Item, str, None] = None,
        refs: Iterable[dict] = (),
    ) -> dict:
        """Send a message. Returns its item reference.

        ``to`` addresses it: participant names, keys or ``"role:owner"``
        (see :meth:`resolve_recipients`); their listeners wake for it. A
        message without ``to`` goes to everyone: the owner's wakes every
        listener, anyone else's only the author of the item it replies to. ``reply_to`` (an item or its id) links it to
        the item it answers."""
        meta: dict = {"type": "text", "text": text}
        to = list(to)
        if to:
            meta["to"] = self.resolve_recipients(to)
        return self._send("text", None, meta, b"", self._reply_refs(reply_to) + list(refs))

    def _reply_refs(self, reply_to: Union[Item, str, None]) -> List[dict]:
        if reply_to is None:
            return []
        item_id = reply_to.id if isinstance(reply_to, Item) else reply_to
        if item_id not in self._items:
            self.sync()
        item = self._items.get(item_id)
        if item is None:
            raise ValueError(f"no item {item_id} in this session to reply to")
        return [item.ref]

    def resolve_recipients(self, specs: Iterable[str]) -> List[str]:
        """Participant keys for ``specs``: keys, display names (``@``
        optional; a shared name addresses everyone with it) or
        ``role:<owner|sender|observer|runner>``. Never yourself."""
        if not self._participants:
            self.sync()
        live = [p for p in self._participants.values() if not p["left"]]
        out: List[str] = []
        for spec in specs:
            spec = spec.strip()
            if spec.startswith("role:"):
                found = [p for p in live if p["role"] == spec[5:]]
            else:
                found = [p for p in live if p["participant_pub"] == spec] or [
                    p for p in live if p["display_name"] == spec.removeprefix("@")]
            found = [p for p in found if p["participant_pub"] != self.participant_pub]
            if not found:
                names = sorted({p["display_name"] for p in live if p["participant_pub"] != self.participant_pub})
                raise ValueError(f"no other participant matches {spec!r}; participants: {', '.join(names)}")
            out += [p["participant_pub"] for p in found if p["participant_pub"] not in out]
        if len(out) > 64:
            raise ValueError("a message can be addressed to at most 64 participants")
        return out

    def delivery(self) -> Dict[str, dict]:
        """For your own recent items, by id: ``delivered`` (participants
        whose client fetched it) and ``waiting`` (still held for them).
        Fetched, not read."""
        return self._req("GET", "/delivery").json()["items"]

    def send_file(
        self,
        src: Union[str, Path, bytes],
        *,
        name: Optional[str] = None,
        reply_to: Union[Item, str, None] = None,
        refs: Iterable[dict] = (),
    ) -> dict:
        """Send a .py, .md, .zip, .png, .jpg or .webp file, as a reply to
        ``reply_to`` if given. Images are re-encoded first to strip metadata.
        Returns the item reference."""
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
        refs = self._reply_refs(reply_to) + list(refs)
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
            # Whether approval is required comes from the signed manifest, not
            # the relay's listing.
            required = self.manifest["job_limits"]["approve_runners"]
            approved = approvals.get(pub, False) if required else not r["rejected"]
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
                    state=r.get("state"),
                    # The relay caps it, but the relay is not trusted either.
                    detail=r["detail"][:300] if isinstance(r.get("detail"), str) else None,
                    version=info.get("version"),
                    python=info.get("python"),
                )
            )
        return out

    def _runner(self, which: Union[Runner, str]) -> Runner:
        if isinstance(which, Runner):
            return which
        runners = self.runners()
        # A key names exactly one runner; only then try names (a runner may
        # pick another runner's key as its name to make the lookup ambiguous).
        matches = [r for r in runners if r.participant_pub == which] or [r for r in runners if r.name == which]
        if len(matches) != 1:
            raise LookupError(f"{'no' if not matches else 'more than one'} runner matches {which!r}")
        return matches[0]

    def wait_for_runner(
        self, runner: Union[Runner, str], *, approved: bool = False, timeout: float = 120.0, poll: float = 0.25
    ) -> Runner:
        """Block until a runner (a ``Runner``, its name or key) is online and
        return it. With ``approved=True`` also wait until *this* session sees
        the owner's signed approval: a sender that calls ``run_python`` just
        after the owner approved can still get ``PolicyError`` (no signed
        approval yet) until its own sync has fetched the event.

        Raises ``RunnerFailed`` at once if the runner reports that its setup
        failed, ``PolicyError`` if the owner rejected it, ``LookupError`` if a name matches several runners, and
        ``TimeoutError`` if it is not ready after ``timeout`` seconds."""
        which = runner.participant_pub if isinstance(runner, Runner) else runner
        deadline = time.monotonic() + timeout
        seen: Optional[Runner] = None
        while True:
            # A key names exactly one runner; only then try names, as `_runner` does.
            runners = self.runners()
            matches = [r for r in runners if r.participant_pub == which] or [r for r in runners if r.name == which]
            if len(matches) > 1:
                raise LookupError(f"more than one runner matches {which!r}")
            seen = matches[0] if matches else None
            if seen is not None:
                if seen.state == "failed":
                    raise RunnerFailed(seen)
                if seen.rejected:
                    raise ac.PolicyError(f"runner {seen.name} was rejected")
                if seen.online and (seen.approved or not approved):
                    return seen
            if time.monotonic() >= deadline:
                break
            time.sleep(poll)
        if seen is None:
            why = "has not joined"
        elif not seen.online:
            why = "is not online"
        else:
            why = "has no signed approval from the owner yet"
        raise TimeoutError(f"runner {which} {why} after {timeout} s")

    def approve_runner(self, runner: Union[Runner, str]) -> Runner:
        """Let a runner take jobs (owner only): the relay's approval, then a
        signed ``runner_approve`` event for runners and senders to verify.

        In that order: a runner awaiting approval is not a recipient, so the
        relay would not keep the event's blob for it, and a runner that
        fetched it late would never see its own approval."""
        r = self._runner(runner)
        self._req("POST", f"/runners/{r.participant_pub}/approve")
        self._send("event", None, {"type": "event", "event": "runner_approve", "participant_pub": r.participant_pub}, b"", [])
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
        progress_file: Optional[str] = None,
    ) -> Job:
        """Submit Python to a runner. ``files`` are item references from
        ``send_file`` (ZIPs are unpacked into the work dir). Target one
        ``runner`` (by name, key or ``Runner``), any runner with all of
        ``labels``, or any idle runner. Raises ``NoRunnerAvailable`` at once
        if nothing matches, ``RunnerBusy`` if what matches is busy: jobs are
        never queued. Files the job writes to ``os.environ["AIRLOX_OUT"]``
        (``/out`` in containers) come back as out files.

        ``progress_file`` names a file in the job's work dir (``"logs/run.log"``)
        whose tail the runner posts while the job runs; read it with
        ``Job.progress()`` or ``Job.wait(on_progress=...)``."""
        limits = self._require_execute()
        if runner is not None and labels is not None:
            raise ValueError("pass runner or labels, not both")
        if runner is not None:
            # Re-resolved (not a caller's possibly stale Runner) so approval is current.
            r = self._runner(runner.participant_pub if isinstance(runner, Runner) else runner)
            if not r.approved:
                # The relay may still route to it (if posting the owner's
                # signed approval failed); it would get the code only to refuse.
                raise ac.PolicyError(f"runner {r.name} has no signed approval from the owner yet")
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
        # Absent rather than null: the canonical form leaves it out.
        if progress_file is not None:
            meta["progress_file"] = progress_file
        _, env, blob, frame = self._seal("job", "py", meta, b"", [])
        job = Job(self, json.loads(ac.item_ref(env, blob)), meta)
        try:
            resp = self._req("POST", "/jobs", content=frame, headers={"Airlox-Target": json.dumps(target)})
        except RelayError as e:
            if e.code == "runner_busy":
                raise RunnerBusy(job, e.message) from None
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
            if e.status in (401, 404, 410):
                self.closed = self.closed or _gone_reason(e.status)
                return out
            raise
        self.synced_at_ms = _now_ms()
        out += [i for i in (self._apply(e) for e in evs) if i is not None and i.status != "pending"]
        self._trade_blobs()
        if self._reseeded:
            out += self._retry(set(self._reseeded))  # back on the relay: fetch them now
        return out

    def items(self) -> List[Item]:
        """All items, oldest first: what the relay still has plus local history."""
        self.sync()
        return [self._items[i] for i in self._order]

    def participants(self) -> List[dict]:
        return list(self._participants.values())

    @property
    def latest_seq(self) -> Optional[int]:
        """The highest event sequence number this client has seen."""
        return self._last_seq if self._last_seq >= 0 else None

    def wake_reason(self, item: Item) -> Optional[str]:
        """Why ``item`` concerns you, if it does: ``"addressed"`` (its ``to``
        names you), ``"reply"`` (it answers one of your items, a job result
        included) or ``"owner"`` (the owner's message to everyone). Your own
        items, progress, items addressed to others and other participants'
        broadcasts concern no one."""
        if item.mine or item.status != "ok" or item.kind == "progress":
            return None
        if item.to is not None and self.participant_pub in item.to:
            return "addressed"
        # A reply reaches the author of what it answers, whoever else it names.
        parent = self._items.get(item.reply_to) if item.reply_to else None
        if parent is not None and parent.mine:
            return "reply"
        if item.to is not None:
            return None
        if item.author_role == "owner" and item.kind in ("text", "file"):
            return "owner"
        return None

    def agent_hops(self, item: Item) -> int:
        """How many items in a row came from programs (anything but the web
        client): up ``item``'s reply chain or, for an addressed item that
        replies to nothing, among the text items just before it since a web
        participant last spoke, whichever is more. Long agent-only exchanges
        are how agents end up answering each other forever. Participant kind
        is self-declared, so this is a safety net against accidental loops,
        not a security boundary."""

        def web(author: str) -> bool:
            return (self._participants.get(author) or {}).get("kind") == "web"

        chain, cur = 0, item
        while cur is not None and chain <= 1000 and not web(cur.author):
            chain += 1
            cur = self._items.get(cur.reply_to) if cur.reply_to else None
        run = 0
        if item.to is not None and item.reply_to is None:
            run = 1
            for item_id in reversed(self._order):
                i = self._items[item_id]
                if i.seq >= item.seq:
                    continue
                if web(i.author) or run > 1000:
                    break
                if i.kind == "text":
                    run += 1
        return max(chain, run)

    def _author_in(self, item: Item, specs: List[str]) -> bool:
        if not specs:
            return True
        p = self._participants.get(item.author)
        if p is None:
            return False
        for spec in specs:
            spec = spec.strip()
            if spec == "owner":
                ok = p["role"] == "owner"
            elif spec.startswith("role:"):
                ok = p["role"] == spec[5:]
            else:
                ok = p["participant_pub"] == spec or p["display_name"] == spec.removeprefix("@")
            if ok:
                return True
        return False

    @property
    def handled_seq(self) -> Optional[int]:
        """The local cursor :meth:`mark_handled` keeps (shared with ``airlox listen``)."""
        return self._cache.handled(self.role)

    def mark_handled(self, seq: Optional[int] = None) -> None:
        """Record that items up to ``seq`` were handled. Only moves forward.
        Without ``seq``, commit the batch :meth:`wait_for_messages` last
        returned."""
        if seq is None:
            seq, self._uncommitted = self._uncommitted, None
            if seq is None:
                return
        if (self.handled_seq or -1) < seq:
            self._cache.save_handled(self.role, seq)

    def _settled_seq(self, pending_timeout: Optional[float] = None) -> int:
        """The highest sequence number below every item still being fetched.
        An item pending longer than ``pending_timeout`` seconds (if given) is
        skipped with a warning, so one that never arrives holds nothing up."""
        now = time.monotonic()
        pending = [i.seq for i in self._items.values() if i.status == "pending"]
        self._pending_since = {seq: self._pending_since.get(seq, now) for seq in pending}
        waiting = []
        for seq in pending:
            if pending_timeout and now - self._pending_since[seq] >= pending_timeout:
                if seq not in self._pending_skipped:
                    self._pending_skipped.add(seq)
                    log.warning(
                        "skipping #%d: still not fetched after %gs; waking for later items", seq, pending_timeout
                    )
            else:
                waiting.append(seq)
        if waiting:
            return min(waiting) - 1
        return max((i.seq for i in self._items.values()), default=0)

    def wait_for_messages(
        self,
        timeout: Optional[float] = None,
        *,
        include_all: bool = False,
        from_: Union[str, Iterable[str], None] = None,
        max_hops: int = 8,
        settle: float = 2.0,
        pending_timeout: Optional[float] = 60.0,
    ) -> List[Item]:
        """Block until items for you arrive (see :meth:`wake_reason`; every
        item from others with ``include_all``) after the handled cursor, and
        return them as one batch. A burst that lands within ``settle``
        seconds comes as one batch. Reply chains with more than ``max_hops``
        program-authored items in a row are skipped (0: no limit; see
        :meth:`agent_hops`). ``from_`` limits who can wake you: ``"owner"``,
        ``"role:<role>"``, display names or keys (default: anyone). An item
        still being fetched after ``pending_timeout`` seconds is skipped with
        a warning (``None`` or 0: wait forever). Returns ``[]`` on timeout or
        when the session closes.

        The batch is acknowledged late: it is marked handled when you next
        call this method, or when you call :meth:`mark_handled` with no
        argument, so a crash while handling it wakes you for it again."""
        deadline = None if timeout is None else time.monotonic() + timeout
        specs = [from_] if isinstance(from_, str) else list(from_ or [])

        def wakes(i: Item) -> bool:
            if include_all:
                ok = not i.mine and i.status == "ok" and i.kind not in ("progress", "event")
            else:
                ok = self.wake_reason(i) is not None
            return ok and self._author_in(i, specs) and (max_hops <= 0 or self.agent_hops(i) <= max_hops)

        self.mark_handled()  # the previous batch was handled if we are asked again
        self.sync()
        cursor = self.handled_seq or 0
        while True:
            upto = self._settled_seq(pending_timeout)
            batch = [self._items[i] for i in self._order if cursor < self._items[i].seq <= upto]
            batch = [i for i in batch if wakes(i)]
            cursor = max(cursor, upto)
            if batch:
                self._uncommitted = cursor
                return batch
            self.mark_handled(cursor)
            left = None if deadline is None else deadline - time.monotonic()
            if self.closed or (left is not None and left <= 0):
                return []
            wait = 300.0 if left is None else min(left, 300.0)
            if pending_timeout:  # come back when a pending item is due to be skipped
                now = time.monotonic()
                due = [pending_timeout - (now - t) for q, t in self._pending_since.items() if q not in self._pending_skipped]
                if due:
                    wait = min(wait, max(0.1, min(due)))
            woke = False
            for item in self.stream(timeout=wait):
                if item.seq > cursor and wakes(item):
                    woke = True
                    break
            if woke:
                time.sleep(settle if left is None else max(0.0, min(settle, deadline - time.monotonic())))
            self.sync()

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
            self._trade_blobs()
            yield from self._retry()
            try:
                with self._http.stream(
                    "GET",
                    self._url("/stream"),
                    headers=headers,
                    timeout=httpx.Timeout(read, connect=10.0),
                ) as r:
                    if r.status_code in (401, 404, 410):
                        self.closed = self.closed or _gone_reason(r.status_code)
                        return
                    if r.status_code != 200:
                        r.read()
                        _check(r)
                    for ev in _sse_events(r.iter_lines()):
                        self.synced_at_ms = _now_ms()
                        item = None if ev is None else self._apply(ev)
                        if item is not None and item.status != "pending":
                            yield item
                        if (ev is not None and ev["kind"] in ("want", "reseeded", "evicted")) or self._reask_due():
                            self._trade_blobs()
                            if self._reseeded:
                                yield from self._retry(set(self._reseeded))
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
        elif kind in ("evicted", "want", "reseeded") and not isinstance(data.get("item"), str):
            pass  # malformed: these name an item
        elif kind == "evicted":
            self._evicted.add(data["item"])
            pending = self._items.get(data["item"])
            if pending is not None and pending.status == "pending":
                pending.status = "evicted"
        elif kind == "want":
            # Only live wants: replayed ones were answered or expired.
            # Only for an item this client verified, never a name the relay made up.
            known = self._items.get(data["item"])
            if fetch and data.get("by") != self.participant_pub and known is not None and known.status == "ok":
                self._asked.add(data["item"])
        elif kind == "reseeded":
            self._reappeared(data["item"])
        elif kind == "left":
            p = self._participants.get(data.get("participant_pub"))
            if p is not None:
                p["left"] = True
        elif kind == "revoked":
            cut = data.get("participants") or []
            for pk in cut:
                p = self._participants.get(pk)
                if p is not None:
                    p["left"] = True
            if self.participant_pub in cut:
                self.closed = f"the owner revoked the {data.get('role', 'this')} role"
        elif kind == "closed":
            self.closed = data.get("reason", "closed")
        if record:
            self._cache.append_event(ev)
        self._last_seq = max(self._last_seq, seq)
        return item

    def _trade_blobs(self) -> None:
        """Re-seeding: ask holders for evicted items this participant never
        got, and upload the blobs others asked for that this cache holds. The
        relay takes an upload only if it matches the author's signed hash, so
        a cached blob is safe to offer."""
        if self.closed:
            return
        auth = {"Authorization": f"Bearer {self._token}"}
        if self._asked:
            # Every holder sees the same want: wait a moment at random, so
            # the first upload usually lands before the others start.
            time.sleep(random.uniform(0, 2))
        for item_id in list(self._asked):
            blob = self._cache.read_blob(item_id)
            if blob is not None:
                try:
                    r = self._http.put(self._url(f"/items/{item_id}/blob"), headers=auth, content=blob)
                except httpx.TransportError:
                    continue
                if r.status_code == 429 or r.status_code >= 500:
                    continue
            self._asked.discard(item_id)
        # Never asked first, then the longest ago; a want lapses on the
        # relay, so one still unanswered is asked for again.
        now = time.monotonic()
        due = [
            i
            for i in self._order
            if self._items[i].status == "evicted"
            and not self._items[i].mine
            and now - self._wanted.get(i, -REASK_S) >= REASK_S
        ]
        for item_id in sorted(due, key=lambda i: self._wanted.get(i, -REASK_S)):
            try:
                r = self._http.post(self._url(f"/items/{item_id}/want"), headers=auth)
            except httpx.TransportError:
                return
            if r.status_code == 429 or r.status_code >= 500:
                return  # too many open, or a busy relay: ask again on a later sync
            if r.status_code == 409 and _error_code(r) == "present":
                self._reappeared(item_id)  # already back: fetch it
            self._wanted[item_id] = time.monotonic()

    def _reask_due(self) -> bool:
        """Whether an unanswered want is due to be asked again."""
        now = time.monotonic()
        return not self.closed and any(
            now - t >= REASK_S and getattr(self._items.get(i), "status", None) == "evicted"
            for i, t in self._wanted.items()
        )

    def _reappeared(self, item_id: str) -> None:
        """An evicted blob is on the relay again: fetch it on the next retry."""
        self._evicted.discard(item_id)
        self._wanted.pop(item_id, None)
        self._asked.discard(item_id)
        item = self._items.get(item_id)
        if item is not None and item.status == "evicted":
            item.status = "pending"
            self._reseeded.add(item_id)

    def _retry(self, only: Optional[set] = None) -> List[Item]:
        """Retry pending downloads (or just those in ``only``) and unsent acks."""
        out = []
        if only is None:
            self._reseeded.clear()
        else:
            self._reseeded -= only
        for item_id in [i for i in self._order if self._items[i].status == "pending" and (only is None or i in only)]:
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
            mine=header["author"] == self.participant_pub,
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
            if not item.mine:
                self._ack(item_id)
        return item


@dataclass
class TransferCode:
    """A one-time code carrying one invite, as its sender holds it."""

    code: str
    role: str
    relay: str
    expires_at_ms: int
    _nameplate: int = field(repr=False)
    _token: str = field(repr=False)
    _http: httpx.Client = field(repr=False)

    def _url(self) -> str:
        return f"{self.relay}/v1/drops/{self._nameplate}"

    def state(self) -> str:
        """``waiting``, ``picked_up``, ``burned``, ``cancelled`` or ``expired``."""
        r = self._http.get(self._url(), headers={"Authorization": f"Bearer {self._token}"})
        return _check(r).json()["state"]

    def wait(self, timeout: Optional[float] = None, poll: float = 2.0) -> str:
        """Block until the code is no longer waiting; returns its state.
        Returns ``"waiting"`` if ``timeout`` (seconds) runs out first."""
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            state = self.state()
            if state != "waiting" or (deadline is not None and time.monotonic() >= deadline):
                return state
            time.sleep(poll if deadline is None else max(0.0, min(poll, deadline - time.monotonic())))

    def cancel(self) -> None:
        """Stop the code from working."""
        _check(self._http.delete(self._url(), headers={"Authorization": f"Bearer {self._token}"}))


def receive_code(code: str, relay: str = "https://airlox.app", *, allow_insecure_http: bool = False) -> str:
    """Trade a one-time transfer code for the invite link it carries. The
    code is used up; a wrong one spends one of its few tries.

    Over plain ``http://`` to another machine the code and the invite cross
    the network in the clear, so that needs ``allow_insecure_http``."""
    if not allow_insecure_http:
        try:
            ac.check_transport(relay.rstrip("/"))
        except ac.ValidationError:
            raise ValueError(
                f"{relay}: a code claimed over plain http:// crosses the network in the clear; use https, "
                "or pass allow_insecure_http=True on a network you trust"
            ) from None
    nameplate, claim = ac.transfer_claim(code)
    with httpx.Client(timeout=httpx.Timeout(30.0, connect=10.0)) as http:
        r = _check(http.post(f"{relay.rstrip('/')}/v1/drops/{nameplate}/claim", json={"claim": claim}))
    return ac.transfer_open(code, r.json()["box"])


def _gone_reason(status: int) -> str:
    """Why the relay stopped answering: the session is gone, or (401) this
    participant left or its role was revoked."""
    if status == 401:
        return "the relay no longer accepts this participant (it left, or its role was revoked)"
    return "no longer on the relay"


def _check(r: httpx.Response) -> httpx.Response:
    if r.status_code >= 400:
        try:
            body = r.json()
            code, message = body.get("error", "error"), body.get("message", "")
        except ValueError:
            code, message = "error", r.text
        raise RelayError(r.status_code, code, message)
    return r


def _error_code(r: httpx.Response) -> Optional[str]:
    try:
        body = r.json()
    except ValueError:
        return None
    return body.get("error") if isinstance(body, dict) else None


def _sse_events(lines: Iterator[str]) -> Iterator[Optional[dict]]:
    """Minimal SSE parser yielding ``{seq, kind, data}``, and ``None`` for
    each comment (keepalive)."""
    event = data = ident = None
    for line in lines:
        if line == "":
            if data is not None and event is not None:
                yield {"seq": int(ident) if ident else -1, "kind": event, "data": json.loads(data)}
            event = data = ident = None
        elif line.startswith(":"):
            yield None  # a keepalive: lets the caller do periodic work
        else:
            name, _, value = line.partition(":")
            value = value[1:] if value.startswith(" ") else value
            if name == "event":
                event = value
            elif name == "data":
                data = value if data is None else data + "\n" + value
            elif name == "id":
                ident = value
