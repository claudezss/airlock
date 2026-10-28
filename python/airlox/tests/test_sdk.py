import io
import struct
import threading
import time
import zipfile
import zlib

import httpx
import pytest

import airlox
from airlox import Session


def png(w=3, h=2, rgb=(200, 10, 10)) -> bytes:
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d))
    raw = b"".join(b"\x00" + bytes(rgb) * w for _ in range(h))
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)
    exif_like = chunk(b"tEXt", b"Comment\x00gps=51.5,-0.1")
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + exif_like + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")


def a_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("dataset/orders.csv", "region,total\neast,10\n")
    return buf.getvalue()


def wait_for(pred, timeout=5.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(0.05)
    return False


def relay_blob_status(relay, s, item_id):
    return httpx.get(
        f"{relay.url}/v1/sessions/{s.session_id}/items/{item_id}/blob",
        headers={"Authorization": f"Bearer {s._token}"},
    ).status_code


def test_end_to_end_all_types_and_delete_on_delivery(relay, caches):
    owner = Session.create(relay.url, cache_dir=caches("owner"))
    agent = Session.join(owner.invites["sender"], display_name="planner-agent", cache_dir=caches("agent"))

    text_ref = agent.send_text("Cleaned dataset attached.")
    md = agent.send_file(b"# Orders\n\nDeduplicated export.\n", name="README.md", refs=[text_ref])
    zp = agent.send_file(a_zip(), name="dataset.zip")
    img = agent.send_file(png(), name="chart.png")
    py = agent.send_file(b"print('hi')\n", name="summarize.py")

    items = {i.id: i for i in owner.items() if i.author == agent.participant_pub}
    assert len(items) == 5
    t, m, z, p, code = (items[r["id"]] for r in (text_ref, md, zp, img, py))
    assert t.text == "Cleaned dataset attached." and t.author_name == "planner-agent" and t.author_role == "sender"
    assert m.name == "README.md" and m.body.startswith(b"# Orders") and m.refs == [text_ref]
    assert z.mime == "application/zip" and zipfile.ZipFile(io.BytesIO(z.body)).namelist() == ["dataset/orders.csv"]
    assert p.mime == "image/png" and p.body.startswith(b"\x89PNG") and b"gps=" not in p.body, "metadata stripped"
    assert code.body == b"print('hi')\n"
    assert all(i.ref == r for i, r in zip((t, m, z, p, code), (text_ref, md, zp, img, py)))

    # The owner was the only recipient and acked everything: the relay drops the blobs.
    assert wait_for(lambda: all(relay_blob_status(relay, owner, r["id"]) == 410 for r in (text_ref, md, zp, img, py)))
    blobs = list((relay.data / "sessions" / owner.session_id / "blobs").iterdir())
    assert blobs == []


def test_history_survives_eviction(relay, caches):
    owner = Session.create(relay.url, cache_dir=caches("owner"))
    agent = Session.join(owner.invites["sender"], cache_dir=caches("agent"))
    ref = agent.send_text("keep me")
    assert [i.text for i in owner.items()] == ["keep me"]
    assert wait_for(lambda: relay_blob_status(relay, owner, ref["id"]) == 410)

    # Reopening from the same cache rejoins as the same participant and reads from history.
    reopened = Session.join(owner.invites["owner"], cache_dir=caches("owner"))
    assert reopened.participant_pub == owner.participant_pub
    assert [(i.text, i.status) for i in reopened.items()] == [("keep me", "ok")]


def test_items_know_which_are_mine(relay, caches):
    owner = Session.create(relay.url, cache_dir=caches("owner"))
    agent = Session.join(owner.invites["sender"], cache_dir=caches("agent"))
    owner.send_text("from the owner")
    agent.send_text("from the agent")
    assert {i.text: i.mine for i in owner.items()} == {"from the owner": True, "from the agent": False}
    assert {i.text: i.mine for i in agent.items()} == {"from the owner": False, "from the agent": True}

    # Items loaded from the local cache are marked the same way.
    reopened = Session.join(owner.invites["sender"], cache_dir=caches("agent"))
    assert {i.text: i.mine for i in reopened.items()} == {"from the owner": False, "from the agent": True}


def test_late_joiner_sees_evicted_items(relay, caches):
    owner = Session.create(relay.url, cache_dir=caches("owner"))
    agent = Session.join(owner.invites["sender"], cache_dir=caches("agent"))
    ref = agent.send_text("early")
    owner.items()
    assert wait_for(lambda: relay_blob_status(relay, owner, ref["id"]) == 410)
    late = Session.join(owner.invites["observer"], cache_dir=caches("late"))
    [item] = late.items()
    assert item.status == "evicted" and item.text is None
    # Something posted after it joined reaches it.
    agent.send_text("after you joined")
    assert [i.text for i in late.items() if i.available] == ["after you joined"]


def test_relay_restart_keeps_session(relay, caches):
    owner = Session.create(relay.url, cache_dir=caches("owner"))
    agent = Session.join(owner.invites["sender"], cache_dir=caches("agent"))
    agent.send_text("before restart")
    relay.restart()
    for s in (owner, agent):
        s.relay = relay.url
    agent.send_text("after restart")
    assert [i.text for i in owner.items()] == ["before restart", "after restart"]


def test_stream_yields_live_items(relay, caches):
    owner = Session.create(relay.url, cache_dir=caches("owner"))
    agent = Session.join(owner.invites["sender"], cache_dir=caches("agent"))

    def later():
        time.sleep(0.3)
        agent.send_text("one")
        agent.send_text("two")

    threading.Thread(target=later).start()
    got = []
    for item in owner.stream(timeout=5):
        got.append(item.text)
        if len(got) == 2:
            break
    assert got == ["one", "two"]


def test_policy_is_enforced_client_and_relay_side(relay, caches):
    owner = Session.create(relay.url, allowed_types=["text"], cache_dir=caches("owner"))
    agent = Session.join(owner.invites["sender"], cache_dir=caches("agent"))
    with pytest.raises(airlox.PolicyError):
        agent.send_file(b"# no", name="x.md")
    observer = Session.join(owner.invites["observer"], cache_dir=caches("obs"))
    with pytest.raises(airlox.RelayError) as e:
        observer.send_text("observers are read-only")
    assert e.value.status == 403
    with pytest.raises(PermissionError):
        agent.invites


def test_owner_close_ends_streams(relay, caches):
    owner = Session.create(relay.url, cache_dir=caches("owner"))
    agent = Session.join(owner.invites["sender"], cache_dir=caches("agent"))
    threading.Timer(0.3, owner.close).start()
    list(agent.stream(timeout=5))
    assert agent.closed == "closed by owner"


def test_failed_download_stays_pending_and_is_retried(relay, caches):
    owner = Session.create(relay.url, cache_dir=caches("owner"))
    agent = Session.join(owner.invites["sender"], cache_dir=caches("agent"))
    ref = agent.send_text("first")

    real_get = owner._http.get
    calls = {"n": 0}

    def flaky_get(url, **kw):
        if "/blob" in url and calls["n"] == 0:
            calls["n"] += 1
            raise httpx.ReadError("connection reset")
        return real_get(url, **kw)

    owner._http.get = flaky_get
    first = owner.sync()
    assert first == []
    pending = [i for i in owner.items() if i.id == ref["id"]]
    assert pending and pending[0].status == "ok"  # items() synced again and retried
    owner._http.get = real_get
    # The retried download was acked, so the relay evicts the blob.
    assert wait_for(lambda: relay_blob_status(relay, owner, ref["id"]) == 410)


def test_participants_come_from_the_signed_join(relay, caches):
    owner = Session.create(relay.url, cache_dir=caches("owner"))
    agent = Session.join(owner.invites["sender"], display_name="planner-agent", cache_dir=caches("agent"))
    owner.sync()
    real = next(p for p in owner.participants() if p["participant_pub"] == agent.participant_pub)
    assert (real["role"], real["display_name"]) == ("sender", "planner-agent")
    # A relay that relabels the unsigned fields changes nothing.
    events = owner._req("GET", "/events").json()["events"]
    ev = next(e for e in events if e["kind"] == "participant" and e["data"]["participant_pub"] == agent.participant_pub)
    forged = dict(ev, seq=10_000, data=dict(ev["data"], role="owner", display_name="Owner"))
    owner._apply(forged, record=False)
    again = next(p for p in owner.participants() if p["participant_pub"] == agent.participant_pub)
    assert (again["role"], again["display_name"]) == ("sender", "planner-agent")


def test_history_opens_after_the_relay_purged_the_session(relay, caches):
    owner = Session.create(relay.url, cache_dir=caches("owner"))
    invite = owner.invites["owner"]
    agent = Session.join(owner.invites["sender"], cache_dir=caches("agent"))
    agent.send_text("keep me")
    assert [i.text for i in owner.items()] == ["keep me"]
    owner.close()
    reopened = Session.join(invite, cache_dir=caches("owner"))
    assert reopened.closed
    assert [i.text for i in reopened.items()] == ["keep me"]
    assert list(reopened.stream(timeout=1)) == []


def test_leave_releases_deliveries_and_revokes_the_token(relay, caches):
    owner = Session.create(relay.url, cache_dir=caches("owner"))
    stale = Session.join(owner.invites["observer"], cache_dir=caches("stale"))
    agent = Session.join(owner.invites["sender"], cache_dir=caches("agent"))
    ref = agent.send_text("for everyone")
    owner.sync()  # owner fetches and acks; the stale observer never does
    time.sleep(0.5)
    assert relay_blob_status(relay, owner, ref["id"]) == 200
    stale.leave(delete_cache=True)
    assert wait_for(lambda: relay_blob_status(relay, owner, ref["id"]) == 410)
    with pytest.raises(airlox.RelayError) as e:
        stale._req("GET", "/events")
    assert e.value.status == 401


def test_one_cache_holds_an_identity_per_role(relay, caches):
    owner = Session.create(relay.url, cache_dir=caches("shared"))
    observer = Session.join(owner.invites["observer"], cache_dir=caches("shared"))
    again = Session.join(owner.invites["owner"], cache_dir=caches("shared"))
    assert again.participant_pub == owner.participant_pub
    assert observer.participant_pub != owner.participant_pub


def test_a_late_joiner_gets_an_evicted_file_from_a_peer(relay, caches, tmp_path):
    owner = Session.create(relay.url, cache_dir=caches("owner"))
    sender = Session.join(owner.invites["sender"], display_name="sender", cache_dir=caches("sender"))
    report = tmp_path / "report.md"
    report.write_text("# Findings\n\nAll green.\n")
    sent = sender.send_file(report)
    # The only recipient stores and acks it, so the relay deletes the blob.
    assert [i.name for i in owner.items() if i.kind == "file"] == ["report.md"]
    deadline = time.monotonic() + 10
    while sent["id"] not in owner._evicted:
        assert time.monotonic() < deadline, "the relay never evicted the blob"
        time.sleep(0.1)
        owner.sync()

    late = Session.join(owner.invites["observer"], display_name="late", cache_dir=caches("late"))
    (item,) = [i for i in late.items() if i.kind == "file"]
    assert item.status == "evicted"
    # Its sync asked for the blob; the sender's next sync uploads it from its cache.
    sender.sync()
    (item,) = [i for i in late.items() if i.kind == "file"]
    assert item.status == "ok" and item.body == report.read_bytes()
    # The relay keeps a re-seeded blob only until its askers have it.
    deadline = time.monotonic() + 10
    while sent["id"] not in late._evicted:
        assert time.monotonic() < deadline, "the re-seeded blob was never evicted"
        time.sleep(0.1)
        late.sync()
    # Nothing is asked for again: the late joiner has the file now.
    sender.sync()
    assert [i.status for i in late.items() if i.kind == "file"] == ["ok"]


def test_revoking_a_role_and_exporting_the_audit_trail(relay, caches):
    owner = Session.create(relay.url, cache_dir=caches("owner"))
    agent = Session.join(owner.invites["sender"], display_name="agent", cache_dir=caches("agent"))
    viewer = Session.join(owner.invites["observer"], display_name="viewer", cache_dir=caches("viewer"))
    agent.send_text("before")
    with pytest.raises(PermissionError):
        agent.revoke("observer")
    owner.revoke("sender")
    # The revoked participant learns it from the event, or from a dead token.
    agent.sync()
    assert agent.closed and "revoked" in agent.closed
    with pytest.raises(airlox.RelayError) as e:
        Session.join(owner.invites["sender"], display_name="again", cache_dir=caches("again"))
    assert e.value.code == "revoked"
    viewer.sync()
    assert {p["display_name"]: p["left"] for p in viewer.participants()}["agent"] is True
    assert not viewer.closed

    trail = viewer.audit()
    # The viewer's own acks land wherever its syncs happened to run.
    trail = [a for a in trail if a["action"] != "ack"]
    assert [a["action"] for a in trail] == ["create", "join", "join", "join", "item", "revoke"]
    assert trail[-1]["participants"] == [agent.participant_pub]
    assert trail[4]["actor"] == agent.participant_pub and trail[4]["blob_sha256"]


def test_a_session_can_last_until_it_is_closed(relay, caches):
    owner = Session.create(relay.url, ttl=None, cache_dir=caches("owner"))
    assert owner.manifest["expires_at_ms"] is None
    agent = Session.join(owner.invites["sender"], cache_dir=caches("agent"))
    agent.send_text("no deadline")
    assert [i.text for i in owner.items()] == ["no deadline"]


def test_a_transfer_code_carries_one_invite_once(relay, caches):
    owner = Session.create(relay.url, cache_dir=caches("owner"))
    code = owner.transfer_code("sender")
    assert code.state() == "waiting"
    assert airlox.receive_code(code.code, relay.url) == owner.invites["sender"]
    assert code.wait(timeout=5) == "picked_up"
    with pytest.raises(airlox.RelayError) as e:
        airlox.receive_code(code.code, relay.url)
    assert e.value.status == 410
    # A cancelled code carries nothing; only the owner can make codes.
    other = owner.transfer_code("observer")
    other.cancel()
    assert other.state() == "cancelled"
    with pytest.raises(airlox.RelayError):
        airlox.receive_code(other.code, relay.url)
    agent = Session.join(owner.invites["sender"], cache_dir=caches("agent"))
    with pytest.raises(PermissionError):
        agent.transfer_code("sender")
    with pytest.raises(ValueError):
        owner.transfer_code("runner")  # a relay-mode session has no runners
    with pytest.raises(ValueError, match="allow_owner"):
        owner.transfer_code("owner")
    # Not over plain http to another machine unless asked.
    third = owner.transfer_code("sender")
    other = relay.url.replace("127.0.0.1", "127.1")
    with pytest.raises(ValueError, match="allow_insecure_http"):
        airlox.receive_code(third.code, other)
    assert airlox.receive_code(third.code, other, allow_insecure_http=True) == owner.invites["sender"]


def test_package_names_are_normalized(relay, caches):
    limits = {"runtime": "python3.12", "timeout_s": 20, "memory_mb": 512, "network": False,
              "packages": ["pyPowerGEM", "NumPy", "numpy"], "return_out": True, "approve_runners": True}
    owner = Session.create(relay.url, mode="execute", job_limits=limits, cache_dir=caches("owner"))
    assert owner.manifest["job_limits"]["packages"] == ["pypowergem", "numpy"]


def test_the_item_limit_defaults_to_the_relays(tmp_path, caches):
    from conftest import Relay
    r = Relay(tmp_path / "relay", max_item_bytes="40MiB").start()
    try:
        assert Session.create(r.url, cache_dir=caches("a")).manifest["max_item_bytes"] == 40 << 20
        assert Session.create(r.url, max_item_bytes=1 << 20, cache_dir=caches("b")).manifest["max_item_bytes"] == 1 << 20
    finally:
        r.stop()
    # A relay's answer raises the default to 100 MB at most.
    r = Relay(tmp_path / "relay2", max_item_bytes="2GiB").start()
    try:
        assert Session.create(r.url, cache_dir=caches("c")).manifest["max_item_bytes"] == 100 << 20
    finally:
        r.stop()


def test_plain_http_only_to_the_host_the_session_names(relay, caches, monkeypatch):
    # A cluster service name, resolved to this machine in this process only.
    import socket
    real = socket.getaddrinfo

    def resolve(host, *a, **kw):
        return real("127.0.0.1" if host in ("airlox-relay.test", "other-relay.test") else host, *a, **kw)

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    url = relay.url.replace("127.0.0.1", "airlox-relay.test")
    with pytest.raises(airlox.ValidationError, match="insecure-http-host"):
        Session.create(url, cache_dir=caches("refused"))
    owner = Session.create(url, insecure_http_host="Airlox-Relay.test", cache_dir=caches("owner"))
    assert owner.manifest["insecure_http_host"] == "airlox-relay.test"
    link = owner.invites["sender"]
    assert link.startswith("http://airlox-relay.test:")
    agent = Session.join(link, cache_dir=caches("agent"))
    agent.send_text("over plain http")
    assert wait_for(lambda: any(i.text == "over plain http" for i in owner.sync()))
    # The same session's keys with another plain-http host are refused.
    moved = link.replace("airlox-relay.test", "other-relay.test")
    with pytest.raises(airlox.ValidationError):
        Session.join(moved, cache_dir=caches("moved"))
    # Hosts URL parsers read as IPv4 must be plain dotted quads.
    with pytest.raises(airlox.ValidationError, match="four decimal numbers"):
        Session.create(url, insecure_http_host="2130706433", cache_dir=caches("numeric"))


def test_addressed_messages_replies_and_waking(relay, caches):
    owner = Session.create(relay.url, display_name="lead", cache_dir=caches("owner"))
    planner = Session.join(owner.invites["sender"], display_name="planner", cache_dir=caches("planner"))
    coder = Session.join(owner.invites["sender"], display_name="coder", cache_dir=caches("coder"))
    planner.sync()

    planner.send_text("FYI only")  # to everyone: wakes no one
    ask = planner.send_text("@coder write the parser", to=["coder"])
    with pytest.raises(ValueError, match="no other participant"):
        planner.send_text("hi", to=["nobody"])
    with pytest.raises(ValueError, match="no other participant"):
        planner.send_text("hi", to=["planner"])  # never yourself

    batch = coder.wait_for_messages(timeout=10, settle=0.2)
    assert [(i.text, coder.wake_reason(i)) for i in batch] == [("@coder write the parser", "addressed")]
    assert batch[0].to == [coder.participant_pub]
    # The cursor is saved: nothing more until something new arrives.
    assert coder.wait_for_messages(timeout=1, settle=0) == []
    assert coder.handled_seq >= batch[0].seq

    done = coder.send_text("done", reply_to=ask["id"])
    got = planner.wait_for_messages(timeout=10, settle=0.2)
    assert [(i.text, i.reply_to, planner.wake_reason(i)) for i in got] == [("done", ask["id"], "reply")]

    # The owner's broadcasts concern everyone; another sender's do not.
    owner.send_text("wrap up by noon")
    assert [i.text for i in coder.wait_for_messages(timeout=10, settle=0.2)] == ["wrap up by noon"]

    # Agent-only reply chains stop waking past max_hops.
    planner.send_text("thanks", reply_to=done["id"])
    assert coder.wait_for_messages(timeout=2, settle=0, max_hops=2) == []

    # A reply wakes the author of what it answers even when it names others.
    q = coder.send_text("which branch?")
    owner.send_text("main; @planner please merge", to=["planner"], reply_to=q["id"])
    assert [coder.wake_reason(i) for i in coder.wait_for_messages(timeout=10, settle=0.2)] == ["reply"]

    # Delivery: the author sees who fetched its items; fetched, not read.
    assert wait_for(lambda: coder.participant_pub in planner.delivery()[ask["id"]]["delivered"])
    assert planner.synced_at_ms and planner.latest_seq


def test_wait_for_messages_acknowledges_late(relay, caches):
    owner = Session.create(relay.url, display_name="lead", cache_dir=caches("owner"))
    coder = Session.join(owner.invites["sender"], display_name="coder", cache_dir=caches("coder"))
    first = owner.send_text("one", to=["coder"])
    [got] = coder.wait_for_messages(timeout=10, settle=0.2)
    assert got.id == first["id"]
    # Not marked handled yet: a crash here would wake the next process for it.
    assert (coder.handled_seq or 0) < got.seq
    again = Session.join(owner.invites["sender"], display_name="coder", cache_dir=caches("coder"))
    assert [i.id for i in again.wait_for_messages(timeout=10, settle=0.2)] == [first["id"]]
    # Committing explicitly, or by asking again, moves the cursor.
    coder.mark_handled()
    assert coder.handled_seq >= got.seq
    second = owner.send_text("two", to=["coder"])
    [got2] = coder.wait_for_messages(timeout=10, settle=0.2)
    assert got2.id == second["id"] and coder.handled_seq < got2.seq
    assert coder.wait_for_messages(timeout=1, settle=0) == []
    assert coder.handled_seq >= got2.seq


def test_wait_for_messages_can_limit_who_wakes_it(relay, caches):
    owner = Session.create(relay.url, display_name="lead", cache_dir=caches("owner"))
    planner = Session.join(owner.invites["sender"], display_name="planner", cache_dir=caches("planner"))
    coder = Session.join(owner.invites["sender"], display_name="coder", cache_dir=caches("coder"))
    planner.send_text("do the thing", to=["coder"])
    assert coder.wait_for_messages(timeout=2, settle=0, from_="owner") == []
    owner.send_text("wrap up")
    assert [i.text for i in coder.wait_for_messages(timeout=10, settle=0.2, from_=["role:owner"])] == ["wrap up"]
    planner.send_text("again", to=["coder"])
    assert [i.text for i in coder.wait_for_messages(timeout=10, settle=0.2, from_=["@planner"])] == ["again"]
    planner.send_text("by key", to=["coder"])
    assert [i.text for i in coder.wait_for_messages(timeout=10, settle=0.2, from_=planner.participant_pub)] == ["by key"]


def test_agents_addressing_each_other_without_replying_hit_the_hop_limit(relay, caches):
    owner = Session.create(relay.url, display_name="lead", cache_dir=caches("owner"))
    a = Session.join(owner.invites["sender"], display_name="a", cache_dir=caches("a"))
    b = Session.join(owner.invites["sender"], display_name="b", cache_dir=caches("b"))
    for n in range(6):
        who, other = (a, "b") if n % 2 == 0 else (b, "a")
        who.send_text(f"ping {n}", to=[other])  # no reply_to: no chain to follow
    b.sync()
    hops = [b.agent_hops(i) for i in b.items() if i.kind == "text"]
    assert hops == [1, 2, 3, 4, 5, 6]
    # b is the addressee of pings 0, 2 and 4, at 1, 3 and 5 hops.
    assert [i.text for i in b.wait_for_messages(timeout=10, settle=0.2, max_hops=3)] == ["ping 0", "ping 2"]
    # A person speaking resets the run (participant kind is self-declared).
    b._participants[owner.participant_pub]["kind"] = "web"
    owner.send_text("carry on")
    a.send_text("next", to=["b"])
    b.sync()
    [nxt] = [i for i in b.items() if i.text == "next"]
    assert b.agent_hops(nxt) == 1
    assert [i.text for i in b.wait_for_messages(timeout=10, settle=0.2, max_hops=3)] == ["carry on", "next"]


def test_an_item_that_never_arrives_stops_holding_up_later_ones(relay, caches, caplog):
    owner = Session.create(relay.url, display_name="lead", cache_dir=caches("owner"))
    coder = Session.join(owner.invites["sender"], display_name="coder", cache_dir=caches("coder"))
    lost = owner.send_text("lost", to=["coder"])
    later = owner.send_text("later", to=["coder"])
    coder.sync()
    stuck = coder._items[lost["id"]]
    stuck.status = "pending"  # as if its blob could not be fetched
    coder._retry = lambda only=None: []  # and nobody can supply it
    assert coder._settled_seq(None) == stuck.seq - 1
    assert coder._settled_seq(0.3) == stuck.seq - 1
    time.sleep(0.4)
    with caplog.at_level("WARNING", logger="airlox.session"):
        assert coder._settled_seq(0.3) == coder._items[later["id"]].seq
        coder._settled_seq(0.3)
    assert [r.getMessage() for r in caplog.records if f"#{stuck.seq}" in r.getMessage()] == [
        f"skipping #{stuck.seq}: still not fetched after 0.3s; waking for later items"
    ]
    assert [i.text for i in coder.wait_for_messages(timeout=10, settle=0, pending_timeout=0.3)] == ["later"]


def test_an_item_given_up_on_wakes_you_when_it_arrives_after_all(relay, caches):
    owner = Session.create(relay.url, display_name="lead", cache_dir=caches("owner"))
    coder = Session.join(owner.invites["sender"], display_name="coder", cache_dir=caches("coder"))
    lost = owner.send_text("lost", to=["coder"])
    owner.send_text("later", to=["coder"])
    coder.sync()
    stuck = coder._items[lost["id"]]
    stuck.status = "pending"  # as if its blob could not be fetched
    coder._retry = lambda only=None: []
    apply, gone = coder._apply, [True]

    def still_missing(ev, **kw):  # the relay says it is evicted: here it stays unfetched
        got = apply(ev, **kw)
        if gone[0]:
            stuck.status = "pending"
        return got

    coder._apply = still_missing
    assert [i.text for i in coder.wait_for_messages(timeout=10, settle=0, pending_timeout=0.3)] == ["later"]
    coder.mark_handled()
    # It turns up after the cursor went past it: it is not lost.
    gone[0], stuck.status = False, "ok"
    assert [i.text for i in coder.wait_for_messages(timeout=10, settle=0, pending_timeout=0.3)] == ["lost"]
    assert coder.wait_for_messages(timeout=1, settle=0, pending_timeout=0.3) == []


def test_tree_globs_match_the_cli():
    from airlox.tree import _credential_name, glob_match, pattern_matches

    assert glob_match("*.pem", "server.pem") and not glob_match("*.pem", "a/server.pem")
    assert glob_match(".env.*", ".env.local") and not glob_match(".env.*", ".env")
    assert glob_match("id_rsa*", "id_rsa.pub")
    assert glob_match("**/fixtures/*.bin", "tests/fixtures/a.bin") and glob_match("**/fixtures/*.bin", "fixtures/a.bin")
    assert glob_match("data/**", "data/x/y.csv")
    assert pattern_matches("*.pem", "certs/server.pem")
    assert pattern_matches("fixtures", "tests/fixtures/big.bin")
    assert pattern_matches("tests/fixtures", "tests/fixtures/big.bin")
    assert not pattern_matches("tests/fixtures", "other/tests/fixtures/big.bin")
    assert pattern_matches("/build/", "build/out.o") and not pattern_matches("/build/", "src/build/out.o")
    for p in [".env", "app/.env.production", "deploy/key.pem", "id_rsa", ".netrc", "x/credentials.json",
              ".ENV", "keys/ID_ED25519", "home/.aws/credentials", ".npmrc", "infra/prod.tfvars",
              "u/.docker/config.json", ".kube/config"]:
        assert _credential_name(p), p
    for p in ["env.py", "README.md", "src/pem.rs", "credentials.json.example", "app/config.json", "kube/config"]:
        assert not _credential_name(p), p


def test_a_home_directory_outside_git_is_not_a_tree(tmp_path, monkeypatch):
    from airlox.tree import TreeRefused, build

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))  # Windows
    (tmp_path / ".npmrc").write_text("//registry/:_authToken=x\n")
    with pytest.raises(TreeRefused, match="home directory"):
        build(tmp_path)


def test_a_plain_directory_becomes_a_tree_and_a_delta_lists_everything(tmp_path):
    import json as _json

    from airlox.tree import TREE_JSON, build

    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("print(1)\n")
    (tmp_path / "run.sh").write_text("#!/bin/sh\n")
    (tmp_path / "run.sh").chmod(0o755)
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "HEAD").write_text("x")
    (tmp_path / ".airloxignore").write_text("# comment\n*.log\n")
    (tmp_path / "debug.log").write_text("x")
    # Outside a repository the directory is the root, `.git` and ignored files left out.
    t = build(tmp_path)
    assert not t.in_git and t.cwd is None and t.json["head"] is None and t.json["dirty"]
    assert sorted(t.listing()) == [".airloxignore", "run.sh", "src/a.py"]
    modes = {f["path"]: f["mode"] for f in t.json["files"]}
    assert modes["run.sh"] == 0o100755 and modes["src/a.py"] == 0o100644
    airlox._core.inspect_zip(t.zip)
    assert build(tmp_path).zip == t.zip, "the same files make the same zip"
    assert sorted(build(tmp_path / "src").listing()) == ["a.py"]

    held = dict(t.listing(), **{"src/a.py": "0" * 64})
    data, n = t.delta(held)
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        assert sorted(z.namelist()) == [TREE_JSON, "src/a.py"] and n == 1
        desc = _json.loads(z.read(TREE_JSON))
    assert desc["delta"] is True and desc["count"] == 3 and len(desc["files"]) == 3
    assert t.delta(t.listing())[1] == 0 and t.delta({}) is None
