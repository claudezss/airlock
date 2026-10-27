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
