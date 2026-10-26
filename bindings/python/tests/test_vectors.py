"""Replays crates/airlock-core/vectors/v1.json through the Python binding."""

import base64
import io
import json
import pathlib
import zipfile

import pytest

import airlock_core as ac

VEC = json.loads(
    (pathlib.Path(__file__).parents[3] / "crates/airlock-core/vectors/v1.json").read_text()
)
MANIFEST = VEC["manifest"]["signed_canonical"]
CERTS = {c["role"]: c for c in VEC["certs"]}
CREATED = VEC["inputs"]["session_params"]["created_at_ms"]


def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def test_protocol_version():
    assert ac.PROTOCOL_VERSION == VEC["version"] == 1


def test_session_derivation_and_manifest():
    seed = b64d(VEC["inputs"]["owner_seed"])
    params = json.dumps(VEC["inputs"]["session_params"])
    out_seed, signed = ac.create_session(params, seed)
    assert out_seed == seed
    assert signed == MANIFEST
    assert ac.verify_manifest(MANIFEST) == VEC["manifest"]["canonical"]
    assert ac.public_key(seed) == VEC["session"]["owner_pub"]


def test_manifest_tamper_and_non_canonical_rejected():
    m = json.loads(MANIFEST)
    m["manifest"]["job_limits"]["network"] = True
    with pytest.raises(ac.SignatureError):
        ac.verify_manifest(canonical(m))
    for n in VEC["negative_canonical"]:
        with pytest.raises(ac.ValidationError):
            ac.verify_manifest(n["signed_manifest"])


@pytest.mark.parametrize("role", ["owner", "sender", "runner", "observer"])
def test_invites(role):
    url = VEC["invites"][role]
    info, session_key, role_seed = ac.parse_invite(url)
    info = json.loads(info)
    assert info["role"] == role
    assert info["session_id"] == VEC["session"]["session_id"]
    assert session_key == b64d(VEC["session"]["session_key"])
    if role != "owner":
        assert role_seed == b64d(VEC["session"]["role_seeds"][role])
    ac.check_invite(url, MANIFEST)
    seed = b64d(VEC["inputs"]["owner_seed"])
    base = VEC["inputs"]["base_url"]
    rebuilt = ac.owner_invite(base, seed) if role == "owner" else ac.member_invite(base, seed, role)
    assert rebuilt == url


@pytest.mark.parametrize("case", VEC["negative_invites"], ids=lambda c: c["name"])
def test_bad_invites_rejected(case):
    with pytest.raises(ac.ValidationError):
        ac.parse_invite(case["url"])


def test_certs_and_join():
    for c in VEC["certs"]:
        assert ac.verify_cert(c["signed_canonical"], MANIFEST) == c["role"]
        assert ac.public_key(b64d(c["participant_seed"])) == c["participant_pub"]
        assert ac.fingerprint(c["participant_pub"]) == c["participant_fingerprint"]
    ac.verify_join(VEC["join"]["signed_canonical"], MANIFEST)
    # The sender role key cannot certify a runner.
    sender_seed = b64d(VEC["session"]["role_seeds"]["sender"])
    forged = ac.issue_cert(sender_seed, VEC["session"]["session_id"], "runner", CERTS["runner"]["participant_pub"], 1)
    with pytest.raises(ac.SignatureError):
        ac.verify_cert(forged, MANIFEST)


def test_items_open_checked():
    key = b64d(VEC["session"]["session_key"])
    for it in VEC["items"]:
        env, blob = it["envelope_canonical"], b64d(it["blob"])
        cert = VEC["certs"][it["author_cert_index"]]["signed_canonical"]
        assert ac.check_header(MANIFEST, cert, env, blob) == it["author_role"]
        role, meta, _body = ac.open_checked(MANIFEST, cert, key, env, blob)
        assert role == it["author_role"]
        assert meta == it["payload_meta_canonical"]
        assert ac.open_item(key, env, blob) == b64d(it["payload"]), it["name"]
        assert json.loads(ac.item_ref(env, blob))["blob_sha256"] == it["blob_sha256"]


def test_role_comes_from_the_cert_not_the_caller():
    # The text item was written by the sender; the owner's certificate names a
    # different key, so it cannot be used to give that item owner rights.
    it = VEC["items"][0]
    with pytest.raises(ac.PolicyError, match="author does not match"):
        ac.check_header(MANIFEST, CERTS["owner"]["signed_canonical"], it["envelope_canonical"], b64d(it["blob"]))


def test_negative_items():
    key = b64d(VEC["session"]["session_key"])
    expected = {"signature": ac.SignatureError, "decrypt": ac.DecryptError, "invalid": ac.ValidationError}
    for n in VEC["negative_items"]:
        k = b64d(n["session_key"]) if "session_key" in n else key
        with pytest.raises(expected[n["expect"]]):
            ac.open_item(k, n["envelope_canonical"], b64d(n["blob"]))


@pytest.mark.parametrize("case", VEC["negative_payloads"], ids=lambda c: c["name"])
def test_negative_payloads(case):
    with pytest.raises(ac.ValidationError):
        ac.decode_payload(b64d(case["payload"]))


def seal(kind, subkind, meta, author="sender", body=b""):
    key = b64d(VEC["session"]["session_key"])
    new = {
        "id": ac.new_item_id(),
        "session_id": VEC["session"]["session_id"],
        "kind": kind,
        "subkind": subkind,
        "created_at_ms": CREATED + 100,
    }
    payload = ac.encode_payload(json.dumps(meta), body)
    env, blob = ac.seal_item(key, b64d(CERTS[author]["participant_seed"]), json.dumps(new), payload)
    return key, env, blob


def test_seal_roundtrip_and_observer_cannot_post():
    key, env, blob = seal("text", None, {"type": "text", "text": "hello"}, author="observer")
    assert ac.open_item(key, env, blob)
    with pytest.raises(ac.PolicyError):
        ac.check_header(MANIFEST, CERTS["observer"]["signed_canonical"], env, blob)


def test_job_outside_allowlist_is_refused():
    ref = json.loads(ac.item_ref(VEC["items"][1]["envelope_canonical"], b64d(VEC["items"][1]["blob"])))
    job = {
        "type": "job", "filename": "fit.py", "code": "import scipy", "runtime": "python3.12",
        "timeout_s": 30, "memory_mb": None, "files": [ref], "requirements": ["scipy"],
        "target": {"type": "labels", "labels": ["cpu"]},
    }
    key, env, blob = seal("job", "py", job)
    with pytest.raises(ac.PolicyError, match="scipy not in allowlist"):
        ac.open_checked(MANIFEST, CERTS["sender"]["signed_canonical"], key, env, blob)


def test_zip_payload_gets_archive_rules():
    evil = io.BytesIO()
    with zipfile.ZipFile(evil, "w") as z:
        z.writestr("../escape.txt", "x")
    key, env, blob = seal("file", "zip", {"type": "file", "name": "data.zip", "mime": "application/zip"},
                          body=evil.getvalue())
    with pytest.raises(ac.ValidationError):
        ac.open_checked(MANIFEST, CERTS["sender"]["signed_canonical"], key, env, blob)


def test_zip_inspect_and_extract(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("dataset/orders.csv", "a,b\n1,2\n")
    entries = json.loads(ac.inspect_zip(buf.getvalue()))
    assert entries[0]["path"] == "dataset/orders.csv"
    ac.extract_zip(buf.getvalue(), str(tmp_path))
    assert (tmp_path / "dataset/orders.csv").read_text() == "a,b\n1,2\n"
    with pytest.raises(ac.ValidationError, match="not empty"):
        ac.extract_zip(buf.getvalue(), str(tmp_path))


def test_sanitize_image_rejects_garbage():
    with pytest.raises(ac.ValidationError):
        ac.sanitize_image(b"GIF89a")


def test_shim_source_is_embedded():
    assert "SHIM_VERSION = 1" in ac.shim_source()
