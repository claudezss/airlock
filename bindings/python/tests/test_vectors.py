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
MANIFEST = json.dumps(VEC["manifest"]["signed"])


def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def test_protocol_version():
    assert ac.PROTOCOL_VERSION == VEC["version"] == 1


def test_session_derivation_and_manifest():
    seed = b64d(VEC["inputs"]["owner_seed"])
    params = json.dumps(VEC["inputs"]["session_params"])
    out_seed, signed = ac.create_session(params, seed)
    assert out_seed == seed
    assert json.loads(signed) == VEC["manifest"]["signed"]
    assert ac.verify_manifest(MANIFEST) == VEC["manifest"]["canonical"]
    assert ac.public_key(seed) == VEC["session"]["owner_pub"]


def test_manifest_tamper_detected():
    m = json.loads(MANIFEST)
    m["manifest"]["job_limits"]["network"] = True
    with pytest.raises(ac.SignatureError):
        ac.verify_manifest(json.dumps(m))


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


def test_bad_invite_rejected():
    with pytest.raises(ac.ValidationError):
        ac.parse_invite(VEC["invites"]["sender"].replace("v=1", "v=9"))


def test_certs_and_join():
    for c in VEC["certs"]:
        assert ac.verify_cert(json.dumps(c["signed"]), MANIFEST) == c["role"]
        seed = b64d(c["participant_seed"])
        assert ac.public_key(seed) == c["participant_pub"]
        assert ac.fingerprint(c["participant_pub"]) == c["participant_fingerprint"]
    ac.verify_join(json.dumps(VEC["join"]["signed"]), MANIFEST)
    # The sender role key cannot certify a runner.
    sender_seed = b64d(VEC["session"]["role_seeds"]["sender"])
    forged = ac.issue_cert(
        sender_seed, VEC["session"]["session_id"], "runner", VEC["certs"][2]["participant_pub"], 1
    )
    with pytest.raises(ac.SignatureError):
        ac.verify_cert(forged, MANIFEST)


def test_items_open_and_pass_policy():
    key = b64d(VEC["session"]["session_key"])
    for it in VEC["items"]:
        env = json.dumps(it["envelope"])
        blob = b64d(it["blob"])
        ac.verify_item(env, blob)
        payload = ac.open_item(key, env, blob)
        assert payload == b64d(it["payload"]), it["name"]
        meta, _body = ac.decode_payload(payload)
        assert meta == it["payload_meta_canonical"]
        ac.check_header(MANIFEST, it["author_role"], env)
        ac.check_payload(MANIFEST, it["author_role"], env, payload)


def test_negative_items():
    key = b64d(VEC["session"]["session_key"])
    expected = {"signature": ac.SignatureError, "decrypt": ac.DecryptError}
    for n in VEC["negative_items"]:
        k = b64d(n["session_key"]) if "session_key" in n else key
        with pytest.raises(expected[n["expect"]]):
            ac.open_item(k, json.dumps(n["envelope"]), b64d(n["blob"]))


def test_seal_roundtrip_and_policy_errors():
    key = b64d(VEC["session"]["session_key"])
    sender_seed = b64d(VEC["certs"][1]["participant_seed"])
    observer_role = "observer"
    new = {
        "id": ac.new_item_id(),
        "session_id": VEC["session"]["session_id"],
        "kind": "text",
        "subkind": None,
        "created_at_ms": VEC["inputs"]["session_params"]["created_at_ms"] + 100,
    }
    payload = ac.encode_payload(json.dumps({"type": "text", "text": "hello"}))
    env, blob = ac.seal_item(key, sender_seed, json.dumps(new), payload)
    assert ac.open_item(key, env, blob) == payload
    with pytest.raises(ac.PolicyError):
        ac.check_header(MANIFEST, observer_role, env)


def test_job_outside_allowlist_is_refused():
    key = b64d(VEC["session"]["session_key"])
    sender_seed = b64d(VEC["certs"][1]["participant_seed"])
    job = {
        "type": "job", "filename": "fit.py", "code": "import scipy", "runtime": "python3.12",
        "timeout_s": 30, "memory_mb": None, "files": [], "requirements": ["scipy"],
        "target": {"type": "labels", "labels": ["cpu"]},
    }
    payload = ac.encode_payload(json.dumps(job))
    new = {
        "id": ac.new_item_id(), "session_id": VEC["session"]["session_id"], "kind": "job",
        "subkind": "py", "created_at_ms": VEC["inputs"]["session_params"]["created_at_ms"] + 5,
    }
    env, _ = ac.seal_item(key, sender_seed, json.dumps(new), payload)
    with pytest.raises(ac.PolicyError, match="scipy not in allowlist"):
        ac.check_payload(MANIFEST, "sender", env, payload)


def test_zip_inspect_and_extract(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("dataset/orders.csv", "a,b\n1,2\n")
    entries = json.loads(ac.inspect_zip(buf.getvalue()))
    assert entries[0]["path"] == "dataset/orders.csv"
    ac.extract_zip(buf.getvalue(), str(tmp_path))
    assert (tmp_path / "dataset/orders.csv").read_text() == "a,b\n1,2\n"

    evil = io.BytesIO()
    with zipfile.ZipFile(evil, "w") as z:
        z.writestr("../escape.txt", "x")
    with pytest.raises(ac.ValidationError):
        ac.inspect_zip(evil.getvalue())


def test_sanitize_image_rejects_garbage():
    with pytest.raises(ac.ValidationError):
        ac.sanitize_image(b"GIF89a")


def test_shim_source_is_embedded():
    assert "SHIM_VERSION = 1" in ac.shim_source()
