//! Checks the committed vectors two ways:
//! 1. The generator still produces them byte for byte (the format is frozen).
//! 2. Every derived value and verification step passes using only the file.
//!
//! The Python and wasm binding tests repeat step 2 through their own APIs.

use airlox_core::api;
use airlox_core::cert::{SignedJoinRequest, SignedRoleCert};
use airlox_core::encoding::{b64d, b64d_32, canonical_json};
use airlox_core::invite::Invite;
use airlox_core::item::{item_key, ItemEnvelope, ItemRef, SealedItem};
use airlox_core::keys::Keypair;
use airlox_core::payload::Payload;
use airlox_core::policy;
use airlox_core::session::{Role, SessionParams, SessionSecrets, SignedManifest};
use airlox_core::Error;
use serde_json::Value;

const FILE: &str = include_str!("../vectors/v1.json");

fn v() -> Value {
    serde_json::from_str(FILE).unwrap()
}

fn st(v: &Value) -> &str {
    v.as_str().unwrap()
}

#[test]
fn vectors_are_frozen() {
    let generated = airlox_core::vectors::generate().unwrap();
    assert_eq!(
        generated,
        v(),
        "vectors/v1.json is stale or the wire format changed; a format change needs a protocol version bump"
    );
}

#[test]
fn derivation_and_manifest() {
    let v = v();
    let seed = b64d_32(st(&v["inputs"]["owner_seed"])).unwrap();
    let s = SessionSecrets::from_owner_seed(seed);
    assert_eq!(s.session_id(), st(&v["session"]["session_id"]));
    assert_eq!(b64d(st(&v["session"]["session_key"])).unwrap(), s.session_key());
    assert_eq!(s.owner().public().to_b64(), st(&v["session"]["owner_pub"]));
    for role in Role::MEMBERS {
        assert_eq!(b64d(st(&v["session"]["role_seeds"][role.as_str()])).unwrap(), s.role_seed(role));
    }

    let params: SessionParams = serde_json::from_value(v["inputs"]["session_params"].clone()).unwrap();
    let signed: SignedManifest = serde_json::from_value(v["manifest"]["signed"].clone()).unwrap();
    signed.verify().unwrap();
    assert_eq!(s.manifest(&params).unwrap(), signed);
    assert_eq!(signed.manifest.canonical_bytes().unwrap(), st(&v["manifest"]["canonical"]).as_bytes());
    assert_eq!(SignedManifest::from_json(st(&v["manifest"]["signed_canonical"])).unwrap(), signed);
    for n in v["negative_canonical"].as_array().unwrap() {
        assert!(SignedManifest::from_json(st(&n["signed_manifest"])).is_err(), "{}", n["name"]);
    }
}

#[test]
fn invites_certs_join() {
    let v = v();
    let m: SignedManifest = serde_json::from_value(v["manifest"]["signed"].clone()).unwrap();
    for (name, role) in [
        ("owner", Role::Owner),
        ("sender", Role::Sender),
        ("runner", Role::Runner),
        ("observer", Role::Observer),
    ] {
        let i = Invite::parse(st(&v["invites"][name])).unwrap();
        assert_eq!(i.role, role);
        i.check_against(&m.manifest).unwrap();
        assert_eq!(i.to_url(), st(&v["invites"][name]));
    }
    for c in v["certs"].as_array().unwrap() {
        let cert: SignedRoleCert = serde_json::from_value(c["signed"].clone()).unwrap();
        cert.verify(&m.manifest).unwrap();
        assert_eq!(cert.role().as_str(), st(&c["role"]));
        assert_eq!(canonical_json(&cert.cert).unwrap(), st(&c["canonical"]).as_bytes());
        let p = Keypair::from_seed(&b64d_32(st(&c["participant_seed"])).unwrap());
        assert_eq!(p.public().to_b64(), st(&c["participant_pub"]));
        assert_eq!(p.public().fingerprint(), st(&c["participant_fingerprint"]));
    }
    let j: SignedJoinRequest = serde_json::from_value(v["join"]["signed"].clone()).unwrap();
    j.verify(&m.manifest).unwrap();
    assert_eq!(canonical_json(&j.join).unwrap(), st(&v["join"]["canonical"]).as_bytes());
    let cert_json = api::join_cert(st(&v["join"]["signed_canonical"])).unwrap();
    assert_eq!(api::verify_cert(&cert_json, st(&v["manifest"]["signed_canonical"])).unwrap(), "runner");
    for n in v["negative_invites"].as_array().unwrap() {
        assert!(Invite::parse(st(&n["url"])).is_err(), "{}", n["name"]);
    }
    for n in v["negative_invites_for_manifest"].as_array().unwrap() {
        let i = Invite::parse(st(&n["url"])).unwrap();
        assert!(i.check_against(&m.manifest).is_err(), "{}", n["name"]);
    }
}

#[test]
fn negative_payloads() {
    for n in v()["negative_payloads"].as_array().unwrap() {
        assert!(Payload::decode(&b64d(st(&n["payload"])).unwrap()).is_err(), "{}", n["name"]);
    }
}

#[test]
fn items_open_and_pass_policy() {
    let v = v();
    let m: SignedManifest = serde_json::from_value(v["manifest"]["signed"].clone()).unwrap();
    let key = b64d_32(st(&v["session"]["session_key"])).unwrap();
    for it in v["items"].as_array().unwrap() {
        let env: ItemEnvelope = serde_json::from_value(it["envelope"].clone()).unwrap();
        let sealed = SealedItem { envelope: env, blob: b64d(st(&it["blob"])).unwrap() };
        assert_eq!(canonical_json(&sealed.envelope).unwrap(), st(&it["envelope_canonical"]).as_bytes());
        assert_eq!(airlox_core::encoding::b64e(&sealed.blob_sha256()), st(&it["blob_sha256"]));
        let h = sealed.header().clone();
        assert_eq!(h.canonical_bytes().unwrap(), st(&it["header_canonical"]).as_bytes());
        assert_eq!(b64d(st(&it["item_key"])).unwrap(), item_key(&key, &h.session_id, &h.id));
        let pt = sealed.open(&key).unwrap();
        assert_eq!(pt, b64d(st(&it["payload"])).unwrap(), "{}", it["name"]);
        let p = Payload::decode(&pt).unwrap();
        assert_eq!(canonical_json(&p.meta).unwrap(), st(&it["payload_meta_canonical"]).as_bytes());
        let cert: SignedRoleCert = serde_json::from_value(
            v["certs"][it["author_cert_index"].as_u64().unwrap() as usize]["signed"].clone(),
        )
        .unwrap();
        let role = policy::author_role(&m.manifest, &cert, &h).unwrap();
        assert_eq!(role, Role::parse(st(&it["author_role"])).unwrap());
        policy::check_payload(&m.manifest, role, &h, &p).unwrap();
        // Re-sealing with the recorded nonce reproduces the blob exactly.
        let author = Keypair::from_seed(&b64d_32(st(&it["author_seed"])).unwrap());
        let nonce: [u8; 12] = b64d(st(&it["nonce"])).unwrap().try_into().unwrap();
        let new = serde_json::from_value(it["new_item"].clone()).unwrap();
        let again = airlox_core::item::seal_with_nonce(&key, &author, new, &pt, nonce).unwrap();
        assert_eq!(again, sealed);
    }
}

#[test]
fn refs_chain_through_the_vectors() {
    let v = v();
    let items = v["items"].as_array().unwrap();
    let sealed = |i: usize| SealedItem {
        envelope: serde_json::from_value(items[i]["envelope"].clone()).unwrap(),
        blob: b64d(st(&items[i]["blob"])).unwrap(),
    };
    // markdown -> text, job -> markdown, result -> job
    for (from, to) in [(1, 0), (2, 1), (3, 2)] {
        let r: &ItemRef = &sealed(from).envelope.header.refs[0];
        assert!(r.matches(&sealed(to)), "item {from} must pin item {to}");
    }
}

#[test]
fn negative_items_fail_as_expected() {
    let v = v();
    let key = b64d(st(&v["session"]["session_key"])).unwrap();
    for n in v["negative_items"].as_array().unwrap() {
        let k = n.get("session_key").map(|k| b64d(st(k)).unwrap()).unwrap_or(key.clone());
        let err =
            api::open_item(&k, st(&n["envelope_canonical"]), &b64d(st(&n["blob"])).unwrap()).unwrap_err();
        match st(&n["expect"]) {
            "signature" => assert!(matches!(err, Error::Signature(_)), "{}: {err}", n["name"]),
            "decrypt" => assert_eq!(err, Error::Decrypt, "{}", n["name"]),
            "invalid" => {
                assert!(matches!(err, Error::Invalid { .. } | Error::Json(_)), "{}: {err}", n["name"])
            }
            other => panic!("unknown expectation {other}"),
        }
    }
}
