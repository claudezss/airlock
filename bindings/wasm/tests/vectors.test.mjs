// Replays crates/airlox-core/vectors/v1.json through the wasm binding.
// Run: npm test  (after `npm run build`)
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const ac = require("../pkg/node/airlox_core_wasm.js");
const VEC = JSON.parse(
  readFileSync(new URL("../../../crates/airlox-core/vectors/v1.json", import.meta.url), "utf8"),
);
const MANIFEST = VEC.manifest.signed_canonical;
const CERTS = Object.fromEntries(VEC.certs.map((c) => [c.role, c]));
const b64d = (s) => new Uint8Array(Buffer.from(s, "base64url"));
const errClass = (fn) => {
  try {
    fn();
  } catch (e) {
    return e.message.split(":")[0];
  }
  return null;
};

test("protocol version", () => assert.equal(ac.protocolVersion(), 1));

test("session derivation and manifest", () => {
  const seed = b64d(VEC.inputs.owner_seed);
  const out = ac.createSession(JSON.stringify(VEC.inputs.session_params), seed);
  assert.deepEqual(out.ownerSeed, seed);
  assert.equal(out.signedManifest, MANIFEST);
  assert.equal(ac.verifyManifest(MANIFEST), VEC.manifest.canonical);
  for (const n of VEC.negative_canonical) {
    assert.equal(errClass(() => ac.verifyManifest(n.signed_manifest)), "ValidationError", n.name);
  }
});

test("invites", () => {
  for (const role of ["owner", "sender", "runner", "observer"]) {
    const inv = ac.parseInvite(VEC.invites[role]);
    assert.equal(inv.role, role);
    assert.equal(inv.sessionId, VEC.session.session_id);
    assert.deepEqual(inv.sessionKey, b64d(VEC.session.session_key));
    ac.checkInvite(VEC.invites[role], MANIFEST);
  }
  for (const n of VEC.negative_invites) {
    assert.equal(errClass(() => ac.parseInvite(n.url)), "ValidationError", n.name);
  }
  for (const n of VEC.negative_invites_for_manifest) {
    ac.parseInvite(n.url);
    assert.equal(errClass(() => ac.checkInvite(n.url, MANIFEST)), "ValidationError", n.name);
  }
});

test("certs and join", () => {
  for (const c of VEC.certs) {
    assert.equal(ac.verifyCert(c.signed_canonical, MANIFEST), c.role);
    assert.equal(ac.publicKey(b64d(c.participant_seed)), c.participant_pub);
    assert.equal(ac.fingerprint(c.participant_pub), c.participant_fingerprint);
  }
  ac.verifyJoin(VEC.join.signed_canonical, MANIFEST);
});

test("items open with cert-bound roles", () => {
  const key = b64d(VEC.session.session_key);
  for (const it of VEC.items) {
    const blob = b64d(it.blob);
    const cert = VEC.certs[it.author_cert_index].signed_canonical;
    assert.equal(ac.checkHeader(MANIFEST, cert, it.envelope_canonical, blob), it.author_role);
    const out = ac.openChecked(MANIFEST, cert, key, it.envelope_canonical, blob);
    assert.equal(out.role, it.author_role);
    assert.equal(out.meta, it.payload_meta_canonical);
    assert.equal(JSON.parse(ac.itemRef(it.envelope_canonical, blob)).blob_sha256, it.blob_sha256);
  }
  const it = VEC.items[0];
  assert.equal(
    errClass(() => ac.checkHeader(MANIFEST, CERTS.owner.signed_canonical, it.envelope_canonical, b64d(it.blob))),
    "PolicyError",
  );
});

test("negative items and payloads", () => {
  const key = b64d(VEC.session.session_key);
  const want = { signature: "SignatureError", decrypt: "DecryptError", invalid: "ValidationError" };
  for (const n of VEC.negative_items) {
    const k = n.session_key ? b64d(n.session_key) : key;
    assert.equal(errClass(() => ac.openItem(k, n.envelope_canonical, b64d(n.blob))), want[n.expect], n.name);
  }
  for (const n of VEC.negative_payloads) {
    assert.equal(errClass(() => ac.decodePayload(b64d(n.payload))), "ValidationError", n.name);
  }
});

test("seal in wasm, open with vectors key", () => {
  const key = b64d(VEC.session.session_key);
  const payload = ac.encodePayload(JSON.stringify({ type: "text", text: "from the browser" }), new Uint8Array());
  const created = VEC.inputs.session_params.created_at_ms + 50;
  const out = ac.sealItem(
    key,
    b64d(CERTS.observer.participant_seed),
    JSON.stringify({ id: ac.newItemId(), session_id: VEC.session.session_id, kind: "text", subkind: null, created_at_ms: created }),
    payload,
  );
  assert.deepEqual(ac.openItem(key, out.envelope, out.blob), payload);
  assert.equal(errClass(() => ac.checkHeader(MANIFEST, CERTS.observer.signed_canonical, out.envelope, out.blob)), "PolicyError");
});
