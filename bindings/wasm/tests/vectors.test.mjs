// Replays crates/airlock-core/vectors/v1.json through the wasm binding.
// Run: npm test  (after `npm run build`)
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const ac = require("../pkg/node/airlock_core_wasm.js");
const VEC = JSON.parse(
  readFileSync(new URL("../../../crates/airlock-core/vectors/v1.json", import.meta.url), "utf8"),
);
const MANIFEST = JSON.stringify(VEC.manifest.signed);
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
  assert.deepEqual(JSON.parse(out.signedManifest), VEC.manifest.signed);
  assert.equal(ac.verifyManifest(MANIFEST), VEC.manifest.canonical);
  const m = JSON.parse(MANIFEST);
  m.manifest.max_item_bytes += 1;
  assert.equal(errClass(() => ac.verifyManifest(JSON.stringify(m))), "SignatureError");
});

test("invites", () => {
  for (const role of ["owner", "sender", "runner", "observer"]) {
    const inv = ac.parseInvite(VEC.invites[role]);
    assert.equal(inv.role, role);
    assert.equal(inv.sessionId, VEC.session.session_id);
    assert.deepEqual(inv.sessionKey, b64d(VEC.session.session_key));
    ac.checkInvite(VEC.invites[role], MANIFEST);
  }
});

test("certs and join", () => {
  for (const c of VEC.certs) {
    assert.equal(ac.verifyCert(JSON.stringify(c.signed), MANIFEST), c.role);
    assert.equal(ac.publicKey(b64d(c.participant_seed)), c.participant_pub);
    assert.equal(ac.fingerprint(c.participant_pub), c.participant_fingerprint);
  }
  ac.verifyJoin(JSON.stringify(VEC.join.signed), MANIFEST);
});

test("items open and pass policy", () => {
  const key = b64d(VEC.session.session_key);
  for (const it of VEC.items) {
    const env = JSON.stringify(it.envelope);
    const blob = b64d(it.blob);
    const pt = ac.openItem(key, env, blob);
    assert.deepEqual(pt, b64d(it.payload), it.name);
    assert.equal(ac.decodePayload(pt).meta, it.payload_meta_canonical);
    ac.checkPayload(MANIFEST, it.author_role, env, pt);
  }
});

test("negative items", () => {
  const key = b64d(VEC.session.session_key);
  const want = { signature: "SignatureError", decrypt: "DecryptError" };
  for (const n of VEC.negative_items) {
    const k = n.session_key ? b64d(n.session_key) : key;
    assert.equal(errClass(() => ac.openItem(k, JSON.stringify(n.envelope), b64d(n.blob))), want[n.expect], n.name);
  }
});

test("seal in wasm, open with vectors key", () => {
  const key = b64d(VEC.session.session_key);
  const sender = b64d(VEC.certs[1].participant_seed);
  const payload = ac.encodePayload(JSON.stringify({ type: "text", text: "from the browser" }), new Uint8Array());
  const created = VEC.inputs.session_params.created_at_ms + 50;
  const out = ac.sealItem(
    key,
    sender,
    JSON.stringify({ id: ac.newItemId(), session_id: VEC.session.session_id, kind: "text", subkind: null, created_at_ms: created }),
    payload,
  );
  assert.deepEqual(ac.openItem(key, out.envelope, out.blob), payload);
  assert.equal(errClass(() => ac.checkHeader(MANIFEST, "observer", out.envelope)), "PolicyError");
});
