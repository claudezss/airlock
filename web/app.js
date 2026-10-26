// Airlock web client (M1 timeline). All cryptography runs in the
// airlock-core WebAssembly module; the relay only sees ciphertext.
import init, * as ac from "/assets/pkg/airlock_core_wasm.js";

const MAX_ITEM_BYTES = 25 * 1024 * 1024;
const FILE_TYPES = {
  ".py": ["py", "text/x-python"],
  ".md": ["md", "text/markdown"],
  ".markdown": ["md", "text/markdown"],
  ".zip": ["zip", "application/zip"],
  ".png": ["image", "image/png"],
  ".jpg": ["image", "image/jpeg"],
  ".jpeg": ["image", "image/jpeg"],
  ".webp": ["image", "image/webp"],
};

// ---------- DOM helpers (no innerHTML: all content is untrusted) ----------
function el(tag, props = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v === true ? "" : String(v));
  }
  for (const c of children.flat()) if (c !== null && c !== undefined) e.append(c instanceof Node ? c : String(c));
  return e;
}
const app = document.getElementById("app");
const show = (...nodes) => app.replaceChildren(...nodes);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const errClass = (e) => String(e?.message || e).split(":")[0];
const fmtBytes = (n) => (n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`);

// ---------- IndexedDB: identity, events and ciphertext blobs ----------
const db = await new Promise((res, rej) => {
  const r = indexedDB.open("airlock", 1);
  r.onupgradeneeded = () => {
    for (const s of ["identity", "events", "blobs"]) r.result.createObjectStore(s);
  };
  r.onsuccess = () => res(r.result);
  r.onerror = () => rej(r.error);
});
function tx(store, mode, fn) {
  return new Promise((res, rej) => {
    const t = db.transaction(store, mode);
    const req = fn(t.objectStore(store));
    t.oncomplete = () => res(req?.result);
    t.onerror = () => rej(t.error);
    t.onabort = () => rej(t.error);
  });
}
const idbGet = (s, k) => tx(s, "readonly", (o) => o.get(k));
const idbPut = (s, k, v) => tx(s, "readwrite", (o) => o.put(v, k));
const range = (sid) => IDBKeyRange.bound([sid], [sid, []]);
async function clearSession(sid) {
  await tx("identity", "readwrite", (o) => o.delete(range(sid)));
  await tx("events", "readwrite", (o) => o.delete(range(sid)));
  await tx("blobs", "readwrite", (o) => o.delete(range(sid)));
}

// ---------- HTTP ----------
async function api(method, path, { token, body, headers = {} } = {}) {
  if (token) headers.Authorization = `Bearer ${token}`;
  const r = await fetch(path, { method, body, headers });
  if (!r.ok) {
    let msg = `${r.status}`;
    try {
      const j = await r.json();
      msg = `${r.status} ${j.error}: ${j.message}`;
    } catch {}
    const e = new Error(msg);
    e.status = r.status;
    throw e;
  }
  return r;
}

// ---------- landing: create a session ----------
function landing() {
  const ttl = el("select", { id: "ttl" },
    el("option", { value: 900000 }, "15 minutes"),
    el("option", { value: 3600000, selected: true }, "1 hour"),
    el("option", { value: 86400000 }, "24 hours"));
  const types = ["text", "md", "py", "zip", "image"].map((t) =>
    el("label", { class: "choice" }, el("input", { type: "checkbox", value: t, checked: true }), t));
  const out = el("div", { class: "stack" });
  const create = el("button", { class: "primary", onclick: async () => {
    create.disabled = true;
    try {
      const allowed = types.map((l) => l.querySelector("input")).filter((i) => i.checked).map((i) => i.value);
      const params = { mode: "relay", created_at_ms: Date.now(), ttl_ms: Number(ttl.value), allowed_types: allowed,
        max_item_bytes: MAX_ITEM_BYTES, job_limits: null };
      const s = ac.createSession(JSON.stringify(params), undefined);
      await api("POST", "/v1/sessions", { body: s.signedManifest });
      const base = location.origin;
      const invites = [
        ["Owner", ac.ownerInvite(base, s.ownerSeed), "you; keep it private"],
        ["Sender", ac.memberInvite(base, s.ownerSeed, "sender"), "the agent that sends"],
        ["Observer", ac.memberInvite(base, s.ownerSeed, "observer"), "read-only"],
      ];
      out.replaceChildren(
        el("h2", {}, "Hand out invites"),
        el("p", { class: "muted" }, "Each link carries its role and the session key. Copy them now; they cannot be shown again."),
        ...invites.map(([name, url, hint]) => inviteRow(name, url, hint)),
        el("a", { class: "button primary", href: invites[0][1] }, "Open session"),
      );
    } catch (e) {
      out.replaceChildren(el("p", { class: "error" }, String(e.message || e)));
      create.disabled = false;
    }
  } }, "Create session");
  show(el("div", { class: "stack" },
    el("div", {}, el("h1", {}, "New session"),
      el("p", { class: "muted" }, "Keys are generated in this browser. The relay never sees them.")),
    el("div", { class: "panel stack" },
      el("label", { for: "ttl" }, "Expires after"), ttl,
      el("div", {}, el("div", { class: "muted" }, "Allowed content"), el("div", { class: "row" }, types)),
      el("div", { class: "row" }, create)),
    out));
}

function inviteRow(name, url, hint) {
  const btn = el("button", { onclick: async () => {
    await navigator.clipboard.writeText(url);
    btn.textContent = "Copied";
    setTimeout(() => (btn.textContent = "Copy"), 1500);
  } }, "Copy");
  return el("div", { class: "stack" },
    el("div", { class: "row" }, el("strong", {}, name), el("span", { class: "muted" }, hint)),
    el("div", { class: "invite" }, el("code", {}, url), btn));
}

// ---------- session view ----------
async function sessionView() {
  const url = location.href;
  let inv;
  try {
    inv = ac.parseInvite(url);
  } catch (e) {
    return show(el("p", { class: "error" }, "This link is not a valid Airlock invite."));
  }
  const sid = inv.sessionId;
  // The signed manifest is cached with the identity, so history stays
  // readable after the relay has purged the session.
  let identity = await idbGet("identity", [sid, inv.role]);
  let signed;
  let offline = false;
  try {
    signed = (await (await api("GET", `/v1/sessions/${sid}`)).json()).signed_manifest;
  } catch (e) {
    if (e.status !== 404) return show(el("p", { class: "error" }, `Cannot open session: ${e.message}`));
    if (!identity?.signed) return show(el("p", { class: "error" }, "This session has ended or does not exist."));
    signed = identity.signed;
    offline = true;
  }
  try {
    ac.checkInvite(url, signed);
  } catch (e) {
    return show(el("p", { class: "error" }, `This invite does not match the session: ${e.message}`));
  }
  const manifest = JSON.parse(ac.verifyManifest(signed));

  if (!identity) {
    const seed = ac.generateSeed();
    const pub = ac.publicKey(seed);
    const cert = ac.issueCert(inv.roleSeed, sid, inv.role, pub, Date.now());
    const join = { v: 1, session_id: sid, cert: JSON.parse(cert), display_name: `${inv.role} (web)`, kind: "web",
      runner: null, created_at_ms: Date.now() };
    const body = ac.signJoin(seed, JSON.stringify(join));
    const resp = await (await api("POST", `/v1/sessions/${sid}/participants`, { body })).json();
    identity = { seed, token: resp.token, role: inv.role, signed };
    await idbPut("identity", [sid, inv.role], identity);
  } else if (!identity.signed) {
    identity.signed = signed;
    await idbPut("identity", [sid, inv.role], identity);
  }
  const me = ac.publicKey(identity.seed);
  const s = { sid, inv, manifest, signed, identity, me, participants: new Map(), items: new Map(), lastSeq: -1, closed: null };

  // layout
  const timeline = el("div", { class: "timeline", "aria-live": "polite" });
  const people = el("ul", { class: "people" });
  const banner = el("div", { class: "banner", hidden: true });
  const status = el("p", { class: "muted", role: "status" });
  const text = el("textarea", { id: "msg", placeholder: "Message the session" });
  const file = el("input", { type: "file", id: "file", accept: Object.keys(FILE_TYPES).join(",") });
  const canSend = ["owner", "sender"].includes(inv.role);
  const sendBtn = el("button", { class: "primary", onclick: () => sendText(s, text, status) }, "Send");
  const fileBtn = el("button", { onclick: () => sendFile(s, file, status) }, "Send file");
  const composer = canSend
    ? el("div", { class: "panel stack" },
        el("label", { for: "msg", class: "sr-only" }, "Message"), text,
        el("div", { class: "row" }, sendBtn, el("label", { for: "file", class: "sr-only" }, "File"), file, fileBtn), status)
    : el("p", { class: "muted" }, `You joined as ${inv.role}: read-only.`);
  const closeBtn = inv.role === "owner" ? el("button", { class: "danger", onclick: async () => {
    if (!confirm("Close the session and purge it from the relay for everyone?")) return;
    await api("POST", `/v1/sessions/${sid}/close`, { token: identity.token });
  } }, "Close & purge") : null;
  const invites = inv.role === "owner" ? el("div", { class: "panel stack" }, el("h2", {}, "Invites"),
    inviteRow("Sender", ac.memberInvite(location.origin, inv.roleSeed, "sender"), ""),
    inviteRow("Observer", ac.memberInvite(location.origin, inv.roleSeed, "observer"), "")) : null;
  const side = el("aside", { class: "stack" },
    el("div", { class: "panel stack" }, el("h2", {}, "Participants"), people),
    el("div", { class: "panel stack" }, el("h2", {}, "Session"),
      el("div", { class: "mono muted" }, sid),
      el("div", { class: "muted" }, `Expires ${new Date(manifest.expires_at_ms).toLocaleString()}`),
      el("div", { class: "muted" }, `Allowed: ${manifest.allowed_types.join(", ")}`),
      el("button", { onclick: async () => {
        await clearSession(sid);
        location.reload();
      } }, "Clear local history"),
      closeBtn),
    invites);
  show(el("div", { class: "stack" }, banner,
    el("div", { class: "grid" }, el("div", { class: "stack" }, timeline, composer), side)));
  const badge = document.getElementById("badge");
  badge.hidden = false;
  badge.textContent = `E2E · ${inv.role}`;

  s.render = {
    people: () => people.replaceChildren(...[...s.participants.values()].map((p) =>
      el("li", {}, el("span", {}, p.display_name), el("span", { class: "tag" }, p.role)))),
    item: (it) => {
      const node = renderItem(s, it);
      const old = document.getElementById(`item-${it.id}`);
      if (old) old.replaceWith(node);
      else timeline.append(node);
    },
    closed: (reason) => {
      banner.hidden = false;
      banner.textContent = `Session closed: ${reason}. History stays in this browser until you clear it.`;
      for (const c of [sendBtn, fileBtn, text, file, closeBtn]) if (c) c.disabled = true;
      if (invites) invites.hidden = true;
    },
  };

  // cached history first, then catch up, then stream
  const cached = await tx("events", "readonly", (o) => o.getAll(range(sid)));
  for (const ev of cached) await applyEvent(s, ev, { fetch: false, record: false });
  if (offline) {
    if (!s.closed) s.render.closed("no longer on the relay");
    return;
  }
  try {
    const q = s.lastSeq >= 0 ? `?after=${s.lastSeq}` : "";
    const evs = (await (await api("GET", `/v1/sessions/${sid}/events${q}`, { token: identity.token })).json()).events;
    for (const ev of evs) await applyEvent(s, ev, { fetch: true, record: true });
  } catch (e) {
    if (e.status === 404 || e.status === 410) s.render.closed("no longer on the relay");
  }
  streamLoop(s);
}

async function applyEvent(s, ev, { fetch, record }) {
  if (record && ev.seq <= s.lastSeq) return;
  if (ev.kind === "participant") {
    try {
      ac.verifyJoin(ev.data.signed_join, s.signed);
      s.participants.set(ev.data.participant_pub, { ...ev.data, cert: ac.joinCert(ev.data.signed_join) });
      s.render.people();
    } catch (e) {
      console.warn("ignoring unverifiable participant", e);
    }
  } else if (ev.kind === "item") {
    await receive(s, ev.seq, ev.data.envelope, fetch);
  } else if (ev.kind === "closed") {
    s.closed = ev.data.reason;
    s.render.closed(ev.data.reason);
  }
  if (record) await idbPut("events", [s.sid, ev.seq], ev);
  s.lastSeq = Math.max(s.lastSeq, ev.seq);
}

async function receive(s, seq, envelope, fetchBlob) {
  const h = JSON.parse(envelope).header;
  if (s.items.get(h.id)?.status === "ok") return;
  const author = s.participants.get(h.author);
  const it = { seq, id: h.id, kind: h.kind, subkind: h.subkind, author: h.author, created: h.created_at_ms,
    authorName: author?.display_name || "unknown", role: author?.role, status: "ok" };
  s.items.set(h.id, it);
  if (!author) {
    Object.assign(it, { status: "rejected", error: "author is not a verified participant" });
    return s.render.item(it);
  }
  let blob = await idbGet("blobs", [s.sid, h.id]);
  let fresh = false;
  if (!blob) {
    if (!fetchBlob) {
      it.status = "evicted";
      return s.render.item(it);
    }
    const r = await fetch(`/v1/sessions/${s.sid}/items/${h.id}/blob`, { headers: { Authorization: `Bearer ${s.identity.token}` } });
    if (r.status === 410) {
      it.status = "evicted";
      return s.render.item(it);
    }
    if (!r.ok) {
      Object.assign(it, { status: "rejected", error: `download failed (${r.status})` });
      return s.render.item(it);
    }
    blob = new Uint8Array(await r.arrayBuffer());
    fresh = true;
  }
  try {
    const out = ac.openChecked(s.signed, author.cert, s.inv.sessionKey, envelope, blob);
    Object.assign(it, { role: out.role, meta: JSON.parse(out.meta), body: out.body });
  } catch (e) {
    Object.assign(it, { status: "rejected", error: String(e.message || e) });
    return s.render.item(it);
  }
  if (fresh) {
    try {
      await idbPut("blobs", [s.sid, h.id], blob);
      if (h.author !== s.me) {
        await fetch(`/v1/sessions/${s.sid}/items/${h.id}/ack`, { method: "POST", headers: { Authorization: `Bearer ${s.identity.token}` } });
      }
    } catch (e) {
      // Out of browser storage: show the item but do not ack, so the relay keeps it.
      it.note = "Not saved locally (browser storage full).";
    }
  }
  s.render.item(it);
}

function renderItem(s, it) {
  const mine = it.author === s.me;
  const head = el("div", { class: "meta" },
    el("strong", {}, it.authorName), it.role ? el("span", { class: "tag" }, it.role) : null,
    el("span", {}, new Date(it.created).toLocaleTimeString()),
    el("span", { class: "tag" }, it.kind === "file" ? it.subkind : it.kind));
  const node = el("article", { class: `item${mine ? " mine" : ""}`, id: `item-${it.id}` }, head);
  if (it.status === "evicted") {
    node.append(el("p", { class: "note" }, "Delivered and removed from the relay before this browser fetched it."));
    return node;
  }
  if (it.status === "rejected") {
    node.append(el("p", { class: "error" }, `Rejected: ${it.error}`));
    return node;
  }
  const m = it.meta;
  if (m.type === "text") node.append(el("p", {}, m.text));
  else if (m.type === "file") {
    const blobUrl = URL.createObjectURL(new Blob([it.body], { type: m.mime }));
    node.append(el("div", { class: "row" }, el("span", { class: "mono" }, m.name), el("span", { class: "muted" }, fmtBytes(it.body.length)),
      el("a", { class: "button", href: blobUrl, download: m.name }, "Download")));
    if (it.subkind === "image") node.append(el("img", { src: blobUrl, alt: m.name }));
    else if (it.subkind === "zip") {
      try {
        const entries = JSON.parse(ac.inspectZip(it.body));
        node.append(el("ul", { class: "ziplist" }, entries.map((e) => el("li", {}, `${e.path}${e.is_dir ? "/" : ` · ${fmtBytes(e.size)}`}`))));
      } catch (e) {
        node.append(el("p", { class: "error" }, String(e.message || e)));
      }
    } else node.append(el("pre", {}, new TextDecoder().decode(it.body)));
  } else node.append(el("pre", {}, JSON.stringify(m, null, 2)));
  if (it.note) node.append(el("p", { class: "note" }, it.note));
  return node;
}

// ---------- sending ----------
async function sendPayload(s, kind, subkind, meta, body) {
  const needed = kind === "text" ? "text" : subkind;
  if (!s.manifest.allowed_types.includes(needed)) throw new Error(`${needed} is not allowed in this session`);
  const payload = ac.encodePayload(JSON.stringify(meta), body);
  if (payload.length > s.manifest.max_item_bytes) throw new Error(`too large: limit is ${fmtBytes(s.manifest.max_item_bytes)}`);
  const item = { id: ac.newItemId(), session_id: s.sid, kind, subkind, created_at_ms: Date.now(), refs: [] };
  const out = ac.sealItem(s.inv.sessionKey, s.identity.seed, JSON.stringify(item), payload);
  const env = new TextEncoder().encode(out.envelope);
  const frame = new Uint8Array(4 + env.length + out.blob.length);
  new DataView(frame.buffer).setUint32(0, env.length);
  frame.set(env, 4);
  frame.set(out.blob, 4 + env.length);
  await idbPut("blobs", [s.sid, item.id], out.blob);
  await api("POST", `/v1/sessions/${s.sid}/items`, { token: s.identity.token, body: frame,
    headers: { "Content-Type": "application/octet-stream" } });
}

async function sendText(s, textarea, status) {
  const value = textarea.value.trim();
  if (!value) return;
  try {
    await sendPayload(s, "text", null, { type: "text", text: value }, new Uint8Array());
    textarea.value = "";
    status.textContent = "";
  } catch (e) {
    status.textContent = `Not sent: ${e.message || e}`;
  }
}

async function sendFile(s, input, status) {
  const f = input.files?.[0];
  if (!f) return;
  const ext = f.name.slice(f.name.lastIndexOf(".")).toLowerCase();
  const t = FILE_TYPES[ext];
  try {
    if (!t) throw new Error(`unsupported file type ${ext}`);
    let [subkind, mime] = t;
    let bytes = new Uint8Array(await f.arrayBuffer());
    if (subkind === "image") {
      const clean = ac.sanitizeImage(bytes);
      mime = clean.mime;
      bytes = clean.data;
    } else if (subkind === "zip") ac.inspectZip(bytes);
    await sendPayload(s, "file", subkind, { type: "file", name: f.name, mime }, bytes);
    input.value = "";
    status.textContent = "";
  } catch (e) {
    status.textContent = `Not sent: ${errClass(e) === "ValidationError" || errClass(e) === "PolicyError" ? e.message : e.message || e}`;
  }
}

// ---------- live updates over SSE (fetch, so the token stays in a header) ----------
function parseSse(block) {
  const ev = {};
  for (const line of block.split("\n")) {
    if (!line || line.startsWith(":")) continue;
    const i = line.indexOf(":");
    const k = i < 0 ? line : line.slice(0, i);
    const v = i < 0 ? "" : line.slice(i + 1).replace(/^ /, "");
    if (k === "event") ev.kind = v;
    else if (k === "id") ev.seq = Number(v);
    else if (k === "data") ev.data = (ev.data ? ev.data + "\n" : "") + v;
  }
  return ev.kind && ev.data ? { seq: ev.seq, kind: ev.kind, data: JSON.parse(ev.data) } : null;
}

async function streamLoop(s) {
  while (!s.closed) {
    try {
      const headers = { Authorization: `Bearer ${s.identity.token}` };
      if (s.lastSeq >= 0) headers["Last-Event-ID"] = String(s.lastSeq);
      const r = await fetch(`/v1/sessions/${s.sid}/stream`, { headers });
      if (r.status === 404 || r.status === 410) {
        s.closed = "no longer on the relay";
        s.render.closed(s.closed);
        return;
      }
      if (!r.ok) throw new Error(`stream ${r.status}`);
      const reader = r.body.pipeThrough(new TextDecoderStream()).getReader();
      let buf = "";
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += value;
        let i;
        while ((i = buf.indexOf("\n\n")) >= 0) {
          const ev = parseSse(buf.slice(0, i));
          buf = buf.slice(i + 2);
          if (ev) await applyEvent(s, ev, { fetch: true, record: true });
        }
      }
    } catch (e) {
      console.warn("stream interrupted", e);
    }
    if (!s.closed) await sleep(1000);
  }
}

// ---------- boot ----------
try {
  await init();
  if (location.pathname.startsWith("/s/")) await sessionView();
  else landing();
} catch (e) {
  show(el("p", { class: "error" }, `Airlock failed to start: ${e.message || e}`));
}
