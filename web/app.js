// Airlock web client (M1 timeline). All cryptography runs in the
// airlock-core WebAssembly module; the relay only sees ciphertext.
import init, * as ac from "/assets/pkg/airlock_core_wasm.js";

const MB = 1024 * 1024;
const MAX_ITEM_MB = 25;
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
const TYPE_LABELS = [
  ["text", "text", "messages"],
  ["md", "markdown", ".md"],
  ["py", "python", ".py"],
  ["zip", "zip", ".zip"],
  ["image", "image", ".png .jpg .webp"],
];

// ---------- DOM helpers (no innerHTML: all content is untrusted) ----------
function el(tag, props = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (k === "value") e.value = v;
    else e.setAttribute(k, v === true ? "" : String(v));
  }
  for (const c of children.flat()) if (c !== null && c !== undefined && c !== false) e.append(c instanceof Node ? c : String(c));
  return e;
}
function svg(paths, size = 18) {
  const ns = "http://www.w3.org/2000/svg";
  const s = document.createElementNS(ns, "svg");
  for (const [k, v] of Object.entries({ width: size, height: size, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor",
    "stroke-width": 1.8, "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true" })) s.setAttribute(k, v);
  for (const d of paths) {
    const p = document.createElementNS(ns, "path");
    p.setAttribute("d", d);
    s.append(p);
  }
  return s;
}
const ICON_CLIP = ["M21 11.5l-8.5 8.5a5 5 0 0 1-7-7L14 4.5a3.3 3.3 0 0 1 4.7 4.7L10.2 17.7a1.7 1.7 0 0 1-2.4-2.4L15.5 7.6"];
const app = document.getElementById("app");
const show = (...nodes) => app.replaceChildren(...nodes);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const fmtBytes = (n) => (n < 1024 ? `${n} B` : n < MB ? `${(n / 1024).toFixed(1)} KB` : `${(n / MB).toFixed(1)} MB`);
const hhmm = (ms) => new Date(ms).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
const initials = (name) => (name.split(/[^\p{L}\p{N}]+/u).filter(Boolean).slice(0, 2).map((w) => w[0]).join("") || "?").toUpperCase();

function deadEnd(title, cause) {
  show(el("div", { class: "panel stack dead-end", role: "alert" },
    el("h1", {}, title), el("p", { class: "muted" }, cause),
    el("div", { class: "row" }, el("a", { class: "button primary", href: "/" }, "New session"))));
}

// Plain-language reasons for items that fail verification.
function explain(err) {
  const msg = String(err?.message || err);
  const cls = msg.split(":")[0];
  if (cls === "SignatureError") return "The signature does not match a member of this session.";
  if (cls === "DecryptError") return "It could not be decrypted with this session's key.";
  if (cls === "PolicyError") return "This session's rules do not allow it.";
  return "It is malformed.";
}

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
    let code;
    try {
      const j = await r.json();
      code = j.error;
      msg = j.message;
    } catch {}
    const e = new Error(msg);
    e.status = r.status;
    e.code = code;
    throw e;
  }
  return r;
}

// ---------- invites ----------
// Show enough of a link to recognise it without putting the secret on screen.
function maskInvite(url) {
  const [base, frag = ""] = url.split("#");
  const parts = frag.split("&").map((p) => {
    const [k, v = ""] = p.split("=");
    return ["k", "rk", "ok"].includes(k) ? `${k}=${v.slice(0, 4)}…` : p;
  });
  return `${base}#${parts.join("&")}`;
}

function inviteRow(name, url, hint) {
  const shown = el("code", { title: "Hidden: Copy puts the full link on the clipboard" }, maskInvite(url));
  const box = el("div", { class: "invite" }, shown);
  const btn = el("button", { class: "small", type: "button", onclick: async () => {
    try {
      await navigator.clipboard.writeText(url);
      btn.textContent = "Copied";
      setTimeout(() => (btn.textContent = "Copy"), 1500);
    } catch {
      // Clipboard denied: reveal the link in a selected field for manual copy.
      const input = el("input", { type: "text", readonly: true, value: url, "aria-label": `${name} invite link` });
      shown.replaceWith(input);
      input.select();
      btn.textContent = navigator.platform.startsWith("Mac") ? "Press ⌘C" : "Press Ctrl+C";
    }
  } }, "Copy");
  box.append(btn);
  return el("div", { class: "invite-row" },
    el("div", { class: "head" }, el("strong", {}, name), hint ? el("span", { class: "muted" }, hint) : null), box);
}

// ---------- new session ----------
function landing() {
  const radio = (name, value, label, checked, extra = {}) =>
    el("label", { class: "option" }, el("input", { type: "radio", name, value, checked, ...extra }), label);
  const mode = el("fieldset", { class: "stack" }, el("legend", {}, "Mode"),
    el("div", { class: "mode" },
      el("label", { class: "option" }, el("input", { type: "radio", name: "mode", value: "relay", checked: true }),
        el("strong", {}, "Relay"), el("span", {}, "Share messages and files")),
      el("label", { class: "option" }, el("input", { type: "radio", name: "mode", value: "execute", disabled: true }),
        el("strong", {}, "Execute"), el("span", {}, "Run Python on runners · coming in M2"))));
  const ttl = el("fieldset", {}, el("legend", {}, "Expires after"),
    el("div", { class: "options" },
      radio("ttl", 900000, "15 min", false), radio("ttl", 3600000, "1 hour", true), radio("ttl", 86400000, "24 hours", false)));
  const types = el("fieldset", {}, el("legend", {}, "Allowed content"),
    el("div", { class: "options" }, TYPE_LABELS.map(([v, label, ext]) =>
      el("label", { class: "option" }, el("input", { type: "checkbox", name: "type", value: v, checked: true }),
        label, el("span", { class: "ext" }, ext)))));
  const size = el("input", { type: "number", id: "size", min: 1, max: MAX_ITEM_MB, step: 1, value: MAX_ITEM_MB });
  const sizeField = el("div", { class: "stack" }, el("label", { for: "size" }, el("strong", {}, "Max file size")),
    el("div", { class: "size" }, size, el("span", { class: "muted" }, "MB")));
  const err = el("p", { class: "error", role: "alert" });
  const create = el("button", { class: "primary cta", type: "submit" }, "Create session");
  const fields = el("fieldset", { class: "stack" }, mode, ttl, types, sizeField);
  const aside = el("aside", { class: "panel stack" },
    el("h2", {}, "Invites"),
    el("p", { class: "muted" }, "Invite links appear here once the session exists. Each one carries a role and the session key."));

  const form = el("form", { class: "stack", onsubmit: async (ev) => {
    ev.preventDefault();
    err.textContent = "";
    const fd = new FormData(form);
    const allowed = fd.getAll("type");
    const mb = Number(size.value);
    if (!allowed.length) return (err.textContent = "Pick at least one content type.");
    if (!Number.isInteger(mb) || mb < 1 || mb > MAX_ITEM_MB) return (err.textContent = `Max file size must be 1 to ${MAX_ITEM_MB} MB.`);
    create.disabled = true;
    try {
      const params = { mode: "relay", created_at_ms: Date.now(), ttl_ms: Number(fd.get("ttl")), allowed_types: allowed,
        max_item_bytes: mb * MB, job_limits: null };
      const s = ac.createSession(JSON.stringify(params), undefined);
      const { session_id } = await (await api("POST", "/v1/sessions", { body: s.signedManifest })).json();
      fields.disabled = true;
      const base = location.origin;
      const owner = ac.ownerInvite(base, s.ownerSeed);
      const heading = el("h2", { tabindex: -1 }, "Hand out invites");
      aside.replaceChildren(
        el("div", { class: "eyebrow" }, `Created · ${session_id.slice(0, 7)}`),
        heading,
        el("p", { class: "muted" }, "Copy these now. They are not stored anywhere and cannot be shown again."),
        inviteRow("Owner", owner, "you · keep it private"),
        inviteRow("Sender", ac.memberInvite(base, s.ownerSeed, "sender"), "your code agent"),
        inviteRow("Observer", ac.memberInvite(base, s.ownerSeed, "observer"), "read-only, optional"),
        el("div", { class: "row" },
          el("a", { class: "button primary cta", href: owner }, "Open session"),
          el("button", { type: "button", onclick: () => location.reload() }, "Create another")));
      heading.focus();
    } catch (e) {
      err.textContent = `Could not create the session: ${e.message || e}`;
      create.disabled = false;
    }
  } },
    el("div", {}, el("h1", {}, "New session"),
      el("p", { class: "lede" }, "Keys are generated in this browser. The relay never sees them.")),
    fields, err, el("div", { class: "row" }, create));
  show(el("div", { class: "layout" }, form, aside));
}

// ---------- live session ----------
// The invite fragment holds the session key. Keep it out of the address bar
// and browser history; this tab keeps it in sessionStorage so a reload works.
function takeInvite() {
  const path = location.pathname;
  let frag = location.hash.slice(1);
  try {
    if (frag) {
      sessionStorage.setItem(`invite:${path}`, frag);
      history.replaceState(null, "", path);
    } else frag = sessionStorage.getItem(`invite:${path}`) || "";
  } catch {}
  return frag ? `${location.origin}${path}#${frag}` : null;
}

async function sessionView() {
  const url = takeInvite();
  let inv;
  try {
    inv = ac.parseInvite(url);
  } catch {
    return deadEnd("This link is not a valid invite", "Open the full invite link you were given, including the part after #.");
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
    if (e.status !== 404) return deadEnd("Cannot reach the relay", e.message);
    if (!identity?.signed) return deadEnd("This session has ended", "It expired or its owner closed it. Nothing is left on the relay.");
    signed = identity.signed;
    offline = true;
  }
  try {
    ac.checkInvite(url, signed);
  } catch {
    return deadEnd("This invite does not match the session", "The link may be damaged or belong to a different session.");
  }
  const manifest = JSON.parse(ac.verifyManifest(signed));

  if (!identity) {
    const seed = ac.generateSeed();
    const pub = ac.publicKey(seed);
    const cert = ac.issueCert(inv.roleSeed, sid, inv.role, pub, Date.now());
    const join = { v: 1, session_id: sid, cert: JSON.parse(cert), display_name: `${inv.role} (web)`, kind: "web",
      runner: null, created_at_ms: Date.now() };
    const body = ac.signJoin(seed, JSON.stringify(join));
    let resp;
    try {
      resp = await (await api("POST", `/v1/sessions/${sid}/participants`, { body })).json();
    } catch (e) {
      return deadEnd("Could not join", e.message);
    }
    identity = { seed, token: resp.token, role: inv.role, signed };
    await idbPut("identity", [sid, inv.role], identity);
  } else if (!identity.signed) {
    identity.signed = signed;
    await idbPut("identity", [sid, inv.role], identity);
  }
  const me = ac.publicKey(identity.seed);
  const s = { sid, inv, manifest, signed, identity, me, participants: new Map(), items: new Map(), evicted: new Set(),
    lastSeq: -1, closed: null };
  buildSessionLayout(s);

  // Cached history first, then catch up, then stream. Blobs missing locally
  // are fetched again while the relay still has the session.
  const cached = await tx("events", "readonly", (o) => o.getAll(range(sid)));
  for (const ev of cached) if (ev.kind === "evicted") s.evicted.add(ev.data.item);
  for (const ev of cached) await applyEvent(s, ev, { fetch: !offline, record: false });
  s.render.scroll(true);
  if (offline) {
    if (!s.closed) s.render.closed("it is no longer on the relay");
    return;
  }
  try {
    const q = s.lastSeq >= 0 ? `?after=${s.lastSeq}` : "";
    const evs = (await (await api("GET", `/v1/sessions/${sid}/events${q}`, { token: identity.token })).json()).events;
    for (const ev of evs) await applyEvent(s, ev, { fetch: true, record: true });
    s.render.scroll(true);
  } catch (e) {
    if (e.status === 404 || e.status === 410) return s.render.closed("it is no longer on the relay");
  }
  streamLoop(s);
}

function buildSessionLayout(s) {
  const { sid, inv, manifest, identity } = s;
  app.classList.add("wide");
  const timeline = el("div", { class: "timeline", role: "log", "aria-live": "polite", "aria-relevant": "additions" },
    el("div", { class: "pill" }, `you opened the session · keys stay in this browser`),
    el("p", { class: "empty" }, "No messages yet. Items appear here as soon as someone sends one."));
  const people = el("ul", { class: "people" });
  const banner = el("div", { class: "banner", role: "status", hidden: true });
  const canSend = ["owner", "sender"].includes(inv.role);

  // composer
  const status = el("p", { class: "status", role: "status" });
  const text = el("textarea", { id: "msg", rows: 2, placeholder: "Message the session…" });
  const file = el("input", { type: "file", id: "file", class: "sr-only", accept: Object.keys(FILE_TYPES).join(",") });
  const pending = el("span", { class: "pending-file", hidden: true });
  const sendBtn = el("button", { class: "primary", type: "submit" }, "Send");
  const attach = el("label", { class: "button icon-btn", for: "file", title: "Attach a file", "aria-label": "Attach a file" }, svg(ICON_CLIP));
  const showPending = () => {
    const f = file.files?.[0];
    pending.hidden = !f;
    if (f) pending.replaceChildren(svg(ICON_CLIP, 14), el("span", {}, f.name),
      el("button", { type: "button", class: "small", "aria-label": "Remove attachment", onclick: () => {
        file.value = "";
        showPending();
      } }, "✕"));
  };
  file.addEventListener("change", showPending);
  const submit = async () => {
    if (sendBtn.disabled) return;
    sendBtn.disabled = true;
    status.textContent = "";
    try {
      if (file.files?.[0]) {
        await sendFile(s, file.files[0]);
        file.value = "";
        showPending();
      }
      const value = text.value.trim();
      if (value) {
        await sendPayload(s, "text", null, { type: "text", text: value }, new Uint8Array());
        text.value = "";
      }
    } catch (e) {
      status.textContent = `Not sent: ${e.message || e}`;
    } finally {
      sendBtn.disabled = !!s.closed;
    }
  };
  text.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter" && (ev.metaKey || ev.ctrlKey)) {
      ev.preventDefault();
      submit();
    }
  });
  const composer = canSend
    ? el("form", { class: "composer-wrap", onsubmit: (ev) => {
        ev.preventDefault();
        submit();
      } },
        el("div", { class: "composer" },
          el("label", { for: "msg", class: "sr-only" }, "Message the session"), text,
          el("div", { class: "toolbar" }, attach, file, pending,
            el("span", { class: "hint" }, navigator.platform.startsWith("Mac") ? "⌘↵ to send" : "Ctrl+↵ to send"), sendBtn)),
        status)
    : el("div", { class: "panel readonly" }, `You joined as ${inv.role}. You can read this session but not post to it.`);

  // rail
  const closeBtn = inv.role === "owner" ? el("button", { class: "danger", type: "button", onclick: async () => {
    if (!confirm("Close the session and purge it from the relay for everyone?")) return;
    try {
      await api("POST", `/v1/sessions/${sid}/close`, { token: identity.token });
    } catch (e) {
      alert(`Could not close: ${e.message}`);
    }
  } }, "Close & purge") : null;
  const invites = inv.role === "owner" ? el("details", {},
    el("summary", {}, "Invites"),
    el("div", { class: "stack" },
      inviteRow("Sender", ac.memberInvite(location.origin, inv.roleSeed, "sender"), "your code agent"),
      inviteRow("Observer", ac.memberInvite(location.origin, inv.roleSeed, "observer"), "read-only"))) : null;
  const rail = el("aside", { class: "rail" },
    el("section", {}, el("h2", {}, "Participants"), people),
    el("section", {}, el("h2", {}, "Allowed types"), el("div", { class: "chips" }, manifest.allowed_types.map((t) => el("span", { class: "chip" }, t)))),
    el("section", { class: "stack" }, el("h2", {}, "Session"),
      el("p", { class: "mono muted" }, sid),
      el("p", { class: "muted" }, `Expires ${new Date(manifest.expires_at_ms).toLocaleString()}`),
      el("p", { class: "muted" }, `Files up to ${fmtBytes(manifest.max_item_bytes)}`),
      invites, closeBtn),
    el("section", { class: "stack" }, el("h2", {}, "This browser"),
      el("p", { class: "muted" }, "Received items are kept here, still encrypted, so they survive the relay deleting them."),
      el("button", { type: "button", onclick: async () => {
        if (!confirm("Delete this browser's copy of the session and leave it?")) return;
        try {
          await api("POST", `/v1/sessions/${sid}/leave`, { token: identity.token });
        } catch {}
        await clearSession(sid);
        location.reload();
      } }, "Clear local history")));
  show(el("div", { class: "session" }, rail, el("div", { class: "main-col" }, banner, timeline, composer)));

  // header
  document.getElementById("title").hidden = false;
  document.getElementById("title-name").textContent = `Session ${sid.slice(0, 7)}`;
  document.getElementById("title-sub").textContent = `${manifest.mode} · ${inv.role}`;
  document.getElementById("badge").hidden = false;
  document.getElementById("badge-text").textContent = "E2E sealed";
  const expiry = document.getElementById("expiry");
  expiry.hidden = false;
  const tick = () => {
    const left = manifest.expires_at_ms - Date.now();
    if (left <= 0 || s.closed) {
      expiry.textContent = s.closed ? "closed" : "expired";
      expiry.classList.remove("soon");
      return clearInterval(timer);
    }
    const t = Math.floor(left / 1000);
    const h = Math.floor(t / 3600);
    const mm = String(Math.floor((t % 3600) / 60)).padStart(2, "0");
    const ss = String(t % 60).padStart(2, "0");
    expiry.textContent = `expires in ${h ? `${h}:` : ""}${mm}:${ss}`;
    expiry.classList.toggle("soon", left < 5 * 60 * 1000);
  };
  const timer = setInterval(tick, 1000);
  tick();

  const nearBottom = () => window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 160;
  s.render = {
    people: () => people.replaceChildren(...[...s.participants.values()].map((p) =>
      el("li", {},
        el("span", { class: "dot", "aria-hidden": "true" }),
        el("div", { class: "who" },
          el("div", { class: "name" }, p.display_name, p.participant_pub === s.me ? el("span", { class: "you" }, "you") : null),
          el("div", { class: "sub" }, `${p.role} · ${p.kind}${p.left ? " · left" : ""}`)),
        el("span", { class: "key", title: "Key fingerprint" }, ac.fingerprint(p.participant_pub).slice(0, 4))))),
    item: (it) => {
      const stick = nearBottom();
      const node = renderItem(s, it);
      const old = document.getElementById(`item-${it.id}`);
      if (old) old.replaceWith(node);
      else timeline.append(node);
      if (stick && !old) node.scrollIntoView({ block: "end" });
    },
    scroll: () => timeline.lastElementChild?.scrollIntoView({ block: "end" }),
    closed: (reason) => {
      banner.hidden = false;
      banner.textContent = `This session is closed: ${reason}. Its history stays in this browser until you clear it.`;
      for (const c of [sendBtn, text, file, closeBtn]) if (c) c.disabled = true;
      attach.setAttribute("aria-disabled", "true");
      if (invites) invites.hidden = true;
      tick();
    },
  };
}

// Participants come only from verified signed joins, never from the
// relay's unsigned event fields.
async function applyEvent(s, ev, { fetch, record }) {
  if (record && ev.seq <= s.lastSeq) return;
  if (ev.kind === "participant") {
    try {
      ac.verifyJoin(ev.data.signed_join, s.signed);
      const j = JSON.parse(ev.data.signed_join).join;
      const c = j.cert.cert;
      s.participants.set(c.participant_pub, { participant_pub: c.participant_pub, role: c.role,
        display_name: j.display_name, kind: j.kind, cert: ac.joinCert(ev.data.signed_join) });
      s.render.people();
    } catch (e) {
      console.warn("ignoring unverifiable participant", e);
    }
  } else if (ev.kind === "item") {
    await receive(s, ev.seq, ev.data.envelope, fetch);
  } else if (ev.kind === "evicted") {
    s.evicted.add(ev.data.item);
    const it = s.items.get(ev.data.item);
    if (it && it.status === "retry") {
      it.status = "evicted";
      s.render.item(it);
    }
  } else if (ev.kind === "left") {
    const p = s.participants.get(ev.data.participant_pub);
    if (p) {
      p.left = true;
      s.render.people();
    }
  } else if (ev.kind === "closed") {
    s.closed = ev.data.reason;
    const why = { "closed by owner": "the owner closed it", expired: "it expired", idle: "it was idle too long" };
    s.render.closed(why[ev.data.reason] || ev.data.reason);
  }
  if (record) await idbPut("events", [s.sid, ev.seq], ev);
  s.lastSeq = Math.max(s.lastSeq, ev.seq);
}

// Transient download failures (network, 429, 5xx) retry with backoff;
// only a decrypted, verified and stored item counts as done.
async function receive(s, seq, envelope, fetchBlob, attempt = 0) {
  const h = JSON.parse(envelope).header;
  const prev = s.items.get(h.id);
  if (attempt === 0 && prev && prev.status !== "retry") return;
  const author = s.participants.get(h.author);
  const it = { seq, id: h.id, kind: h.kind, subkind: h.subkind, author: h.author, created: h.created_at_ms,
    authorName: author?.display_name || "unknown", role: author?.role, status: "ok", envelope };
  s.items.set(h.id, it);
  if (!author) {
    Object.assign(it, { status: "rejected", error: "The author is not a verified member of this session." });
    return s.render.item(it);
  }
  let blob = await idbGet("blobs", [s.sid, h.id]);
  let fresh = false;
  if (!blob) {
    if (!fetchBlob || s.evicted.has(h.id)) {
      it.status = "evicted";
      return s.render.item(it);
    }
    let r;
    try {
      r = await fetch(`/v1/sessions/${s.sid}/items/${h.id}/blob`, { headers: { Authorization: `Bearer ${s.identity.token}` } });
    } catch {
      r = null;
    }
    if (r?.status === 410 || r?.status === 404) {
      it.status = "evicted";
      return s.render.item(it);
    }
    if (!r || !r.ok) {
      it.status = "retry";
      s.render.item(it);
      if (attempt < 6 && !s.closed) setTimeout(() => receive(s, seq, envelope, true, attempt + 1), 1000 * 2 ** attempt);
      return;
    }
    blob = new Uint8Array(await r.arrayBuffer());
    fresh = true;
  }
  try {
    const out = ac.openChecked(s.signed, author.cert, s.inv.sessionKey, envelope, blob);
    Object.assign(it, { role: out.role, meta: JSON.parse(out.meta), body: out.body });
  } catch (e) {
    Object.assign(it, { status: "rejected", error: explain(e), detail: String(e.message || e) });
    return s.render.item(it);
  }
  if (fresh) {
    let stored = false;
    try {
      await idbPut("blobs", [s.sid, h.id], blob);
      stored = true;
    } catch {
      // Out of browser storage: show the item but do not ack, so the relay keeps it.
      it.note = "Not saved in this browser (storage is full). The relay keeps it until its hold limit.";
    }
    if (stored && h.author !== s.me) {
      fetch(`/v1/sessions/${s.sid}/items/${h.id}/ack`, { method: "POST", headers: { Authorization: `Bearer ${s.identity.token}` } })
        .catch(() => {});
    }
  }
  s.render.item(it);
}

function renderItem(s, it) {
  const mine = it.author === s.me;
  const cls = ["item", mine && "mine", it.status !== "ok" && it.status].filter(Boolean).join(" ");
  const av = ["owner", "sender", "runner"].includes(it.role) ? `av-${it.role}` : "";
  const label = it.kind === "file" ? it.subkind : it.kind;
  const meta = el("div", { class: "meta" },
    el("strong", {}, it.authorName),
    it.role ? el("span", { class: "muted" }, it.role) : null,
    el("span", { class: "when" }, hhmm(it.created),
      it.status === "ok" ? el("span", { class: "verified" }, " · ✓ verified") : null));
  const card = el("div", { class: "card" });
  const node = el("article", { class: cls, id: `item-${it.id}` },
    el("div", { class: `avatar ${av}`, "aria-hidden": "true" }, initials(it.authorName)),
    el("div", { class: "body" }, meta, card));
  if (it.status === "evicted") {
    card.append(el("p", { class: "note" }, `A ${label} item was delivered and then removed from the relay before this browser downloaded it.`));
    return node;
  }
  if (it.status === "retry") {
    card.append(el("p", { class: "note" }, `Downloading this ${label} item failed. Retrying…`));
    return node;
  }
  if (it.status === "rejected") {
    card.append(el("p", {}, `✕ Not shown: ${it.error}`));
    if (it.detail) card.append(el("div", { class: "detail" }, it.detail));
    return node;
  }
  const m = it.meta;
  if (m.type === "text") card.append(el("p", {}, m.text));
  else if (m.type === "file") {
    const blobUrl = URL.createObjectURL(new Blob([it.body], { type: m.mime }));
    card.append(el("div", { class: "file-head" },
      el("span", { class: "chip type" }, it.subkind),
      el("span", { class: "fname", title: m.name }, m.name),
      el("span", { class: "size" }, fmtBytes(it.body.length)),
      el("a", { class: "button small", href: blobUrl, download: m.name }, "Download")));
    if (it.subkind === "image") card.append(el("img", { src: blobUrl, alt: m.name }));
    else if (it.subkind === "zip") {
      try {
        const entries = JSON.parse(ac.inspectZip(it.body));
        const files = entries.filter((e) => !e.is_dir);
        card.append(el("ul", { class: "ziplist" }, entries.map((e) =>
          el("li", {}, el("span", {}, e.is_dir ? `${e.path}/` : e.path), el("span", {}, e.is_dir ? "" : fmtBytes(e.size))))),
          el("div", { class: "zipnote" }, `${files.length} file${files.length === 1 ? "" : "s"} · paths and sizes checked`));
      } catch (e) {
        card.append(el("p", { class: "error" }, String(e.message || e)));
      }
    } else card.append(el("pre", {}, new TextDecoder().decode(it.body)));
  } else card.append(el("pre", {}, JSON.stringify(m, null, 2)));
  if (it.note) card.append(el("p", { class: "note" }, it.note));
  return node;
}

// ---------- sending ----------
async function sendPayload(s, kind, subkind, meta, body) {
  const needed = kind === "text" ? "text" : subkind;
  if (!s.manifest.allowed_types.includes(needed)) throw new Error(`${needed} is not allowed in this session`);
  const payload = ac.encodePayload(JSON.stringify(meta), body);
  if (payload.length > s.manifest.max_item_bytes) throw new Error(`too large: the limit is ${fmtBytes(s.manifest.max_item_bytes)}`);
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

async function sendFile(s, f) {
  const dot = f.name.lastIndexOf(".");
  const ext = dot < 0 ? "" : f.name.slice(dot).toLowerCase();
  const t = FILE_TYPES[ext];
  if (!t) throw new Error(`${ext || "files without an extension"} cannot be shared (allowed: .py .md .zip .png .jpg .webp)`);
  let [subkind, mime] = t;
  let bytes = new Uint8Array(await f.arrayBuffer());
  if (subkind === "image") {
    const clean = ac.sanitizeImage(bytes);
    mime = clean.mime;
    bytes = clean.data;
  } else if (subkind === "zip") ac.inspectZip(bytes);
  await sendPayload(s, "file", subkind, { type: "file", name: f.name, mime }, bytes);
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
  let delay = 1000;
  while (!s.closed) {
    try {
      const headers = { Authorization: `Bearer ${s.identity.token}` };
      if (s.lastSeq >= 0) headers["Last-Event-ID"] = String(s.lastSeq);
      const r = await fetch(`/v1/sessions/${s.sid}/stream`, { headers });
      if (r.status === 404 || r.status === 410) {
        s.closed = "gone";
        s.render.closed("it is no longer on the relay");
        return;
      }
      if (!r.ok) throw new Error(`stream ${r.status}`);
      delay = 1000;
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
    if (!s.closed) {
      await sleep(delay);
      delay = Math.min(delay * 2, 30000);
    }
  }
}

// ---------- boot ----------
try {
  await init();
  if (location.pathname.startsWith("/s/")) await sessionView();
  else landing();
} catch (e) {
  deadEnd("Airlock failed to start", String(e.message || e));
}
