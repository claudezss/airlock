// Airlox web client (M1 timeline). All cryptography runs in the
// airlox-core WebAssembly module; the relay only sees ciphertext.
import init, * as ac from "/assets/pkg/airlox_core_wasm.js";

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

// One polite live region for job and runner transitions.
let liveTimer;
let liveQueue = [];
function announce(msg) {
  liveQueue.push(msg);
  clearTimeout(liveTimer);
  liveTimer = setTimeout(() => {
    const live = document.getElementById("live");
    if (live) live.textContent = liveQueue.join(". ");
    liveQueue = [];
  }, 100);
}

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
  const r = indexedDB.open("airlox", 1);
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

// Runner invites come with the command that uses them. The shown command
// carries the masked link; Copy always copies the full link.
function runnerInviteRow(url) {
  return el("div", { class: "stack" }, inviteRow("Runner", url, "your sandboxed machine"),
    el("p", { class: "muted hint-text" }, "Run on the runner host: ",
      el("code", {}, `airlox runner join --invite '${maskInvite(url)}' --name runner-01 --sandbox docker`)));
}

// ---------- new session ----------
function landing() {
  const radio = (name, value, label, checked, extra = {}) =>
    el("label", { class: "option" }, el("input", { type: "radio", name, value, checked, ...extra }), label);
  const mode = el("fieldset", { class: "stack" }, el("legend", {}, "Mode"),
    el("div", { class: "mode" },
      el("label", { class: "option" }, el("input", { type: "radio", name: "mode", value: "relay", checked: true }),
        el("strong", {}, "Relay"), el("span", {}, "Share messages and files")),
      el("label", { class: "option" }, el("input", { type: "radio", name: "mode", value: "execute" }),
        el("strong", {}, "Execute"), el("span", {}, "Run Python on runners you approve"))));
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
  const lim = {
    runtime: el("input", { type: "text", id: "j-runtime", value: "python3.12", autocomplete: "off" }),
    timeout: el("input", { type: "number", id: "j-timeout", min: 1, max: 3600, step: 1, value: 30 }),
    memory: el("input", { type: "number", id: "j-memory", min: 32, max: 65536, step: 1, value: 512 }),
    packages: el("input", { type: "text", id: "j-packages", placeholder: "numpy, pandas", autocomplete: "off" }),
    approve: el("input", { type: "checkbox", id: "j-approve", checked: true }),
  };
  const field = (id, label, input, hint) => el("div", { class: "stack field" }, el("label", { for: id }, el("strong", {}, label)), input,
    hint ? el("span", { class: "muted hint-text" }, hint) : null);
  const jobBox = el("fieldset", { class: "stack", hidden: true }, el("legend", {}, "Job limits"),
    el("div", { class: "limits" },
      field("j-runtime", "Runtime", lim.runtime), field("j-timeout", "Timeout (seconds)", lim.timeout, "1 to 3600"),
      field("j-memory", "Memory (MB)", lim.memory, "32 to 65536")),
    field("j-packages", "Packages", lim.packages, "Comma-separated. Only these can be requested by jobs."),
    el("label", { class: "option check" }, lim.approve, "Require owner approval for runners"),
    el("p", { class: "muted" }, "Network access is always off and runners return their output files."));
  const pyBox = types.querySelector('input[value="py"]');
  const isExecute = () => form.elements.mode.value === "execute";
  const pyNote = el("p", { class: "muted hint-text", hidden: true, id: "py-note" }, "Python is always allowed in Execute sessions: jobs are Python.");
  pyBox.setAttribute("aria-describedby", "py-note");
  const syncMode = () => {
    jobBox.hidden = !isExecute();
    pyNote.hidden = !isExecute();
    pyBox.disabled = isExecute();
    if (isExecute()) pyBox.checked = true;
  };
  mode.addEventListener("change", syncMode);
  const err = el("p", { class: "error", role: "alert" });
  const create = el("button", { class: "primary cta", type: "submit" }, "Create session");
  const fields = el("fieldset", { class: "stack" }, mode, jobBox, ttl, types, pyNote, sizeField);
  const aside = el("aside", { class: "panel stack" },
    el("h2", {}, "Invites"),
    el("p", { class: "muted" }, "Invite links appear here once the session exists. Each one carries a role and the session key."));

  const form = el("form", { class: "stack", onsubmit: async (ev) => {
    ev.preventDefault();
    err.textContent = "";
    const fd = new FormData(form);
    const allowed = fd.getAll("type");
    const mb = Number(size.value);
    const execute = isExecute();
    if (execute && !allowed.includes("py")) allowed.push("py");
    if (!allowed.length) return (err.textContent = "Pick at least one content type.");
    let job_limits = null;
    if (execute) {
      const timeout_s = Number(lim.timeout.value);
      const memory_mb = Number(lim.memory.value);
      const runtime = lim.runtime.value.trim();
      if (!/^python3\.\d{1,2}$/.test(runtime)) return (err.textContent = "Runtime must look like python3.12.");
      if (!Number.isInteger(timeout_s) || timeout_s < 1 || timeout_s > 3600) return (err.textContent = "Timeout must be 1 to 3600 seconds.");
      if (!Number.isInteger(memory_mb) || memory_mb < 32 || memory_mb > 65536) return (err.textContent = "Memory must be 32 to 65536 MB.");
      const packages = [];
      for (const raw of lim.packages.value.split(",").map((x) => x.trim()).filter(Boolean)) {
        if (!/^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$/.test(raw)) return (err.textContent = `"${raw}" is not a valid package name.`);
        const norm = raw.toLowerCase().replace(/[-_.]+/g, "-");
        if (!packages.includes(norm)) packages.push(norm);
      }
      job_limits = { runtime, timeout_s, memory_mb, network: false, packages, return_out: true, approve_runners: lim.approve.checked };
    }
    if (!Number.isInteger(mb) || mb < 1 || mb > MAX_ITEM_MB) return (err.textContent = `Max file size must be 1 to ${MAX_ITEM_MB} MB.`);
    create.disabled = true;
    try {
      const params = { mode: execute ? "execute" : "relay", created_at_ms: Date.now(), ttl_ms: Number(fd.get("ttl")), allowed_types: allowed,
        max_item_bytes: mb * MB, job_limits };
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
        execute ? runnerInviteRow(ac.memberInvite(base, s.ownerSeed, "runner")) : null,
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
    lastSeq: -1, closed: null, jobs: new Map(), results: new Map(), runners: [], picked: new Set(), approvedList: null,
    said: new Map(), announce: false, jobErrors: new Map(), runnerErrors: new Map(), runnerSeen: new Map(), open: new Set() };
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
  s.announce = true;
  streamLoop(s);
}

function buildSessionLayout(s) {
  const { sid, inv, manifest, identity } = s;
  app.classList.add("wide");
  const timeline = el("div", { class: "timeline", role: "log", "aria-live": "off", "aria-label": "Session timeline" },
    el("div", { class: "pill" }, `you opened the session · keys stay in this browser`),
    el("p", { class: "empty" }, "No messages yet. Items appear here as soon as someone sends one."));
  const people = el("ul", { class: "people" });
  const banner = el("div", { class: "banner", role: "status", hidden: true });
  const canSend = ["owner", "sender"].includes(inv.role);

  // composer
  const status = el("p", { class: "status", role: "alert" });
  const text = el("textarea", { id: "msg", rows: 2, placeholder: "Message the session…" });
  const file = el("input", { type: "file", id: "file", class: "sr-only", accept: Object.keys(FILE_TYPES).join(",") });
  const pending = el("span", { class: "pending-file", hidden: true });
  const sendBtn = el("button", { class: "primary", type: "submit" }, "Send");
  const execute = manifest.mode === "execute";
  const jobUi = canSend && execute ? buildJobPanel(s, text, file) : null;
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
  if (jobUi) jobUi.setSend(sendBtn);
  const submit = async () => {
    if (sendBtn.disabled) return;
    sendBtn.disabled = true;
    status.textContent = "";
    try {
      if (jobUi?.active()) {
        if (await jobUi.submit()) {
          file.value = "";
          showPending();
          text.value = "";
        }
        return;
      }
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
      status.textContent = e.final ? e.message : `Not sent: ${e.message || e}`;
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
          jobUi?.panel,
          el("label", { for: "msg", class: "sr-only" }, "Message the session"), text,
          el("div", { class: "toolbar" }, attach, file, pending, jobUi?.toggle,
            el("span", { class: "hint" }, navigator.platform.startsWith("Mac") ? "⌘↵ to send" : "Ctrl+↵ to send"), sendBtn)),
        status)
    : el("div", { class: "panel readonly" }, `You joined as ${inv.role}. You can read this session but not post to it.`);

  // rail
  const closeErr = el("p", { class: "error", role: "alert" });
  const closeBtn = inv.role === "owner" ? el("button", { class: "danger", type: "button", onclick: async () => {
    if (!confirm("Close the session and purge it from the relay for everyone?")) return;
    closeErr.textContent = "";
    try {
      await api("POST", `/v1/sessions/${sid}/close`, { token: identity.token });
    } catch (e) {
      closeErr.textContent = `Could not close: ${e.message}`;
    }
  } }, "Close & purge") : null;
  const invites = inv.role === "owner" ? el("details", {},
    el("summary", {}, "Invites"),
    el("div", { class: "stack" },
      inviteRow("Sender", ac.memberInvite(location.origin, inv.roleSeed, "sender"), "your code agent"),
      inviteRow("Observer", ac.memberInvite(location.origin, inv.roleSeed, "observer"), "read-only"),
      execute ? runnerInviteRow(ac.memberInvite(location.origin, inv.roleSeed, "runner")) : null)) : null;
  const runnerList = el("ul", { class: "runners" });
  const runnerNote = el("p", { class: "muted" });
  const rail = el("aside", { class: "rail" },
    el("section", {}, el("h2", {}, "Participants"), people),
    execute ? el("section", { class: "stack", id: "runner-console", tabindex: -1, "aria-label": "Runner console" }, el("h2", {}, "Runners"), runnerList, runnerNote) : null,
    el("section", {}, el("h2", {}, "Allowed types"), el("div", { class: "chips" }, manifest.allowed_types.map((t) => el("span", { class: "chip" }, t)))),
    el("section", { class: "stack" }, el("h2", {}, "Session"),
      el("p", { class: "mono muted" }, sid),
      el("p", { class: "muted" }, `Expires ${new Date(manifest.expires_at_ms).toLocaleString()}`),
      el("p", { class: "muted" }, `Files up to ${fmtBytes(manifest.max_item_bytes)}`),
      invites, closeBtn, closeErr),
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
  // Owners see pending runner approvals above the timeline; on narrow
  // screens the rail (and the runner console) sits below it.
  const approvalText = el("span", {});
  const approvalBanner = el("div", { class: "banner approval", hidden: true }, approvalText,
    el("button", { type: "button", class: "small primary", onclick: () => {
      const sec = document.getElementById("runner-console");
      sec?.scrollIntoView({ block: "start" });
      (sec?.querySelector("button.primary") || sec)?.focus({ preventScroll: true });
    } }, "Review runners"));
  show(el("div", { class: "session" }, rail, el("div", { class: "main-col" }, approvalBanner, banner, timeline, composer)));
  // The sticky composer must not cover the newest card when it scrolls into view.
  if (canSend && typeof ResizeObserver !== "undefined") {
    const wrap = document.querySelector(".composer-wrap");
    new ResizeObserver(() => document.documentElement.style.setProperty("--composer-h", `${Math.ceil(wrap.getBoundingClientRect().height)}px`))
      .observe(wrap);
  }

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

  if (execute) runnerLoop(s);
  const nearBottom = () => window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 160;
  s.render = {
    people: () => people.replaceChildren(...[...s.participants.values()].map((p) =>
      el("li", {},
        el("span", { class: "dot", "aria-hidden": "true" }),
        el("div", { class: "who" },
          el("div", { class: "name" }, p.display_name, p.participant_pub === s.me ? el("span", { class: "you" }, "you") : null),
          el("div", { class: "sub" }, `${p.role} · ${p.kind}${p.left ? " · left" : ""}`),
          p.description ? el("div", { class: "desc" }, p.description) : null),
        el("span", { class: "key", title: "Key fingerprint" }, ac.fingerprint(p.participant_pub).slice(0, 4))))),
    item: (it) => {
      const stick = nearBottom();
      // Files an accepted result lists live only inside that result.
      if (it.kind === "file" && it.status === "ok" && claimedBy(s, it)) {
        document.getElementById(`item-${it.id}`)?.remove();
        return;
      }
      // A result with a known job lives inside the job's card.
      const host = hostJob(s, it);
      if (host) {
        document.getElementById(`item-${it.id}`)?.remove();
        it = host;
      }
      const node = renderItem(s, it);
      node.dataset.seq = it.seq;
      const old = document.getElementById(`item-${it.id}`);
      if (old) old.replaceWith(node);
      else {
        const next = [...timeline.children].find((n) => n.dataset?.seq !== undefined && Number(n.dataset.seq) > it.seq);
        if (next) next.before(node);
        else timeline.append(node);
      }
      if (stick && !old) node.scrollIntoView({ block: "end" });
      settle(s, it);
      if (it.kind === "job") announceJob(s, it);
      else if (!old && s.announce && it.status === "ok" && it.author !== s.me && (it.kind === "text" || it.kind === "file"))
        announce(`${it.authorName}: ${it.kind === "text" ? it.meta.text : it.meta.name}`);
      jobUi?.refresh();
    },
    runners: () => {
      renderRunners(s, runnerList, runnerNote);
      const n = s.runners.filter((r) => !r.approved && !r.rejected).length;
      approvalBanner.hidden = !(inv.role === "owner" && n && !s.closed);
      approvalText.textContent = `${n} runner${n === 1 ? "" : "s"} awaiting approval`;
      jobUi?.refresh();
    },
    scroll: () => timeline.lastElementChild?.scrollIntoView({ block: "end" }),
    closed: (reason) => {
      banner.hidden = false;
      banner.textContent = `This session is closed: ${reason}. Its history stays in this browser until you clear it.`;
      for (const c of [sendBtn, text, file, closeBtn]) if (c) c.disabled = true;
      attach.setAttribute("aria-disabled", "true");
      approvalBanner.hidden = true;
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
        display_name: j.display_name, description: j.description, kind: j.kind, cert: ac.joinCert(ev.data.signed_join) });
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
  } else if (ev.kind === "job") {
    s.jobs.set(ev.data.job, ev.data);
    const it = s.items.get(ev.data.job);
    if (it) s.render.item(it);
  } else if (ev.kind === "runner") {
    if (record) pollRunners(s);
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
    if (it.kind === "file" || it.kind === "job") it.ref = JSON.parse(ac.itemRef(envelope, blob));
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
  if (it.kind === "result" && it.meta?.job?.id) {
    const list = s.results.get(it.meta.job.id) || [];
    if (!list.some((r) => r.id === it.id)) list.push(it);
    s.results.set(it.meta.job.id, list);
  }
  s.render.item(it);
  if (it.kind === "event" && it.role === "owner" && ["runner_approve", "runner_reject"].includes(it.meta?.event)) approvalsChanged(s);
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
  if (m.type === "event") return renderEvent(s, it, meta);
  if (m.type === "text") card.append(el("p", {}, m.text));
  else if (m.type === "file") {
    if (it.role === "runner") card.append(el("p", { class: "note" }, `Output file from runner ${it.authorName}, not listed by an accepted result.`));
    appendFileView(card, it);
  }
  else if (m.type === "job") renderJob(s, it, card);
  else if (m.type === "result") {
    const chk = resultCheck(s, it);
    card.append(chk.ok ? renderResult(s, it) : rejectedResult(chk.error));
    if (!chk.ok) node.classList.add("rejected");
  } else card.append(el("pre", {}, JSON.stringify(m, null, 2)));
  if (it.note) card.append(el("p", { class: "note" }, it.note));
  return node;
}

function appendFileView(card, it) {
  const m = it.meta;
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
}

// ---------- execute mode: jobs, results, events ----------
const short = (id) => String(id).slice(0, 6);
const memberName = (s, pub) => s.runners.find((r) => r.pub === pub)?.name || s.participants.get(pub)?.display_name || "unknown";
const STATUS_LABELS = { completed: "completed", refused: "refused", timed_out: "timed out", cancelled: "cancelled", failed: "failed" };

// A completed run is only a success with exit 0.
function outcome(m) {
  if (m.status === "completed") {
    if (m.exit_code === 0) return { text: "completed", bad: false };
    return { text: Number.isInteger(m.exit_code) ? `failed · exit ${m.exit_code}` : "failed", bad: true };
  }
  return { text: STATUS_LABELS[m.status] || m.status, bad: true };
}

function targetText(t) {
  if (t?.type === "runner") return `runner ${t.name}`;
  if (t?.type === "labels") return `labels: ${t.labels.join(", ")}`;
  return "any idle runner";
}

// "failed · runner-01 not available · not queued" (DESIGN §6, protocol §13).
function notAvailableText(tgt) {
  if (tgt?.type === "runner") return `failed · ${tgt.name} not available · not queued`;
  if (tgt?.type === "labels") return `failed · no runner with ${tgt.labels.join(",")} · not queued`;
  return "failed · no runner available · not queued";
}

function failureText(s, tgt, st) {
  if (st.reason === "not_available") return notAvailableText(tgt);
  if (st.reason === "cancelled") return "cancelled";
  const name = (st.runner ? memberName(s, st.runner) : null) || (tgt?.type === "runner" ? tgt.name : null) || "the runner";
  const tail = { runner_unresponsive: "did not claim it", runner_lost: "went offline", runner_left: "left", runner_rejected: "was rejected" }[st.reason];
  return tail ? `failed · ${name} ${tail}` : `failed${st.reason ? ` · ${st.reason}` : ""}`;
}

// Verified runner_approve events from the owner, minus any runner the owner
// rejected (a rejection is final). undefined when approval is not required.
function approvedRunners(s) {
  if (!s.manifest.job_limits?.approve_runners) return undefined;
  if (s.approvedList) return s.approvedList;
  const approved = new Set();
  const rejected = new Set();
  for (const it of [...s.items.values()].sort((a, b) => a.seq - b.seq)) {
    if (it.kind !== "event" || it.status !== "ok" || it.role !== "owner" || it.meta?.type !== "event" || !it.meta.participant_pub) continue;
    if (it.meta.event === "runner_reject") rejected.add(it.meta.participant_pub);
    else if (it.meta.event === "runner_approve") approved.add(it.meta.participant_pub);
  }
  s.approvedList = [...approved].filter((k) => !rejected.has(k));
  return s.approvedList;
}

// Approvals changed: results that arrived earlier are checked again.
function approvalsChanged(s) {
  s.approvedList = null;
  for (const it of s.items.values()) if (it.kind === "result") delete it.check;
  for (const it of [...s.items.values()]) {
    if (it.status === "ok" && (it.kind === "result" || (it.kind === "file" && it.role === "runner"))) s.render.item(it);
  }
}

// The job card that should show this result, when its job is in the timeline.
function hostJob(s, it) {
  if (it.kind !== "result" || it.status !== "ok") return null;
  const job = s.items.get(it.meta?.job?.id);
  return job && job.status === "ok" && job.kind === "job" ? job : null;
}

// Cached: does this result belong to its job and come from an approved runner?
function resultCheck(s, r) {
  if (r.check) return r.check;
  if (r.role !== "runner") return { ok: false, error: "the author is not a runner" };
  const approved = approvedRunners(s);
  if (approved && !approved.includes(r.author)) return { ok: false, error: "the author is not an approved runner" };
  const job = s.items.get(r.meta.job?.id);
  if (!job || job.status !== "ok" || !job.ref) return { ok: true, unbound: true };
  let chk;
  try {
    ac.checkResultForJob(JSON.stringify(job.ref), JSON.stringify(job.meta), r.author, JSON.stringify(r.meta),
      approved === undefined ? undefined : JSON.stringify(approved));
    chk = { ok: true };
  } catch (e) {
    chk = { ok: false, error: String(e.message || e).replace(/^\w+Error: /, "") };
  }
  r.check = chk;
  return chk;
}

// The accepted result that lists this file as an output, if any.
function claimedBy(s, f) {
  if (f.role !== "runner") return null;
  for (const list of s.results.values()) {
    for (const r of list) {
      if (r.status !== "ok" || r.author !== f.author || !resultCheck(s, r).ok) continue;
      if ((r.meta.out_files || []).some((o) => o.item?.id === f.id)) return r;
    }
  }
  return null;
}

// After a card is drawn: drop standalone copies of what it now contains.
function settle(s, it) {
  const rs = it.kind === "job" ? s.results.get(it.id) || [] : it.kind === "result" ? [it] : [];
  for (const r of rs) {
    if (r.status !== "ok") continue;
    if (it.kind === "job") document.getElementById(`item-${r.id}`)?.remove();
    if (!resultCheck(s, r).ok) continue;
    for (const o of r.meta.out_files || []) {
      const f = s.items.get(o.item?.id);
      if (f && f.author === r.author) document.getElementById(`item-${f.id}`)?.remove();
    }
  }
}

function rejectedResult(reason) {
  return el("div", {}, el("p", { class: "note error" }, `✕ Result not accepted: ${reason}`));
}

function logBlock(label, text, truncated) {
  if (!text && !truncated) return null;
  return el("div", { class: "logblock" }, el("div", { class: "logname" }, label, truncated ? el("span", { class: "chip" }, "truncated") : null),
    el("pre", {}, text || "(empty)"));
}

function renderResult(s, r, extra = "") {
  const m = r.meta;
  const out = outcome(m);
  const parts = [];
  if (m.exit_code !== null && m.exit_code !== undefined) parts.push(`exit ${m.exit_code}`);
  parts.push(`${(m.wall_ms / 1000).toFixed(2)} s`, `${m.peak_mem_mb} MB peak`);
  const files = m.out_files || [];
  return el("div", { class: "result", id: `result-${r.id}` },
    el("div", { class: "result-head" },
      el("span", { class: `state ${out.bad ? "bad" : "good"}` }, out.text),
      el("span", { class: "mono muted" }, parts.join(" · ")),
      extra ? el("span", { class: "chip" }, extra) : null),
    m.reason ? el("p", { class: "note" }, m.reason) : null,
    logBlock("stdout", m.stdout, m.stdout_truncated), logBlock("stderr", m.stderr, m.stderr_truncated),
    files.length ? el("div", { class: "outfiles" }, el("div", { class: "logname" }, `Output files (${files.length})`),
      files.map((f) => renderOutFile(s, f))) : null);
}

function renderOutFile(s, f) {
  const fi = s.items.get(f.item?.id);
  const box = el("div", { class: "outfile" });
  if (!fi || fi.status !== "ok" || fi.kind !== "file") {
    box.append(el("div", { class: "file-head" }, el("span", { class: "fname" }, f.name), el("span", { class: "size" }, fmtBytes(f.size)),
      el("span", { class: "muted" }, fi?.status === "evicted" ? "removed from the relay" : "not in this timeline")));
    return box;
  }
  if (!fi.ref || fi.ref.blob_sha256 !== f.item.blob_sha256) {
    box.append(el("p", { class: "note error" }, `✕ ${f.name}: the file does not match the runner's result`));
    return box;
  }
  appendFileView(box, fi);
  return box;
}

const sha256Hex = async (text) => {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
  return [...d].map((b) => b.toString(16).padStart(2, "0")).join("");
};

// Keep a disclosure open across re-renders of its card.
function keepOpen(s, key, details) {
  if (s.open.has(key)) details.open = true;
  details.addEventListener("toggle", () => (details.open ? s.open.add(key) : s.open.delete(key)));
  return details;
}

// State of a job for its card and for announcements.
function jobStatus(s, it) {
  const st = s.jobs.get(it.id);
  const entries = [];
  let accepted = null;
  for (const r of s.results.get(it.id) || []) {
    if (r.status !== "ok") continue;
    const chk = resultCheck(s, r);
    if (!chk.ok) entries.push({ r, error: chk.error });
    else if (!accepted) {
      accepted = r;
      entries.push({ r });
    } else entries.push({ r, dup: true });
  }
  let text;
  let bad = false;
  if (accepted) ({ text, bad } = outcome(accepted.meta));
  else if (st?.state === "failed") {
    text = failureText(s, it.meta.target, st);
    bad = text !== "cancelled";
  } else if (st?.state === "done") text = "done · waiting for the result";
  else text = st?.state || "submitted";
  const runner = st?.runner ? memberName(s, st.runner) : null;
  return { st, entries, accepted, text, tone: bad ? "bad" : accepted ? "good" : text === "cancelled" ? "bad" : "run", runner };
}

function announceJob(s, it) {
  const { text, runner } = jobStatus(s, it);
  const prev = s.said.get(it.id);
  if (prev === text) return;
  s.said.set(it.id, text);
  if (!s.announce || (prev === undefined && text === "submitted")) return;
  announce(`${it.meta.filename}${runner ? ` on ${runner}` : ""}: ${text}`);
}

function renderJob(s, it, card) {
  const m = it.meta;
  const { st, entries, accepted, text, tone, runner } = jobStatus(s, it);
  const rendered = entries.map((e) => (e.error ? rejectedResult(e.error) : renderResult(s, e.r, e.dup ? "ignored: duplicate" : "")));
  const lines = m.code.split("\n");
  const code = el("pre", {}, m.code);
  const files = (m.files || []).map((ref) => s.items.get(ref.id)?.meta?.name || `item ${short(ref.id)}`);
  const active = !accepted && (st?.state === "assigned" || st?.state === "running");
  const canCancel = active && (s.inv.role === "owner" || it.author === s.me);
  const codeHash = el("span", { class: "mono" }, "computing…");
  (it.codeSha ||= sha256Hex(m.code)).then((h) => (codeHash.textContent = h), () => (codeHash.textContent = "unavailable"));
  const am = accepted?.meta;
  const details = keepOpen(s, `details:${it.id}`, el("details", { class: "codebox" }, el("summary", {}, "Details"),
    el("dl", { class: "jobmeta" },
      el("dt", {}, "Job id"), el("dd", { class: "mono" }, it.id),
      el("dt", {}, "Code SHA-256"), el("dd", {}, codeHash),
      am?.code_sha256 ? el("dt", {}, "Result code") : null, am?.code_sha256 ? el("dd", { class: "mono" }, am.code_sha256) : null,
      am?.input_sha256 ? el("dt", {}, "Result inputs") : null, am?.input_sha256 ? el("dd", { class: "mono" }, am.input_sha256) : null)));
  const err = s.jobErrors.get(it.id);
  card.append(
    el("div", { class: "file-head job-head" }, el("span", { class: "chip type" }, "job"), el("span", { class: "fname", title: m.filename }, m.filename),
      el("span", { class: "mono muted jobid", title: it.id }, `#${short(it.id)}`),
      el("span", { class: `state ${tone}` }, text),
      canCancel ? el("button", { type: "button", class: "small danger", onclick: (ev) => cancelJob(s, it, ev.currentTarget) }, "Cancel") : null),
    ...(err ? [el("p", { class: "note error", role: "alert" }, err)] : []),
    el("dl", { class: "jobmeta" },
      el("dt", {}, "Target"), el("dd", {}, targetText(m.target)),
      runner ? el("dt", {}, "Runner") : null, runner ? el("dd", {}, runner) : null,
      el("dt", {}, "Limits"), el("dd", {}, `${m.runtime} · ${m.timeout_s} s${m.memory_mb ? ` · ${m.memory_mb} MB` : ""}`),
      files.length ? el("dt", {}, "Inputs") : null, files.length ? el("dd", {}, files.join(", ")) : null),
    lines.length > 12
      ? keepOpen(s, `code:${it.id}`, el("details", { class: "codebox" }, el("summary", {}, `Code · ${lines.length} lines`), code))
      : code,
    details,
    ...rendered);
}

async function cancelJob(s, it, btn) {
  btn.disabled = true;
  s.jobErrors.delete(it.id);
  try {
    await sendPayload(s, "event", null, { type: "event", event: "job_cancel", job: it.ref }, new Uint8Array());
    await api("POST", `/v1/sessions/${s.sid}/jobs/${it.id}/cancel`, { token: s.identity.token });
  } catch (e) {
    s.jobErrors.set(it.id, `Could not cancel: ${e.message || e}`);
    s.render.item(it);
  }
}

// Signed events render as one line.
function renderEvent(s, it, meta) {
  const m = it.meta;
  const who = it.authorName;
  let text;
  if (m.event === "runner_approve") text = `${who} approved runner ${memberName(s, m.participant_pub)}`;
  else if (m.event === "runner_reject") text = `${who} rejected runner ${memberName(s, m.participant_pub)}${m.reason ? ` · ${m.reason}` : ""}`;
  else if (m.event === "job_cancel") {
    const j = s.items.get(m.job?.id);
    text = `${who} cancelled job ${j?.meta?.filename || short(m.job?.id || "")}`;
  } else if (m.event === "session_close") text = `${who} closed the session`;
  else text = `${who} posted an event`;
  const ownerOnly = m.event !== "job_cancel";
  const suspect = ownerOnly && it.role !== "owner";
  return el("article", { class: `item evline${suspect ? " rejected" : ""}`, id: `item-${it.id}` },
    el("div", { class: "pill" }, suspect ? `✕ ignored: ${text} (not from the owner)` : text, " · ", hhmm(it.created)));
}

// ---------- runner console ----------
// Runner details come only from a verified signed join, never from the
// relay's unsigned fields.
async function pollRunners(s) {
  if (s.polling || s.closed) return;
  s.polling = true;
  try {
    const r = await (await api("GET", `/v1/sessions/${s.sid}/runners`, { token: s.identity.token })).json();
    const list = [];
    for (const e of r.runners) {
      try {
        ac.verifyJoin(e.signed_join, s.signed);
        const j = JSON.parse(e.signed_join).join;
        if (j.cert.cert.participant_pub !== e.participant_pub || j.cert.cert.role !== "runner" || !j.runner) continue;
        list.push({ pub: e.participant_pub, name: j.runner.name, description: j.description, labels: j.runner.labels,
          host: j.runner.host, sandbox: j.runner.sandbox,
          networkUnblocked: !!j.runner.network_unblocked, online: !!e.online, job: e.job, rejected: !!e.rejected,
          // Approval as the owner signed it (and whether it is required, from
          // the signed manifest), never the relay's unsigned listing.
          approved: approvedRunners(s)?.includes(e.participant_pub) ?? !e.rejected });
      } catch (err) {
        console.warn("ignoring unverifiable runner", err);
      }
    }
    const first = !s.runnersLoaded;
    for (const x of list) {
      const label = x.rejected ? "rejected" : x.approved ? "approved" : "awaiting approval";
      if (!first && s.announce && s.runnerSeen.get(x.pub) !== label) announce(`Runner ${x.name}: ${label}`);
      s.runnerSeen.set(x.pub, label);
    }
    s.runnersLoaded = true;
    s.runners = list;
    s.approvalRequired = !!r.approval_required;
    s.render.runners();
  } catch (e) {
    if (e.status === 404 || e.status === 410 || e.status === 401) s.closed ||= "gone";
  } finally {
    s.polling = false;
  }
}

function runnerLoop(s) {
  const tick = () => {
    if (!s.closed && document.visibilityState === "visible") pollRunners(s);
  };
  tick();
  setInterval(tick, 3000);
  document.addEventListener("visibilitychange", tick);
}

function renderRunners(s, list, note) {
  note.textContent = s.runners.length ? "" : "No runners yet. Hand out the runner invite from Invites.";
  list.replaceChildren(...s.runners.map((r) => {
    const approval = r.rejected ? "rejected" : r.approved ? "approved" : "awaiting approval";
    const owner = s.inv.role === "owner";
    const live = r.rejected ? "rejected" : !r.approved ? "awaiting approval" : r.online ? (r.job ? `busy · #${short(r.job)}` : "idle") : "offline";
    const dot = r.rejected ? "" : !r.approved ? "wait" : r.online ? "on" : "";
    const err = s.runnerErrors.get(r.pub);
    return el("li", { class: `runner${r.rejected ? " is-rejected" : ""}` },
      el("div", { class: "rhead" },
        el("span", { class: `dot ${dot}`, "aria-hidden": "true" }),
        el("strong", { class: "name" }, r.name),
        el("span", { class: "sub" }, live)),
      el("div", { class: "sub" }, `${r.sandbox} · ${r.host}`),
      r.description ? el("div", { class: "desc" }, r.description) : null,
      r.labels.length ? el("div", { class: "chips" }, r.labels.map((l) => el("span", { class: "chip" }, l))) : null,
      el("div", { class: "chips" },
        el("span", { class: `chip approval ${r.rejected ? "bad" : r.approved ? "good" : "wait"}` }, approval),
        r.networkUnblocked && !r.rejected ? el("span", { class: "chip warn", title: "This runner's sandbox cannot block network access" }, "⚠ network not blocked") : null),
      owner && !r.rejected ? el("div", { class: "row" },
        r.approved ? null : el("button", { type: "button", class: "small primary", onclick: (ev) => decideRunner(s, r, true, ev.currentTarget) }, "Approve"),
        el("button", { type: "button", class: "small danger", onclick: (ev) => decideRunner(s, r, false, ev.currentTarget) }, "Reject")) : null,
      err ? el("p", { class: "error", role: "alert" }, err) : null);
  }));
}

async function decideRunner(s, r, approve, btn) {
  if (!approve && !confirm(`Reject runner ${r.name}? It is removed from the session and its job fails.`)) return;
  btn.disabled = true;
  s.runnerErrors.delete(r.pub);
  try {
    const meta = approve ? { type: "event", event: "runner_approve", participant_pub: r.pub }
      : { type: "event", event: "runner_reject", participant_pub: r.pub, reason: null };
    await sendPayload(s, "event", null, meta, new Uint8Array());
    await api("POST", `/v1/sessions/${s.sid}/runners/${encodeURIComponent(r.pub)}/${approve ? "approve" : "reject"}`, { token: s.identity.token });
    await pollRunners(s);
  } catch (e) {
    s.runnerErrors.set(r.pub, `Could not ${approve ? "approve" : "reject"} the runner: ${e.message || e}`);
    s.render.runners();
  } finally {
    btn.disabled = false;
  }
}

// ---------- composer: run as job ----------
function buildJobPanel(s, text, file) {
  const lim = s.manifest.job_limits;
  let on = false;
  let sendBtn;
  let optsSig = "";
  let filesSig = null;
  const target = el("select", { id: "job-target" });
  const labels = el("input", { type: "text", id: "job-labels", placeholder: "gpu, cpu", autocomplete: "off", "aria-label": "Runner labels" });
  const labelField = el("div", { class: "stack field", hidden: true }, el("label", { for: "job-labels" }, "Labels"), labels);
  const timeout = el("input", { type: "number", id: "job-timeout", min: 1, max: lim.timeout_s, step: 1, value: lim.timeout_s,
    title: `1 to ${lim.timeout_s} seconds` });
  const files = el("div", { class: "pickfiles" });
  const filesSummary = el("summary", {}, "Input files · none selected");
  const status = el("p", { class: "muted hint-text" });
  const panel = el("div", { class: "jobpanel", hidden: true },
    el("div", { class: "jobrow" },
      el("div", { class: "stack field" }, el("label", { for: "job-target" }, "Target"), target),
      el("div", { class: "stack field narrow" }, el("label", { for: "job-timeout" }, "Timeout (s)"), timeout),
      labelField),
    el("details", { class: "inputfiles" }, filesSummary, files),
    status);
  const countPicked = () => {
    const n = s.picked.size;
    filesSummary.textContent = `Input files · ${n ? `${n} selected` : "none selected"}`;
  };
  const toggle = el("button", { type: "button", class: "small", "aria-pressed": "false", onclick: () => {
    on = !on;
    toggle.setAttribute("aria-pressed", String(on));
    toggle.classList.toggle("on", on);
    panel.hidden = !on;
    optsSig = "";
    filesSig = null;
    text.placeholder = on ? "Python code to run (or attach a .py file)…" : "Message the session…";
    if (sendBtn) sendBtn.textContent = on ? "Send job" : "Send";
    refresh();
  } }, "Send as job");
  target.addEventListener("change", () => (labelField.hidden = target.value !== "labels"));

  function refresh() {
    if (!on) return;
    const cur = target.value;
    const opts = [el("option", { value: "any" }, "Any idle runner"), el("option", { value: "labels" }, "Labels…")];
    for (const r of s.runners) {
      if (r.rejected) continue;
      opts.push(el("option", { value: `runner:${r.pub}` }, `${r.name}${r.online ? "" : " (offline)"}${r.approved ? "" : " (not approved)"}`));
    }
    const sig = s.runners.map((r) => `${r.pub}${r.name}${r.online}${r.approved}${r.rejected}`).join("|");
    if (sig !== optsSig) {
      optsSig = sig;
      target.replaceChildren(...opts);
    }
    target.value = [...target.options].some((o) => o.value === cur) ? cur : "any";
    labelField.hidden = target.value !== "labels";
    const cands = [...s.items.values()].filter((i) => i.kind === "file" && i.status === "ok" && i.ref).sort((a, b) => a.seq - b.seq);
    countPicked();
    const fsig = cands.map((i) => i.id).join("|");
    if (fsig === filesSig) return;
    filesSig = fsig;
    files.replaceChildren(...(cands.length ? cands.map((i) => el("label", { class: "option check" },
      el("input", { type: "checkbox", checked: s.picked.has(i.id), onchange: (ev) => {
        if (ev.target.checked) s.picked.add(i.id);
        else s.picked.delete(i.id);
        countPicked();
      } }), `${i.meta.name}`, el("span", { class: "ext" }, i.subkind))) : [el("span", { class: "muted hint-text" }, "No files in the timeline yet.")]));
  }

  async function submit() {
    const f = file.files?.[0];
    let filename = "main.py";
    let code;
    if (f) {
      if (!/\.py$/i.test(f.name)) throw new Error("attach a .py file, or write the code in the message box");
      filename = f.name;
      code = new TextDecoder("utf-8", { fatal: true }).decode(await f.arrayBuffer());
    } else {
      code = text.value;
      if (!code.trim()) throw new Error("attach a .py file or write code in the message box");
    }
    if (new TextEncoder().encode(code).length > MB) throw new Error("the code is over 1 MiB");
    const t = Number(timeout.value);
    if (!Number.isInteger(t) || t < 1 || t > lim.timeout_s) throw new Error(`timeout must be 1 to ${lim.timeout_s} seconds`);
    let tgt;
    if (target.value === "any") tgt = { type: "any" };
    else if (target.value === "labels") {
      const ls = labels.value.split(",").map((x) => x.trim().toLowerCase()).filter(Boolean);
      if (!ls.length) throw new Error("enter at least one label, such as gpu");
      if (ls.length > 16) throw new Error("use at most 16 labels");
      const bad = ls.find((l) => !/^[a-z0-9][a-z0-9._-]{0,62}$/.test(l));
      if (bad) throw new Error(`"${bad.slice(0, 20)}" is not a valid label: use letters, digits, . _ - (up to 63, starting with a letter or digit)`);
      tgt = { type: "labels", labels: ls };
    } else {
      const r = s.runners.find((x) => `runner:${x.pub}` === target.value);
      if (!r) throw new Error("that runner is gone");
      tgt = { type: "runner", participant_pub: r.pub, name: r.name };
    }
    const refs = [...s.picked].map((id) => s.items.get(id)?.ref).filter(Boolean);
    const meta = { type: "job", filename, code, runtime: lim.runtime, timeout_s: t, memory_mb: null, files: refs, requirements: [], target: tgt };
    try {
      await sendPayload(s, "job", "py", meta, new Uint8Array(), { path: "jobs", headers: { "Airlox-Target": JSON.stringify(tgt) } });
    } catch (e) {
      if (e.code !== "no_runner_available") throw e;
      const err = new Error(notAvailableText(tgt));
      err.final = true;
      throw err;
    }
    s.picked.clear();
    refresh();
    return true;
  }

  return { panel, toggle, refresh, submit, active: () => on, setSend: (b) => (sendBtn = b) };
}

// ---------- sending ----------
async function sendPayload(s, kind, subkind, meta, body, { path = "items", headers = {} } = {}) {
  const needed = kind === "text" ? "text" : kind === "event" || kind === "result" ? null : subkind;
  if (needed && !s.manifest.allowed_types.includes(needed)) throw new Error(`${needed} is not allowed in this session`);
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
  await api("POST", `/v1/sessions/${s.sid}/${path}`, { token: s.identity.token, body: frame,
    headers: { "Content-Type": "application/octet-stream", ...headers } });
  return item.id;
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
  deadEnd("Airlox failed to start", String(e.message || e));
}
