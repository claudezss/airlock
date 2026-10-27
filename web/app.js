// Airlox web client (M1 timeline). All cryptography runs in the
// airlox-core WebAssembly module; the relay only sees ciphertext.
// The WebAssembly core is loaded on demand so the landing page renders even if
// it (or IndexedDB) is unavailable; only /new, /receive and /s/<id> need them.
let ac;
let corePromise;
const loadCore = () =>
  (corePromise ??= (async () => {
    const m = await import("/assets/pkg/airlox_core_wasm.js");
    await m.default();
    ac = m;
  })());

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
// Invite links are shown once and kept nowhere; warn before the page that
// shows them is closed or reloaded.
let invitesShown = false;
addEventListener("beforeunload", (ev) => {
  if (!invitesShown) return;
  ev.preventDefault();
  ev.returnValue = "";
});
// Never leave invite links in a page the back/forward cache could restore:
// empty the page when it is hidden, and start over if it comes back.
let invitesCreated = false;
addEventListener("pagehide", () => {
  if (!invitesCreated) return;
  invitesShown = false; // the page is gone; a restore must not prompt on leaving
  app.replaceChildren();
});
addEventListener("pageshow", (ev) => {
  if (ev.persisted && invitesCreated) {
    invitesShown = false;
    location.reload();
  }
});
const show = (...nodes) => app.replaceChildren(...nodes);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const fmtBytes = (n) => (n < 1024 ? `${n} B` : n < MB ? `${(n / 1024).toFixed(1)} KB` : `${(n / MB).toFixed(1)} MB`);
const hhmm = (ms) => new Date(ms).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
// Status symbols are decoration next to words: screen readers skip them.
const sym = (c) => el("span", { "aria-hidden": "true" }, c);
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

// Only the owner of an ended session is offered a new one; a retry reloads the page.
function deadEnd(title, cause, { newSession = false, retry = false } = {}) {
  document.title = `${title} · Airlox`;
  show(el("div", { class: "panel stack dead-end", role: "alert" },
    el("h1", {}, title), el("p", { class: "muted" }, cause),
    newSession || retry ? el("div", { class: "row" },
      newSession ? el("a", { class: "button primary", href: "/new" }, "New session") : null,
      retry ? el("button", { class: "primary", type: "button", onclick: () => location.reload() }, "Try again") : null) : null));
}

// Plain-language reasons for items that fail verification.
function explain(err) {
  const msg = String(err?.message || err);
  const cls = msg.split(":")[0];
  if (cls === "SignatureError") return "It does not come from a member of this session.";
  if (cls === "DecryptError") return "It could not be decrypted with this session's key.";
  if (cls === "PolicyError") return "This session's rules do not allow it.";
  return "It is malformed.";
}

// ---------- IndexedDB: identity, events and ciphertext blobs ----------
let dbPromise;
const openDb = () =>
  (dbPromise ??= new Promise((res, rej) => {
    const r = indexedDB.open("airlox", 1);
    r.onupgradeneeded = () => {
      for (const s of ["identity", "events", "blobs"]) r.result.createObjectStore(s);
    };
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  }));
async function tx(store, mode, fn) {
  const db = await openDb();
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

// Copy to the clipboard and say so on the button and the live region.
// Returns false when the clipboard is denied.
async function copyText(btn, text, label) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    return false;
  }
  btn.textContent = "Copied";
  announce("Copied");
  setTimeout(() => (btn.textContent = label), 1500);
  return true;
}
const touchOnly = () => matchMedia("(hover: none) and (pointer: coarse)").matches;
const pressCopy = () => (touchOnly() ? "Long-press to copy" : navigator.platform.startsWith("Mac") ? "Press ⌘C" : "Press Ctrl+C");

function inviteRow(name, url, hint, label = "Copy") {
  const shown = el("code", {}, maskInvite(url));
  const box = el("div", { class: "invite" }, shown);
  const btn = el("button", { class: "small", type: "button", onclick: async () => {
    if (await copyText(btn, url, label)) return;
    // Clipboard denied: reveal the link in a selected field for manual copy.
    const input = el("input", { type: "text", readonly: true, value: url, "aria-label": `${name} invite link` });
    shown.replaceWith(input);
    input.select();
    btn.textContent = pressCopy();
  } }, label);
  box.append(btn);
  return el("div", { class: "invite-row", "data-role": name.toLowerCase() },
    el("div", { class: "head" }, el("strong", {}, name), hint ? el("span", { class: "muted" }, hint) : null), box,
    sendCode(name, url));
}

// ---------- one-time transfer codes ----------
// "Send to another machine": park the invite on the relay, sealed under two
// random words, and show `{nameplate}-{words}` to type in on the other
// machine. The relay hands it out once; see crates/airlox-core/src/transfer.rs.
const PUBLIC_RELAY = "https://airlox.app";
const openDrops = new Map(); // nameplate → token, cancelled when the page goes
addEventListener("pagehide", () => {
  for (const [n, token] of openDrops) fetch(`/v1/drops/${n}`, { method: "DELETE", keepalive: true, headers: { Authorization: `Bearer ${token}` } }).catch(() => {});
  openDrops.clear();
});
const relayFlag = () => (location.origin === PUBLIC_RELAY ? "" : ` --relay ${location.origin}`);
const mmss = (ms) => { const s = Math.max(0, Math.ceil(ms / 1000)); return `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`; };

function sendCode(name, url) {
  const wrap = el("div", { class: "send-code" });
  const start = el("button", { class: "small", type: "button", onclick: () => open() }, "Send to another machine");
  const idle = ({ focus = false } = {}) => {
    wrap.replaceChildren(el("div", { class: "row" }, start));
    if (focus) start.focus();
  };
  let drop = null; // { n, token, timer }
  const stop = ({ cancel }) => {
    if (!drop) return;
    clearInterval(drop.timer);
    openDrops.delete(drop.n);
    if (cancel) api("DELETE", `/v1/drops/${drop.n}`, { token: drop.token }).catch(() => {});
    drop = null;
  };
  // markRevoked() calls this before it removes the row's controls.
  wrap.cancelCode = () => stop({ cancel: true });
  const panel = (...kids) => wrap.replaceChildren(el("div", { class: "send-panel stack", role: "group", "aria-label": `Send ${name.toLowerCase()} invite` }, ...kids));
  const ended = (cls, text, { again = true } = {}) => {
    stop({ cancel: false });
    const next = again ? el("button", { class: "small", type: "button", onclick: () => open() }, "New code") : null;
    const done = el("button", { class: "small", type: "button", onclick: () => idle({ focus: true }) }, "Done");
    panel(el("p", { class: `send-note ${cls}` }, text), el("div", { class: "row" }, next, done));
    announce(text);
    (next || done).focus();
  };

  async function open() {
    stop({ cancel: true });
    panel(el("p", { class: "muted hint-text" }, "Making a code…"));
    let code, n, token, deadline;
    try {
      const s = ac.transferSeal(url);
      const r = await (await api("POST", "/v1/drops", { body: JSON.stringify({ claim_hash: s.claimHash, box: s.box }), headers: { "Content-Type": "application/json" } })).json();
      ({ nameplate: n, token } = r);
      // Count down from now rather than trust this browser's clock against the relay's.
      deadline = Date.now() + r.ttl_ms;
      code = `${n}-${s.secret}`;
    } catch (e) {
      return ended("bad", `Could not make a code: ${e.message || e}`);
    }
    const left = el("span", {}, mmss(deadline - Date.now()));
    const cli = name === "Runner"
      ? `airlox runner join --code ${code} --name my-runner --sandbox docker${relayFlag()}`
      : `airlox receive ${code}${relayFlag()}`;
    const cmd = el("code", {}, cli);
    const big = el("div", { class: "send-big", tabindex: -1 }, el("span", { class: "sr-only" }, "Code: "), code);
    panel(
      el("div", { class: "send-head" }, el("strong", {}, `Send ${name.toLowerCase()} invite`),
        el("span", { class: "mono send-clock" }, el("span", { class: "sr-only" }, "Expires in "), left)),
      el("p", { class: "muted hint-text" }, "On the other machine, open ", el("span", { class: "mono" }, `${location.host}/receive`), " and type:"),
      big,
      el("p", { class: "muted hint-text" }, name === "Runner" ? "Or run this there:" : "Or print the link there with:"),
      cmd,
      el("div", { class: "row" }, copyButton("Copy command", () => cli, () => cmd, "Command with the code")),
      el("p", { class: "muted hint-text send-wait" }, "Waiting for the other machine · works once. Keep this page open: leaving it cancels the code."),
      el("div", { class: "row" },
        el("button", { class: "small", type: "button", onclick: () => open() }, "New code"),
        el("button", { class: "small", type: "button", onclick: () => { stop({ cancel: true }); idle({ focus: true }); } }, "Cancel")));
    big.focus();
    announce(`Code ${code} ready`);
    openDrops.set(n, token);
    drop = { n, token, timer: null };
    let polling = false;
    const mine = drop;
    drop.timer = setInterval(async () => {
      if (drop !== mine) return;
      left.textContent = mmss(deadline - Date.now());
      if (polling) return;
      polling = true;
      try {
        const st = await (await api("GET", `/v1/drops/${n}`, { token })).json();
        if (drop !== mine) return;
        if (st.state === "picked_up") {
          ended("good", `Picked up ${hhmm(st.picked_up_at_ms)} · the code is gone.${name === "Owner" ? "" : ` If that wasn't you, revoke ${name}.`}`, { again: false });
        } else if (st.state === "burned") {
          ended("bad", "Someone typed wrong words too many times, so the code was cancelled. Make a new one.");
        } else if (st.state === "expired") {
          ended("", "The code expired before anyone used it.");
        } else if (st.state === "cancelled") {
          ended("", "The code was cancelled when this page was left. Make a new one.");
        }
      } catch (e) {
        if (e.status === 404 && drop === mine) ended("", "The code is no longer on the relay (it expired, or the relay restarted).");
      } finally {
        polling = false;
      }
    }, 1000);
  }
  idle();
  return wrap;
}

// ---------- receive (at /receive) ----------
const RECEIVE_ERRORS = {
  used: "This code was already used. Ask for a new one.",
  burned: "Too many wrong tries cancelled this code. Ask for a new one.",
  cancelled: "The sender cancelled this code. Ask for a new one.",
  expired: "This code expired. Ask for a new one.",
};

function receivePage() {
  const input = el("input", { type: "text", id: "code", class: "mono receive-input", placeholder: "7-guitar-orbit", autocomplete: "off",
    autocapitalize: "none", spellcheck: "false", enterkeyhint: "go", "aria-describedby": "code-err" });
  const err = el("p", { class: "error", id: "code-err", role: "alert" });
  const go = el("button", { class: "primary", type: "submit" }, "Open session");
  const fail = (msg) => {
    err.textContent = msg;
    input.setAttribute("aria-invalid", "true");
    input.focus();
  };
  input.addEventListener("input", () => {
    err.textContent = "";
    input.removeAttribute("aria-invalid");
  });
  const form = el("form", { class: "panel stack receive", onsubmit: async (ev) => {
    ev.preventDefault();
    const code = input.value.trim();
    if (!code) return fail("Enter the code first.");
    let c;
    try {
      c = ac.transferClaim(code);
    } catch (e) {
      return fail(String(e.message || e).replace(/^\w+Error: (invalid code: )?/, "").replace(/^./, (m) => m.toUpperCase()) + ".");
    }
    go.disabled = true;
    try {
      const r = await (await api("POST", `/v1/drops/${c.nameplate}/claim`, { body: JSON.stringify({ claim: c.claim }), headers: { "Content-Type": "application/json" } })).json();
      const link = ac.transferOpen(code, r.box);
      // Runners join from the command line, not a browser: hand over the command.
      if (ac.parseInvite(link).role === "runner") return showRunnerCommand(link);
      const u = new URL(link);
      // Same hand-off as the owner link: the key never enters the address bar here.
      if (u.origin === location.origin) {
        try {
          sessionStorage.setItem(`invite:${u.pathname}`, u.hash.slice(1));
          return location.assign(u.pathname);
        } catch {}
      }
      location.assign(link);
    } catch (e) {
      go.disabled = false;
      fail(e.status === 404 ? `There is no code ${c.nameplate} on this relay. Check the number, or ask for a new code.`
        : e.status === 403 ? "Wrong code. Check the two words; a few wrong tries cancel the code."
        : e.status === 410 ? RECEIVE_ERRORS[e.code] || "This code no longer works. Ask for a new one."
        : e.status === 429 ? "Too many wrong codes from this network. Wait a few minutes and try again."
        : `Could not receive the invite: ${e.message || e}`);
    }
  } },
    el("h1", {}, "Receive an invite"),
    el("p", { class: "muted" }, "Enter the code shown on the other machine, under Send to another machine."),
    el("label", { for: "code", class: "receive-label" }, "Code"),
    input, err, go,
    el("p", { class: "muted hint-text" }, "The link is decrypted in this browser. The relay stores it only encrypted, for a few minutes, and gives it out once."));
  show(form);
  input.focus();
}

function showRunnerCommand(link) {
  const cmd = (l) => `airlox runner join --invite '${l}' --name my-runner --sandbox docker`;
  const shown = el("code", {}, "airlox runner join --invite '", el("span", { class: "link" }, maskInvite(link)), "' --name my-runner --sandbox docker");
  // Keep the link out of the back/forward cache, as on the create page.
  invitesShown = true;
  invitesCreated = true;
  const heading = el("h1", { tabindex: -1 }, "Runner invite received");
  show(el("div", { class: "panel stack receive runner-cmd" },
    heading,
    el("p", { class: "muted" }, "Runners join from the command line. Run this on this machine; the code is used up, so copy it now."),
    shown,
    el("div", { class: "row" }, copyButton("Copy command", () => cmd(link), () => shown, "Runner command", "primary")),
    el("p", { class: "muted hint-text" }, "Install the airlox runner first: ", el("a", { href: INSTALL_URL, target: "_blank", rel: "noopener noreferrer" }, "see the install guide"), ".")));
  heading.focus();
}

// A revoked role's invite no longer works: drop its link and Copy buttons.
function markRevoked(row) {
  if (!row || row.querySelector(".revoked-note")) return;
  row.querySelector(".send-code")?.cancelCode();
  row.querySelectorAll(".invite, .runner-cmd, .send-code").forEach((n) => n.remove());
  row.append(el("p", { class: "muted revoked-note" }, "Revoked for good · this link no longer works"));
}

const INSTALL_URL = "https://github.com/claudezss/airlox#install";
const MASKED_NOTE = "Links are partly hidden here. Copy puts the full link on the clipboard.";

// A button that copies `text()`; when the clipboard is denied, `shown()` is
// swapped for a selected field holding the same text.
function copyButton(label, text, shown, name, cls = "small") {
  const btn = el("button", { class: cls, type: "button", onclick: async () => {
    if (await copyText(btn, text(), label)) return;
    const input = el("input", { type: "text", readonly: true, value: text(), "aria-label": name });
    shown().replaceWith(input);
    input.select();
    btn.textContent = pressCopy();
  } }, label);
  return btn;
}

// Runner invites come with the command that uses them. The shown command
// carries the masked link; Copy command always copies the full one.
function runnerInviteRow(url) {
  const cmd = (link) => `airlox runner join --invite '${link}' --name my-runner --sandbox docker`;
  // Only the link part may break mid-word; the rest wraps at spaces.
  const shown = el("code", {}, "airlox runner join --invite '", el("span", { class: "link" }, maskInvite(url)), "' --name my-runner --sandbox docker");
  const btn = copyButton("Copy command", () => cmd(url), () => shown, "Runner command", "small primary");
  const row = inviteRow("Runner", url, "a machine that runs jobs", "Copy link");
  row.append(el("div", { class: "runner-cmd stack" },
    el("p", { class: "muted hint-text" },
      "Install the airlox runner first: ", el("a", { href: INSTALL_URL, target: "_blank", rel: "noopener noreferrer" }, "see the install guide"), "."),
    el("p", { class: "muted hint-text" }, "Then run this on the runner host. Change ", el("code", {}, "my-runner"), " to a name senders will recognise."),
    shown, el("div", { class: "row" }, btn)));
  return row;
}

// Sender invites come with how to hand them to a coding agent: add the
// airlox MCP server once, then ask the agent to join with the link.
const AGENTS = {
  "Claude Code": "claude mcp add airlox -- npx -y airlox mcp",
  Codex: "codex mcp add airlox -- npx -y airlox mcp",
};
const MCP_DOCS_URL = "https://github.com/claudezss/airlox#from-an-ai-agent";

function senderInviteRow(url) {
  const row = inviteRow("Sender", url, "can post messages, files and jobs, e.g. your code agent", "Copy link");
  let agent = "Claude Code";
  const setup = () => row.querySelector("[data-part=setup]");
  const prompt = el("code", {}, "Join the Airlox session ", el("span", { class: "link" }, maskInvite(url)));
  const picks = Object.keys(AGENTS).map((name) => el("button", {
    type: "button", class: "small", "aria-pressed": String(name === agent), onclick: () => {
      agent = name;
      picks.forEach((b) => b.setAttribute("aria-pressed", String(b.textContent === name)));
      // Also undoes a denied clipboard's swap to an input field.
      setup().replaceWith(el("code", { "data-part": "setup" }, AGENTS[name]));
    } }, name));
  row.append(el("div", { class: "runner-cmd stack" },
    el("p", { class: "muted hint-text" }, "Connect Codex or Claude Code:"),
    el("div", { class: "row agent-pick", role: "group", "aria-label": "Coding agent" }, picks),
    el("p", { class: "muted hint-text" }, "1. In the folder the agent works in, add the airlox MCP server once. The agent can send and save files only inside that folder."),
    el("code", { "data-part": "setup" }, AGENTS[agent]),
    el("div", { class: "row" }, copyButton("Copy command", () => AGENTS[agent], setup, "Setup command")),
    el("p", { class: "muted hint-text" }, "2. Start the agent there and ask it to join. It asks you before each step; to run it unattended, see ",
      el("a", { href: MCP_DOCS_URL, target: "_blank", rel: "noopener noreferrer" }, "airlox mcp config"), "."),
    prompt,
    el("div", { class: "row" }, copyButton("Copy prompt", () => `Join the Airlox session ${url}`, () => prompt, "Prompt for the agent", "small primary")),
    el("p", { class: "muted hint-text" }, "Two agents on one machine that use this link act as one participant, under the first one's name.")));
  return row;
}

// Open the session as its owner without ever putting the key in a URL the
// browser could keep in history: hand the fragment to the session page through
// sessionStorage, the same place takeInvite() keeps it.
function openOwnerSession(link) {
  invitesShown = false;
  const u = new URL(link);
  try {
    sessionStorage.setItem(`invite:${u.pathname}`, u.hash.slice(1));
    location.assign(u.pathname);
  } catch {
    location.assign(link);
  }
}

// ---------- new session (the create flow, at /new) ----------
function newSession() {
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
      radio("ttl", 900000, "15 min", false), radio("ttl", 3600000, "1 hour", true), radio("ttl", 86400000, "24 hours", false),
      radio("ttl", "never", "Never (until closed)", false)));
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
    el("p", { class: "muted" }, "Jobs ask runners to run without network access. Runners that cannot block it are flagged before you approve them."));
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
    el("p", { class: "muted" }, "Invite links appear here once the session exists. Each one carries a role and the session key."),
    el("p", { class: "muted" }, "Joining a session someone else opened? Skip this page and open the invite link you were given, including the part after #."));

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
      const params = { mode: execute ? "execute" : "relay", created_at_ms: Date.now(), ttl_ms: fd.get("ttl") === "never" ? null : Number(fd.get("ttl")), allowed_types: allowed,
        max_item_bytes: mb * MB, job_limits };
      const s = ac.createSession(JSON.stringify(params), undefined);
      const { session_id } = await (await api("POST", "/v1/sessions", { body: s.signedManifest })).json();
      fields.disabled = true;
      const base = location.origin;
      const owner = ac.ownerInvite(base, s.ownerSeed);
      const heading = el("h2", { tabindex: -1 }, "Hand out invites");
      const ownerRow = inviteRow("Owner", owner, "you · keep it private");
      // Without the owner link nobody can approve runners, revoke or close:
      // opening the session waits until it has been saved one way or another.
      // A button, not a link: the owner key must not show in the status bar on hover.
      const openBtn = el("button", { class: "primary cta", type: "button", disabled: true, "aria-describedby": "owner-gate",
        onclick: () => openOwnerSession(owner) }, "Open session");
      const gate = el("p", { class: "muted hint-text", id: "owner-gate" }, "Save the owner link first: copy it, download it or send it to another machine.");
      const saved = el("input", { type: "checkbox", id: "owner-saved" });
      const markSaved = () => {
        openBtn.disabled = false;
        gate.hidden = true;
        saved.checked = true;
      };
      saved.addEventListener("change", () => (saved.checked ? markSaved() : ((openBtn.disabled = true), (gate.hidden = false))));
      const download = el("button", { class: "small", type: "button", onclick: () => {
        const name = `airlox-owner-${session_id.slice(0, 7)}.txt`;
        const body = `Airlox owner link for session ${session_id}\n\n${owner}\n\n` +
          "Anyone with this link controls the session: keep it private. It cannot be shown again.\n";
        const url = URL.createObjectURL(new Blob([body], { type: "text/plain" }));
        const a = el("a", { href: url, download: name, hidden: true });
        document.body.append(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 10000);
        announce(`Downloaded ${name}`);
        markSaved();
      } }, "Download as .txt");
      ownerRow.querySelector(".send-code").before(el("div", { class: "row" }, download));
      // Copy and Send to another machine both count as saving it.
      ownerRow.addEventListener("click", (ev) => {
        if (ev.target.closest("button")) markSaved();
      });
      aside.replaceChildren(
        el("div", { class: "eyebrow" }, `Created · ${session_id.slice(0, 7)}`),
        heading,
        el("div", { class: "callout", role: "note" },
          el("strong", {}, "Save your owner link now: it is shown only once."),
          el("span", {}, "Without it you cannot approve runners, revoke access or close the session. Sender, observer and runner links stay available under Invites in the session.")),
        el("p", { class: "muted hint-text" }, MASKED_NOTE),
        ownerRow,
        el("label", { class: "option check" }, saved, "I've saved it somewhere safe"),
        senderInviteRow(ac.memberInvite(base, s.ownerSeed, "sender")),
        inviteRow("Observer", ac.memberInvite(base, s.ownerSeed, "observer"), "can read everything and export the audit log"),
        ...(execute ? [runnerInviteRow(ac.memberInvite(base, s.ownerSeed, "runner"))] : []),
        el("div", { class: "row" },
          // A button, not a link: the owner key must not show in the status bar on hover.
          openBtn,
          el("button", { type: "button", onclick: () => { invitesShown = false; location.reload(); } }, "Create another")),
        gate);
      heading.focus();
      invitesShown = true;
      invitesCreated = true;
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

const REMOVED_UNSURE = "This browser's access was removed (it left, or the owner revoked its role). The session may still be open for others; you keep what this browser already received.";

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
    if (e.status !== 404) return deadEnd("Cannot reach the relay", "Could not reach the relay. Check your connection and try again.", { retry: true });
    if (!identity?.signed) return deadEnd("This session has ended", "It expired or its owner closed it. Nothing is left on the relay.", { newSession: inv.role === "owner" });
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
      if (e.code === "revoked") return deadEnd("This invite was revoked",
        "The owner removed this link. They would need to start a new session to invite you again.");
      return deadEnd("Could not join", e.message, { retry: !e.status });
    }
    identity = { seed, token: resp.token, role: inv.role, signed };
    await idbPut("identity", [sid, inv.role], identity);
  } else if (!identity.signed) {
    identity.signed = signed;
    await idbPut("identity", [sid, inv.role], identity);
  }
  const me = ac.publicKey(identity.seed);
  const s = { sid, inv, manifest, signed, identity, me, participants: new Map(), items: new Map(), evicted: new Set(),
    wanted: new Map(), askOk: new Set(), askErrors: new Map(), asked: new Set(), uploads: new Set(), uploaded: new Map(), uploading: 0,
    revokedRoles: new Set(),
    lastSeq: -1, closed: null, jobs: new Map(), results: new Map(), runners: [], picked: new Set(), decisions: null,
    said: new Map(), announce: false, jobErrors: new Map(), runnerErrors: new Map(), runnerSeen: new Map(), open: new Set() };
  buildSessionLayout(s);

  // Cached history first, then catch up, then stream. Blobs missing locally
  // are fetched again while the relay still has the session.
  const cached = await tx("events", "readonly", (o) => o.getAll(range(sid)));
  // Which blobs the relay lacks now, so cached items without a blob show as
  // removed rather than being fetched.
  for (const ev of cached) {
    if (ev.kind === "evicted") s.evicted.add(ev.data.item);
    else if (ev.kind === "reseeded") s.evicted.delete(ev.data.item);
  }
  for (const ev of cached) await applyEvent(s, ev, { fetch: !offline, record: false });
  s.render.scroll(true);
  if (offline) {
    if (!s.closed) s.render.closed("it is no longer on the relay");
    return;
  }
  try {
    const q = s.lastSeq >= 0 ? `?after=${s.lastSeq}` : "";
    const evs = (await (await api("GET", `/v1/sessions/${sid}/events${q}`, { token: identity.token })).json()).events;
    for (const ev of evs) await applyEvent(s, ev, { fetch: true, record: true, batch: true });
    s.render.scroll(true);
    tradeBlobs(s); // wants the batch left standing, once per item
  } catch (e) {
    if (e.status === 404 || e.status === 410) return s.render.closed("it is no longer on the relay");
    if (e.status === 401) return s.render.removed(REMOVED_UNSURE);
  }
  s.announce = true;
  streamLoop(s);
  reaskLoop(s);
}

function buildSessionLayout(s) {
  const { sid, inv, manifest, identity } = s;
  app.classList.add("wide");
  const timeline = el("div", { class: "timeline", role: "log", "aria-live": "off", "aria-label": "Session timeline", tabindex: -1 },
    el("div", { class: "pill" }, `${inv.role === "owner" ? "you opened the session" : `you joined as ${inv.role}`} · keys stay in this browser`),
    el("p", { class: "empty" }, "No messages yet. Items appear here as soon as someone sends one."));
  const people = el("ul", { class: "people" });
  const banner = el("div", { class: "banner", tabindex: -1, hidden: true });
  const canSend = ["owner", "sender"].includes(inv.role);

  // composer
  const status = el("p", { class: "status", role: "alert" });
  const text = el("textarea", { id: "msg", rows: 2, placeholder: "Message the session…" });
  // The attach button opens the picker; the input itself stays out of the tab order.
  const file = el("input", { type: "file", id: "file", class: "sr-only", tabindex: -1, "aria-hidden": "true", accept: Object.keys(FILE_TYPES).join(",") });
  const pending = el("span", { class: "pending-file", hidden: true });
  const sendBtn = el("button", { class: "primary", type: "submit" }, "Send");
  const execute = manifest.mode === "execute";
  const jobUi = canSend && execute ? buildJobPanel(s, text, file) : null;
  const attach = el("button", { class: "icon-btn", type: "button", title: "Attach a file", "aria-label": "Attach a file", onclick: () => file.click() }, svg(ICON_CLIP));
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
    sendBtn.dataset.busy = "1";
    status.textContent = "";
    try {
      if (jobUi?.active()) {
        if (await jobUi.submit()) {
          file.value = "";
          showPending();
          text.value = "";
          jobUi.off();
          announce("Job submitted");
        }
        return;
      }
      let sent = false;
      if (file.files?.[0]) {
        await sendFile(s, file.files[0]);
        file.value = "";
        showPending();
        sent = true;
      }
      const value = text.value.trim();
      if (value) {
        await sendPayload(s, "text", null, { type: "text", text: value }, new Uint8Array());
        text.value = "";
        sent = true;
      }
      if (sent) announce("Sent");
    } catch (e) {
      if (e.clearFile) {
        file.value = "";
        showPending();
      }
      status.replaceChildren(...[e.final ? e.message : `Not sent: ${e.message || e}`, e.detail && el("span", { class: "detail" }, e.detail)].filter(Boolean));
    } finally {
      delete sendBtn.dataset.busy;
      sendBtn.disabled = !!s.closed || !!jobUi?.blocked();
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
            touchOnly() ? null : el("span", { class: "hint" }, navigator.platform.startsWith("Mac") ? "⌘↵ to send" : "Ctrl+↵ to send"), sendBtn)),
        status)
    : el("div", { class: "panel readonly", tabindex: -1 }, `You joined as ${inv.role}. You can read this session but not post to it.`);

  // rail
  const closeErr = el("p", { class: "error", role: "alert" });
  const closeBtn = inv.role === "owner" ? el("button", { class: "danger", type: "button", onclick: async () => {
    if (!confirm("Close the session and purge it from the relay for everyone? Export the audit log first: closing deletes it.")) return;
    closeErr.textContent = "";
    try {
      await api("POST", `/v1/sessions/${sid}/close`, { token: identity.token });
    } catch (e) {
      closeErr.textContent = `Could not close: ${e.message}`;
    }
  } }, "Close & purge") : null;
  // Revoking cuts off a role's participants and disables its invite.
  const revokeErr = el("p", { class: "error", role: "alert" });
  const revokeNote = el("p", { class: "muted revoke-note", tabindex: -1 });
  const revokeBtns = inv.role === "owner"
    ? ["sender", "observer", ...(execute ? ["runner"] : [])].map((role) => {
      const b = el("button", { class: "small danger", type: "button", "data-role": role, onclick: async () => {
        const ps = [...s.participants.values()].filter((p) => p.role === role && !p.left && !p.revoked && p.participant_pub !== s.me);
        const n = ps.length;
        const names = ps.slice(0, 4).map((p) => p.display_name).join(", ") + (n > 4 ? ` and ${n - 4} more` : "");
        const effect = n ? `${n} ${n === 1 ? "person" : "people"} (${names}) ${n === 1 ? "is" : "are"} cut off now and the ${role} link stops working.`
          : `No one has joined with the ${role} link yet; the link stops working.`;
        if (!confirm(`Revoke the ${role} role? ${effect} This is permanent for this session: you cannot issue a new ${role} link. To let someone back in, start a new session. ` +
          "Revoking does not change the session key: anyone who kept the link or copies of files still has them. To end access completely, close the session.")) return;
        revokeErr.textContent = "";
        try {
          await api("POST", `/v1/sessions/${sid}/roles/${role}/revoke`, { token: identity.token });
          revokeNote.textContent = `Revoked the ${role} role.`;
          announce(`Revoked the ${role} role`);
          revokeNote.focus();
        } catch (e) {
          revokeErr.textContent = `Could not revoke: ${e.message}`;
        }
      } }, `Revoke ${role}s`);
      return b;
    })
    : [];
  const access = revokeBtns.length ? el("details", {},
    el("summary", {}, "Revoke access"),
    el("div", { class: "stack" },
      el("p", { class: "muted" }, "Cuts off everyone who joined with that role's link, and the link stops working for good. To end access to what was shared, close the session."),
      el("div", { class: "chips" }, revokeBtns), revokeNote, revokeErr)) : null;
  // The audit trail goes with the session when it is purged.
  const auditErr = el("p", { class: "error", role: "alert" });
  const auditDone = el("p", { class: "muted audit-done" });
  let auditTimer;
  const auditBtn = ["owner", "observer"].includes(inv.role) ? el("button", { type: "button", onclick: async () => {
    auditErr.textContent = "";
    try {
      const r = await api("GET", `/v1/sessions/${sid}/audit.jsonl`, { token: identity.token });
      const url = URL.createObjectURL(new Blob([await r.arrayBuffer()], { type: "application/x-ndjson" }));
      const name = `${sid}-audit.jsonl`;
      const a = el("a", { href: url, download: name, hidden: true });
      document.body.append(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 10000);
      auditDone.textContent = `Downloaded ${name}`;
      announce(auditDone.textContent);
      clearTimeout(auditTimer);
      auditTimer = setTimeout(() => (auditDone.textContent = ""), 6000);
    } catch (e) {
      auditErr.textContent = `Could not export: ${e.message}`;
    }
  } }, "Export audit log") : null;
  const auditHint = auditBtn ? el("div", { class: "stack hint-lines" },
    el("p", { class: "muted hint-text" }, "JSON Lines with the session's records, for checking with airlox tools."),
    el("p", { class: "muted hint-text" }, inv.role === "owner" ? "Download before you close: closing deletes it." : "Download before the owner closes the session: closing deletes it.")) : null;
  const inviteRows = inv.role === "owner" ? {
    sender: senderInviteRow(ac.memberInvite(location.origin, inv.roleSeed, "sender")),
    observer: inviteRow("Observer", ac.memberInvite(location.origin, inv.roleSeed, "observer"), "can read everything and export the audit log"),
    runner: execute ? runnerInviteRow(ac.memberInvite(location.origin, inv.roleSeed, "runner")) : null } : {};
  const invites = inv.role === "owner" ? el("details", {},
    el("summary", {}, "Invites"),
    el("div", { class: "stack" }, el("p", { class: "muted hint-text" }, MASKED_NOTE), Object.values(inviteRows))) : null;
  const runnerList = el("ul", { class: "runners" });
  const runnerNote = el("p", { class: "muted" });
  const rail = el("aside", { class: "rail" },
    el("section", {}, el("h2", {}, "Participants"), people),
    execute ? el("section", { class: "stack", id: "runner-console", tabindex: -1, "aria-label": "Runner console" }, el("h2", {}, "Runners"), runnerList, runnerNote) : null,
    el("section", {}, el("h2", {}, "Allowed types"), el("div", { class: "chips" }, manifest.allowed_types.map((t) => el("span", { class: "chip" }, t)))),
    el("section", { class: "stack" }, el("h2", {}, "Session"),
      el("p", { class: "mono muted" }, sid),
      el("p", { class: "muted" }, manifest.expires_at_ms === null ? "Never expires: it lasts until the owner closes it"
        : `Expires ${new Date(manifest.expires_at_ms).toLocaleString()}`),
      el("p", { class: "muted" }, `Files up to ${fmtBytes(manifest.max_item_bytes)}`),
      invites, access, auditBtn, auditDone, auditHint, auditErr, closeBtn, closeErr),
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
  show(el("div", { class: "session" }, el("h1", { class: "sr-only" }, `Session ${sid.slice(0, 7)}, ${manifest.mode} mode, ${inv.role}`),
    el("div", { class: "main-col" }, approvalBanner, banner, timeline, composer), rail));
  // A #fragment would replace the stored invite on reload: move focus instead.
  const skip = (label, to) => el("a", { class: "skip", href: "#", onclick: (ev) => {
    ev.preventDefault();
    to().focus();
  } }, label);
  const skipMsg = canSend ? skip("Skip to message box", () => text) : null;
  document.body.prepend(...[skipMsg, skip("Skip to timeline", () => timeline)].filter(Boolean));
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
  const setTitle = (state) => (document.title = `Session ${sid.slice(0, 7)} · ${state || inv.role} · Airlox`);
  setTitle();
  const badge = document.getElementById("badge");
  badge.hidden = false;
  document.getElementById("badge-text").textContent = "E2E sealed";
  const expiry = document.getElementById("expiry");
  expiry.hidden = false;
  const conn = el("span", { class: "conn mono", role: "status", hidden: true });
  expiry.before(conn);
  const tick = () => {
    const left = manifest.expires_at_ms === null ? Infinity : manifest.expires_at_ms - Date.now();
    if (left === Infinity && !s.closed) return (expiry.textContent = "no expiry");
    if (left <= 0 || s.closed) {
      expiry.textContent = s.closed ? "closed" : "expired";
      expiry.classList.remove("soon");
      return clearInterval(timer);
    }
    const t = Math.floor(left / 1000);
    const h = Math.floor(t / 3600);
    const mm = String(Math.floor((t % 3600) / 60)).padStart(2, "0");
    const ss = String(t % 60).padStart(2, "0");
    // On phones only the time shows; "expires in" stays for screen readers.
    expiry.replaceChildren(el("span", { class: "exp-word" }, "expires in "), `${h ? `${h}:` : ""}${mm}:${ss}`);
    expiry.classList.toggle("soon", left < 5 * 60 * 1000);
  };
  const timer = setInterval(tick, 1000);
  tick();

  if (execute) runnerLoop(s);
  // Follow new items when the reader is at the end of the timeline (not of the
  // page: on narrow screens the sidebar follows it), or has not scrolled yet and
  // sees the end. Scrolled up, or well into the sidebar below: leave them be.
  const composerH = () => parseFloat(document.documentElement.style.getPropertyValue("--composer-h")) || 0;
  const nearBottom = () => {
    // The newest item, not the timeline box: that can stretch to fill the column.
    const end = (timeline.lastElementChild || timeline).getBoundingClientRect().bottom;
    const d = end - (window.innerHeight - composerH()); // > 0: end below the visible area
    return (d >= -48 && d <= 160) || (window.scrollY === 0 && end <= window.innerHeight);
  };
  // The last item ends just above the sticky composer.
  const toEnd = () => {
    const last = timeline.lastElementChild;
    if (!last) return;
    const delta = last.getBoundingClientRect().bottom - (window.innerHeight - composerH());
    if (Math.abs(delta) >= 1) window.scrollBy(0, delta);
  };
  // Timeline entries are kept in event order.
  const place = (node, seq, old) => {
    node.dataset.seq = seq;
    if (old) return old.replaceWith(node);
    const next = [...timeline.children].find((n) => n.dataset?.seq !== undefined && Number(n.dataset.seq) > seq);
    if (next) next.before(node);
    else timeline.append(node);
  };
  // The session is closed or this browser lost access: nothing can be posted
  // or decided any more. Focus on a control that goes away moves to the banner.
  const lock = (why) => {
    const a = document.activeElement;
    for (const c of [sendBtn, text, file, attach, closeBtn, auditBtn, ...revokeBtns]) if (c) c.disabled = true;
    jobUi?.lock();
    if (auditHint) auditHint.hidden = true;
    approvalBanner.hidden = true;
    skipMsg?.remove();
    composer.replaceWith(el("div", { class: "panel readonly", id: "composer-note" }, why));
    document.documentElement.style.removeProperty("--composer-h");
    s.render.runners();
    if (a && a !== document.body && (!a.isConnected || a.disabled)) banner.focus({ preventScroll: true });
  };
  const gone = (msg) => {
    banner.hidden = false;
    banner.textContent = msg;
    announce(msg);
    s.render.conn(false);
  };
  s.render = {
    people: () => people.replaceChildren(...[...s.participants.values()].map((p) =>
      el("li", {},
        el("span", { class: "dot", "aria-hidden": "true" }),
        el("div", { class: "who" },
          el("div", { class: "name", title: p.display_name }, p.display_name, p.participant_pub === s.me ? el("span", { class: "you" }, "you") : null),
          el("div", { class: "sub" }, `${p.role} · ${p.kind}${p.revoked ? " · revoked" : p.left ? " · left" : ""}`),
          p.description ? el("div", { class: "desc", title: "Their own description, not verified" }, el("span", { class: "claim" }, "says "), p.description) : null),
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
      const old = document.getElementById(`item-${it.id}`);
      // Owner events (approvals) that left the relay unread have nothing to show.
      if (it.status === "evicted" && it.kind === "event") return old?.remove();
      // Keep keyboard focus across the redraw: on the same control, or on the
      // card when that control is gone. The clicked button may already be
      // disabled (focus on the page), hence s.refocus.
      const a = document.activeElement;
      const idle = !a || a === document.body || !a.isConnected;
      const held = old && old.contains(a) ? { keep: a.dataset?.keep } : old && idle && s.refocus === it.id ? { keep: "ask" } : null;
      if (s.refocus === it.id) s.refocus = null;
      const node = renderItem(s, it);
      place(node, it.seq, old);
      if (held) (held.keep && node.querySelector(`[data-keep="${held.keep}"]:not(:disabled)`) || node).focus({ preventScroll: true });
      // A reader at the bottom stays there, also when a card grows in place
      // (its file arrives, its job gets a result).
      if (stick) toEnd();
      settle(s, it);
      if (it.kind === "job") announceJob(s, it);
      else if (!old && s.announce && it.status === "ok" && it.author !== s.me && (it.kind === "text" || it.kind === "file"))
        announce(`${it.authorName}: ${it.kind === "text" ? it.meta.text : it.meta.name}`);
      jobUi?.refresh();
    },
    runners: () => {
      renderRunners(s, runnerList, runnerNote);
      const n = s.runners.filter((r) => !r.approved && !r.rejected && r.setup !== "failed").length;
      approvalBanner.hidden = !(inv.role === "owner" && n && !s.closed);
      approvalText.textContent = `${n} runner${n === 1 ? "" : "s"} awaiting approval`;
      jobUi?.refresh();
    },
    scroll: toEnd,
    conn: (bad) => {
      conn.textContent = bad && !s.closed ? "Reconnecting…" : "";
      conn.hidden = !conn.textContent;
    },
    revoked: () => {
      for (const b of revokeBtns) {
        const gone = s.revokedRoles.has(b.dataset.role);
        b.disabled = gone || !!s.closed;
        b.textContent = gone ? `${b.dataset.role}s revoked` : `Revoke ${b.dataset.role}s`;
      }
      for (const role of s.revokedRoles) markRevoked(inviteRows[role]);
      s.render.runners();
    },
    // A local line in the timeline: the relay's revoke event is not a signed item.
    note: (seq, text, at) => {
      const id = `note-${seq}`;
      if (document.getElementById(id)) return;
      place(el("article", { class: "item evline", id }, el("div", { class: "pill" }, text, at ? ` · ${hhmm(at)}` : "")), seq);
    },
    closed: (reason) => {
      s.closed ||= "closed";
      gone(`This session is closed: ${reason}. Its history stays in this browser until you clear it.`);
      lock(canSend ? "This session is closed." : "This session is closed. You can still read what this browser received.");
      if (auditBtn) auditBtn.textContent = "Audit log deleted with the session";
      if (invites) invites.hidden = true;
      setTitle("closed");
      tick();
    },
    // This browser lost its access but the session lives on for others.
    removed: (msg) => {
      s.closed ||= "removed";
      s.removed = true;
      gone(msg);
      lock("Your access was removed. You can still read what this browser received.");
      if (auditBtn) auditBtn.textContent = "Audit log unavailable";
      badge.classList.add("off");
      document.getElementById("badge-text").textContent = "access removed";
      expiry.hidden = true;
      setTitle("access removed");
      tick();
    },
  };
}

// Participants come only from verified signed joins, never from the
// relay's unsigned event fields.
async function applyEvent(s, ev, { fetch, record, batch = false }) {
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
    s.asked.delete(ev.data.item); // evicted again: an older ask for it no longer stands
    const it = s.items.get(ev.data.item);
    if (it && it.status === "retry") {
      it.status = "evicted";
      s.render.item(it);
    }
    // Cached history (record false) never asks; the catch-up batch and the stream do.
    if (fetch && record && it?.status === "evicted" && it.author !== s.me) wantBlob(s, it.id);
  } else if (ev.kind === "want") {
    // Not from cached history, and only for an item this browser verified: the
    // id could be anything the relay made up. A catch-up batch uploads once at
    // its end, for the wants no later event has settled.
    if (record && ev.data.by !== s.me && s.items.get(ev.data.item)?.status === "ok") {
      s.asked.add(ev.data.item);
      if (!batch) tradeBlobs(s);
    }
  } else if (ev.kind === "reseeded") {
    reappeared(s, ev.data.item, { live: fetch && record });
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
  } else if (ev.kind === "revoked") {
    const cut = ev.data.participants || [];
    s.revokedRoles.add(ev.data.role);
    for (const pk of cut) {
      const p = s.participants.get(pk);
      if (p) p.revoked = true;
    }
    s.render.people();
    s.render.revoked();
    s.render.note(ev.seq, `owner revoked the ${ev.data.role} role (${cut.length} ${cut.length === 1 ? "person" : "people"})`, ev.at);
    if (cut.includes(s.me)) {
      s.closed = "revoked";
      s.render.removed("The owner removed your access. The session is still open for others; you keep what this browser already received.");
    }
  } else if (ev.kind === "closed") {
    s.closed = ev.data.reason;
    const why = { "closed by owner": "the owner closed it", expired: "it expired", idle: "it was idle too long" };
    s.render.closed(why[ev.data.reason] || ev.data.reason);
  }
  if (record) await idbPut("events", [s.sid, ev.seq], ev);
  s.lastSeq = Math.max(s.lastSeq, ev.seq);
}

// Re-seeding: a blob the relay deleted before this browser fetched it can
// come back from a participant who still has it. Ask for it, and upload the
// blobs others ask for that this browser holds; the relay takes an upload
// only if it matches the author's signed hash. A want expires on the relay
// after 10 minutes, so s.wanted (item -> time of the last ask) is asked again
// every REASK_MS for as long as the item is missing.
const REASK_MS = 5 * 60 * 1000;
const ASK_GRACE_MS = 30 * 1000;

// "ok", "limit" (the relay has too many open wants: stop this round) or "error".
async function wantBlob(s, id, { force = false } = {}) {
  if (s.closed) return "ok";
  const last = s.wanted.get(id);
  if (!force && last !== undefined && Date.now() - last <= REASK_MS) return "ok";
  s.wanted.set(id, Date.now());
  // Let the card say nobody has answered yet.
  setTimeout(() => {
    const it = s.items.get(id);
    if (it?.status === "evicted") s.render.item(it);
  }, ASK_GRACE_MS + 500);
  try {
    await api("POST", `/v1/sessions/${s.sid}/items/${id}/want`, { token: s.identity.token });
    s.askOk.add(id);
    s.askErrors.delete(id);
  } catch (e) {
    // The blob is on the relay: fetch it. It stays wanted, so a relay that
    // says present but then serves 410 cannot make this loop.
    if (e.code === "present") reappeared(s, id, { keepWanted: true, live: true });
    else {
      // Ask again in about half a minute rather than waiting a full interval.
      s.wanted.set(id, Date.now() - REASK_MS + 30000);
      s.askOk.delete(id);
      s.askErrors.set(id, e.status ? e.message || `the relay answered ${e.status}` : "no connection to the relay");
      const it = s.items.get(id);
      if (it?.status === "evicted") s.render.item(it);
      return e.status === 429 ? "limit" : "error";
    }
  }
  return "ok";
}

// Ask again for everything still missing whose last ask is old. Wants the
// relay already has open come first (refreshing one needs no new slot), then
// the rest; each group oldest first. The relay's limit on open wants only
// ends the round once it reaches the ones that need a new slot.
async function reask(s) {
  if (s.closed || s.reasking) return;
  s.reasking = true;
  try {
    const due = [...s.wanted].filter(([id, at]) => s.items.get(id)?.status === "evicted" && Date.now() - at > REASK_MS)
      .sort((a, b) => s.askOk.has(b[0]) - s.askOk.has(a[0]) || a[1] - b[1]);
    for (const [id] of due) {
      const open = s.askOk.has(id);
      if ((await wantBlob(s, id)) === "limit" && !open) break;
    }
  } finally {
    s.reasking = false;
  }
}

function reaskLoop(s) {
  const tick = () => document.visibilityState === "visible" && reask(s);
  setInterval(tick, 60000);
  document.addEventListener("visibilitychange", tick);
}

// Upload what others asked for: at most MAX_UPLOADS at once, one per item at a
// time, each after a random wait so every holder does not upload together. An
// item whose ask was settled in the meantime (reseeded, evicted again) is
// skipped. A refused upload (409, 429, ...) is dropped like any other.
const MAX_UPLOADS = 2;
async function tradeBlobs(s) {
  if (s.uploading >= MAX_UPLOADS) return;
  s.uploading++;
  try {
    for (;;) {
      const id = [...s.asked].find((x) => !s.uploads.has(x));
      if (!id) break;
      s.uploads.add(id);
      try {
        await sleep(Math.random() * 2000);
        if (!s.asked.delete(id) || s.closed) continue;
        if (Date.now() - (s.uploaded.get(id) ?? 0) < 20000) continue;
        const blob = await idbGet("blobs", [s.sid, id]);
        if (!blob || s.closed) continue;
        s.uploaded.set(id, Date.now());
        await fetch(`/v1/sessions/${s.sid}/items/${id}/blob`, { method: "PUT", body: blob,
          headers: { Authorization: `Bearer ${s.identity.token}` } }).catch(() => {});
      } finally {
        s.uploads.delete(id);
      }
    }
  } finally {
    s.uploading--;
  }
}

// An evicted blob is on the relay again: fetch it, unless this is a replay of
// history (offline, closed, cached) where nothing should touch the network.
function reappeared(s, id, { keepWanted = false, live = false } = {}) {
  s.evicted.delete(id);
  if (!keepWanted) s.wanted.delete(id);
  s.askErrors.delete(id);
  s.asked.delete(id);
  const it = s.items.get(id);
  if (live && !s.closed && it && it.status === "evicted") {
    it.status = "retry";
    receive(s, it.seq, it.envelope, true);
  }
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
      if (fetchBlob && h.author !== s.me) wantBlob(s, h.id);
      return s.render.item(it);
    }
    let r;
    try {
      r = await fetch(`/v1/sessions/${s.sid}/items/${h.id}/blob`, { cache: "no-store",
        headers: { Authorization: `Bearer ${s.identity.token}` } });
    } catch {
      r = null;
    }
    if (r?.status === 410 || r?.status === 404) {
      it.status = "evicted";
      if (h.author !== s.me) wantBlob(s, h.id);
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
  s.wanted.delete(h.id);
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
      it.status === "ok" ? el("span", { class: "verified" }, " · ", sym("✓"), " verified") : null));
  const card = el("div", { class: "card" });
  const node = el("article", { class: cls, id: `item-${it.id}`, tabindex: -1 },
    el("div", { class: `avatar ${av}`, "aria-hidden": "true" }, initials(it.authorName)),
    el("div", { class: "body" }, meta, card));
  if (it.status === "evicted") {
    const noun = { text: "message", file: "file", job: "job", result: "result" }[it.kind] || "item";
    if (mine) card.append(el("p", { class: "note" }, `You sent this ${noun}, but this browser no longer has it and it is no longer on the relay.`));
    else {
      const asked = s.wanted.get(it.id);
      const silent = asked !== undefined && Date.now() - asked > ASK_GRACE_MS;
      const failed = s.askErrors.get(it.id);
      card.append(el("p", { class: "note" }, `A ${noun} from ${it.authorName} was sent before this browser got it and is no longer on the relay. ` +
        (failed ? `Could not ask: ${failed.replace(/\.$/, "")}. Try again.`
          : silent ? "No one has answered yet. It appears when someone who has it opens this session."
          : "Asking the others for a copy; it appears here if one of them has the session open.")),
        el("div", { class: "row note-actions" }, el("button", { type: "button", class: "small", "data-keep": "ask", onclick: async (ev) => {
          ev.currentTarget.disabled = true;
          s.refocus = it.id;
          await wantBlob(s, it.id, { force: true });
          s.render.item(it);
        } }, "Ask again")));
    }
    return node;
  }
  if (it.status === "retry") {
    card.append(el("p", { class: "note" }, `Downloading this ${label} item failed. Retrying…`));
    return node;
  }
  if (it.status === "rejected") {
    card.append(el("p", {}, sym("✕ "), `Not shown: ${it.error}`));
    if (it.detail) card.append(el("div", { class: "detail" }, it.detail));
    return node;
  }
  const m = it.meta;
  if (m.type === "event") return renderEvent(s, it, meta);
  if (m.type === "text") card.append(el("p", {}, m.text));
  else if (m.type === "file") {
    if (it.role === "runner") card.append(el("p", { class: "note" }, s.runners.find((x) => x.pub === it.author)?.relayOnly
      ? `Output file from runner ${it.authorName}. ${NOT_SHOWN_YET.replace("Not shown yet", "Not accepted yet")}`
      : `Output file from runner ${it.authorName}, not listed by an accepted result.`));
    appendFileView(card, it);
  }
  else if (m.type === "job") renderJob(s, it, card);
  else if (m.type === "result") {
    const chk = resultCheck(s, it);
    card.append(chk.ok ? renderResult(s, it) : rejectedResult(chk.error, chk.pending));
    if (!chk.ok && !chk.pending) node.classList.add("rejected");
  } else card.append(el("pre", { tabindex: 0 }, JSON.stringify(m, null, 2)));
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
      card.append(el("ul", { class: "ziplist", tabindex: 0, "aria-label": "Files in the ZIP" }, entries.map((e) =>
        el("li", {}, el("span", {}, e.is_dir ? `${e.path}/` : e.path), el("span", {}, e.is_dir ? "" : fmtBytes(e.size))))),
        el("div", { class: "zipnote" }, `${files.length} file${files.length === 1 ? "" : "s"} · paths and sizes checked`));
    } catch (e) {
      card.append(el("p", { class: "error" }, "This file is not a valid ZIP."), el("div", { class: "detail" }, String(e.message || e)));
    }
  } else card.append(el("pre", { tabindex: 0 }, new TextDecoder().decode(it.body)));
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
  if (st.reason === "author_revoked") return "cancelled · its sender's access was revoked";
  const name = (st.runner ? memberName(s, st.runner) : null) || (tgt?.type === "runner" ? tgt.name : null) || "the runner";
  const tail = { runner_unresponsive: "did not claim it", runner_lost: "went offline", runner_left: "left", runner_rejected: "was rejected", runner_revoked: "was revoked" }[st.reason];
  return tail ? `failed · ${name} ${tail}` : `failed${st.reason ? ` · ${st.reason}` : ""}`;
}

// The owner's verified runner_approve and runner_reject events: who is
// approved (minus anyone rejected: a rejection is final) and who is rejected.
function signedDecisions(s) {
  if (s.decisions) return s.decisions;
  const approved = new Set();
  const rejected = new Set();
  for (const it of [...s.items.values()].sort((a, b) => a.seq - b.seq)) {
    if (it.kind !== "event" || it.status !== "ok" || it.role !== "owner" || it.meta?.type !== "event" || !it.meta.participant_pub) continue;
    if (it.meta.event === "runner_reject") rejected.add(it.meta.participant_pub);
    else if (it.meta.event === "runner_approve") approved.add(it.meta.participant_pub);
  }
  s.decisions = { approved: [...approved].filter((k) => !rejected.has(k)), rejected };
  return s.decisions;
}

// Runners with the owner's signed approval; undefined when approval is not required.
function approvedRunners(s) {
  if (!s.manifest.job_limits?.approve_runners) return undefined;
  return signedDecisions(s).approved;
}

// Approvals changed: results that arrived earlier are checked again.
function approvalsChanged(s) {
  s.decisions = null;
  if (s.runnersLoaded) pollRunners(s); // runner cards depend on the signed approvals too
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

const NOT_SHOWN_YET = "Not shown yet: this browser has not received the owner's approval of this runner.";

// Cached: does this result belong to its job and come from an approved runner?
function resultCheck(s, r) {
  if (r.check) return r.check;
  if (r.role !== "runner") return { ok: false, error: "the author is not a runner" };
  const approved = approvedRunners(s);
  if (approved && !approved.includes(r.author)) {
    // The relay's word is not enough: until the owner's approval reaches this
    // browser (it may have left the relay before this browser joined), the
    // result is not accepted. Not cached: the approval can still arrive.
    if (s.runners.find((x) => x.pub === r.author)?.relayOnly) return { ok: false, pending: true, error: NOT_SHOWN_YET };
    return { ok: false, error: "the author is not an approved runner" };
  }
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

// `pending`: a neutral note, since the owner's approval may still arrive.
function rejectedResult(reason, pending) {
  return el("div", {}, pending ? el("p", { class: "note" }, reason) : el("p", { class: "note error" }, sym("✕ "), `Result not accepted: ${reason}`));
}

function logBlock(label, text, truncated) {
  if (!text && !truncated) return null;
  return el("div", { class: "logblock" }, el("div", { class: "logname" }, label, truncated ? el("span", { class: "chip" }, "truncated") : null),
    el("pre", { tabindex: 0 }, text || "(empty)"));
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
    box.append(el("p", { class: "note error" }, sym("✕ "), `${f.name}: the file does not match the runner's result`));
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
    if (!chk.ok) entries.push({ r, error: chk.error, pending: chk.pending });
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
  const rendered = entries.map((e) => (e.error ? rejectedResult(e.error, e.pending) : renderResult(s, e.r, e.dup ? "ignored: duplicate" : "")));
  const lines = m.code.split("\n");
  const code = el("pre", { tabindex: 0 }, m.code);
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
    el("div", { class: "pill" }, suspect ? [sym("✕ "), `ignored: ${text} (not from the owner)`] : text, " · ", hhmm(it.created)));
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
          networkUnblocked: !!j.runner.network_unblocked, online: !!e.online, job: e.job,
          setup: e.state || null, detail: typeof e.detail === "string" ? (e.detail.length > 300 ? `${e.detail.slice(0, 300)}…` : e.detail) : null,
          ...runnerStatus(s, e) });
      } catch (err) {
        console.warn("ignoring unverifiable runner", err);
      }
    }
    const first = !s.runnersLoaded;
    for (const x of list) {
      const label = x.rejected ? "rejected" : x.approved ? "approved" : x.setup === "failed" ? "failed to start" : "awaiting approval";
      if (!first && s.announce && s.runnerSeen.get(x.pub) !== label) announce(`Runner ${x.name}: ${label}`);
      s.runnerSeen.set(x.pub, label);
    }
    s.runnersLoaded = true;
    s.runners = list;
    connState(s, "poll", true);
    // Results from runners only the relay vouches for are held back until the approval arrives.
    const relaySig = list.filter((x) => x.relayOnly).map((x) => x.pub).sort().join("|");
    if (relaySig !== s.relaySig) {
      s.relaySig = relaySig;
      approvalsChanged(s);
    }
    s.render.runners();
  } catch (e) {
    if (s.closed) return;
    if (e.status === 404 || e.status === 410) {
      s.closed = "gone";
      s.render.closed("it is no longer on the relay");
    } else if (e.status === 401) {
      s.closed = "gone";
      s.render.removed(REMOVED_UNSURE);
    } else connState(s, "poll", false);
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

// A runner's approval as the owner signed it (and whether approval is
// required, from the signed manifest), never the relay's unsigned listing.
// `relayOnly`: the relay says approved but no approval signed by the owner has
// reached this browser (it may have left the relay before this browser joined).
// Such a runner counts as awaiting approval here.
function runnerStatus(s, e) {
  const signed = approvedRunners(s);
  const rejected = !!e.rejected || signedDecisions(s).rejected.has(e.participant_pub);
  if (signed === undefined) return { rejected, approved: !rejected, relayOnly: false };
  const approved = !rejected && signed.includes(e.participant_pub);
  return { rejected, approved, relayOnly: !rejected && !approved && !!e.approved };
}

function renderRunners(s, list, note) {
  const owner = s.inv.role === "owner";
  const text = (r) => {
    const approval = r.rejected ? "rejected"
      : r.approved ? "approved"
      : r.relayOnly ? (owner ? "needs your confirmation" : "approval not received here")
      : r.setup === "failed" ? "not approved"
      : "awaiting approval";
    const live = r.rejected ? "rejected" : r.setup === "failed" ? "setup failed"
      : r.setup === "preparing" && !r.online ? "preparing its sandbox"
      : !r.approved ? "awaiting approval" : r.online ? (r.job ? `busy · #${short(r.job)}` : "idle") : "offline";
    return { approval, live, err: s.runnerErrors.get(r.pub) };
  };
  const revoked = s.revokedRoles.has("runner");
  // The poll runs every few seconds: leave the list (and keyboard focus) alone
  // unless something it shows has changed.
  const sig = JSON.stringify([!!s.closed, revoked, s.runners.map((r) => [r.pub, r.name, r.description, r.labels, r.host, r.sandbox, r.networkUnblocked,
    r.rejected, r.approved, r.relayOnly, r.setup, r.detail, text(r)])]);
  if (list.dataset.sig === sig) return;
  list.dataset.sig = sig;
  const a = document.activeElement;
  const idle = !a || a === document.body || !a.isConnected;
  const focus = list.contains(a) && a.dataset?.act ? { pub: a.dataset.pub, act: a.dataset.act }
    : idle && s.runnerFocus && Date.now() - s.runnerFocus.at < 10000 ? s.runnerFocus : null;
  s.runnerFocus = null;
  note.textContent = revoked ? "Runner access was revoked. Runners cannot join this session any more."
    : s.runners.length ? "" : owner ? "No runners yet. Hand out the runner invite from Invites." : "No runners have joined yet.";
  list.replaceChildren(...s.runners.map((r) => {
    const { approval, live, err } = text(r);
    const dot = r.rejected ? "" : !r.approved ? "wait" : r.online ? "on" : "";
    // Kept after a failed approval: the relay may say approved while the
    // owner's approval never got posted, and the owner must be able to retry.
    // A runner that failed to start has nothing to approve: show why instead.
    const failed = r.setup === "failed" && !r.rejected;
    const canApprove = owner && !r.rejected && !failed && (!r.approved || !!err);
    const warn = r.networkUnblocked && !r.rejected
      ? el("span", { class: "chip warn", title: "This runner's sandbox cannot block network access" }, sym("⚠ "), "network not blocked") : null;
    const act = (name, label, cls, approve) => el("button", { type: "button", class: `small ${cls}`, "data-pub": r.pub, "data-act": name,
      disabled: !!s.closed, onclick: (ev) => decideRunner(s, r, approve, ev.currentTarget) }, label);
    return el("li", { class: `runner${r.rejected ? " is-rejected" : ""}` },
      el("div", { class: "rhead" },
        el("span", { class: `dot ${dot}`, "aria-hidden": "true" }),
        el("strong", { class: "name", title: r.name }, r.name),
        el("span", { class: "sub" }, live),
        el("span", { class: "key", title: "Key fingerprint" }, ac.fingerprint(r.pub).slice(0, 4))),
      el("div", { class: "sub" }, `${r.sandbox} · ${r.host}`),
      r.description ? el("div", { class: "desc", title: "The runner's own description, not verified" }, el("span", { class: "claim" }, "says "), r.description) : null,
      r.labels.length ? el("div", { class: "chips" }, r.labels.map((l) => el("span", { class: "chip" }, l))) : null,
      el("div", { class: "chips" },
        el("span", { class: `chip approval ${r.rejected ? "bad" : r.approved ? "good" : "wait"}` }, approval),
        canApprove ? null : warn),
      owner && r.relayOnly && !r.rejected ? el("p", { class: "sub confirm-note" },
        "The relay says this runner is approved, but this browser has no approval from you on record. Confirm only if you approved it. Its key: ",
        el("span", { class: "mono" }, ac.fingerprint(r.pub).slice(0, 16).replace(/(.{4})(?=.)/g, "$1 ")), ".") : null,
      owner && canApprove && warn ? el("p", { class: "sub net-note" }, "Jobs on this runner can reach the internet. Approve only if you trust the code senders submit.") : null,
      failed ? el("p", { class: "sub setup-failed", title: "The runner's own report, not verified" }, r.detail || "The runner could not start.") : null,
      owner && !r.rejected ? el("div", { class: "row" },
        canApprove ? [warn, act("approve", r.relayOnly ? "Confirm approval" : "Approve", "primary", true)] : null,
        act("reject", "Reject", "danger", false)) : null,
      err ? el("p", { class: "error", role: "alert" }, err) : null);
  }));
  if (focus) {
    const btns = [...list.querySelectorAll("button[data-act]")].filter((b) => b.dataset.pub === focus.pub && !b.disabled);
    // The same button, or its runner's remaining one when the clicked one is gone.
    (btns.find((b) => b.dataset.act === focus.act) || btns[0] || document.getElementById("runner-console"))?.focus({ preventScroll: true });
  }
}

async function decideRunner(s, r, approve, btn) {
  if (!approve && !confirm(`Reject runner ${r.name}? It is removed from the session and its job fails.`)) return;
  // The poll redraws the list: remember what had focus, since the clicked
  // button is disabled (and unfocused) by then.
  s.runnerFocus = { pub: r.pub, act: btn.dataset.act, at: Date.now() };
  btn.disabled = true;
  s.runnerErrors.delete(r.pub);
  try {
    const meta = approve ? { type: "event", event: "runner_approve", participant_pub: r.pub }
      : { type: "event", event: "runner_reject", participant_pub: r.pub, reason: null };
    const relay = () => api("POST", `/v1/sessions/${s.sid}/runners/${encodeURIComponent(r.pub)}/${approve ? "approve" : "reject"}`, { token: s.identity.token });
    // Approve on the relay first: a runner awaiting approval is not a
    // recipient, so the relay would not keep the owner's event for it.
    // (A runner the relay already approved needs only the event.)
    if (approve && !r.relayOnly) await relay();
    await sendPayload(s, "event", null, meta, new Uint8Array());
    if (!approve) await relay();
    await pollRunners(s);
  } catch (e) {
    s.runnerErrors.set(r.pub, `Could not ${approve ? "approve" : "reject"} the runner: ${e.message || e}`);
    s.render.runners();
  } finally {
    btn.disabled = false;
    if (btn.isConnected && (!document.activeElement || document.activeElement === document.body)) btn.focus({ preventScroll: true });
  }
}

// ---------- composer: run as job ----------
function buildJobPanel(s, text, file) {
  const lim = s.manifest.job_limits;
  let on = false;
  let sendBtn;
  let chipsSig = null; // null: the chips are not drawn yet
  let filesSig = null;
  let locked = false;
  // "any", "labels" or "runner:<pub>"; the relay picks the runner, this only says which.
  let target = "any";
  const chips = el("div", { class: "runchips", role: "group", "aria-labelledby": "job-target-label" });
  const labels = el("input", { type: "text", id: "job-labels", placeholder: "gpu, cpu", autocomplete: "off", "aria-label": "Runner labels" });
  const labelField = el("div", { class: "stack field", hidden: true }, el("label", { for: "job-labels" }, "Labels"), labels);
  const timeout = el("input", { type: "number", id: "job-timeout", min: 1, max: lim.timeout_s, step: 1, value: lim.timeout_s,
    title: `1 to ${lim.timeout_s} seconds` });
  const files = el("div", { class: "pickfiles" });
  const filesSummary = el("summary", {}, "Input files · none selected");
  // Why a job sent now would fail, with what would fix it.
  const readyText = el("span", { id: "job-ready" });
  const readyAct = el("span", { class: "ready-act" });
  const ready = el("div", { class: "job-ready", hidden: true }, el("span", { class: "ready-icon", "aria-hidden": "true" }, "!"), readyText, readyAct);
  const panel = el("div", { class: "jobpanel", hidden: true },
    el("div", { class: "stack field" }, el("span", { class: "field-label", id: "job-target-label" }, "Run on"), chips),
    el("div", { class: "jobrow" },
      labelField,
      el("div", { class: "stack field narrow" }, el("label", { for: "job-timeout" }, "Timeout (s)"), timeout)),
    ready,
    el("details", { class: "inputfiles" }, filesSummary, files));
  const countPicked = () => {
    const n = s.picked.size;
    filesSummary.textContent = `Input files · ${n ? `${n} selected` : "none selected"}`;
  };
  const setOn = (v) => {
    on = v;
    toggle.setAttribute("aria-pressed", String(on));
    toggle.classList.toggle("on", on);
    panel.hidden = !on;
    chipsSig = null;
    filesSig = null;
    text.placeholder = on ? "Python code to run (or attach a .py file)…" : "Message the session…";
    text.classList.toggle("code", on);
    text.spellcheck = !on;
    text.rows = on ? 7 : 2;
    if (sendBtn) sendBtn.textContent = on ? "Send job" : "Send";
    if (!on && sendBtn && !sendBtn.dataset.busy) {
      sendBtn.disabled = !!s.closed;
      sendBtn.removeAttribute("aria-describedby");
    }
    refresh();
  };
  const toggle = el("button", { type: "button", class: "small", "aria-pressed": "false", onclick: () => setOn(!on) }, "Send as job");
  labels.addEventListener("input", () => syncReady());

  // The relay's rule: approved (signed by the owner here), online, idle, and
  // matching the target. Anything else fails at once: there is no queue.
  const usable = (r) => !r.rejected && r.approved && r.setup !== "failed" && r.online;
  const runnerState = (r) => r.setup === "failed" ? "setup failed" : !r.approved ? "needs approval"
    : !r.online ? (r.setup === "preparing" ? "preparing" : "offline") : r.job ? "busy" : "idle";
  const wantedLabels = () => labels.value.split(",").map((x) => x.trim().toLowerCase()).filter(Boolean);
  const matches = (r) => target === "any" ? true : target === "labels" ? wantedLabels().every((l) => r.labels?.includes(l)) : `runner:${r.pub}` === target;

  // null when a job could go now; otherwise { text, act }.
  function blocker() {
    // Until the first poll, or while it fails, the list may be stale: let the relay decide.
    if (!s.runnersLoaded || s.connBad?.has("poll")) return null;
    if (target === "labels" && !wantedLabels().length) return null; // submit() explains
    const live = s.runners.filter((r) => !r.rejected);
    const fit = live.filter(matches);
    if (fit.some((r) => usable(r) && !r.job)) return null;
    const pending = fit.find((r) => !r.approved && r.setup !== "failed");
    const one = target.startsWith("runner:") ? fit[0] : null;
    let why;
    if (one) why = `${one.name} ${{ "needs approval": "needs approval", "setup failed": "failed to set up", preparing: "is still preparing its sandbox" }[runnerState(one)] || `is ${runnerState(one)}`}`;
    else if (fit.some(usable)) why = target === "labels" ? "Every runner with those labels is busy" : "Every runner is busy";
    else if (target === "labels" && !fit.length) why = `No runner has the labels ${wantedLabels().join(", ")}`;
    else if (!live.length) why = "No runner has joined yet";
    else why = target === "labels" ? "No approved runner with those labels is online" : "No approved runner is online";
    return { text: `${why}, so a job sent now would fail right away.`, pending: s.inv.role === "owner" ? pending : null, none: !live.length };
  }

  function syncReady() {
    if (!on) return;
    const b = locked ? null : blocker();
    ready.hidden = !b;
    // Not while a send is in flight: that would allow a second one.
    if (sendBtn && !sendBtn.dataset.busy) {
      sendBtn.disabled = !!s.closed || !!b;
      if (b) sendBtn.setAttribute("aria-describedby", "job-ready");
      else sendBtn.removeAttribute("aria-describedby");
    }
    if (!b) return;
    readyText.textContent = b.text;
    const sig = `${b.pending?.pub || ""}|${b.none}`;
    if (readyAct.dataset.sig === sig) return;
    readyAct.dataset.sig = sig;
    const owner = s.inv.role === "owner";
    if (b.pending) {
      readyAct.replaceChildren(el("button", { type: "button", class: "small", onclick: () => {
        const sec = document.getElementById("runner-console");
        sec?.scrollIntoView({ block: "start" });
        (sec?.querySelector(`button[data-act=approve][data-pub="${CSS.escape(b.pending.pub)}"]`) || sec)?.focus({ preventScroll: true });
      } }, `Review ${b.pending.name}`));
    } else if (b.none && owner && !s.revokedRoles.has("runner")) {
      const cmd = `airlox runner join --invite '${ac.memberInvite(location.origin, s.inv.roleSeed, "runner")}' --name my-runner --sandbox docker`;
      const btn = el("button", { type: "button", class: "small", onclick: async () => {
        if (!(await copyText(btn, cmd, "Copy runner command"))) btn.textContent = "Copy it from Invites";
      } }, "Copy runner command");
      readyAct.replaceChildren(btn);
    } else readyAct.replaceChildren(...(owner ? [] : [el("span", { class: "muted" }, "Ask the session owner to start and approve a runner.")]));
  }

  function drawChips() {
    const live = s.runners.filter((r) => !r.rejected);
    if (target.startsWith("runner:") && !live.some((r) => `runner:${r.pub}` === target)) target = "any";
    labelField.hidden = target !== "labels";
    const sig = JSON.stringify([target, locked, live.map((r) => [r.pub, r.name, r.labels, runnerState(r)])]);
    if (sig === chipsSig) return;
    chipsSig = sig;
    const a = document.activeElement;
    const keep = chips.contains(a) ? a.dataset.target : null;
    const chip = (value, ...label) => el("button", { type: "button", class: "small runchip", "data-target": value, disabled: locked,
      "aria-pressed": String(target === value), onclick: () => {
        target = value;
        refresh();
        if (value === "labels") labels.focus();
      } }, ...label);
    chips.replaceChildren(
      chip("any", "Any idle runner"),
      ...live.map((r) => {
        const st = runnerState(r);
        return chip(`runner:${r.pub}`, el("span", { class: `dot ${st === "idle" ? "on" : st === "needs approval" ? "wait" : st === "busy" ? "busy" : ""}`, "aria-hidden": "true" }),
          r.name, r.labels?.length ? el("span", { class: "muted" }, ` · ${r.labels.join(", ")}`) : null, el("span", { class: "state" }, st));
      }),
      chip("labels", "By label…"));
    if (keep) chips.querySelector(`[data-target="${CSS.escape(keep)}"]`)?.focus({ preventScroll: true });
  }

  function refresh() {
    if (!on) return;
    drawChips();
    syncReady();
    const cands = [...s.items.values()].filter((i) => i.kind === "file" && i.status === "ok" && i.ref).sort((a, b) => a.seq - b.seq);
    countPicked();
    const fsig = cands.map((i) => i.id).join("|");
    if (fsig === filesSig) return;
    filesSig = fsig;
    files.replaceChildren(...(cands.length ? cands.map((i) => el("label", { class: "option check" },
      el("input", { type: "checkbox", checked: s.picked.has(i.id), disabled: locked, onchange: (ev) => {
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
      if (!/\.py$/i.test(f.name)) throw rejectFile(f, "is not a .py file: attach a .py file, or write the code in the message box");
      filename = f.name;
      try {
        code = new TextDecoder("utf-8", { fatal: true }).decode(await f.arrayBuffer());
      } catch {
        throw rejectFile(f, "is not valid UTF-8 text");
      }
    } else {
      code = text.value;
      if (!code.trim()) throw new Error("attach a .py file or write code in the message box");
    }
    if (new TextEncoder().encode(code).length > MB) throw new Error("the code is over 1 MiB");
    const t = Number(timeout.value);
    if (!Number.isInteger(t) || t < 1 || t > lim.timeout_s) throw new Error(`timeout must be 1 to ${lim.timeout_s} seconds`);
    let tgt;
    if (target === "any") tgt = { type: "any" };
    else if (target === "labels") {
      const ls = wantedLabels();
      if (!ls.length) throw new Error("enter at least one label, such as gpu");
      if (ls.length > 16) throw new Error("use at most 16 labels");
      const bad = ls.find((l) => !/^[a-z0-9][a-z0-9._-]{0,62}$/.test(l));
      if (bad) throw new Error(`"${bad.slice(0, 20)}" is not a valid label: use letters, digits, . _ - (up to 63, starting with a letter or digit)`);
      tgt = { type: "labels", labels: ls };
    } else {
      const r = s.runners.find((x) => `runner:${x.pub}` === target);
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

  // Access gone or session closed: job mode off, nothing in the panel live.
  const lock = () => {
    locked = true;
    setOn(false);
    toggle.disabled = true;
    for (const c of panel.querySelectorAll("button, input, summary")) c.disabled = true;
  };
  return { panel, toggle, refresh, submit, lock, off: () => setOn(false), active: () => on, setSend: (b) => (sendBtn = b),
    blocked: () => on && !locked && !!blocker() };
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

// A file that can never be sent is dropped from the composer, not kept to fail again.
function rejectFile(f, why) {
  const e = new Error(`"${f.name}" ${why}`);
  e.clearFile = true;
  return e;
}

async function sendFile(s, f) {
  const dot = f.name.lastIndexOf(".");
  const ext = dot < 0 ? "" : f.name.slice(dot).toLowerCase();
  const t = FILE_TYPES[ext];
  if (!t) throw rejectFile(f, `cannot be shared: ${ext ? `${ext} files are not` : "files without an extension are not"} allowed (allowed: .py .md .zip .png .jpg .webp)`);
  let [subkind, mime] = t;
  if (!s.manifest.allowed_types.includes(subkind)) throw rejectFile(f, `cannot be shared: ${subkind} files are not allowed in this session`);
  let bytes = new Uint8Array(await f.arrayBuffer());
  try {
    if (subkind === "image") {
      const clean = ac.sanitizeImage(bytes);
      mime = clean.mime;
      bytes = clean.data;
    } else if (subkind === "zip") ac.inspectZip(bytes);
  } catch (e) {
    const why = String(e.message || e).replace(/^\w+Error: /, "");
    if (subkind !== "zip") throw rejectFile(f, `cannot be shared: ${why}`);
    const err = new Error(`"${f.name}" is not a valid ZIP.`);
    Object.assign(err, { clearFile: true, detail: why });
    throw err;
  }
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

// Show "Reconnecting…" only once the stream or the runner poll has been failing
// for a moment, so a reconnect that works at once shows nothing.
function connState(s, key, ok) {
  s.connBad ||= new Set();
  if (ok) s.connBad.delete(key);
  else s.connBad.add(key);
  if (!s.connBad.size) {
    clearTimeout(s.connTimer);
    s.connTimer = 0;
    return s.render.conn(false);
  }
  s.connTimer ||= setTimeout(() => {
    s.connTimer = 0;
    s.render.conn(s.connBad.size > 0);
  }, 2500);
}

// The relay's keep-alive comment arrives about every 15 s; a stream silent for
// much longer is dead even if the browser has not noticed.
const STREAM_SILENCE_MS = 45000;

async function streamLoop(s) {
  let delay = 1000;
  addEventListener("offline", () => connState(s, "net", false));
  addEventListener("online", () => connState(s, "net", true));
  if (navigator.onLine === false) connState(s, "net", false);
  while (!s.closed) {
    let watchdog;
    try {
      const headers = { Authorization: `Bearer ${s.identity.token}` };
      if (s.lastSeq >= 0) headers["Last-Event-ID"] = String(s.lastSeq);
      const ctl = new AbortController();
      const arm = () => {
        clearTimeout(watchdog);
        watchdog = setTimeout(() => ctl.abort(), STREAM_SILENCE_MS);
      };
      arm();
      const r = await fetch(`/v1/sessions/${s.sid}/stream`, { headers, signal: ctl.signal });
      if (r.status === 404 || r.status === 410 || r.status === 401) {
        s.closed = "gone";
        if (r.status === 401) s.render.removed(REMOVED_UNSURE);
        else s.render.closed("it is no longer on the relay");
        return;
      }
      if (!r.ok) throw new Error(`stream ${r.status}`);
      delay = 1000;
      connState(s, "stream", true);
      reask(s); // wants may have run out while the stream was down
      const reader = r.body.pipeThrough(new TextDecoderStream()).getReader();
      let buf = "";
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        arm();
        buf += value;
        let i;
        while ((i = buf.indexOf("\n\n")) >= 0) {
          const ev = parseSse(buf.slice(0, i));
          buf = buf.slice(i + 2);
          if (ev) {
            ev.at = Date.now();
            await applyEvent(s, ev, { fetch: true, record: true });
          }
        }
      }
    } catch (e) {
      console.warn("stream interrupted", e);
      if (!s.closed) connState(s, "stream", false);
    }
    clearTimeout(watchdog);
    if (!s.closed) {
      await sleep(delay);
      delay = Math.min(delay * 2, 30000);
    }
  }
}

// ---------- landing page and routing ----------
// "/" is the landing page, "/new" the create-session form and "/s/<id>" a
// session. They are separate documents (full page loads), so the landing page
// can be served with a different policy from pages that hold keys. The landing
// page needs nothing but this file; the others wait for the WebAssembly core.
function showHome() {
  document.body.classList.add("landing");
  document.getElementById("site-nav").hidden = false;
  document.getElementById("site-foot").hidden = false;
  app.classList.add("wide");
  document.title = "Airlox · Secure sessions for code and LLM agents";
  show(document.getElementById("home-tpl").content.cloneNode(true));
  demoTabs(document.querySelector(".lp-demo-tabs"));
  demoPause(document.querySelector(".lp-demo-pause"));
  let target = null;
  try {
    target = location.hash.length > 1 ? document.getElementById(decodeURIComponent(location.hash.slice(1))) : null;
  } catch {}
  if (target) target.scrollIntoView();
}

// The use case tabs: one panel shown at a time, arrow keys move between tabs.
function demoTabs(list) {
  const tabs = [...list.querySelectorAll("[role=tab]")];
  const select = (tab) => {
    for (const t of tabs) {
      const on = t === tab;
      t.setAttribute("aria-selected", String(on));
      t.tabIndex = on ? 0 : -1;
      document.getElementById(t.getAttribute("aria-controls")).hidden = !on;
    }
  };
  list.addEventListener("click", (e) => {
    const tab = e.target.closest("[role=tab]");
    if (tab) select(tab);
  });
  list.addEventListener("keydown", (e) => {
    const i = tabs.indexOf(document.activeElement);
    const step = { ArrowRight: 1, ArrowLeft: -1, Home: -i, End: tabs.length - 1 - i }[e.key];
    if (i < 0 || step === undefined) return;
    e.preventDefault();
    const next = tabs[(i + step + tabs.length) % tabs.length];
    select(next);
    next.focus();
  });
}

// The recordings loop forever (WCAG 2.2.2): one toggle swaps every GIF for its
// still. Reduced motion starts paused (the <picture> source already shows the still).
function demoPause(btn) {
  const imgs = [...document.querySelectorAll(".lp-demo-media img")];
  const set = (paused) => {
    for (const img of imgs) {
      // The <source> would win over src under reduced motion: switch it off and drive src alone.
      img.previousElementSibling?.setAttribute("media", "not all");
      img.src = img.getAttribute("src").replace(/\.(gif|webp)$/, paused ? ".webp" : ".gif");
    }
    btn.setAttribute("aria-pressed", String(paused));
    btn.querySelector(".glyph").textContent = paused ? "▶" : "❚❚";
  };
  btn.addEventListener("click", () => set(btn.getAttribute("aria-pressed") !== "true"));
  if (matchMedia("(prefers-reduced-motion: reduce)").matches) set(true);
}

// ---------- boot ----------
if (location.pathname.startsWith("/s/")) {
  try {
    await loadCore();
    await sessionView();
  } catch (e) {
    deadEnd("Airlox failed to start", String(e.message || e));
  }
} else if (location.pathname === "/new") {
  document.title = "New session · Airlox";
  try {
    await loadCore();
    newSession();
  } catch (e) {
    deadEnd("Airlox failed to start", String(e.message || e));
  }
} else if (location.pathname === "/receive") {
  document.title = "Receive an invite · Airlox";
  try {
    await loadCore();
    receivePage();
  } catch (e) {
    deadEnd("Airlox failed to start", String(e.message || e));
  }
} else if (location.hash === "#new") {
  location.replace("/new"); // old links to /#new
} else {
  showHome();
}
