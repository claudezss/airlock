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
// The size offered when the relay does not say what it allows, and the
// largest default its answer can raise that to.
const MAX_ITEM_MB = 25;
const MAX_DEFAULT_ITEM_MB = 100;
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
// Whole seconds as "6 h", "2 h 5 min", "45 s" (zero parts left out).
function fmtDuration(sec) {
  sec = Math.max(0, Math.floor(sec));
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const x = sec % 60;
  return [h && `${h} h`, m && `${m} min`, x && `${x} s`].filter(Boolean).join(" ") || "0 s";
}
// Status symbols are decoration next to words: screen readers skip them.
const sym = (c) => el("span", { "aria-hidden": "true" }, c);
const initials = (name) => (name.split(/[^\p{L}\p{N}]+/u).filter(Boolean).slice(0, 2).map((w) => w[0]).join("") || "?").toUpperCase();

const clip = (t, n) => (t.length > n ? `${t.slice(0, n)}…` : t);

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
const DEAD_ICONS = {
  ended: ["M3 12a9 9 0 1 0 18 0 9 9 0 1 0-18 0", "M5.6 5.6l12.8 12.8"],
  offline: ["M2 9a15 15 0 0 1 20 0", "M5.5 12.5a10 10 0 0 1 13 0", "M9 16a5 5 0 0 1 6 0", "M12 19.5h.01", "M3 3l18 18"],
};
function deadEnd(title, cause, { newSession = false, retry = false } = {}) {
  document.title = `${title} · Airlox`;
  // Without a retry, there is always somewhere to go: a new session, or a
  // transfer code for someone else's.
  show(el("div", { class: "ncard dead-end", role: "alert" },
    el("span", { class: "dead-icon" }, svg(DEAD_ICONS[retry ? "offline" : "ended"], 26)),
    el("h1", {}, title), el("p", { class: "muted" }, cause),
    el("div", { class: "row" },
      retry ? el("button", { class: "primary cta", type: "button", onclick: () => location.reload() }, "Try again")
        : el("a", { class: `button cta${newSession ? " primary" : ""}`, href: "/new" }, "New session"),
      retry ? null : el("a", { class: "button cta", href: "/receive" }, "Enter a transfer code"))));
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

// ---------- Markdown → DOM ----------
// A CommonMark-ish subset of what agents actually send: headings, paragraphs
// (single newlines are line breaks, as in chat), lists (nested by indent, task
// boxes), blockquotes, fenced code, tables, rules, emphasis, inline code and
// links. Everything is built with el() from text nodes, never innerHTML. Raw
// HTML is shown as text. Only http(s) and mailto links are live, and remote
// images are never fetched (that would tell a third party when and from where
// this session is read).
const reducedMotion = () => matchMedia("(prefers-reduced-motion: reduce)").matches;
const SAFE_URL = /^(https?:|mailto:)/i;
// Past these sizes the renderer shows plain text instead: its regexes are
// not meant for megabytes, and a sender should not be able to stall a reader.
// Block rules are linear; the inline regexes can backtrack quadratically on
// crafted input, so each paragraph and each message get a budget.
const MD_MAX_CHARS = 200000;
const MD_MAX_INLINE = 4000;
const MD_INLINE_BUDGET = 40000;
const MD_MAX_DEPTH = 6;
const MD_MAX_COLS = 50;
const MD_MAX_CELLS = 5000;
let mdBudget = MD_INLINE_BUDGET;
const I_COPY = ["M9 9h10v10H9z", "M5 15V5h10"];
const I_CHECK = ["M5 12l5 5 9-10"];
const I_CODE = ["M8 6l-5 6 5 6", "M16 6l5 6-5 6"];
const I_WRAP = ["M3 6h18", "M3 12h15a3 3 0 0 1 0 6h-4", "M16 16l-2 2 2 2", "M3 18h7"];
const I_DOWN = ["M12 5v14", "M6 13l6 6 6-6"];
const I_UP = ["M6 15l6-6 6 6"];
const I_CHEV = ["M6 9l6 6 6-6"];
const I_SEND = ["M12 19V5", "M6 11l6-6 6 6"];
const I_REPLY = ["M9 14L4 9l5-5", "M4 9h10a6 6 0 0 1 6 6v5"];
const I_AT = ["M16 12a4 4 0 1 1-8 0 4 4 0 0 1 8 0z", "M16 12v1.5a2.5 2.5 0 0 0 5 0V12a9 9 0 1 0-3.5 7.1"];
const I_PANEL = ["M5 4h14a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2z", "M15 4v16"];

// A URL may hold balanced parentheses one level deep, as in wiki/Foo_(bar).
const MD_URL = "(?:[^()\\s]|\\([^()\\s]*\\))+";
const MD_INLINE = new RegExp([
  `!\\[([^\\]\\n]{0,300})\\]\\((${MD_URL})\\)`, // 1,2 image
  `\\[([^\\]\\n]{1,300})\\]\\((${MD_URL})\\)`, // 3,4 link
  "\\*\\*(.+?)\\*\\*|__(.+?)__", // 5,6 strong
  "~~(.+?)~~", // 7 strikethrough
  "(?<![\\w*])\\*(?!\\s)(.+?)(?<!\\s)\\*(?![\\w*])", // 8 emphasis
  "(?<!\\w)_(?!\\s)(.+?)(?<!\\s)_(?!\\w)", // 9 emphasis
  "(https?:\\/\\/(?:[^\\s<>()]|\\([^\\s<>()]*\\))*(?:[^\\s<>().,:;!?\"'\\]]|\\([^\\s<>()]*\\)))", // 10 bare link
  "(\\n)", // 11 line break
].join("|"), "g");

// Code spans are cut out first by a linear scan, since a regex for them
// backtracks on many unmatched backtick runs: a run closes at the next run of
// the same length. Each span becomes a private-use placeholder so the other
// inline rules still apply around it.
const CODE_MARK = /\uE000(\d+)\uE001/g;
function codeSpans(text) {
  text = text.replace(/[\uE000\uE001]/g, "\uFFFD");
  const runs = [];
  const byLen = new Map();
  for (let i = text.indexOf("`"); i >= 0; ) {
    let j = i;
    while (text[j] === "`") j++;
    runs.push([i, j - i]);
    if (!byLen.has(j - i)) byLen.set(j - i, []);
    byLen.get(j - i).push(i);
    i = text.indexOf("`", j);
  }
  const seen = new Map(); // run length → how far its list has been passed
  const codes = [];
  let out = "";
  let last = 0;
  for (const [start, n] of runs) {
    if (start < last) continue;
    const list = byLen.get(n);
    let k = seen.get(n) ?? 0;
    while (k < list.length && list[k] <= start) k++;
    seen.set(n, k);
    if (k === list.length) continue;
    const end = list[k];
    const body = text.slice(start + n, end);
    out += text.slice(last, start) + `\uE000${codes.length}\uE001`;
    codes.push({ body: body.replace(/^ ([\s\S]*) $/, "$1"), raw: text.slice(start, end + n) });
    last = end + n;
  }
  return [out + text.slice(last), codes];
}

function mdInline(text, depth = 0, codes = null) {
  if (!codes) [text, codes] = codeSpans(text);
  const unmark = (s) => s.replace(CODE_MARK, (_, i) => codes[i].raw);
  const plain = (s) => s.split(CODE_MARK).map((p, i) => (i % 2 ? el("code", {}, codes[p].body) : p)).filter((p) => p !== "");
  mdBudget -= text.length;
  if (depth > MD_MAX_DEPTH || text.length > MD_MAX_INLINE || mdBudget < 0) return plain(text);
  const out = [];
  const re = new RegExp(MD_INLINE);
  let last = 0;
  let m;
  while ((m = re.exec(text))) {
    if (m.index > last) out.push(...plain(text.slice(last, m.index)));
    if (m[2] !== undefined) out.push(el("span", { class: "img-blocked", title: unmark(m[2]) }, "Image: ", unmark(m[1]) || "no description", " · not loaded"));
    else if (m[4] !== undefined) out.push(...mdLink(unmark(m[4]), mdInline(m[3], depth + 1, codes)));
    else if (m[5] !== undefined || m[6] !== undefined) out.push(el("strong", {}, mdInline(m[5] ?? m[6], depth + 1, codes)));
    else if (m[7] !== undefined) out.push(el("del", {}, mdInline(m[7], depth + 1, codes)));
    else if (m[8] !== undefined || m[9] !== undefined) out.push(el("em", {}, mdInline(m[8] ?? m[9], depth + 1, codes)));
    else if (m[10]) out.push(...mdLink(unmark(m[10]), [unmark(m[10])], true));
    else if (m[11]) out.push(el("br"));
    last = re.lastIndex;
  }
  if (last < text.length) out.push(...plain(text.slice(last)));
  return out;
}

const hostOf = (u) => {
  try {
    return new URL(u).host;
  } catch {
    return "";
  }
};
// Returns an array of nodes: the link, or just its text when the scheme is not allowed.
function mdLink(href, kids, bare = false) {
  if (!SAFE_URL.test(href)) return kids;
  const host = hostOf(href);
  // Always say where a link really goes, unless its own text is a link to the same host.
  const label = kids.map((k) => (typeof k === "string" ? k : k.textContent)).join("").trim();
  const labelHost = /^https?:\/\//i.test(label) ? hostOf(label) : /^[\w-]+(\.[\w-]+)+(\/\S*)?$/.test(label) ? hostOf(`https://${label}`) : "";
  const differs = !bare && host && labelHost !== host;
  return [el("a", { href, target: "_blank", rel: "noopener noreferrer nofollow", title: href }, kids,
    differs ? el("span", { class: "host" }, host) : null)];
}

function markdown(src) {
  if (src.length > MD_MAX_CHARS) return [el("p", {}, src)];
  mdBudget = MD_INLINE_BUDGET;
  try {
    return mdBlocks(src.replace(/\r\n?/g, "\n").split("\n"), 0);
  } catch {
    return [el("p", {}, src)];
  }
}

function mdBlocks(lines, depth) {
  const out = [];
  let i = 0;
  const para = [];
  const flush = () => {
    if (para.length) out.push(el("p", {}, mdInline(para.join("\n"))));
    para.length = 0;
  };
  while (i < lines.length) {
    const line = lines[i];
    let m;
    if (!line.trim()) {
      flush();
      i++;
    } else if ((m = line.match(/^\s{0,3}(```+|~~~+)\s*([\w+#.-]*)/))) {
      flush();
      const fence = m[1];
      const body = [];
      i++;
      while (i < lines.length && !lines[i].trimStart().startsWith(fence)) body.push(lines[i++]);
      i++;
      out.push(codeBlock(body.join("\n"), m[2]));
    } else if ((m = mdHeading(line))) {
      flush();
      out.push(el(`h${Math.min(m[0] + 1, 4)}`, {}, mdInline(m[1])));
      i++;
    } else if (/^\s{0,3}[-*_]/.test(line) && /^(?:-{3,}|\*{3,}|_{3,})$/.test(line.replace(/\s+/g, ""))) {
      flush();
      out.push(el("hr"));
      i++;
    } else if (/^\s{0,3}>/.test(line)) {
      flush();
      const q = [];
      while (i < lines.length && /^\s{0,3}>/.test(lines[i])) q.push(lines[i++].replace(/^\s{0,3}>\s?/, ""));
      out.push(el("blockquote", {}, depth < MD_MAX_DEPTH ? mdBlocks(q, depth + 1) : el("p", {}, q.join("\n"))));
    } else if (line.includes("|") && i + 1 < lines.length && mdTableRule(lines[i + 1])) {
      flush();
      const cells = (l) => l.trim().replace(/^\||\|$/g, "").split("|").map((c) => c.trim());
      const head = cells(line).slice(0, MD_MAX_COLS);
      i += 2;
      // Every row gets one cell per column, so the cell count, not the
      // source size, is what to bound: past it, rows are counted, not shown.
      const rows = [];
      let skipped = 0;
      for (; i < lines.length && lines[i].includes("|") && lines[i].trim(); i++) {
        if ((rows.length + 1) * head.length > MD_MAX_CELLS) skipped++;
        else rows.push(cells(lines[i]));
      }
      out.push(el("div", { class: "tbl", tabindex: 0, role: "region", "aria-label": "Table" }, el("table", {},
        el("thead", {}, el("tr", {}, head.map((h) => el("th", {}, mdInline(h))))),
        el("tbody", {}, rows.map((r) => el("tr", {}, head.map((_, j) => el("td", {}, r[j] ? mdInline(r[j]) : null))))))));
      if (skipped) out.push(el("p", { class: "muted" }, `… ${skipped} more row${skipped === 1 ? "" : "s"} not shown`));
    } else if (/^(\s*)([-*+]|\d{1,9}[.)])\s+/.test(line) && depth < MD_MAX_DEPTH) {
      flush();
      const [list, next] = mdList(lines, i, depth + 1);
      out.push(list);
      i = next;
    } else {
      para.push(line.trim());
      i++;
    }
  }
  flush();
  return out;
}

// The block rules are written as scans, not one regex each: patterns such as
// `\s*#*\s*$` backtrack quadratically on a long run of spaces.
function mdHeading(line) {
  const m = line.match(/^ {0,3}(#{1,6})[ \t]/);
  if (!m) return null;
  let s = line.slice(m[0].length).trim();
  let e = s.length;
  while (e > 0 && s[e - 1] === "#") e--;
  // A closing run of #s goes when a space sets it apart (or it is all there is).
  if (e === 0 || s[e - 1] === " " || s[e - 1] === "\t") s = s.slice(0, e).trimEnd();
  return [m[1].length, s];
}
const mdTableRule = (line) => {
  const t = line.trim();
  if (!t.includes("-")) return false;
  const cells = t.replace(/^\|/, "").replace(/\|$/, "").split("|");
  return cells.every((c) => /^:?-{2,}:?$/.test(c.trim()));
};

function mdList(lines, i, depth) {
  const first = lines[i].match(/^(\s*)([-*+]|(\d{1,9})[.)])\s+/);
  const indent = first[1].length;
  const ordered = first[3] !== undefined;
  const list = el(ordered ? "ol" : "ul", ordered && first[3] !== "1" ? { start: first[3] } : {});
  const pad = (l) => l.match(/^\s*/)[0].length;
  while (i < lines.length) {
    const m = lines[i].match(/^(\s*)([-*+]|\d{1,9}[.)])\s+(.*)$/);
    if (!m || m[1].length !== indent) break;
    const body = [m[3]];
    i++;
    // Continuation: deeper-indented lines (nested lists, wrapped text).
    while (i < lines.length && (lines[i].trim() === "" ? pad(lines[i + 1] ?? "") > indent : pad(lines[i]) > indent)) {
      body.push(lines[i].slice(Math.min(indent + 2, pad(lines[i]))));
      i++;
    }
    const task = body[0].match(/^\[([ xX])\]\s+(.*)$/);
    if (task) body[0] = task[2];
    const kids = body.length === 1 ? mdInline(body[0]) : mdBlocks(body, depth).flatMap((b) => (b.tagName === "P" ? [...b.childNodes] : [b]));
    list.append(el("li", {}, task ? el("input", { type: "checkbox", disabled: true, checked: task[1] !== " ", "aria-label": task[1] !== " " ? "done" : "not done" }) : null,
      task ? " " : null, kids));
  }
  return [list, i];
}

// Light colouring for what agents trade here: Python, JavaScript, shell, JSON.
const KEYWORDS = {
  python: "and as assert async await break class continue def del elif else except False finally for from global if import in is lambda None nonlocal not or pass raise return True try while with yield",
  js: "async await break case catch class const continue default delete do else export extends false finally for function if import in instanceof let new null return super switch this throw true try typeof undefined var void while yield",
  sh: "if then else fi for do done case esac in function export echo cd",
};
const LANGS = { py: "python", python: "python", js: "js", javascript: "js", ts: "js", typescript: "js", json: "js", sh: "sh", bash: "sh", shell: "sh", console: "sh" };
const MD_MAX_HIGHLIGHT = 100000;
// One pass, left to right: an unclosed string or comment runs to the end of
// its line (or of the code, for the multi-line kinds) instead of being
// retried from every quote, so the time is linear in the code's length.
function highlight(code, lang) {
  const kind = LANGS[lang?.toLowerCase()];
  if (!kind || code.length > MD_MAX_HIGHLIGHT) return [code];
  const kws = new Set(KEYWORDS[kind].split(" "));
  const out = [];
  let plain = "";
  const tok = (cls, text) => {
    if (plain) out.push(plain);
    plain = "";
    out.push(cls ? el("span", { class: cls }, text) : text);
  };
  const eol = (i) => (code.indexOf("\n", i) < 0 ? code.length : code.indexOf("\n", i));
  const until = (close, from) => {
    const j = code.indexOf(close, from);
    return j < 0 ? code.length : j + close.length;
  };
  const isId = (c) => /[A-Za-z0-9_]/.test(c);
  let i = 0;
  while (i < code.length) {
    const c = code[i];
    const two = code.slice(i, i + 2);
    const three = code.slice(i, i + 3);
    let j = -1;
    let cls = null;
    if ((kind !== "js" && c === "#") || (kind === "js" && two === "//")) [j, cls] = [eol(i), "tk-com"];
    else if (kind === "js" && two === "/*") [j, cls] = [until("*/", i + 2), "tk-com"];
    else if (kind === "python" && (three === '"""' || three === "'''")) [j, cls] = [until(three, i + 3), "tk-str"];
    else if (c === '"' || c === "'" || (kind === "js" && c === "`")) {
      // Escapes skip a character; a plain quote string ends at its line.
      const stop = c === "`" ? code.length : eol(i);
      j = i + 1;
      while (j < stop && code[j] !== c) j += code[j] === "\\" ? 2 : 1;
      [j, cls] = [Math.min(j + 1, stop), "tk-str"];
    } else if (/[0-9]/.test(c) && !isId(code[i - 1] ?? " ")) {
      j = i;
      while (j < code.length && /[0-9.]/.test(code[j])) j++;
      cls = "tk-num";
    } else if (/[A-Za-z_]/.test(c) && !isId(code[i - 1] ?? " ")) {
      j = i;
      while (j < code.length && isId(code[j])) j++;
      const word = code.slice(i, j);
      let k = j;
      while (code[k] === " " || code[k] === "\t") k++;
      cls = kws.has(word) ? "tk-kw" : code[k] === "(" ? "tk-fn" : null;
      if (kind === "python" && word === "f" && (code[j] === '"' || code[j] === "'")) cls = "tk-str";
    }
    if (j < 0) {
      plain += c;
      i++;
      continue;
    }
    if (cls) tok(cls, code.slice(i, j));
    else plain += code.slice(i, j);
    i = j;
  }
  if (plain) out.push(plain);
  return out;
}

// A copy button that says so on itself and in the live region.
function copyBtn(get, label = "Copy") {
  const idle = () => [svg(I_COPY, 14), el("span", {}, label)];
  const b = el("button", { class: "act", type: "button", title: label }, idle());
  let t;
  b.addEventListener("click", async () => {
    let ok = true;
    try {
      await navigator.clipboard.writeText(get());
    } catch {
      ok = false;
    }
    b.replaceChildren(...(ok ? [svg(I_CHECK, 14), el("span", {}, "Copied")] : [el("span", {}, "Copy failed")]));
    announce(ok ? "Copied" : "Could not copy");
    clearTimeout(t);
    t = setTimeout(() => b.replaceChildren(...idle()), 1400);
  });
  return b;
}

const CODE_CLAMP_LINES = 16;
// `keep` = { set, key }: remembers "Show all" across re-renders of the card that holds the block.
function codeBlock(code, lang, keep = null) {
  const n = code.split("\n").length;
  const wrap = el("button", { class: "act", type: "button", "aria-pressed": "false", title: "Wrap long lines", onclick: (ev) => {
    ev.currentTarget.setAttribute("aria-pressed", String(box.classList.toggle("wrap")));
  } }, svg(I_WRAP, 14), el("span", { class: "sr-only" }, "Wrap lines"));
  const box = el("div", { class: "codeblock" },
    el("div", { class: "ch" }, el("span", {}, lang || "text", el("span", { class: "dim" }, ` · ${n} line${n === 1 ? "" : "s"}`)), el("span", { class: "chtools" }, wrap, copyBtn(() => code))),
    el("pre", { tabindex: 0 }, el("code", {}, highlight(code, lang))));
  if (n > CODE_CLAMP_LINES) {
    const open = !!keep?.set.has(keep.key);
    box.classList.toggle("clamp", !open);
    const b = el("button", { type: "button", "aria-expanded": String(open) }, open ? "Show fewer lines" : `Show all ${n} lines`);
    b.addEventListener("click", () => {
      const clamped = box.classList.toggle("clamp");
      b.setAttribute("aria-expanded", String(!clamped));
      b.replaceChildren(clamped ? `Show all ${n} lines` : "Show fewer lines");
      if (keep) clamped ? keep.set.delete(keep.key) : keep.set.add(keep.key);
    });
    box.append(el("div", { class: "cfoot" }, b));
  }
  return box;
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

// `onSaved` runs once the link has really left this page: copied, or its
// transfer code picked up.
function inviteRow(name, url, hint, label = "Copy", onSaved = () => {}) {
  const shown = el("code", {}, maskInvite(url));
  const box = el("div", { class: "invite" }, shown);
  const btn = el("button", { class: "small", type: "button", onclick: async () => {
    if (await copyText(btn, url, label)) return onSaved();
    // Clipboard denied: reveal the link in a selected field for manual copy.
    const input = el("input", { type: "text", readonly: true, value: url, "aria-label": `${name} invite link` });
    shown.replaceWith(input);
    input.select();
    btn.textContent = pressCopy();
  } }, label);
  box.append(btn);
  return el("div", { class: "invite-row", "data-role": name.toLowerCase() },
    el("div", { class: "head" }, el("strong", {}, name), hint ? el("span", { class: "muted" }, hint) : null), box,
    sendCode(name, url, onSaved));
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

function sendCode(name, url, onSaved = () => {}) {
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
          onSaved();
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

const RECEIVE_ICON = ["M7.5 15.5a4 4 0 1 1 3.9-4.9H21v4h-3v3h-3v-3h-3.6", "M7.5 11.5h.01"];
const SEAL_ICON = ["M6 11h12v9H6z", "M8.5 11V8a3.5 3.5 0 0 1 7 0v3"];

function receivePage() {
  const input = el("input", { type: "text", id: "code", class: "mono receive-input", placeholder: "7-guitar-orbit", autocomplete: "off",
    autocapitalize: "none", spellcheck: "false", enterkeyhint: "go", "aria-describedby": "code-err" });
  const err = el("p", { class: "error", id: "code-err", role: "alert" });
  const go = el("button", { class: "primary cta", type: "submit" }, "Open session", svg(["M5 12h14", "M13 6l6 6-6 6"]));
  const fail = (msg) => {
    err.textContent = msg;
    input.setAttribute("aria-invalid", "true");
    input.focus();
  };
  input.addEventListener("input", () => {
    err.textContent = "";
    input.removeAttribute("aria-invalid");
  });
  const form = el("form", { class: "nform", onsubmit: async (ev) => {
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
    el("div", { class: "nfields" },
      el("div", { class: "ncard" },
        el("label", { for: "code", class: "codelabel" }, el("span", { class: "pick-icon" }, svg(RECEIVE_ICON, 22)),
          el("span", {}, el("strong", {}, "Transfer code"), el("small", {}, "Shown on the other machine, under Send to another machine."))),
        input, err,
        el("p", { class: "seal muted" }, svg(SEAL_ICON, 16),
          el("span", {}, "The link is decrypted in this browser. The relay stores it only encrypted, for a few minutes, and gives it out once.")))),
    el("aside", { class: "nside" },
      el("div", { class: "ncard sum" },
        el("h2", {}, "What happens"),
        el("dl", {}, el("dt", {}, "Opens in"), el("dd", {}, "This browser"), el("dt", {}, "Given out"), el("dd", {}, "Once"),
          el("dt", {}, "Stored"), el("dd", {}, "Encrypted, minutes")),
        el("p", { class: "sum-line mono" }, "One-time code · decrypted here"), go)));
  show(el("div", { class: "new" },
    el("div", { class: "nhead" },
      el("div", {}, el("h1", {}, "Receive an invite"),
        el("p", { class: "lede" }, "Enter the code shown on the other machine, under Send to another machine."))),
    form));
  input.focus();
}

function showRunnerCommand(link) {
  const cmd = (l) => `airlox runner join --invite '${l}' --name my-runner --sandbox docker`;
  const shown = el("code", {}, "airlox runner join --invite '", el("span", { class: "link" }, maskInvite(link)), "' --name my-runner --sandbox docker");
  // Keep the link out of the back/forward cache, as on the create page.
  invitesShown = true;
  invitesCreated = true;
  const heading = el("h1", { tabindex: -1 }, "Runner invite received");
  show(el("div", { class: "new" },
    el("div", { class: "nhead" },
      el("div", {}, heading,
        el("p", { class: "lede" }, "Runners join from the command line. Run this on this machine; the code is used up, so copy it now."))),
    el("div", { class: "nform" },
      el("div", { class: "nfields" },
        el("div", { class: "ncard runner-cmd" }, shown,
          el("p", { class: "muted hint-text" }, "Install the airlox runner first: ", el("a", { href: INSTALL_URL, target: "_blank", rel: "noopener noreferrer" }, "see the install guide"), "."))),
      el("aside", { class: "nside" },
        el("div", { class: "ncard sum" },
          el("h2", {}, "Runner command"),
          el("p", { class: "sum-line mono" }, "Runner invite · code used up"),
          copyButton("Copy command", () => cmd(link), () => shown, "Runner command", "primary cta"),
          el("p", { class: "seal muted" }, svg(SEAL_ICON, 16), el("span", {}, "The link is masked on screen; Copy command copies the full one.")))))));
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
const NEW_ICONS = {
  relay: ["M4 5h16v11H9l-5 4z", "M8 9.5h8M8 12.5h5"],
  execute: ["M3 4h18v16H3z", "M7 9l3 3-3 3", "M12 15h5"],
  text: ["M5 6h14M5 10h14M5 14h9M5 18h6"],
  md: ["M3 6h18v12H3z", "M6.5 15V9l2.5 3 2.5-3v6", "M16 9v6M14 13l2 2 2-2"],
  py: ["M9 8l-4 4 4 4", "M15 8l4 4-4 4", "M13 6l-2 12"],
  zip: ["M5 3h14v18H5z", "M12 3v2M12 7v2M12 11v2", "M10.5 15h3v3h-3z"],
  image: ["M3 5h18v14H3z", "M3 16l5-5 4 4 3-3 6 6", "M15 9h.01"],
};
const TTL_WORDS = { 900000: "15 minutes", 3600000: "1 hour", 86400000: "24 hours", never: "until closed" };

// Configure → save the owner link → hand out invites.
function newSteps(at) {
  return el("ol", { class: "steps", "aria-label": "Progress" }, ["Configure", "Save owner link", "Invite agents"].map((label, i) =>
    el("li", { class: i < at ? "done" : i === at ? "now" : null, "aria-current": i === at ? "step" : null },
      el("span", { class: "n", "aria-hidden": "true" }, i < at ? "✓" : String(i + 1)), el("span", {}, label))));
}

function newSession() {
  const card = (title, sub, ...kids) => el("fieldset", { class: "ncard" },
    el("legend", {}, title), sub ? el("p", { class: "nsub" }, sub) : null, ...kids);
  const mode = card("Mode", null,
    el("div", { class: "modes" }, [["relay", "Relay", "Agents and people share messages and files."],
      ["execute", "Execute", "Senders post Python; runners you approve run it and post the result."]].map(([v, name, desc]) =>
      el("label", { class: "pick mode-pick" }, el("input", { type: "radio", name: "mode", value: v, checked: v === "relay" }),
        el("span", { class: "pick-icon" }, svg(NEW_ICONS[v], 22)),
        el("span", { class: "pick-text" }, el("strong", {}, name), el("span", {}, desc)),
        el("span", { class: "tick", "aria-hidden": "true" })))));
  const ttl = card("Expires after", "The relay deletes everything when the session ends. You can close it earlier.",
    el("div", { class: "seg" }, [[900000, "15 min"], [3600000, "1 hour"], [86400000, "24 hours"], ["never", "Never"]].map(([v, label]) =>
      el("label", {}, el("input", { type: "radio", name: "ttl", value: v, checked: v === 3600000 }), el("span", {}, label)))));
  const types = card("Allowed content", "Every client refuses any other kind of item.",
    el("div", { class: "tiles" }, TYPE_LABELS.map(([v, label, ext]) =>
      el("label", { class: "pick tile" }, el("input", { type: "checkbox", name: "type", value: v, checked: true }),
        el("span", { class: "pick-icon" }, svg(NEW_ICONS[v], 20)),
        el("span", { class: "pick-text" }, el("strong", {}, label), el("span", { class: "mono" }, ext)),
        el("span", { class: "tick", "aria-hidden": "true" })))));
  const size = el("input", { type: "number", id: "size", min: 1, max: MAX_ITEM_MB, step: 1, value: MAX_ITEM_MB,
    "aria-describedby": "size-hint" });
  const sizeHint = el("span", { class: "muted hint-text", id: "size-hint", "aria-live": "polite" }, "Checking this relay's limit…");
  // Offer files as large as this relay allows, up to 100 MB: the relay is not
  // trusted to pick a larger default. Older relays do not say.
  let sizeTouched = false;
  size.addEventListener("input", () => (sizeTouched = true));
  fetch("/v1/health").then((r) => r.json()).then((h) => {
    const relayMb = Math.floor((typeof h.max_item_bytes === "number" ? h.max_item_bytes : 0) / MB);
    if (relayMb < 1) throw new Error("no limit");
    size.max = relayMb;
    if (!sizeTouched) size.value = Math.min(relayMb, MAX_DEFAULT_ITEM_MB);
    sizeHint.textContent = `1 to ${relayMb} MB on this relay`;
    sync();
  }).catch(() => (sizeHint.textContent = `1 to ${MAX_ITEM_MB} MB (could not read this relay's limit)`));
  const sizeField = card("Max file size", null,
    el("div", { class: "stack field" }, el("label", { for: "size", class: "sr-only" }, "Max file size in MB"),
      el("div", { class: "unit" }, size, el("span", { "aria-hidden": "true" }, "MB")), sizeHint));
  const lim = {
    runtime: el("input", { type: "text", id: "j-runtime", value: "python3.12", autocomplete: "off" }),
    timeout: el("input", { type: "number", id: "j-timeout", min: 1, max: 86400, step: 1, value: 60 }),
    memory: el("input", { type: "number", id: "j-memory", min: 32, max: 65536, step: 1, value: 2048 }),
    packages: el("input", { type: "text", id: "j-packages", placeholder: "numpy, pandas", autocomplete: "off" }),
    approve: el("input", { type: "checkbox", id: "j-approve", checked: true }),
  };
  const field = (id, label, input, hint) => el("div", { class: "stack field" }, el("label", { for: id }, el("strong", {}, label)), input,
    hint ? el("span", { class: "muted hint-text" }, hint) : null);
  const jobBox = card("Job limits", "Jobs ask runners to run without network access. Runners that cannot block it are flagged before you approve them.",
    el("div", { class: "limits" },
      field("j-runtime", "Runtime", lim.runtime), field("j-timeout", "Timeout", lim.timeout, "seconds"),
      field("j-memory", "Memory", lim.memory, "MB")),
    field("j-packages", "Packages", lim.packages, "Comma-separated. Only these can be requested by jobs."),
    el("label", { class: "switch" }, lim.approve, el("span", {}, el("strong", {}, "Require owner approval for runners"),
      el("span", { class: "muted hint-text" }, "A runner can take jobs only after you approve it in the session."))));
  jobBox.hidden = true;
  const pyBox = types.querySelector('input[value="py"]');
  const isExecute = () => form.elements.mode.value === "execute";
  const pyNote = el("p", { class: "muted hint-text", hidden: true, id: "py-note" }, "Python is always allowed in Execute sessions: jobs are Python.");
  pyBox.setAttribute("aria-describedby", "py-note");
  types.append(pyNote);
  const syncMode = () => {
    jobBox.hidden = !isExecute();
    pyNote.hidden = !isExecute();
    pyBox.disabled = isExecute();
    if (isExecute()) pyBox.checked = true;
  };
  mode.addEventListener("change", syncMode);

  // The summary restates the choices next to the button, and on phones as a
  // bar above it.
  const sum = { mode: el("dd"), ttl: el("dd"), types: el("dd"), size: el("dd") };
  const sumLine = el("p", { class: "sum-line mono" });
  const summarize = () => {
    const fd = new FormData(form);
    const allowed = fd.getAll("type");
    if (isExecute() && !allowed.includes("py")) allowed.push("py"); // a disabled box is not in the form data
    const ttlWord = TTL_WORDS[fd.get("ttl")];
    sum.mode.textContent = isExecute() ? `Execute${lim.approve.checked ? " · approval on" : ""}` : "Relay";
    sum.ttl.textContent = fd.get("ttl") === "never" ? "Never (until closed)" : ttlWord;
    sum.types.textContent = allowed.length ? TYPE_LABELS.filter(([t]) => allowed.includes(t)).map(([, label]) => label).join(", ") : "none";
    sum.size.textContent = `${size.value || "?"} MB per file`;
    sumLine.textContent = `${isExecute() ? "Execute" : "Relay"} · ${fd.get("ttl") === "never" ? "no expiry" : ttlWord} · ${allowed.length} type${allowed.length === 1 ? "" : "s"} · ${size.value || "?"} MB`;
  };
  const err = el("p", { class: "error", role: "alert" });
  const create = el("button", { class: "primary cta", type: "submit" }, "Create session",
    svg(["M5 12h14", "M13 6l6 6-6 6"]));
  const fields = el("div", { class: "nfields" }, mode, jobBox, ttl, types, sizeField);
  const aside = el("aside", { class: "nside" },
    el("div", { class: "ncard sum" },
      el("h2", {}, "Summary"),
      el("dl", {}, el("dt", {}, "Mode"), sum.mode, el("dt", {}, "Expires"), sum.ttl, el("dt", {}, "Content"), sum.types,
        el("dt", {}, "Files"), sum.size),
      sumLine, err, create,
      el("p", { class: "seal muted" }, svg(["M6 11h12v9H6z", "M8.5 11V8a3.5 3.5 0 0 1 7 0v3"], 16),
        el("span", {}, "Keys are generated in this browser. The relay only stores ciphertext."))));
  fields.append(el("p", { class: "muted hint-text njoin" }, "Joining a session someone else opened? Open the invite link you were given, or ",
    el("a", { href: "/receive" }, "enter a transfer code"), "."));

  const form = el("form", { class: "nform", onsubmit: async (ev) => {
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
      if (!Number.isInteger(timeout_s) || timeout_s < 1 || timeout_s > 86400) return (err.textContent = "Timeout must be 1 to 86400 seconds.");
      if (!Number.isInteger(memory_mb) || memory_mb < 32 || memory_mb > 65536) return (err.textContent = "Memory must be 32 to 65536 MB.");
      const packages = [];
      for (const raw of lim.packages.value.split(",").map((x) => x.trim()).filter(Boolean)) {
        if (!/^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$/.test(raw)) return (err.textContent = `"${raw}" is not a valid package name.`);
        const norm = raw.toLowerCase().replace(/[-_.]+/g, "-");
        if (!packages.includes(norm)) packages.push(norm);
      }
      job_limits = { runtime, timeout_s, memory_mb, network: false, packages, return_out: true, approve_runners: lim.approve.checked };
    }
    const maxMb = Number(size.max);
    if (!Number.isInteger(mb) || mb < 1 || mb > maxMb) return (err.textContent = `Max file size must be a whole number from 1 to ${maxMb} MB: this relay allows up to ${maxMb} MB.`);
    create.disabled = true;
    try {
      const params = { mode: execute ? "execute" : "relay", created_at_ms: Date.now(), ttl_ms: fd.get("ttl") === "never" ? null : Number(fd.get("ttl")), allowed_types: allowed,
        max_item_bytes: mb * MB, job_limits };
      const s = ac.createSession(JSON.stringify(params), undefined);
      const { session_id } = await (await api("POST", "/v1/sessions", { body: s.signedManifest })).json();
      summarize();
      createdView(session_id, s, execute, aside.querySelector("dl"));
    } catch (e) {
      err.textContent = `Could not create the session: ${e.message || e}`;
      create.disabled = false;
    }
  } },
    fields, aside);
  const sync = () => summarize();
  form.addEventListener("input", sync);
  form.addEventListener("change", sync);
  summarize();
  show(el("div", { class: "new" },
    el("div", { class: "nhead" },
      el("div", {}, el("h1", {}, "New session"),
        el("p", { class: "lede" }, "Pick what this session allows. Everything is end-to-end encrypted, and the rules are signed into the session so every client enforces them.")),
      newSteps(0)),
    form));
}

// Step two: the owner link, shown once, then the invites to hand out.
function createdView(session_id, s, execute, summary) {
  const base = location.origin;
  const owner = ac.ownerInvite(base, s.ownerSeed);
  let steps = newSteps(1);
  const step = (n) => {
    const next = newSteps(n);
    steps.replaceWith(next);
    steps = next;
  };
  const heading = el("h1", { tabindex: -1 }, "Save your owner link");
  const ownerRow = inviteRow("Owner", owner, "you · keep it private", "Copy", () => markSaved());
  // Without the owner link nobody can approve runners, revoke or close:
  // opening the session waits until it has been saved one way or another.
  // A button, not a link: the owner key must not show in the status bar on hover.
  const openBtn = el("button", { class: "primary cta", type: "button", disabled: true, "aria-describedby": "owner-gate",
    onclick: () => openOwnerSession(owner) }, "Open session", svg(["M5 12h14", "M13 6l6 6-6 6"]));
  const gate = el("p", { class: "muted hint-text", id: "owner-gate" }, "Save the owner link first: copy it, download it, or send it to another machine and enter the code there.");
  const saved = el("input", { type: "checkbox", id: "owner-saved" });
  const markSaved = () => {
    openBtn.disabled = false;
    openBtn.removeAttribute("aria-describedby");
    gate.hidden = true;
    saved.checked = true;
    step(2);
  };
  saved.addEventListener("change", () => {
    if (saved.checked) return markSaved();
    openBtn.disabled = true;
    openBtn.setAttribute("aria-describedby", "owner-gate");
    gate.hidden = false;
    step(1);
  });
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
  show(el("div", { class: "new created" },
    el("div", { class: "nhead" },
      el("div", {}, el("p", { class: "eyebrow" }, `Created · ${session_id.slice(0, 7)}`), heading,
        el("p", { class: "lede" }, "It is shown only once. Without it you cannot approve runners, revoke access or close the session.")),
      steps),
    el("div", { class: "nform" },
      el("div", { class: "nfields" },
        el("section", { class: "ncard owner" }, ownerRow,
          el("label", { class: "switch" }, saved, el("span", {}, el("strong", {}, "I've saved it somewhere safe"))),
          el("p", { class: "muted hint-text" }, MASKED_NOTE)),
        el("h2", { class: "nh2" }, "Invite agents and people"),
        el("p", { class: "nsub" }, "These links stay available under Invites in the session, so you can hand them out later."),
        el("section", { class: "ncard" }, senderInviteRow(ac.memberInvite(base, s.ownerSeed, "sender"))),
        el("section", { class: "ncard" }, inviteRow("Observer", ac.memberInvite(base, s.ownerSeed, "observer"), "can read everything and export the audit log")),
        ...(execute ? [el("section", { class: "ncard" }, runnerInviteRow(ac.memberInvite(base, s.ownerSeed, "runner")))] : [])),
      el("aside", { class: "nside" },
        el("div", { class: "ncard sum" }, el("h2", {}, "Session"), summary, openBtn, gate,
          el("button", { type: "button", onclick: () => { invitesShown = false; location.reload(); } }, "Create another"))))));
  heading.focus();
  invitesShown = true;
  invitesCreated = true;
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
    lastSeq: -1, closed: null, jobs: new Map(), results: new Map(), progress: new Map(), runners: [], picked: new Set(), decisions: null,
    said: new Map(), announce: false, jobErrors: new Map(), runnerErrors: new Map(), runnerSeen: new Map(), open: new Set(), chunkTimers: new Map() };
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
  s.lastEventAt ||= Date.now(); // the catch-up read just now
  s.render.fresh();
  streamLoop(s);
  reaskLoop(s);
  deliveryLoop(s);
}

// Ask the relay who has fetched this participant's recent items while some
// are still on their way, so their "fetched by" marks stay current. Only the
// author can ask, and only about its own items.
const DELIVERY_POLL_MS = 5000;
const DELIVERY_WINDOW_MS = 30 * 60 * 1000;
function deliveryLoop(s) {
  if (!["owner", "sender"].includes(s.inv.role)) return;
  // Not in the last report: sent since (or too old for the report's 500 items).
  const unknown = (it) => !s.delivery || it.created >= s.deliveryAt - DELIVERY_POLL_MS;
  const due = () => [...s.items.values()].some((it) => it.author === s.me && ["text", "file", "job"].includes(it.kind)
    && Date.now() - it.created < DELIVERY_WINDOW_MS && (s.delivery?.[it.id] ? s.delivery[it.id].waiting?.length > 0 : unknown(it)));
  // Every 5 s while your newest item is fresh, then every 30 s: someone who
  // has not fetched in minutes is probably not about to.
  let lastAsk = 0;
  const pace = () => {
    const newest = Math.max(0, ...[...s.items.values()].filter((it) => it.author === s.me).map((it) => it.created));
    return Date.now() - newest < 2 * 60 * 1000 ? DELIVERY_POLL_MS : 30000;
  };
  const tick = async () => {
    if (s.closed || document.visibilityState !== "visible" || !due() || Date.now() - lastAsk < pace() - 500) return;
    lastAsk = Date.now();
    try {
      const at = Date.now();
      s.delivery = (await (await api("GET", `/v1/sessions/${s.sid}/delivery`, { token: s.identity.token })).json()).items;
      s.deliveryAt = at;
      s.render.delivery();
    } catch {
      // An older relay has no delivery report: items just say "sent".
    }
  };
  tick();
  const timer = setInterval(() => (s.closed ? clearInterval(timer) : tick()), DELIVERY_POLL_MS);
}

function buildSessionLayout(s) {
  const { sid, inv, manifest, identity } = s;
  // The session page is an app shell: the header stays put and the timeline
  // and the details rail scroll on their own. The landing page keeps its own flow.
  document.body.classList.add("app-shell");
  app.classList.add("wide");
  const timeline = el("div", { class: "timeline thread", role: "log", "aria-live": "off", "aria-label": "Session timeline", tabindex: -1 },
    el("div", { class: "pill" }, `${inv.role === "owner" ? "you opened the session" : `you joined as ${inv.role}`} · keys stay in this browser`),
    el("p", { class: "empty" }, "No messages yet. Items appear here as soon as someone sends one."));
  const scroller = el("div", { class: "scroller", id: "scroller" }, timeline);
  const people = el("ul", { class: "people" });
  const banner = el("div", { class: "banner", tabindex: -1, hidden: true });
  const canSend = ["owner", "sender"].includes(inv.role);

  // composer
  const status = el("p", { class: "status", role: "alert" });
  const text = el("textarea", { id: "msg", rows: 1, placeholder: "Message the session…" });
  // The attach button opens the picker; the input itself stays out of the tab order.
  const file = el("input", { type: "file", id: "file", class: "sr-only", tabindex: -1, "aria-hidden": "true", accept: Object.keys(FILE_TYPES).join(",") });
  const pending = el("span", { class: "attach-chip", hidden: true });
  const sendBtn = el("button", { class: "send", type: "submit", title: "Send", "aria-label": "Send", disabled: true }, svg(I_SEND, 18));
  const execute = manifest.mode === "execute";
  const jobUi = canSend && execute ? buildJobPanel(s, text, file) : null;
  const attach = el("button", { class: "icon", type: "button", title: "Attach a file", "aria-label": "Attach a file", onclick: () => file.click() }, svg(ICON_CLIP));
  // The box grows with its text, up to 40% of the window.
  const grow = () => {
    text.style.height = "auto";
    text.style.height = `${Math.min(text.scrollHeight, innerHeight * 0.4)}px`;
  };
  // Send is live only with something to send, and while nothing else blocks it.
  const syncSend = () => {
    sendBtn.disabled = !!s.closed || !!sendBtn.dataset.busy || !!jobUi?.blocked() || (!text.value.trim() && !file.files?.[0]);
  };
  const update = () => {
    grow();
    syncSend();
  };
  const showPending = () => {
    const f = file.files?.[0];
    pending.hidden = !f;
    if (f) pending.replaceChildren(svg(ICON_CLIP, 14), el("span", {}, f.name),
      el("button", { type: "button", "aria-label": "Remove attachment", onclick: () => {
        file.value = "";
        showPending();
        text.focus({ preventScroll: true });
      } }, "✕"));
    syncSend();
  };
  file.addEventListener("change", showPending);
  text.addEventListener("input", update);

  // Who the next message is for, and what it answers. `to` wakes those
  // participants' agents; a reply links to its item and wakes its author.
  const compose = { replyTo: null, to: new Set() };
  const ctx = el("div", { class: "compose-ctx", hidden: true });
  const toMenu = el("div", { class: "to-menu", role: "group", "aria-label": "Address the message to", hidden: true });
  const toBtn = el("button", { class: "icon", type: "button", title: "Address it to someone (or type @name)",
    "aria-label": "Choose who the message is for", "aria-expanded": "false" }, svg(I_AT, 18));
  const others = () => [...s.participants.values()].filter((p) => !p.left && !p.revoked && p.participant_pub !== s.me);
  const showCtx = () => {
    const chips = [];
    const r = compose.replyTo;
    if (r) chips.push(el("span", { class: "ctx-chip reply" }, svg(I_REPLY, 12), "Replying to ", el("strong", {}, r.authorName),
      el("span", { class: "snip" }, snippet(r)),
      el("button", { type: "button", "aria-label": "Stop replying", onclick: () => {
        compose.replyTo = null;
        showCtx();
        text.focus({ preventScroll: true });
      } }, "✕")));
    for (const k of compose.to) chips.push(el("span", { class: "ctx-chip" }, "→ ", nameOf(s, k),
      el("button", { type: "button", "aria-label": `Do not address ${nameOf(s, k)}`, onclick: () => {
        compose.to.delete(k);
        showCtx();
      } }, "✕")));
    ctx.replaceChildren(...chips);
    ctx.hidden = !chips.length;
  };
  const closeMenu = () => {
    toMenu.hidden = true;
    toBtn.setAttribute("aria-expanded", "false");
  };
  toBtn.addEventListener("click", () => {
    if (!toMenu.hidden) return closeMenu();
    const ps = others();
    toMenu.replaceChildren(ps.length ? el("p", { class: "to-head" }, "Address to (wakes their agent)") : el("p", { class: "to-head" }, "No one else has joined yet"),
      ...ps.map((p) => el("button", { type: "button", class: "to-opt", "aria-pressed": String(compose.to.has(p.participant_pub)), onclick: (ev) => {
        const k = p.participant_pub;
        if (compose.to.has(k)) compose.to.delete(k);
        else compose.to.add(k);
        ev.currentTarget.setAttribute("aria-pressed", String(compose.to.has(k)));
        showCtx();
      } }, el("span", { class: `av ${["owner", "sender", "runner"].includes(p.role) ? p.role : ""}`, "aria-hidden": "true" }, initials(p.display_name)),
        el("span", { class: "who" }, p.display_name, el("span", { class: "muted" }, ` ${p.role}`)))));
    toMenu.hidden = false;
    toBtn.setAttribute("aria-expanded", "true");
    toMenu.querySelector("button")?.focus();
  });
  document.addEventListener("pointerdown", (ev) => !toMenu.hidden && !toMenu.contains(ev.target) && !toBtn.contains(ev.target) && closeMenu());
  toMenu.addEventListener("keydown", (ev) => {
    if (ev.key !== "Escape") return;
    closeMenu();
    toBtn.focus();
  });
  // "@name" in the text addresses that participant too.
  const escapeRe = (t) => t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const mentioned = (value) => others()
    .filter((p) => new RegExp(`(^|[\\s(])@${escapeRe(p.display_name)}(?![\\w-])`, "u").test(value))
    .map((p) => p.participant_pub);
  const clearCompose = () => {
    compose.replyTo = null;
    compose.to.clear();
    showCtx();
  };
  s.compose = canSend ? { reply: (it) => {
    compose.replyTo = it;
    showCtx();
    text.focus({ preventScroll: true });
  } } : null;
  if (jobUi) jobUi.setSend(sendBtn, update);
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
          setHint();
          announce("Job submitted");
        }
        return;
      }
      let sent = false;
      const refs = compose.replyTo?.ref ? [compose.replyTo.ref] : [];
      if (file.files?.[0]) {
        await sendFile(s, file.files[0], refs);
        file.value = "";
        showPending();
        sent = true;
      }
      const value = text.value.trim();
      if (value) {
        const to = [...new Set([...compose.to, ...mentioned(value)])];
        const meta = to.length ? { type: "text", text: value, to } : { type: "text", text: value };
        await sendPayload(s, "text", null, meta, new Uint8Array(), { refs });
        text.value = "";
        sent = true;
      }
      if (sent) {
        clearCompose();
        announce("Sent");
      }
    } catch (e) {
      if (e.clearFile) {
        file.value = "";
        showPending();
      }
      status.replaceChildren(...[e.final ? e.message : `Not sent: ${e.message || e}`, e.detail && el("span", { class: "detail" }, e.detail)].filter(Boolean));
    } finally {
      delete sendBtn.dataset.busy;
      update();
      jobUi?.refresh(); // also links the reason to a blocked Send job
      // The button just went disabled under the pointer: keep typing possible.
      if (!s.closed && (!document.activeElement || document.activeElement === document.body)) text.focus({ preventScroll: true });
    }
  };
  // Enter sends, Shift+Enter breaks the line. In job mode the box holds code,
  // so Enter stays a line break and only Ctrl/Cmd+Enter sends; the same on
  // touch screens, where there is no Shift and the Send button is right there.
  text.addEventListener("keydown", (ev) => {
    if (ev.key === "Escape" && (compose.replyTo || compose.to.size)) {
      ev.preventDefault();
      return clearCompose();
    }
    if (ev.key !== "Enter" || ev.isComposing || ev.keyCode === 229) return;
    const mod = ev.metaKey || ev.ctrlKey;
    if (mod || (!ev.shiftKey && !jobUi?.active() && !touchOnly())) {
      ev.preventDefault();
      submit();
    }
  });
  const mac = navigator.platform.startsWith("Mac");
  const hint = el("p", { class: "chint" });
  const kbd = (...keys) => keys.flatMap((k, i) => [i ? "+" : null, el("kbd", {}, k)]).filter(Boolean);
  const setHint = () => {
    hint.replaceChildren(...(jobUi?.active() ? ["Python job · ", ...kbd(mac ? "⌘" : "Ctrl", "Enter"), " send · ", ...kbd("Enter"), " new line"]
      : touchOnly() ? ["Markdown · @name addresses it · encrypted in this browser"]
      : ["Markdown · @name addresses it · ", ...kbd("Enter"), " send · ", ...kbd("Shift", "Enter"), " new line · encrypted in this browser"]));
  };
  jobUi?.toggle.addEventListener("click", setHint);
  setHint();
  const composer = canSend
    ? el("form", { class: "dock", autocomplete: "off", onsubmit: (ev) => {
        ev.preventDefault();
        submit();
      } },
        el("div", { class: "composer" },
          jobUi?.panel,
          el("div", { class: "attach-slot" }, pending),
          ctx,
          el("label", { for: "msg", class: "sr-only" }, "Message the session"), text,
          el("div", { class: "cbar" }, attach, file, toBtn, jobUi?.toggle, el("span", { class: "spacer" }), sendBtn),
          toMenu),
        status, hint)
    : el("div", { class: "panel readonly", tabindex: -1 }, `You joined as ${inv.role}. You can read this session but not post to it.`);
  // The dock keeps its place under the timeline; the note that replaces the
  // composer when the session ends goes into the same slot.
  const dockSlot = el("div", { class: "dock-slot" }, composer);

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
  const fresh = el("p", { class: "muted fresh", role: "status" });
  const runnerList = el("ul", { class: "runners" });
  const runnerNote = el("p", { class: "muted" });
  const rail = el("aside", { class: "rail", id: "rail", "aria-label": "Session details", tabindex: -1 },
    el("section", {}, el("h2", {}, "Participants"), people),
    execute ? el("section", { class: "stack", id: "runner-console", tabindex: -1, "aria-label": "Runner console" }, el("h2", {}, "Runners"), runnerList, runnerNote) : null,
    el("section", {}, el("h2", {}, "Allowed types"), el("div", { class: "chips" }, manifest.allowed_types.map((t) => el("span", { class: "chip" }, t)))),
    execute && manifest.job_limits?.packages?.length ? el("section", {}, el("h2", {}, "Packages"),
      el("div", { class: "chips" }, manifest.job_limits.packages.map((t) => el("span", { class: "chip", title: "Runners refuse to join without these versions" }, t)))) : null,
    el("section", { class: "stack" }, el("h2", {}, "Session"),
      el("p", { class: "mono muted" }, sid),
      fresh,
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
  // The details rail sits at the right of the timeline; below 900px it is a
  // drawer that the header button opens over it.
  const narrow = matchMedia("(max-width: 900px)");
  const railBtn = el("button", { class: "ghost", id: "rail-btn", type: "button", "aria-controls": "rail", title: "Session details" },
    svg(I_PANEL, 18), el("span", { class: "sr-only" }, "Session details"));
  const railOpen = () => (narrow.matches ? session.classList.contains("rail-open") : !session.classList.contains("rail-off"));
  const syncRail = () => railBtn.setAttribute("aria-expanded", String(railOpen()));
  const setRail = (open) => {
    session.classList.toggle(narrow.matches ? "rail-open" : "rail-off", narrow.matches ? open : !open);
    syncRail();
  };
  // Approvals and the runner console live in the rail: make sure it is showing.
  s.openRail = () => {
    if (!railOpen()) setRail(true);
  };
  railBtn.addEventListener("click", () => {
    setRail(!railOpen());
    if (narrow.matches && railOpen()) rail.focus({ preventScroll: true });
  });
  narrow.addEventListener("change", syncRail);
  document.addEventListener("keydown", (ev) => {
    if (ev.key !== "Escape" || !narrow.matches || !railOpen()) return;
    setRail(false);
    railBtn.focus();
  });

  // Owners see pending runner approvals above the timeline.
  const approvalText = el("span", {});
  const approvalBanner = el("div", { class: "banner approval", hidden: true }, approvalText,
    el("button", { type: "button", class: "small primary", onclick: () => {
      s.openRail();
      const sec = document.getElementById("runner-console");
      sec?.scrollIntoView({ block: "start" });
      (sec?.querySelector("button.primary") || sec)?.focus({ preventScroll: true });
    } }, "Review runners"));
  const jumpText = el("span", {});
  const jump = el("button", { class: "jump", type: "button", "aria-label": "Jump to latest" }, svg(I_DOWN, 16), jumpText);
  const session = el("div", { class: "session" }, el("h1", { class: "sr-only" }, `Session ${sid.slice(0, 7)}, ${manifest.mode} mode, ${inv.role}`),
    el("div", { class: "main-col" }, approvalBanner, banner, scroller, jump, dockSlot), rail);
  // Tapping the timeline closes the drawer.
  session.querySelector(".main-col").addEventListener("pointerdown", () => narrow.matches && railOpen() && setRail(false));
  show(session);
  syncRail();
  // A #fragment would replace the stored invite on reload: move focus instead.
  const skip = (label, to) => el("a", { class: "skip", href: "#", onclick: (ev) => {
    ev.preventDefault();
    to().focus({ preventScroll: true });
  } }, label);
  const skipMsg = canSend ? skip("Skip to message box", () => text) : null;
  document.body.prepend(...[skipMsg, skip("Skip to timeline", () => timeline)].filter(Boolean));
  // The jump button rides above the dock, whatever height it has.
  if (typeof ResizeObserver !== "undefined") {
    new ResizeObserver(() => session.style.setProperty("--dock-h", `${Math.ceil(dockSlot.getBoundingClientRect().height)}px`)).observe(dockSlot);
  }

  // header
  document.getElementById("title").hidden = false;
  // Phones drop the word "Session" (.tw) so the id fits beside the badges.
  document.getElementById("title-name").replaceChildren(el("span", { class: "tw" }, "Session "), sid.slice(0, 7));
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
  expiry.after(railBtn);
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

  // ----- scrolling -----
  //  - The timeline opens at its newest item.
  //  - A reader within STICK_PX of the end follows: new items scroll into view,
  //    and cards that grow in place (a file arrives, a job gets its result)
  //    keep the end in view. A new item from someone else that is taller than
  //    three quarters of the view is shown from its top instead.
  //  - A reader who scrolled up is left alone: a "New" divider marks where the
  //    unread items start and the pill counts them. Reaching the end clears both.
  //  - The reader's own sends always go to the end.
  const STICK_PX = 80;
  const distance = () => scroller.scrollHeight - scroller.scrollTop - scroller.clientHeight;
  const atBottom = () => distance() < STICK_PX;
  const behavior = () => (reducedMotion() ? "auto" : "smooth");
  const toBottom = (smooth = true) => scroller.scrollTo({ top: scroller.scrollHeight, behavior: smooth ? behavior() : "auto" });
  const topOf = (node) => scroller.scrollTop + node.getBoundingClientRect().top - scroller.getBoundingClientRect().top;
  const toNode = (node) => scroller.scrollTo({ top: Math.max(0, topOf(node) - 16), behavior: behavior() });
  let stuck = true; // the reader is at the end (or on their way there)
  let followUntil = 0; // a smooth scroll to the end is under way until then
  let handledUntil = 0; // growth until then comes from an append that already moved the view
  let unread = 0;
  let unreadMark = null;
  const following = () => stuck || performance.now() < followUntil;
  const release = () => {
    stuck = false;
    followUntil = 0;
  };
  // Something the reader did (an expanded message) must not drag the view to the end.
  // A reply quote takes the reader to what it answers, and marks it a moment.
  const reveal = (id) => {
    const n = document.getElementById(`item-${id}`);
    if (!n) return;
    release();
    toNode(n);
    n.classList.remove("flash");
    void n.offsetWidth; // restart the animation
    n.classList.add("flash");
    n.focus({ preventScroll: true });
  };
  s.ui = { scroller, release, reveal };
  const updateJump = () => {
    if (unread && atBottom()) unread = 0;
    const far = distance() > 240;
    jump.classList.toggle("on", far || unread > 0);
    jump.classList.toggle("unread", unread > 0);
    jump.classList.toggle("icon-only", !unread);
    jumpText.textContent = unread ? `${unread} new message${unread === 1 ? "" : "s"}` : "";
    jump.setAttribute("aria-label", unread ? `Jump to ${unread} new message${unread === 1 ? "" : "s"}` : "Jump to latest");
  };
  scroller.addEventListener("scroll", () => {
    stuck = atBottom();
    if (stuck && unreadMark) {
      // Leave the divider a moment so the reader sees where the unread items began.
      const mark = unreadMark;
      unreadMark = null;
      setTimeout(() => mark.remove(), 4000);
    }
    updateJump();
  }, { passive: true });
  // The reader takes over from any scroll we started.
  for (const ev of ["wheel", "touchstart", "keydown"]) scroller.addEventListener(ev, () => (followUntil = 0), { passive: true });
  jump.addEventListener("click", () => {
    // With unread items, land on the first one, not the very end.
    if (unread && unreadMark) {
      release();
      toNode(unreadMark);
    } else {
      stuck = true;
      toBottom();
    }
  });
  // A reader at the end stays there when the layout changes under them: a
  // card grows, the composer gets taller, the window is resized. The appends
  // handled below move the view themselves and are left out.
  if (typeof ResizeObserver !== "undefined") {
    const keepEnd = new ResizeObserver(() => {
      if (performance.now() >= handledUntil && following()) toBottom(false);
      updateJump();
    });
    keepEnd.observe(timeline);
    keepEnd.observe(scroller);
  }
  // A node that arrived after the history was shown.
  const arrived = (node, mine, wasFollowing) => {
    handledUntil = performance.now() + 250;
    if (mine || wasFollowing) {
      const tall = !mine && node.getBoundingClientRect().height > scroller.clientHeight * 0.75;
      if (tall) {
        release();
        toNode(node);
      } else {
        stuck = true;
        followUntil = performance.now() + 700;
        toBottom();
      }
    } else if (node.classList.contains("msg")) {
      if (!unreadMark) {
        unreadMark = el("div", { class: "divider unread", role: "separator" }, "New");
        node.before(unreadMark);
        regroup(node);
      }
      unread++;
    }
    updateJump();
  };
  // Messages from the same author within five minutes share one header.
  const regroup = (node) => {
    if (!node?.classList?.contains("msg")) return;
    const prev = node.previousElementSibling;
    node.classList.toggle("cont", !!prev?.classList.contains("msg") && prev.dataset.author === node.dataset.author
      && Math.abs(node.dataset.at - prev.dataset.at) < GROUP_MS);
  };
  // Timeline entries are kept in event order.
  const place = (node, seq, old) => {
    node.dataset.seq = seq;
    if (old) old.replaceWith(node);
    else {
      const next = [...timeline.children].find((n) => n.dataset?.seq !== undefined && Number(n.dataset.seq) > seq);
      if (next) next.before(node);
      else timeline.append(node);
    }
    regroup(node);
    regroup(node.nextElementSibling);
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
        el("span", { class: `av ${p.role}`, "aria-hidden": "true" }, initials(p.display_name)),
        el("div", { class: "who" },
          el("div", { class: "name", title: p.display_name }, p.display_name, p.participant_pub === s.me ? el("span", { class: "you" }, "you") : null),
          el("div", { class: "sub" }, `${p.role} · ${p.kind}${p.revoked ? " · revoked" : p.left ? " · left" : ""}`),
          p.description ? el("div", { class: "desc", title: "Their own description, not verified" }, el("span", { class: "claim" }, "says "), p.description) : null),
        el("span", { class: "key", title: "Key fingerprint" }, ac.fingerprint(p.participant_pub).slice(0, 4))))),
    item: (it) => {
      // Was the reader at the end before this change? (Measured before anything moves.)
      const was = atBottom() || following();
      // Files an accepted result lists live only inside that result.
      if (it.kind === "file" && it.status === "ok" && claimedBy(s, it)) {
        document.getElementById(`item-${it.id}`)?.remove();
        return;
      }
      // A result or progress report with a known job lives inside the job's
      // card. Progress never stands alone: without its job (or verified,
      // or still on the relay) it is not shown.
      const host = hostJob(s, it);
      if (it.kind === "progress" && !host) return document.getElementById(`item-${it.id}`)?.remove();
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
      collapseLong(s, node);
      if (held) (held.keep && node.querySelector(`[data-keep="${held.keep}"]:not(:disabled)`) || node).focus({ preventScroll: true });
      // New items are handled by arrived(). During the first load the resize
      // observer keeps the end in view. A card that grows in place (its file
      // arrives, its job gets a result) keeps a reader at the end there.
      if (old) {
        if (was) toBottom(false);
      } else if (s.announce) arrived(node, it.author === s.me, was);
      settle(s, it);
      if (it.author === s.me && s.delivery !== undefined) s.render.delivery();
      if (it.kind === "job") announceJob(s, it);
      else if (!old && s.announce && it.status === "ok" && it.author !== s.me && (it.kind === "text" || it.kind === "file"))
        announce(`${it.authorName}: ${it.kind === "text" ? clip(it.meta.text, 140) : it.meta.name}`);
      jobUi?.refresh();
    },
    runners: () => {
      renderRunners(s, runnerList, runnerNote);
      const n = s.runners.filter((r) => !r.approved && !r.rejected && r.setup !== "failed").length;
      approvalBanner.hidden = !(inv.role === "owner" && n && !s.closed);
      approvalText.textContent = `${n} runner${n === 1 ? "" : "s"} awaiting approval`;
      jobUi?.refresh();
    },
    // History is in: open at the newest item, at once.
    scroll: () => {
      stuck = true;
      toBottom(false);
      updateJump();
    },
    // "live" while the event stream is up, so an empty timeline can be told
    // from a stale one; the rail says when the relay last sent something.
    conn: (bad) => {
      s.connected = !bad && !s.closed;
      conn.classList.toggle("live", s.connected && !!s.streaming);
      conn.textContent = bad && !s.closed ? "Reconnecting…" : s.connected && s.streaming ? "live" : "";
      conn.hidden = !conn.textContent;
      s.render.fresh();
    },
    fresh: () => {
      const at = s.lastEventAt ? new Date(s.lastEventAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : null;
      const where = s.lastSeq >= 0 ? `#${s.lastSeq}` : "nothing yet";
      fresh.textContent = s.closed ? `Ended · last event ${where}`
        : `${s.connected === false ? "Reconnecting…" : s.connected && s.streaming ? "Live" : "Connecting…"} · latest ${where}${at ? ` · received ${at}` : ""}`;
      conn.title = `Connected to the relay · latest event ${where}${at ? ` at ${at}` : ""}`;
    },
    // Your own items' delivery, as the relay reports it (see deliveryLoop).
    // Once everyone has an item, only the newest of yours keeps saying so.
    delivery: () => {
      const lines = [...timeline.querySelectorAll("[data-dlv]")];
      lines.forEach((line, i) => {
        const it = s.items.get(line.dataset.dlv);
        if (it) fillDelivery(s, line, it);
        line.classList.toggle("latest", i === lines.length - 1);
      });
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
      const was = atBottom() || following();
      const node = el("article", { class: "item evline", id }, el("div", { class: "pill" }, text, at ? ` · ${hhmm(at)}` : ""));
      place(node, seq);
      if (s.announce) arrived(node, false, was);
    },
    closed: (reason) => {
      s.closed ||= "closed";
      gone(`This session is closed: ${reason}. Its history stays in this browser until you clear it.`);
      // The banner says why; the composer's place says only what that means here.
      lock("Read only: nothing more can be sent.");
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
      lock("Read only: nothing more can be sent.");
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
    if (fetch && record && it?.status === "evicted" && it.author !== s.me && askable(it.kind)) wantBlob(s, it.id);
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
// A lost progress report is not worth asking for: a newer one or the result follows.
const askable = (kind) => kind !== "progress";

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
    authorName: author?.display_name || "unknown", role: author?.role, status: "ok", envelope,
    refs: Array.isArray(h.refs) ? h.refs : [] };
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
      if (fetchBlob && h.author !== s.me && askable(h.kind)) wantBlob(s, h.id);
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
      if (h.author !== s.me && askable(h.kind)) wantBlob(s, h.id);
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
    it.ref = JSON.parse(ac.itemRef(envelope, blob)); // what a reply, a job or a result points at
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
  const byJob = it.kind === "result" ? s.results : it.kind === "progress" ? s.progress : null;
  if (byJob && it.meta?.job?.id) {
    const list = byJob.get(it.meta.job.id) || [];
    if (!list.some((r) => r.id === it.id)) list.push(it);
    byJob.set(it.meta.job.id, list);
  }
  if (it.kind === "progress" && it.meta?.stream) return chunkArrived(s, it.meta.job?.id);
  s.render.item(it);
  if (it.kind === "event" && it.role === "owner" && ["runner_approve", "runner_reject"].includes(it.meta?.event)) approvalsChanged(s);
}

// ---------- timeline items ----------
const GROUP_MS = 5 * 60 * 1000; // the same author within this long shares one header
const COLLAPSE_PX = 520; // taller messages are folded (see .collapsed in the stylesheet)
const isoOf = (ms) => (Number.isFinite(ms) ? new Date(ms).toISOString() : "");

// The frame every message, file and job sits in: avatar, header (name, role,
// time, verified mark), content, and a row of hover actions. Pieces that add
// to a message later (a reply quote, delivery ticks, a freshness line) have a
// place to go:
//   head     .mhead    in the header row; `extras.head` nodes go after the ✓
//   content  .mbody    the first child after the header is `content`
//   actions  .actions  `actions` nodes go after Copy/Source, also kept in `node._slots`
// The grouping fields (data-author, data-at) are read by regroup() in the layout.
function messageShell(s, it, { content, actions = [], bubble = false, extras = {} }) {
  const mine = it.author === s.me;
  const ok = it.status === "ok";
  const at = Number.isFinite(it.created) ? it.created : 0;
  const mark = (cls) => el("span", { class: cls, title: "Signature verified against this participant's key" }, svg(I_CHECK, 12), el("span", { class: "sr-only" }, "verified"));
  const head = el("div", { class: "mhead" },
    el("strong", {}, it.authorName),
    it.role ? el("span", { class: "role" }, it.role) : null,
    el("time", { datetime: isoOf(at) }, hhmm(at)),
    ok ? mark("ver") : null,
    extras.head);
  // Your own messages have no header; their time and ✓ sit with the actions.
  const stamp = mine && ok ? el("span", { class: "act stampbox" }, el("span", { class: "stamp" }, hhmm(at)), mark("ver")) : null;
  const all = [stamp, ...actions].filter(Boolean);
  const bar = all.length ? el("div", { class: "actions" }, all) : null;
  const av = ["owner", "sender", "runner"].includes(it.role) ? it.role : "";
  const cls = ["item", "msg", mine && "mine", bubble ? "bubble" : "carded", !ok && it.status].filter(Boolean).join(" ");
  const node = el("article", { class: cls, id: `item-${it.id}`, tabindex: -1, "aria-label": `${it.authorName}, ${hhmm(at)}`, "data-author": it.author, "data-at": at },
    el("div", { class: `av ${av}`, "aria-hidden": "true" }, initials(it.authorName)),
    el("div", { class: "mbody" }, head, content, bar));
  node._slots = { head, content, actions: bar };
  return node;
}

// A text that can be read rendered or as the exact characters that were sent.
function sourceView(text, what = "message") {
  const words = text.split(/\s+/).filter(Boolean).length;
  const md = el("div", { class: "md" }, markdown(text));
  const raw = el("pre", { class: "raw", hidden: true }, text);
  const content = el("div", { class: "content", "data-words": words, "data-what": what }, md, raw);
  const toggle = el("button", { class: "act", type: "button", "aria-pressed": "false", title: "Show the exact text that was sent" },
    svg(I_CODE, 14), el("span", {}, "Source"));
  toggle.addEventListener("click", () => {
    const on = raw.hidden;
    raw.hidden = !on;
    md.hidden = on;
    toggle.setAttribute("aria-pressed", String(on));
  });
  return { content, toggle };
}

// A long message is folded to a few screens once it is on the page and its
// real height is known. "Show less" brings its start back into view.
function collapseLong(s, node) {
  for (const c of node.querySelectorAll(".content[data-words]")) {
    if (c.scrollHeight <= COLLAPSE_PX) continue;
    c.classList.add("collapsed");
    const words = Number(c.dataset.words).toLocaleString();
    const what = c.dataset.what || "message";
    const btn = el("button", { class: "more", type: "button", "aria-expanded": "false" });
    const label = (open) => btn.replaceChildren(svg(open ? I_UP : I_CHEV, 14), open ? "Show less" : `Show full ${what}`, ...(open ? [] : [el("span", { class: "n" }, ` · ${words} words`)]));
    label(false);
    btn.addEventListener("click", () => {
      const open = c.classList.toggle("collapsed") === false;
      btn.setAttribute("aria-expanded", String(open));
      label(open);
      s.ui?.release(); // the reader chose this: do not drag them to the end
      if (!open && s.ui && node.getBoundingClientRect().top < s.ui.scroller.getBoundingClientRect().top) {
        node.scrollIntoView({ block: "start", behavior: "auto" }); // the content just shrank: jump, do not glide
      }
    });
    c.after(btn);
  }
}

// ---------- conversation: replies, addressing, delivery ----------
// A message or file answers the item its first reference names; a result its job.
const replyId = (it) => (["text", "file", "result"].includes(it.kind) ? it.refs?.[0]?.id : undefined);
// The participants a message is addressed to, or null for everyone.
const recipients = (it) => (it.kind === "text" && Array.isArray(it.meta?.to) ? it.meta.to : null);
const nameOf = (s, pub) => (pub === s.me ? "you" : s.participants.get(pub)?.display_name || "someone who left");

// Why an item concerns this participant (the same rules as `airlox listen`):
// addressed to you, a reply to one of your items, or the owner's message to
// everyone. Other participants' broadcasts are for reading, not for answering.
function forMe(s, it) {
  if (it.author === s.me || it.status !== "ok" || it.kind === "progress" || it.kind === "event") return null;
  const to = recipients(it);
  if (to?.includes(s.me)) return "addressed";
  if (s.items.get(replyId(it))?.author === s.me) return "reply"; // whoever else it names
  if (to) return null;
  return it.role === "owner" && (it.kind === "text" || it.kind === "file") ? "owner" : null;
}

// One line saying what an item is, for reply quotes and the reply chip.
function snippet(it) {
  if (it.status !== "ok") return `a ${it.kind}`;
  const m = it.meta || {};
  const t = m.type === "text" ? String(m.text ?? "") : m.type === "file" ? `file ${m.name}` : m.type === "job" ? `job ${m.filename}` : it.kind;
  const line = t.replace(/[*`#>~]+/g, "").replace(/\s+/g, " ").trim(); // plain words, not markup
  return line.length > 120 ? `${line.slice(0, 119)}…` : line;
}

// Above a reply: whom and what it answers. Clicking goes there.
function replyQuote(s, it) {
  const id = replyId(it);
  if (!id || it.kind === "result") return null;
  const p = s.items.get(id);
  return el("button", { class: "quote", type: "button", title: "Go to the message this answers", onclick: () => s.ui?.reveal(id) },
    svg(I_REPLY, 12), p ? [el("strong", {}, p.authorName), " ", el("span", {}, snippet(p))] : el("span", {}, "an earlier message"));
}

// In the header: who a message is for.
function toLine(s, it) {
  const to = recipients(it);
  if (!to) return null;
  const mine = to.includes(s.me);
  return el("span", { class: `to${mine ? " me" : ""}`, title: "Addressed to" }, "→ ", to.map((k) => nameOf(s, k)).join(", "));
}

// Your own items say how far they got: sent, then fetched by the others.
// Fetched means their client stored it, not that anyone read it.
function deliveryText(s, it) {
  const d = s.delivery?.[it.id];
  if (!d) return { text: "sent", title: "Posted to the relay" };
  const got = d.delivered || [];
  const total = got.length + (d.waiting || []).length;
  const names = got.map((k) => nameOf(s, k)).join(", ");
  if (!total) return { text: "sent", title: "No one else has joined yet" };
  if (got.length === total) return { text: total === 1 ? `fetched by ${names}` : "fetched by all", all: true, title: `Fetched by ${names} (stored, not necessarily read)` };
  return { text: `fetched by ${got.length}/${total}`, title: got.length ? `Fetched by ${names}; waiting for ${(d.waiting || []).map((k) => nameOf(s, k)).join(", ")}` : "No one has fetched it yet" };
}

function renderItem(s, it) {
  return decorate(s, it, itemNode(s, it));
}

function fillDelivery(s, span, it) {
  const d = deliveryText(s, it);
  span.replaceChildren(...[d.all ? svg(I_CHECK, 12) : null, d.text].filter(Boolean));
  span.title = d.title;
  span.classList.toggle("all", !!d.all);
}

// What a conversation adds to a message: the quote of what it answers, who
// it is for, a Reply action, and for your own items how far they got.
function decorate(s, it, node) {
  if (!node?._slots || it.status !== "ok") return node;
  const { head, content } = node._slots;
  const mine = it.author === s.me;
  const quote = replyQuote(s, it);
  if (quote) content.before(quote);
  const to = toLine(s, it);
  if (to && mine) (quote || content).before(to);
  else if (to) head.append(to);
  if (forMe(s, it) === "addressed") node.classList.add("for-me");
  let bar = node._slots.actions;
  if (!bar) {
    bar = el("div", { class: "actions" });
    content.parentElement.append(bar);
    node._slots.actions = bar;
  }
  // Under your own items, always in view: how far they got.
  if (mine && ["text", "file", "job"].includes(it.kind)) {
    const line = el("div", { class: "dlv", "data-dlv": it.id });
    fillDelivery(s, line, it);
    content.after(line);
  }
  if (s.compose && it.kind !== "progress") {
    bar.append(el("button", { class: "act", type: "button", title: "Reply to this", onclick: () => s.compose.reply(it) },
      svg(I_REPLY, 14), el("span", {}, "Reply")));
  }
  return node;
}

function itemNode(s, it) {
  const label = it.kind === "file" ? it.subkind : it.kind;
  const mine = it.author === s.me;
  const card = el("div", { class: "card" });
  const shell = (extra = {}) => messageShell(s, it, { content: card, ...extra });
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
    return shell();
  }
  if (it.status === "retry") {
    card.append(el("p", { class: "note" }, `Downloading this ${label} item failed. Retrying…`));
    return shell();
  }
  if (it.status === "rejected") {
    card.append(el("p", {}, sym("✕ "), `Not shown: ${it.error}`));
    if (it.detail) card.append(el("div", { class: "detail" }, it.detail));
    return shell();
  }
  const m = it.meta;
  if (m.type === "event") return renderEvent(s, it);
  if (m.type === "text") {
    // Others' texts read as open prose, your own as a bubble on the right.
    const { content, toggle } = sourceView(String(m.text ?? ""));
    const node = messageShell(s, it, { content, bubble: true, actions: [copyBtn(() => String(m.text ?? "")), toggle] });
    if (it.note) content.after(el("p", { class: "note" }, it.note));
    return node;
  }
  let node;
  if (m.type === "file") {
    if (it.role === "runner") card.append(el("p", { class: "note" }, s.runners.find((x) => x.pub === it.author)?.relayOnly
      ? `Output file from runner ${it.authorName}. ${NOT_SHOWN_YET.replace("Not shown yet", "Not accepted yet")}`
      : `Output file from runner ${it.authorName}, not listed by an accepted result.`));
    appendFileView(card, it);
    node = shell();
  } else if (m.type === "job") {
    renderJob(s, it, card);
    node = shell();
  } else if (m.type === "result") {
    const chk = resultCheck(s, it);
    card.append(chk.ok ? renderResult(s, it) : rejectedResult(chk.error, chk.pending));
    node = shell();
    if (!chk.ok && !chk.pending) node.classList.add("rejected");
  } else {
    card.append(el("pre", { tabindex: 0 }, JSON.stringify(m, null, 2)));
    node = shell();
  }
  if (it.note) card.append(el("p", { class: "note" }, it.note));
  return node;
}

function appendFileView(card, it) {
  const m = it.meta;
  const blobUrl = URL.createObjectURL(new Blob([it.body], { type: m.mime }));
  const head = el("div", { class: "file-head" },
    el("span", { class: "chip type" }, it.subkind),
    el("span", { class: "fname", title: m.name }, m.name),
    el("span", { class: "size" }, fmtBytes(it.body.length)));
  card.append(head);
  const download = el("a", { class: "button small", href: blobUrl, download: m.name }, "Download");
  if (it.subkind === "image") {
    head.append(download);
    card.append(el("img", { src: blobUrl, alt: m.name }));
  } else if (it.subkind === "zip") {
    head.append(download);
    try {
      const entries = JSON.parse(ac.inspectZip(it.body));
      const files = entries.filter((e) => !e.is_dir);
      card.append(el("ul", { class: "ziplist", tabindex: 0, "aria-label": "Files in the ZIP" }, entries.map((e) =>
        el("li", {}, el("span", {}, e.is_dir ? `${e.path}/` : e.path), el("span", {}, e.is_dir ? "" : fmtBytes(e.size))))),
        el("div", { class: "zipnote" }, `${files.length} file${files.length === 1 ? "" : "s"} · paths and sizes checked`));
    } catch (e) {
      card.append(el("p", { class: "error" }, "This file is not a valid ZIP."), el("div", { class: "detail" }, String(e.message || e)));
    }
  } else if (it.subkind === "md") {
    // Markdown reads as formatted text; Source shows the file's exact characters.
    const { content, toggle } = sourceView(new TextDecoder().decode(it.body), "file");
    head.append(toggle, download);
    card.append(el("div", { class: "filebody" }, content));
  } else if (it.subkind === "py") {
    head.append(download);
    card.append(el("div", { class: "filebody" }, codeBlock(new TextDecoder().decode(it.body), "python")));
  } else {
    head.append(download);
    card.append(el("pre", { tabindex: 0 }, new TextDecoder().decode(it.body)));
  }
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

// The relay refused the job (409 runner_busy): a matching runner is online but busy.
const busyText = (name) => `failed · ${name || "the runner"} is busy with another job · not queued`;

function failureText(s, tgt, st) {
  if (st.reason === "not_available") return notAvailableText(tgt);
  if (st.reason === "cancelled") return "cancelled";
  if (st.reason === "author_revoked") return "cancelled · its sender's access was revoked";
  const name = (st.runner ? memberName(s, st.runner) : null) || (tgt?.type === "runner" ? tgt.name : null) || "the runner";
  if (st.reason === "runner_busy") return busyText(name);
  // Not final: the relay revives the job if the runner comes back, and a late signed result still counts.
  if (st.reason === "runner_lost") return `lost contact with ${name} · it may still finish`;
  const tail = { runner_unresponsive: "did not claim it", runner_left: "left", runner_rejected: "was rejected", runner_revoked: "was revoked" }[st.reason];
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
    if (it.status === "ok" && (it.kind === "result" || (it.kind === "file" && it.role === "runner") || (it.kind === "job" && s.progress.has(it.id)))) s.render.item(it);
  }
}

// The job card that should show this result or progress report, when its job is in the timeline.
function hostJob(s, it) {
  if ((it.kind !== "result" && it.kind !== "progress") || it.status !== "ok") return null;
  const job = s.items.get(it.meta?.job?.id);
  return job && job.status === "ok" && job.kind === "job" ? job : null;
}

// Output chunks arrive by the second, and a job's card is rebuilt whole: draw
// it at most a few times a second, and once more when the last one is in.
const CHUNK_REDRAW_MS = 250;
function chunkArrived(s, jobId) {
  if (!jobId || s.chunkTimers.has(jobId)) return;
  s.chunkTimers.set(jobId, setTimeout(() => {
    s.chunkTimers.delete(jobId);
    const job = s.items.get(jobId);
    if (job?.status === "ok") s.render.item(job);
  }, CHUNK_REDRAW_MS));
}

// A progress report counts only from a runner (for a runner-targeted job,
// that runner's key), approved when the session requires approval, and
// about this exact job (pinned by blob hash).
function progressOk(s, p, job) {
  if (p.status !== "ok" || p.role !== "runner" || p.meta?.type !== "progress") return false;
  if (!job.ref || p.meta.job?.id !== job.id || p.meta.job.blob_sha256 !== job.ref.blob_sha256) return false;
  const t = job.meta.target;
  if (t?.type === "runner" && t.participant_pub !== p.author) return false;
  const approved = approvedRunners(s);
  return !approved || approved.includes(p.author);
}

// The newest acceptable progress report for a job, if any (and `want` it).
function lastProgress(s, job, want = () => true) {
  let best = null;
  for (const p of s.progress.get(job.id) || []) {
    if (!progressOk(s, p, job) || !want(p)) continue;
    if (!best || p.meta.elapsed_ms > best.meta.elapsed_ms || (p.meta.elapsed_ms === best.meta.elapsed_ms && p.seq > best.seq)) best = p;
  }
  return best;
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
  const jobId = it.kind === "job" ? it.id : it.meta?.job?.id;
  if (jobId && rs.some((r) => r.status === "ok" && resultCheck(s, r).ok)) dropChunks(s, jobId);
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

// ---------- streamed output ----------
// Chunks of a running job's stdout and stderr, as its runner posted them.
// They are display only: once the signed result is accepted its stdout and
// stderr replace them, never a stitch of chunks.
const LIVE_SHOWN = 256 * 1024; // the end of each stream is shown; the result has all of it
const utf8 = new TextEncoder();

// One stream's chunks in order of offset, end to end. A chunk this browser
// lacks (the relay dropped it before this browser fetched it) leaves a marker.
function stitch(list) {
  list.sort((a, b) => a.meta.offset - b.meta.offset || a.seq - b.seq);
  const parts = [];
  let end = 0;
  for (const p of list) {
    const { offset, data } = p.meta;
    const n = (p.bytes ??= utf8.encode(data).length);
    if (offset < end) continue; // a repeat of what is shown
    if (offset > end) parts.push(`\n[… ${fmtBytes(offset - end)} not received here …]\n`);
    parts.push(data);
    end = offset + n;
  }
  let text = parts.join("");
  const cut = text.length > LIVE_SHOWN;
  if (cut) text = text.slice(-LIVE_SHOWN);
  return { text, cut };
}

// The blocks showing a running job's streamed output, newest line last.
function liveOutput(s, job) {
  const by = { stdout: [], stderr: [] };
  let stopped = false;
  for (const p of s.progress.get(job.id) || []) {
    const m = p.meta;
    if (!by[m.stream] || !progressOk(s, p, job) || typeof m.data !== "string" || !Number.isSafeInteger(m.offset) || m.offset < 0) continue;
    by[m.stream].push(p);
    stopped ||= !!m.truncated;
  }
  const blocks = Object.entries(by).filter(([, list]) => list.some((p) => p.meta.data)).map(([stream, list]) => {
    const { text, cut } = stitch(list);
    const pre = el("pre", { tabindex: 0 }, text);
    // Follow the end while the reader is at it; leave them where they scrolled to otherwise.
    const old = document.getElementById(`item-${job.id}`)?.querySelector(`.live.${stream} pre`);
    const top = old?.scrollTop ?? 0;
    const follow = !old || old.scrollHeight - old.scrollTop - old.clientHeight < 24;
    requestAnimationFrame(() => (pre.scrollTop = follow ? pre.scrollHeight : top));
    return el("div", { class: `logblock live ${stream}` },
      el("div", { class: "logname" }, stream, el("span", { class: "chip" }, "live"), cut ? el("span", { class: "chip" }, "end only") : null), pre);
  });
  if (stopped) blocks.push(el("p", { class: "note" }, "The runner stopped streaming output here; the result will have the rest."));
  return blocks;
}

// An accepted result replaces a job's streamed chunks: forget them here and
// in this browser's cache, which would otherwise keep every one.
function dropChunks(s, jobId) {
  const all = s.progress.get(jobId) || [];
  const chunks = all.filter((p) => p.meta?.stream);
  if (!chunks.length) return;
  s.progress.set(jobId, all.filter((p) => !p.meta?.stream));
  for (const p of chunks) {
    s.items.delete(p.id);
    tx("events", "readwrite", (o) => o.delete([s.sid, p.seq])).catch(() => {});
    tx("blobs", "readwrite", (o) => o.delete([s.sid, p.id])).catch(() => {});
  }
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
    m.env ? envLine(m.env, s.items.get(m.job?.id)?.meta) : null,
    logBlock("stdout", m.stdout, m.stdout_truncated), logBlock("stderr", m.stderr, m.stderr_truncated),
    files.length ? el("div", { class: "outfiles" }, el("div", { class: "logname" }, `Output files (${files.length})`),
      files.map((f) => renderOutFile(s, f))) : null);
}

// Where a job ran, as its runner reported and signed it. `job`: the job's meta, when known.
function envLine(env, job) {
  const shell = job?.kind === "shell";
  const pkgs = shell ? [] : Object.entries(env.packages || {}).map(([k, v]) => `${k} ${v}`);
  const t = env.tree;
  const tree = t && `tree ${t.head ? t.head.slice(0, 8) : "(no git)"}${t.dirty ? " + changes" : ""}, ${t.count} file${t.count === 1 ? "" : "s"}`;
  const parts = [shell ? `shell ${env.shell || "sh"}` : `Python ${env.python}`, ...pkgs, env.sandbox, env.interpreter,
    env.airlox && `airlox ${env.airlox}`, tree].filter(Boolean);
  return el("p", { class: "envline mono", title: "Reported and signed by the runner: the interpreter or shell, package versions, sandbox and working tree this job ran with" },
    el("span", { class: "muted" }, "ran on "), parts.join(" · "));
}

// What a runner says it runs, from its newest accepted result (signed by the runner).
function runnerJobs(s, pub) {
  let best = null;
  for (const list of s.results.values()) {
    for (const r of list) {
      if (r.author !== pub || r.status !== "ok" || !r.meta?.env?.kinds || (best && r.seq < best.seq) || !resultCheck(s, r).ok) continue;
      best = r;
    }
  }
  if (!best) return null;
  const { kinds, shell } = best.meta.env;
  return `${kinds.join(", ")}${kinds.includes("shell") && shell ? ` (${shell})` : ""}`;
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
    bad = text !== "cancelled" && st.reason !== "runner_lost";
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
  const shell = m.kind === "shell";
  const code = codeBlock(m.code, shell ? "sh" : "python", { set: s.open, key: `code:${it.id}` });
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
  // Until a result is accepted, the runner's newest progress report and its output so far.
  const p = accepted ? null : lastProgress(s, it);
  const pt = accepted ? null : lastProgress(s, it, (x) => typeof x.meta.tail === "string");
  const progress = [];
  if (p) {
    const t = Math.floor(p.meta.elapsed_ms / 1000);
    const live = !st || st.state === "assigned" || st.state === "running" || st.reason === "runner_lost";
    const took = fmtDuration(t >= 60 ? t - (t % 60) : t);
    progress.push(el("p", { class: "note progress" }, live ? `Running · ${took} (last report ${hhmm(p.created)})`
      : `Ran for at least ${took} (last report ${hhmm(p.created)})`));
    progress.push(...liveOutput(s, it));
  }
  if (pt) {
    const log = el("pre", { tabindex: 0 }, pt.meta.tail || "(empty)");
    const box = el("details", { class: "codebox progress-log" },
      el("summary", {}, `Last lines of ${m.progress_file || "its log file"}`), log);
    // Open at the end of the log, where the newest lines are.
    box.addEventListener("toggle", () => box.open && requestAnimationFrame(() => (log.scrollTop = log.scrollHeight)));
    progress.push(keepOpen(s, `progress:${it.id}`, box));
  }
  card.append(
    el("div", { class: "file-head job-head" }, el("span", { class: "chip type" }, shell ? "shell" : "job"), el("span", { class: "fname", title: m.filename }, m.filename),
      el("span", { class: "mono muted jobid", title: it.id }, `#${short(it.id)}`),
      el("span", { class: `state ${tone}` }, text),
      canCancel ? el("button", { type: "button", class: "small danger", onclick: (ev) => cancelJob(s, it, ev.currentTarget) }, "Cancel") : null),
    ...(err ? [el("p", { class: "note error", role: "alert" }, err)] : []),
    el("dl", { class: "jobmeta" },
      el("dt", {}, "Target"), el("dd", {}, targetText(m.target)),
      runner ? el("dt", {}, "Runner") : null, runner ? el("dd", {}, runner) : null,
      el("dt", {}, "Limits"), el("dd", {}, `${shell ? "shell" : m.runtime} · ${fmtDuration(m.timeout_s)}${m.memory_mb ? ` · ${m.memory_mb} MB` : ""}`),
      m.cwd ? el("dt", {}, "Directory") : null, m.cwd ? el("dd", { class: "mono" }, m.cwd) : null,
      m.tree || m.fresh ? el("dt", {}, "Workspace") : null,
      m.tree || m.fresh ? el("dd", {}, [m.tree && "the sender's working tree", m.fresh && "starts empty (fresh)"].filter(Boolean).join(" · ")) : null,
      files.length ? el("dt", {}, "Inputs") : null, files.length ? el("dd", {}, files.join(", ")) : null),
    ...progress,
    el("div", { class: "jobcode" }, code),
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
function renderEvent(s, it) {
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
          version: typeof j.runner.version === "string" ? j.runner.version : null,
          python: typeof j.runner.python === "string" ? j.runner.python : null,
          networkUnblocked: !!j.runner.network_unblocked, online: !!e.online, job: e.job, busy: !!(e.busy ?? e.job),
          jobs: runnerJobs(s, e.participant_pub),
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
      : !r.approved ? "awaiting approval" : r.online ? (r.busy ? (r.job ? `busy · #${short(r.job)}` : "busy") : "idle") : "offline";
    return { approval, live, err: s.runnerErrors.get(r.pub) };
  };
  const revoked = s.revokedRoles.has("runner");
  // The poll runs every few seconds: leave the list (and keyboard focus) alone
  // unless something it shows has changed.
  const sig = JSON.stringify([!!s.closed, revoked, s.runners.map((r) => [r.pub, r.name, r.description, r.labels, r.host, r.sandbox, r.version, r.python, r.networkUnblocked,
    r.rejected, r.approved, r.relayOnly, r.setup, r.detail, r.jobs, text(r)])]);
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
      ? el("span", { class: "chip warn", title: "This runner's sandbox cannot block network access" }, sym("⚠\u00a0"), "network not blocked") : null;
    // No isolation at all: "process", and "local" where it cannot sandbox (macOS, Windows).
    const plain = r.sandbox === "process" || (r.sandbox === "local" && r.networkUnblocked);
    const versions = [r.version && `airlox ${r.version}`, r.python && `Python ${r.python}`].filter(Boolean).join(" · ");
    const act = (name, label, cls, approve) => el("button", { type: "button", class: `small ${cls}`, "data-pub": r.pub, "data-act": name,
      disabled: !!s.closed, onclick: (ev) => decideRunner(s, r, approve, ev.currentTarget) }, label);
    return el("li", { class: `runner${r.rejected ? " is-rejected" : ""}` },
      el("div", { class: "rhead" },
        el("span", { class: `dot ${dot}`, "aria-hidden": "true" }),
        el("strong", { class: "name", title: r.name }, r.name),
        el("span", { class: "sub" }, live),
        el("span", { class: "key", title: "Key fingerprint" }, ac.fingerprint(r.pub).slice(0, 4))),
      el("div", { class: "sub" }, `${r.sandbox} · ${r.host}`),
      versions ? el("div", { class: "sub" }, versions) : null,
      r.jobs ? el("div", { class: "sub", title: "From this runner's newest accepted result, signed by the runner" }, `runs ${r.jobs}`) : null,
      r.description ? el("div", { class: "desc", title: "The runner's own description, not verified" }, el("span", { class: "claim" }, "says "), r.description) : null,
      r.labels.length ? el("div", { class: "chips" }, r.labels.map((l) => el("span", { class: "chip" }, l))) : null,
      el("div", { class: "chips" },
        el("span", { class: `chip approval ${r.rejected ? "bad" : r.approved ? "good" : "wait"}` }, approval),
        canApprove ? null : warn),
      owner && r.relayOnly && !r.rejected ? el("p", { class: "sub confirm-note" },
        "The relay says this runner is approved, but this browser has no approval from you on record. Confirm only if you approved it. Its key: ",
        el("span", { class: "mono" }, ac.fingerprint(r.pub).slice(0, 16).replace(/(.{4})(?=.)/g, "$1 ")), ".") : null,
      owner && canApprove && (warn || plain) ? el("p", { class: "sub net-note" }, plain
        ? "Jobs on this runner run as plain processes: they can read this machine's files and reach the internet. Approve only if you trust the code senders submit."
        : "Jobs on this runner can reach the internet. Approve only if you trust the code senders submit.") : null,
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
  let sync = () => {}; // the composer's "is Send allowed" check
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
    text.rows = on ? 7 : 1;
    if (sendBtn) {
      sendBtn.title = on ? "Send job" : "Send";
      sendBtn.setAttribute("aria-label", sendBtn.title);
    }
    if (!on && sendBtn && !sendBtn.dataset.busy) {
      sync();
      sendBtn.removeAttribute("aria-describedby");
    }
    refresh();
  };
  const toggle = el("button", { type: "button", class: "toggle", "aria-pressed": "false", title: "Send Python to a runner to execute", onclick: () => setOn(!on) },
    svg(I_CODE, 14), "Send as job");
  labels.addEventListener("input", () => syncReady());

  // The relay's rule: approved (signed by the owner here), online, idle, and
  // matching the target. Anything else fails at once: there is no queue.
  // A runner the relay approved counts even before the owner's signed
  // approval reaches this browser (relayOnly): the relay would route the job
  // there; only its results wait for the approval.
  const cleared = (r) => r.approved || r.relayOnly;
  const usable = (r) => !r.rejected && cleared(r) && r.setup !== "failed" && r.online;
  const runnerState = (r) => r.setup === "failed" ? "setup failed" : !cleared(r) ? "needs approval"
    : !r.online ? (r.setup === "preparing" ? "preparing" : "offline") : r.busy ? "busy" : "idle";
  const approvalNote = (r) => r.relayOnly ? (s.inv.role === "owner" ? "needs your confirmation" : "approval not received here") : null;
  const wantedLabels = () => labels.value.split(",").map((x) => x.trim().toLowerCase()).filter(Boolean);
  const matches = (r) => target === "any" ? true : target === "labels" ? wantedLabels().every((l) => r.labels?.includes(l)) : `runner:${r.pub}` === target;

  // null when a job could go now; otherwise { text, act }.
  function blocker() {
    // Until the first poll, or while it fails, the list may be stale: let the relay decide.
    if (!s.runnersLoaded || s.connBad?.has("poll")) return null;
    if (target === "labels" && !wantedLabels().length) return null; // submit() explains
    const live = s.runners.filter((r) => !r.rejected);
    const fit = live.filter(matches);
    if (fit.some((r) => usable(r) && !r.busy)) return null;
    const pending = fit.find((r) => !cleared(r) && r.setup !== "failed");
    const one = target.startsWith("runner:") ? fit[0] : null;
    let why;
    if (one) why = `${one.name} ${{ "needs approval": "needs approval", "setup failed": "failed to set up", preparing: "is still preparing its sandbox" }[runnerState(one)] || `is ${runnerState(one)}`}`;
    else if (fit.some(usable)) why = target === "labels" ? "Every runner with those labels is busy" : "Every runner is busy";
    else if (target === "labels" && !fit.length) why = `No runner has the labels ${wantedLabels().join(", ")}`;
    else if (!live.length) why = "No runner has joined yet";
    else why = target === "labels" ? "No approved runner with those labels is online" : "No approved runner is online";
    return { text: `${why}, so a job sent now would fail right away.`, pending: s.inv.role === "owner" ? pending : null, none: !live.length,
      busy: fit.some(usable) };
  }

  let wasBlocked = null; // announce only changes, not the state job mode opens in
  function syncReady() {
    if (!on) return (wasBlocked = null);
    const b = locked ? null : blocker();
    ready.hidden = !b;
    if (wasBlocked !== null && wasBlocked !== !!b && s.announce) announce(b ? `Send job unavailable: ${b.text}` : "A runner is ready: you can send the job");
    wasBlocked = !!b;
    // Not while a send is in flight: that would allow a second one.
    if (sendBtn && !sendBtn.dataset.busy) {
      sync();
      if (b) sendBtn.setAttribute("aria-describedby", "job-ready");
      else sendBtn.removeAttribute("aria-describedby");
    }
    if (!b) return;
    readyText.textContent = b.text;
    const sig = `${b.pending?.pub || ""}|${b.none}|${b.busy}|${s.revokedRoles.has("runner")}`;
    if (readyAct.dataset.sig === sig) return;
    readyAct.dataset.sig = sig;
    const owner = s.inv.role === "owner";
    if (b.pending) {
      readyAct.replaceChildren(el("button", { type: "button", class: "small", onclick: () => {
        s.openRail?.();
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
    } else readyAct.replaceChildren(...(owner || b.busy ? [] : [el("span", { class: "muted" }, "Ask the session owner to start and approve a runner.")]));
  }

  function drawChips() {
    const live = s.runners.filter((r) => !r.rejected);
    if (target.startsWith("runner:") && !live.some((r) => `runner:${r.pub}` === target)) target = "any";
    labelField.hidden = target !== "labels";
    const sig = JSON.stringify([target, locked, live.map((r) => [r.pub, r.name, r.labels, runnerState(r), approvalNote(r)])]);
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
          r.name, r.labels?.length ? el("span", { class: "muted" }, ` · ${r.labels.join(", ")}`) : null,
          el("span", { class: "state" }, approvalNote(r) ? `${st} · ${approvalNote(r)}` : st));
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
      if (e.code !== "no_runner_available" && e.code !== "runner_busy") throw e;
      // The relay kept the job as failed (it shows in the timeline): its inputs are used up.
      s.picked.clear();
      filesSig = null; // job mode stays on: redraw the checkboxes unticked
      refresh();
      const err = new Error(e.code === "runner_busy" ? busyText(tgt.type === "runner" ? tgt.name : null) : notAvailableText(tgt));
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
  return { panel, toggle, refresh, submit, lock, off: () => setOn(false), active: () => on, setSend: (b, check) => {
      sendBtn = b;
      sync = check;
    },
    blocked: () => on && !locked && !!blocker() };
}

// ---------- sending ----------
async function sendPayload(s, kind, subkind, meta, body, { path = "items", headers = {}, refs = [] } = {}) {
  const needed = kind === "text" ? "text" : kind === "event" || kind === "result" ? null : subkind;
  if (needed && !s.manifest.allowed_types.includes(needed)) throw new Error(`${needed} is not allowed in this session`);
  const payload = ac.encodePayload(JSON.stringify(meta), body);
  if (payload.length > s.manifest.max_item_bytes) throw new Error(`too large: the limit is ${fmtBytes(s.manifest.max_item_bytes)}`);
  const item = { id: ac.newItemId(), session_id: s.sid, kind, subkind, created_at_ms: Date.now(), refs };
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

async function sendFile(s, f, refs = []) {
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
  await sendPayload(s, "file", subkind, { type: "file", name: f.name, mime }, bytes, { refs });
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
      s.streaming = true;
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
            s.lastEventAt = ev.at;
            s.render.fresh();
          }
        }
      }
    } catch (e) {
      console.warn("stream interrupted", e);
      s.streaming = false;
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
