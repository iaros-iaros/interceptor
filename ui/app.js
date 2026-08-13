// Interceptor UI. Plain ES modules, no bundler -- see PLAN.md; expect this to
// reverse once virtual scrolling and a real body editor land.
//
// Everything rendered here comes off the wire from sites under test, so text
// goes in via textContent only. Never innerHTML with captured data.

import { currentTheme, toggleTheme } from "./theme.js";
import { RULES_DOC_HTML } from "./rules-doc.js";

const MAX_ROWS = 500; // ponytail: newest-N cap. Virtual scroll when it annoys.
const RENDER_MS = 100; // ~10fps; the bridge already batches at 50ms.
// Retention, not just rendering. Without this the Map grew for the life of the
// tab and every render tick copied all of it -- tens of thousands of entries,
// ten times a second, after a morning of testing. The server evicts too.
const MAX_KEPT = MAX_ROWS * 4;

const token = new URLSearchParams(location.hash.slice(1)).get("token");

const $ = (s) => document.querySelector(s);
const flows = new Map(); // id -> summary, insertion order = arrival
const frames = new Map(); // id -> [ws.message]
const details = new Map(); // `${id}:${which}` -> detail | null
const held = new Map(); // id -> flow.paused payload
const drafts = new Map(); // `${id}:${direction}` -> edited raw text, survives re-render
const framesLoaded = new Set(); // flow ids whose frame history we have backfilled

let state = {};
let sel = null;
let which = "request";
let ws = null;
let pending = false;
let sessions = [];
let retryMs = 1000;
let rowFilter = "";
let rowFilterRe = null;
// Rule forms, not raw specs. {where:"both"|"req"|"resp", url, find, repl, raw}
// `raw` is set only for a spec the form cannot represent, so nothing is ever
// silently dropped just because it is more complex than the form.
let bodyRules = [];
let headerRules = [];

// ------------------------------------------------------------------ transport

function send(msg) {
  if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(msg));
}

function connect() {
  if (!token) {
    setConn(false, "no token");
    note("Open the URL printed by run.sh — it carries the bridge token.");
    return;
  }
  ws = new WebSocket(`ws://${location.host}/ws?token=${encodeURIComponent(token)}`);
  ws.onopen = () => {
    setConn(true);
    retryMs = 1000; // a good connection resets the backoff
    send({ type: "hello" });
  };
  ws.onclose = () => {
    setConn(false);
    // Backoff: a flat 1s retry meant one connection attempt per second forever
    // from any tab left open after the proxy stopped.
    setTimeout(connect, retryMs);
    retryMs = Math.min(retryMs * 2, 30000);
  };
  ws.onmessage = (e) => {
    for (const m of JSON.parse(e.data)) handle(m);
    schedule();
  };
}

// Everything keyed by flow id, so a forgotten flow does not leave its body,
// frames, draft or held entry behind. Clearing only `flows` leaked all four.
function forgetAll() {
  flows.clear();
  frames.clear();
  details.clear();
  framesLoaded.clear();
  held.clear();
  drafts.clear();
  sel = null;
}

function forget(id) {
  flows.delete(id);
  frames.delete(id);
  framesLoaded.delete(id);
  held.delete(id);
  for (const w of ["request", "response"]) details.delete(`${id}:${w}`);
  for (const k of drafts.keys()) if (k.startsWith(id) || k === `repeat:${id}`) drafts.delete(k);
  if (sel === id) sel = null;
}

function handle(m) {
  switch (m.type) {
    case "snapshot":
      forgetAll();
      for (const f of m.flows) flows.set(f.id, f);
      break;
    case "flow": {
      flows.set(m.id, m);
      while (flows.size > MAX_KEPT) {
        // Oldest first, but never the row being read.
        let victim;
        for (const id of flows.keys()) if (id !== sel) { victim = id; break; }
        if (victim === undefined) break;
        forget(victim);
      }
      // A response that arrived after we cached "no response yet" must refetch.
      if (m.id === sel && m.status != null && details.get(`${m.id}:response`) === null) {
        details.delete(`${m.id}:response`);
        send({ type: "body.get", id: m.id, which: "response" });
      }
      break;
    }
    case "state": {
      state = m;
      const live = new Set((m.queue || []).map((q) => q.id));
      for (const id of [...held.keys()]) {
        if (live.has(id)) continue;
        drafts.delete(`${id}:${held.get(id).direction}`);
        held.delete(id);
        if (id === sel) {
          // It was open in the editor. Refetch so the pane shows what actually
          // went on the wire, edits included.
          for (const w of ["request", "response"]) {
            details.delete(`${id}:${w}`);
            send({ type: "body.get", id, which: w });
          }
        }
      }
      break;
    }
    case "flow.paused":
      held.set(m.id, m);
      break;
    case "ws.message": {
      const arr = frames.get(m.id) || [];
      arr.push(m);
      if (arr.length > MAX_ROWS) arr.shift();
      frames.set(m.id, arr);
      break;
    }
    case "frames":
      frames.set(m.id, m.frames);
      framesLoaded.add(m.id);
      // Force a rebuild: the backfill contains seqs the append cursor already
      // passed, so incremental append alone would skip them.
      if (m.id === sel) $("#detail-body").dataset.key = "";
      break;
    case "body":
      details.set(`${m.id}:${m.which}`, m.detail);
      break;
    case "cleared":
      forgetAll();
      break;
    case "sessions":
      sessions = m.items || [];
      $("#sessions-dir").textContent = m.dir || "";
      renderSessions();
      break;
    case "saved":
      note(`saved ${m.flows} flow(s) to ${m.name}`, true);
      break;
    case "loaded":
      note(`loaded ${m.flows} flow(s) from ${m.name}`, true);
      sel = null;
      framesLoaded.clear();
      break;
    case "error":
      note(m.message);
      if (/scope|filter/i.test(m.message)) $("#scope").classList.add("bad");
      break;
  }
}

// -------------------------------------------------------------------- render

function schedule() {
  if (pending) return;
  pending = true;
  setTimeout(() => {
    pending = false;
    render();
  }, RENDER_MS);
}

function render() {
  for (const b of document.querySelectorAll(".modes button")) {
    b.classList.toggle("on", b.dataset.mode === state.mode);
  }
  if (document.activeElement !== $("#scope") && state.scope != null) {
    $("#scope").value = state.scope;
  }
  $("#resp").classList.toggle("on", !!state.intercept_responses);
  $("#noise").classList.toggle("on", !!state.hide_noise);
  // The filter only decides what Intercept stops; in the other modes it does
  // nothing, and saying so beats leaving the user to guess what the box is for.
  const idle = state.mode !== "intercept";
  $(".scope-group").classList.toggle("idle", idle);
  // A filter typed outside Intercept mode cannot stop anything. Rather than a dim
  // note the eye slides over, offer the switch right next to the box.
  $("#scope-arm").hidden = !(idle && ($("#scope").value || "").trim());
  renderModeHint();
  renderProxyWarning();
  renderStats();
  renderQueue();
  renderTable();
  renderDetail();
}

// One line, in plain words, for whatever is currently armed. "Stop replies"
// is not self-explanatory on a button, and a title attribute is only found by
// someone who already guessed there was something to find.
function renderModeHint() {
  const scoped = (state.scope || "").trim();
  const which = scoped ? `each request matching ${scoped}` : "every request";
  let text;
  if (state.mode === "passthrough") {
    text = "Passthrough — bytes are tunnelled straight through. Nothing is decrypted, " +
           "logged or stopped. Connections already open keep being captured until they close.";
  } else if (state.mode === "intercept" && state.intercept_responses) {
    text = `Intercept — ${which} stops so you can read or edit it, and its reply stops ` +
           "again on the way back. Each flow stops twice: once out, once in.";
  } else if (state.mode === "intercept") {
    text = `Intercept — ${which} stops so you can read or edit it before it goes on. ` +
           "Replies come back untouched (turn on “Stop replies” to catch those as well).";
  } else {
    text = "Capture — everything is decrypted and logged, nothing stops. " +
           "Switch to Intercept to stop flows for editing.";
  }
  $("#mode-hint").textContent = text;
}

// A machine whose egress needs a proxy client will 502 on every site behind it,
// and the only clue is a Cloudflare TLS reset in the log. Say it here: the person
// who clicked Launch Chrome is looking at this window, not at a terminal.
function renderProxyWarning() {
  const warn = !!state.env_proxy && !state.chained;
  const el2 = $("#proxy-warn");
  el2.hidden = !warn;
  if (warn) {
    el2.textContent =
      `This machine reaches the internet through ${state.env_proxy}, but Interceptor is ` +
      `connecting directly — anything that needs that proxy will fail with ` +
      `502 Bad Gateway. Relaunch it as:  interceptor --chain`;
  }
}

function renderSessions() {
  const list = $("#sessions-list");
  list.textContent = "";
  if (!sessions.length) {
    list.append(el("p", "hint", "No saved sessions yet. Hit “Save session” to make one."));
    return;
  }
  for (const s of sessions) {
    const row = el("div", "q-item session");
    const name = el("span", "url", s.name);
    name.title = "Open this session";
    name.onclick = () => send({ type: "session.load", name: s.name });
    row.append(
      name,
      el("span", "dim", fmtBytes(s.bytes)),
      el("span", "dim", when(s.mtime)),
      btn("Open", () => send({ type: "session.load", name: s.name }), "primary"),
    );
    list.append(row);
  }
}

function when(ts) {
  if (!ts) return "";
  const d = new Date(ts * 1000);
  return d.toLocaleString(undefined, { dateStyle: "short", timeStyle: "short" });
}

function renderStats() {
  const bits = [];
  if (state.mode === "passthrough") bits.push("passthrough applies to new connections only");
  bits.push(`${state.stored || 0} flows`, fmtBytes(state.bytes || 0));
  if (state.evicted) bits.push(`${state.evicted} evicted`);
  if (state.noise_hidden) bits.push(`${state.noise_hidden} noise hidden`);
  if (state.auto_forwarded) bits.push(`${state.auto_forwarded} auto-forwarded`);
  const n = (state.rules_body || []).length + (state.rules_headers || []).length;
  if (n) bits.push(`${n} rule${n === 1 ? "" : "s"} active`);
  if (state.proxy) {
    // Where traffic actually goes. Chaining is the default now, so the interesting
    // fact is which upstream got adopted -- silence would leave that invisible.
    bits.push(state.chained && state.env_proxy
      ? `${state.proxy} → ${state.env_proxy.replace(/^https?:\/\//, "")}`
      : state.proxy);
  }
  $("#stats").textContent = bits.join("  ·  ");
}

function renderQueue() {
  const q = state.queue || [];
  $("#queue").hidden = q.length === 0;
  if (!q.length) return;
  $("#queue-count").textContent = `${q.length} stopped — waiting for you`;
  const hosts = $("#queue-hosts");
  hosts.textContent = "";
  for (const [h, n] of Object.entries(state.per_host || {})) {
    const b = document.createElement("b");
    b.textContent = `${h}×${n}`;
    hosts.append(b, " ");
  }
  const list = $("#queue-list");
  list.textContent = "";
  for (const item of q) {
    const row = el("div", "q-item");
    if (item.id === sel) row.classList.add("sel");
    const url = el("span", "url", `${item.host}${item.path}`);
    url.title = "Open in the editor";
    url.onclick = () => select(item.id);
    row.append(
      el("span", "dir", item.direction),
      url,
      // Forwarding from here still applies any pending edit, so a typed change
      // is never silently discarded.
      btn("Forward", () => forwardId(item.id), "ok"),
      btn("Drop", () => forwardId(item.id, true), "danger"),
    );
    list.append(row);
  }
}

function matchesRow(f) {
  if (!rowFilter) return true;
  // Everything the row shows, so what you see is what you search.
  const hay = `${f.method} ${f.status ?? ""} ${f.host}${f.port && f.port !== 80 && f.port !== 443 ? ":" + f.port : ""} ${f.path} ${f.ctype || ""}`;
  return rowFilterRe ? rowFilterRe.test(hay) : hay.toLowerCase().includes(rowFilter.toLowerCase());
}

function renderTable() {
  const everything = [...flows.values()];
  const all = everything.filter(matchesRow);
  const shown = all.slice(-MAX_ROWS).reverse();
  const hiddenCount = all.length - shown.length;

  $("#row-filter-clear").hidden = !rowFilter;
  $("#row-filter-count").textContent = rowFilter
    ? `${all.length} of ${everything.length} shown`
    : "";

  $("#empty").hidden = everything.length > 0;
  $("#truncated").hidden = hiddenCount === 0;
  if (hiddenCount) {
    $("#truncated").textContent = `${hiddenCount} older matching flow(s) not rendered (newest ${MAX_ROWS} shown).`;
  }

  const body = document.createElement("tbody");
  for (const f of shown) body.append(row(f));
  $("#flows").tBodies[0].replaceWith(body);
}

function row(f) {
  const tr = document.createElement("tr");
  if (f.id === sel) tr.classList.add("sel");
  if (f.intercepted) tr.classList.add("held");
  tr.onclick = () => select(f.id);

  const port = f.port !== 80 && f.port !== 443 ? `:${f.port}` : "";
  const cells = [
    [f.method, "c-m"],
    [statusText(f), `c-s ${statusClass(f)}`],
    [f.host + port, "host"],
    [f.path, ""],
    [f.ws ? `ws (${f.ws_frames})` : f.ctype || "", "c-t"],
    [fmtBytes(f.resp_bytes || f.req_bytes || 0), "c-n"],
    [f.ms == null ? "" : `${f.ms}ms`, "c-n"],
  ];
  for (const [text, cls] of cells) tr.append(el("td", cls, text));
  if (f.streamed) tr.children[5].append(el("span", "tag tag-streamed", "streamed"));
  if (f.replay_of || f.is_replay) tr.children[0].append(el("span", "tag tag-replay", "replay"));
  if (f.http_version && f.http_version.includes("2")) {
    tr.children[4].append(el("span", "tag tag-h2", "h2"));
  }
  return tr;
}

function renderDetail() {
  const box = $("#detail-body");
  const f = sel ? flows.get(sel) : null;
  const h = sel ? held.get(sel) : null;
  $('#detail-tabs button[data-which="frames"]').hidden = !f?.ws;
  // mitmproxy refuses to replay WebSocket flows, so offering Repeat would only
  // ever produce an error.
  $('#detail-tabs button[data-which="repeat"]').hidden = !!f?.ws;
  if (f?.ws && which === "repeat") which = "request";
  for (const b of document.querySelectorAll("#detail-tabs button")) {
    b.classList.toggle("on", b.dataset.which === which);
  }
  // If a view with live inputs is already mounted for this exact flow, leave it
  // alone. Rebuilding would destroy the caret and whatever is half-typed. The
  // frames view instead gets new frames appended, which is also far cheaper than
  // rebuilding hundreds of rows every tick.
  let key = "";
  if (h) key = `edit:${h.id}:${h.direction}`;
  else if (f && which === "frames") key = `frames:${f.id}`;
  else if (f && which === "repeat") key = `repeat:${f.id}`;
  if (key && box.dataset.key === key) {
    if (key.startsWith("frames:")) appendNewFrames(box, f);
    return;
  }
  box.dataset.key = key;
  box.dataset.lastSeq = "-1";
  box.textContent = "";
  if (h) return renderEditor(box, h);
  if (!f) return box.append(el("p", "hint", "Select a flow."));
  if (which === "frames") return renderFrames(box, f);
  if (which === "repeat") return renderRepeat(box, f);

  const dkey = `${sel}:${which}`;
  if (!details.has(dkey)) return box.append(el("p", "hint", "Loading…"));
  const d = details.get(dkey);
  if (!d) {
    return box.append(el("p", "hint", which === "response" ? "No response yet." : "No data."));
  }

  const line =
    which === "request"
      ? `${d.method} ${d.url}  ${d.http_version}`
      : `${d.status} ${d.reason}`;
  box.append(el("p", "headline", line));
  if (f.replay_of) renderReplayDelta(box, f);

  const kv = document.createElement("table");
  kv.className = "kv";
  for (const [k, v] of d.headers) {
    const tr = document.createElement("tr");
    tr.append(el("td", "", k), el("td", "", v));
    kv.append(tr);
  }
  box.append(el("p", "section", "headers"), kv);

  if (d.encoding === "streamed") {
    box.append(el("p", "note", "Streamed — body was never buffered, so it cannot be shown or edited."));
    return;
  }
  if (d.encoding === "too-large") {
    box.append(el("p", "note", `Body is ${fmtBytes(d.size)} — above the editable limit.`));
    return;
  }
  if (d.encoding === "base64") {
    box.append(el("p", "note", "Binary body, shown base64-encoded."));
  }
  box.append(el("p", "section", `body · ${fmtBytes(d.size)}`));
  const pre = document.createElement("pre");
  pre.textContent = d.body ? pretty(d.body) : "(empty)";
  box.append(pre);
}

function editorArea(key, initial) {
  const ta = document.createElement("textarea");
  ta.className = "editor";
  ta.spellcheck = false;
  ta.dataset.key = key;
  ta.value = drafts.has(key) ? drafts.get(key) : initial;
  ta.oninput = () => drafts.set(key, ta.value);
  return ta;
}

function renderEditor(box, h) {
  box.append(el("p", "headline", `STOPPED · ${h.direction}`));
  const key = `${h.id}:${h.direction}`;
  let ta = null;

  if (h.direction === "websocket" && h.frame?.truncated) {
    box.append(el("p", "note",
      `Frame is ${fmtBytes(h.frame.size ?? 0)} — above the editable limit. Forward or drop it.`));
  } else if (h.direction === "websocket") {
    ta = editorArea(key, h.frame?.body ?? "");
    const dir = h.frame?.from_client ? "client → server" : "server → client";
    box.append(el("p", "section",
      `frame #${h.frame?.seq ?? "?"} · ${dir} · ${fmtBytes(h.frame?.size ?? 0)}`), ta);
  } else if (h.detail && h.detail.raw != null) {
    ta = editorArea(key, h.detail.raw);
    box.append(
      el("p", "section", "edit, then forward — Content-Length is recomputed"),
      ta,
    );
    if (h.detail.body_crlf) {
      // A textarea silently converts CRLF to LF, so this box cannot round-trip
      // one. Header-only edits are safe: the engine restores the original body.
      box.append(el("p", "note",
        "This body uses CRLF line endings. Editing the headers is safe — the body is " +
        "sent unchanged. Editing the body itself will convert its CRLFs to LF, which " +
        "breaks multipart boundaries."));
    }
  } else {
    box.append(el("p", "note",
      "Not editable here: streamed, over the size limit, or its bytes contradict the "
      + "encoding it declares. Forward or drop it."));
  }

  const actions = el("div", "actions");
  actions.append(
    btn("Forward", () => forwardId(h.id), "ok"),
    btn("Drop", () => forwardId(h.id, true), "danger"),
  );
  if (ta) {
    actions.append(btn("Revert", () => {
      drafts.delete(key);
      box.dataset.key = "";
      render();
    }));
  }
  box.append(actions);
  if (ta) ta.focus();
}

function forwardId(id, drop) {
  const h = held.get(id);
  const key = h ? `${id}:${h.direction}` : null;
  const raw = !drop && key && drafts.has(key) ? drafts.get(key) : undefined;
  send({ type: "resume", id, drop: !!drop, seq: h?.frame?.seq, raw });
}

function renderRepeat(box, f) {
  const d = details.get(`${f.id}:request`);
  if (d === undefined) {
    send({ type: "body.get", id: f.id, which: "request" });
    return box.append(el("p", "hint", "Loading…"));
  }
  if (!d || d.raw == null) {
    return box.append(el("p", "note",
      "This request cannot be rebuilt as text: streamed, too large, or its bytes "
      + "contradict the encoding it declares."));
  }
  const key = `repeat:${f.id}`;
  const ta = editorArea(key, d.raw);
  box.append(
    el("p", "section", "resend this request — edits apply to the copy, not the original"),
    ta,
  );
  const actions = el("div", "actions");
  actions.append(
    btn("Send", () => send({ type: "replay", id: f.id, raw: ta.value }), "primary"),
    btn("Reset", () => {
      drafts.delete(key);
      box.dataset.key = "";
      render();
    }),
  );
  box.append(actions);
}

function renderReplayDelta(box, f) {
  const orig = flows.get(f.replay_of);
  if (!orig) return;
  const bit = (a, b) => (a === b ? String(a ?? "—") : `${a ?? "—"} → ${b ?? "—"}`);
  const line = el("p", "note",
    `replay · status ${bit(orig.status, f.status)}` +
    ` · body ${bit(fmtBytes(orig.resp_bytes || 0), fmtBytes(f.resp_bytes || 0))}` +
    ` · ${bit(orig.ms == null ? null : orig.ms + "ms", f.ms == null ? null : f.ms + "ms")}`);
  box.append(line);
}

function renderFrames(box, f) {
  if (!framesLoaded.has(f.id)) send({ type: "frames.get", id: f.id });
  const key = `inject:${f.id}`;
  const ta = document.createElement("textarea");
  ta.className = "inject-input";
  ta.rows = 2;
  ta.spellcheck = false;
  ta.placeholder = "frame payload — text, or hex bytes with the hex toggle on";
  ta.value = drafts.get(key) ?? "";
  ta.oninput = () => drafts.set(key, ta.value);

  const hex = btn("hex", null);
  hex.title = "Treat the payload as hex bytes and send a binary frame";
  hex.onclick = () => hex.classList.toggle("on");

  const row = el("div", "inject-actions");
  row.append(
    btn("→ server", () => injectFrame(f.id, false, ta, hex), "primary"),
    btn("→ client", () => injectFrame(f.id, true, ta, hex), "primary"),
    hex,
  );
  box.append(el("p", "section", "inject a frame neither peer sent"), ta, row);

  box.append(el("p", "section", "frames"), el("div", "frames"));
  appendNewFrames(box, f);
}

function appendNewFrames(box, f) {
  const list = box.querySelector(".frames");
  if (!list) return;
  const all = frames.get(f.id) || [];
  // Keyed on the server's monotonic seq, not array position: the local buffer
  // shifts once it is full, which would silently desync an index-based cursor.
  const last = Number(box.dataset.lastSeq ?? -1);
  let max = last;
  for (const m of all) {
    if (m.seq <= last) continue;
    // The hint is a child too, so it has to go before the first real row lands
    // under it -- otherwise "No frames captured." sat above a list of frames.
    list.querySelector(".hint")?.remove();
    list.append(frameRow(m));
    if (m.seq > max) max = m.seq;
  }
  box.dataset.lastSeq = String(max);
  if (!list.childElementCount) list.append(el("p", "hint", "No frames captured."));
}

function frameRow(m) {
  const d = el("div", `frame ${m.from_client ? "up" : "down"}`);
  const meta = el("div", "meta",
    `${m.from_client ? "↑ client" : "↓ server"}  #${m.seq}  ${fmtBytes(m.size)}`);
  if (m.binary) meta.append(el("span", "tag tag-hex", "hex"));
  if (m.injected) meta.append(el("span", "tag tag-injected", "injected"));
  if (m.dropped) meta.append(el("span", "tag tag-dropped", "dropped"));
  // The preview is a prefix; say so, or the pane reads as the whole frame.
  if (m.truncated) meta.append(el("span", "tag tag-streamed", "preview"));
  d.append(meta);
  const pre = document.createElement("pre");
  // Binary frames are already spaced hex from the engine; do not JSON-prettify.
  pre.textContent = m.binary ? m.preview : pretty(m.preview);
  d.append(pre);
  return d;
}

function injectFrame(id, toClient, ta, hexBtn) {
  if (!ta.value) return;
  send({
    type: "ws.inject", id, to_client: toClient, text: ta.value,
    is_text: !hexBtn.classList.contains("on"),
  });
  ta.value = "";
  drafts.delete(`inject:${id}`);
}

// --------------------------------------------------------------------- utils

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
}

function btn(label, onclick, cls) {
  const b = el("button", cls, label);
  b.onclick = onclick;
  return b;
}

function statusText(f) {
  if (f.killed) return "killed";
  if (f.intercepted) return "stopped";
  return f.status == null ? "···" : String(f.status);
}

function statusClass(f) {
  if (f.killed) return "err";
  if (f.status == null) return "pending";
  return `s${String(f.status)[0]}`;
}

function fmtBytes(n) {
  if (!n) return "0";
  const u = ["B", "K", "M", "G"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) {
    n /= 1024;
    i++;
  }
  return `${n < 10 && i > 0 ? n.toFixed(1) : Math.round(n)}${u[i]}`;
}

function pretty(text) {
  try {
    return JSON.stringify(JSON.parse(text), null, 2);
  } catch {
    return text;
  }
}

function setConn(on, label) {
  const n = $("#conn");
  n.className = on ? "on" : "off";
  n.textContent = label || (on ? "live" : "offline");
}

let noteTimer;
function note(msg, ok) {
  const n = $("#note");
  n.textContent = msg;
  n.classList.toggle("ok", !!ok);
  n.hidden = false;
  clearTimeout(noteTimer);
  // Errors are worth reading twice; a confirmation is not.
  noteTimer = setTimeout(() => { n.hidden = true; }, ok ? 4000 : 12000);
}

function select(id) {
  sel = id;
  // Keep the open tab when the new flow can show it: clicking down a list while
  // reading responses used to throw you back to Request on every row.
  const f = flows.get(id);
  if (which === "frames" && !f?.ws) which = "request";
  if (which === "repeat" && f?.ws) which = "request";
  for (const w of ["request", "response"]) {
    if (!details.has(`${id}:${w}`)) send({ type: "body.get", id, which: w });
  }
  render();
}

// ------------------------------------------------------------------- wiring

for (const b of document.querySelectorAll(".modes button")) {
  b.onclick = () => {
    $("#scope").classList.remove("bad");
    send({ type: "mode.set", mode: b.dataset.mode, scope: $("#scope").value });
  };
}
for (const b of document.querySelectorAll("#detail-tabs button")) {
  b.onclick = () => {
    which = b.dataset.which;
    render();
  };
}
function applyScope() {
  $("#scope").classList.remove("bad");
  $("#note").hidden = true;
  send({ type: "mode.set", mode: state.mode || "capture", scope: $("#scope").value });
}
$("#scope").addEventListener("keydown", (e) => {
  if (e.key === "Enter") applyScope();
});
// change fires on blur when the value differs, so clicking away applies it too --
// pressing Enter was the only way to submit, and nothing said so.
$("#scope").addEventListener("change", applyScope);
$("#scope-arm").onclick = () => {
  send({ type: "mode.set", mode: "intercept", scope: $("#scope").value });
};
$("#theme").onclick = () => {
  toggleTheme();
  $("#theme").title = `Switch to ${currentTheme() === "light" ? "dark" : "light"}`;
};
$("#theme").title = `Switch to ${currentTheme() === "light" ? "dark" : "light"}`;

// Examples fill in a form row rather than pasting syntax, so the example teaches
// the form the user has to use rather than a format they never see again.
for (const chip of document.querySelectorAll("#rules-examples button")) {
  chip.onclick = () => {
    const d = chip.dataset;
    const rule = { where: d.where, url: d.url, find: d.find, repl: d.repl, raw: null };
    (d.kind === "header" ? headerRules : bodyRules).push(rule);
    renderRules();
  };
}
$("#add-body-rule").onclick = () => {
  bodyRules.push({ where: "both", url: "", find: "", repl: "", raw: null });
  renderRules();
  $("#body-rules").querySelector(".rule-row:last-child .rule-input")?.focus();
};
$("#add-header-rule").onclick = () => {
  headerRules.push({ where: "req", url: "", find: "", repl: "", raw: null });
  renderRules();
  $("#header-rules").querySelector(".rule-row:last-child .rule-input")?.focus();
};
$("#rules-raw-toggle").onclick = () => {
  const pre = $("#rules-raw");
  pre.hidden = !pre.hidden;
  $("#rules-raw-toggle").textContent = pre.hidden
    ? "Show generated syntax" : "Hide generated syntax";
  $("#rules-raw-toggle").classList.toggle("on", !pre.hidden);
  renderRawPreview();
};

$("#rules-toggle").onclick = () => {
  const panel = $("#rules");
  panel.hidden = !panel.hidden;
  $("#rules-toggle").classList.toggle("on", !panel.hidden);
  if (!panel.hidden) loadRulesFromState();
};
$("#rules-close").onclick = () => {
  $("#rules").hidden = true;
  $("#rules-toggle").classList.remove("on");
};
$("#rules-apply").onclick = () => {
  const specs = (rules) => rules.map(composeRule).filter(Boolean);
  const body = specs(bodyRules), headers = specs(headerRules);
  const skipped = (bodyRules.length + headerRules.length) - (body.length + headers.length);
  send({ type: "rules.set", body, headers });
  // Say what went, and say what did not: an incomplete row silently doing nothing
  // is how the old textarea version lost people.
  $("#rules-status").textContent =
    `applied ${body.length} body + ${headers.length} header rule(s)` +
    (skipped ? ` — ${skipped} incomplete row(s) skipped (nothing in "find")` : "");
  setTimeout(() => ($("#rules-status").textContent = ""), 6000);
};
$("#resp").onclick = () =>
  send({ type: "opt.set", intercept_responses: !state.intercept_responses });
$("#noise").onclick = () => send({ type: "opt.set", hide_noise: !state.hide_noise });
$("#save-session").onclick = () => send({ type: "session.save" });
$("#open-session").onclick = () => {
  const panel = $("#sessions");
  panel.hidden = !panel.hidden;
  $("#open-session").classList.toggle("on", !panel.hidden);
  if (!panel.hidden) send({ type: "sessions.list" });
};
$("#sessions-refresh").onclick = () => send({ type: "sessions.list" });
$("#sessions-close").onclick = () => {
  $("#sessions").hidden = true;
  $("#open-session").classList.remove("on");
};
function setRowFilter(v) {
  rowFilter = (v || "").trim();
  // Regex when it compiles, so /api/v\d+ works; plain text is a valid regex
  // anyway. A half-typed one like "api(" would throw on every keystroke, so it
  // falls back to a substring match instead of showing nothing.
  try {
    rowFilterRe = rowFilter ? new RegExp(rowFilter, "i") : null;
  } catch {
    rowFilterRe = null;
  }
  renderTable();
}
$("#row-filter").addEventListener("input", (e) => setRowFilter(e.target.value));
$("#row-filter-clear").onclick = () => {
  $("#row-filter").value = "";
  setRowFilter("");
  $("#row-filter").focus();
};

$("#launch").onclick = () => send({ type: "browser.launch" });
$("#clear").onclick = () => send({ type: "clear" });
$("#fwd-all").onclick = () => send({ type: "resume.all" });
$("#drop-all").onclick = () => send({ type: "resume.all", drop: true });

// ---------------------------------------------------------------- rule builder

// mitmproxy wants one packed string per rule: <sep><filter><sep><find><sep><replace>.
// Nobody should have to type that, and a separator that also appears in the pattern
// is the most common way to get it wrong -- so the form owns the syntax and picks a
// separator that appears in neither the filter nor the find text. It may appear in
// the replacement: parse_spec splits with maxsplit=2, so the tail is taken whole.
const SEP_CANDIDATES = ["|", ":", "#", "@", "%", "^", "!", ";", ",", "+", "=", "~",
                        "/", "?", "*", "<", ">", "(", ")", "[", "]", "{", "}"];

function pickSep(...mustNotContain) {
  return SEP_CANDIDATES.find((c) => !mustNotContain.some((f) => (f || "").includes(c)));
}

function filterFor(r) {
  const terms = [];
  if (r.where === "req") terms.push("~q");
  if (r.where === "resp") terms.push("~s");
  if ((r.url || "").trim()) terms.push("~u " + r.url.trim());
  return terms.join(" & ");
}

function composeRule(r) {
  if (r.raw != null) return r.raw.trim() || null;
  const find = r.find || "";
  if (!find.trim()) return null;          // nothing to look for
  const filt = filterFor(r);
  const sep = pickSep(filt, find);
  if (!sep) return null;                  // every candidate occurs in the input
  const repl = r.repl || "";
  return filt ? sep + filt + sep + find + sep + repl
              : sep + find + sep + repl;
}

// The inverse, for rules already set on the server. Mirrors parse_spec exactly:
// the separator is the first character, then two splits, remainder is the
// replacement.
function splitSpec(spec) {
  if (!spec || spec.length < 2) return null;
  const sep = spec[0], rest = spec.slice(1);
  const i = rest.indexOf(sep);
  if (i < 0) return null;
  const j = rest.indexOf(sep, i + 1);
  if (j < 0) return { filter: "", find: rest.slice(0, i), repl: rest.slice(i + 1) };
  return { filter: rest.slice(0, i), find: rest.slice(i + 1, j), repl: rest.slice(j + 1) };
}

// Only shapes the form can round-trip become form rules; anything else stays raw
// and editable as text, so a hand-written rule is never quietly rewritten.
function ruleFromSpec(spec) {
  const parts = splitSpec(spec);
  if (!parts) return { where: "both", url: "", find: "", repl: "", raw: spec };
  const f = parts.filter.trim();
  const m = f.match(/^(?:(~q|~s)\s*(?:&\s*)?)?(?:~u\s+(\S+))?$/);
  if (f && !m) return { where: "both", url: "", find: "", repl: "", raw: spec };
  let where = "both", url = "";
  if (m) {
    if (m[1] === "~q") where = "req";
    if (m[1] === "~s") where = "resp";
    url = m[2] || "";
  }
  return { where, url, find: parts.find, repl: parts.repl, raw: null };
}

function loadRulesFromState() {
  bodyRules = (state.rules_body || []).map(ruleFromSpec);
  headerRules = (state.rules_headers || []).map(ruleFromSpec);
  renderRules();
}

function renderRules() {
  renderRuleList($("#body-rules"), bodyRules, "body");
  renderRuleList($("#header-rules"), headerRules, "header");
  renderRawPreview();
}

function renderRuleList(box, rules, kind) {
  box.textContent = "";
  if (!rules.length) {
    box.append(el("p", "hint", kind === "body"
      ? "No body rules yet."
      : "No header rules yet."));
    return;
  }
  rules.forEach((r, i) => box.append(ruleRow(r, i, rules, kind)));
}

function ruleRow(r, i, rules, kind) {
  const row = el("div", "rule-row");

  if (r.raw != null) {
    // A spec the form cannot express -- shown as it is rather than mangled.
    row.classList.add("raw");
    row.append(el("span", "rule-label", "advanced"));
    const inp = document.createElement("input");
    inp.className = "rule-input grow";
    inp.value = r.raw;
    inp.spellcheck = false;
    inp.oninput = () => { r.raw = inp.value; renderRawPreview(); };
    row.append(inp);
  } else {
    const field = (key, placeholder, cls) => {
      const inp = document.createElement("input");
      inp.className = "rule-input" + (cls ? " " + cls : "");
      inp.placeholder = placeholder;
      inp.value = r[key] || "";
      inp.spellcheck = false;
      inp.oninput = () => { r[key] = inp.value; renderRawPreview(); };
      return inp;
    };

    const sel = document.createElement("select");
    sel.className = "rule-select";
    for (const [v, label] of [["both", "requests + replies"],
                              ["req", "requests"],
                              ["resp", "replies"]]) {
      const o = document.createElement("option");
      o.value = v;
      o.textContent = label;
      if (r.where === v) o.selected = true;
      sel.append(o);
    }
    sel.onchange = () => { r.where = sel.value; renderRawPreview(); };

    row.append(
      el("span", "rule-label", "in"), sel,
      el("span", "rule-label", "URL has"), field("url", "anything"),
      el("span", "rule-label", kind === "body" ? "find" : "header"),
      field("find", kind === "body" ? "text to find" : "header name", "grow"),
      el("span", "rule-label", kind === "body" ? "replace with" : "set to"),
      field("repl", kind === "body" ? "replacement" : "value (empty removes it)", "grow"),
    );
  }

  const rm = btn("✕", () => { rules.splice(i, 1); renderRules(); }, "icon");
  rm.title = "Remove this rule";
  row.append(rm);
  return row;
}

function renderRawPreview() {
  const pre = $("#rules-raw");
  if (pre.hidden) return;
  const lines = [];
  for (const [label, rules] of [["body", bodyRules], ["headers", headerRules]]) {
    for (const r of rules) {
      const spec = composeRule(r);
      if (spec) lines.push(label.padEnd(9) + spec);
    }
  }
  pre.textContent = lines.length
    ? lines.join("\n")
    : "(nothing yet -- the forms above generate these)";
}

// --------------------------------------------------------------- doc modal

// Built once, on first open: the content is static, and parsing it every time a
// user reaches for the syntax reference would be silly.
let docBuilt = false;

function buildDoc() {
  if (docBuilt) return;
  docBuilt = true;
  // Trusted, first-party documentation from rules-doc.js — the one place in this
  // file where innerHTML is correct. Never pass captured traffic through here.
  $("#doc-body").innerHTML = RULES_DOC_HTML;
  const nav = $("#doc-nav");
  for (const h of $("#doc-body").querySelectorAll("h3")) {
    const b = document.createElement("button");
    b.textContent = h.textContent;
    b.onclick = () => h.scrollIntoView({ block: "start" });
    nav.append(b);
  }
}

function openDoc(anchorText) {
  buildDoc();
  $("#doc-backdrop").hidden = false;
  $("#doc-modal").hidden = false;
  $("#doc-close").focus();
  if (!anchorText) return $("#doc-body").scrollTo(0, 0);
  // Jump to a named section: "?" next to the filter field lands on the filter
  // reference rather than making the user hunt for it.
  const want = anchorText.toLowerCase();
  const h = [...$("#doc-body").querySelectorAll("h3")]
    .find((x) => x.textContent.toLowerCase().includes(want));
  h ? h.scrollIntoView({ block: "start" }) : $("#doc-body").scrollTo(0, 0);
}

function closeDoc() {
  $("#doc-backdrop").hidden = true;
  $("#doc-modal").hidden = true;
}

$("#rules-doc-open").onclick = () => openDoc();
$("#scope-help").onclick = () => openDoc("filter");
$("#doc-close").onclick = closeDoc;
$("#doc-backdrop").onclick = closeDoc;
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !$("#doc-modal").hidden) closeDoc();
});

connect();
