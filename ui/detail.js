// The right-hand pane: headers and body, the held-flow editor, WebSocket frames,
// and the repeater.

import { $, btn, el, fmtBytes, note, pretty, statusClass, statusText } from "./util.js";
import {
  closeRepeatTab, details, drafts, frames, framesLoaded, getFlow,
  held, openRepeatTab, sendHistory, ui,
} from "./state.js";
import { select, send } from "./transport.js";
import { refresh } from "./bus.js";

export function renderDetail() {
  const box = $("#detail-body");
  const f = getFlow(ui.sel);
  const h = ui.sel ? held.get(ui.sel) : null;
  $('#detail-tabs button[data-which="frames"]').hidden = !f?.ws;
  // mitmproxy refuses to replay WebSocket flows, so offering Repeat would only
  // ever produce an error.
  $('#detail-tabs button[data-which="repeat"]').hidden = !!f?.ws;
  if (f?.ws && ui.which === "repeat") ui.which = "request";
  for (const b of document.querySelectorAll("#detail-tabs button")) {
    b.classList.toggle("on", b.dataset.which === ui.which);
  }
  // If a view with live inputs is already mounted for this exact flow, leave it
  // alone. Rebuilding would destroy the caret and whatever is half-typed. The
  // frames view instead gets new frames appended, which is also far cheaper than
  // rebuilding hundreds of rows every tick.
  let key = "";
  if (h) key = `edit:${h.id}:${h.direction}`;
  else if (f && ui.which === "frames") key = `frames:${f.id}`;
  else if (f && ui.which === "repeat") key = `repeat:${f.id}`;
  if (key && box.dataset.key === key) {
    if (key.startsWith("frames:")) appendNewFrames(box, f);
    // Same reasoning as frames: the send history grows while the editor above it
    // is being typed into, so it is refreshed on its own rather than by rebuilding
    // the view and taking the caret with it.
    if (key.startsWith("repeat:")) refreshRepeatHistory(box, f);
    return;
  }
  box.dataset.key = key;
  box.dataset.lastSeq = "-1";
  box.textContent = "";
  // The editing layout makes the pane a flex column that does not scroll; every
  // other view needs it back off, or a long response body has nowhere to go.
  box.classList.remove("editing");
  if (h) return renderEditor(box, h);
  if (!f) return box.append(el("p", "hint", "Select a flow."));
  if (ui.which === "frames") return renderFrames(box, f);
  if (ui.which === "repeat") return renderRepeat(box, f);
  renderMessage(box, f);
}

function renderMessage(box, f) {
  const dkey = `${ui.sel}:${ui.which}`;
  if (!details.has(dkey)) return box.append(el("p", "hint", "Loading…"));
  const d = details.get(dkey);
  if (!d) {
    return box.append(
      el("p", "hint", ui.which === "response" ? "No response yet." : "No data."));
  }

  const line = ui.which === "request"
    ? `${d.method} ${d.url}  ${d.http_version}`
    : `${d.status} ${d.reason}`;
  box.append(el("p", "headline", line));
  if (f.faulted) {
    box.append(el("p", "note",
      `Interceptor produced this on purpose — ${f.faulted}. It did not come from the `
      + "server. Clear the rule in Tools → Rules to stop it."));
  }
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
    box.append(el("p", "note",
      "Streamed — body was never buffered, so it cannot be shown or edited."));
    return;
  }
  if (d.encoding === "too-large") {
    box.append(el("p", "note", `Body is ${fmtBytes(d.size)} — above the editable limit.`));
    return;
  }
  if (d.encoding === "base64") {
    box.append(el("p", "note", "Binary body, shown base64-encoded."));
  }
  // `pretty` comes from mitmproxy's contentviews: protobuf, gRPC, form-encoded,
  // multipart, XML, msgpack and the rest, none of which the old JSON-only
  // prettifier could touch. Named in the section line rather than behind a view
  // picker -- one more control here is one more thing to read past.
  const label = d.pretty
    ? `body · ${fmtBytes(d.size)} · shown as ${d.pretty_view}`
    : `body · ${fmtBytes(d.size)}`;
  box.append(el("p", "section", label));
  const pre = document.createElement("pre");
  pre.textContent = d.pretty || (d.body ? pretty(d.body) : "(empty)");
  box.append(pre);
}

// ------------------------------------------------------------------- editor

function editorArea(key, initial) {
  const ta = document.createElement("textarea");
  ta.className = "editor";
  ta.spellcheck = false;
  ta.dataset.key = key;
  ta.value = drafts.has(key) ? drafts.get(key) : initial;
  ta.oninput = () => drafts.set(key, ta.value);
  return ta;
}

// One line. The full explanation lives in the tooltip: three lines of standing
// advice above the action row is how Forward and Drop got pushed off the pane.
const REFORMAT_NOTE =
  "Body indented for reading — forwarding unedited still sends the original bytes.";
const REFORMAT_WHY =
  "The indentation is for display. An edited body is only sent if you actually typed "
  + "something, so forwarding this flow untouched puts the original bytes on the wire "
  + "byte-for-byte. Edit anything and the indented body is what is sent — press Raw "
  + "first if the payload is signed or hashed.";

function reformatNote() {
  const p = el("p", "note", REFORMAT_NOTE);
  p.title = REFORMAT_WHY;
  return p;
}

// Pretty/Raw for the box in hand. `served` is what actually came off the wire and
// `prettify` its indented form, so "Raw" can mean the original bytes rather than
// "whatever minifying the box produces" -- an API that already indents its JSON
// would otherwise be silently re-encoded by a button labelled Raw.
function prettyToggle(ta, key, served, prettify) {
  const b = btn(ui.prettyBody ? "Raw" : "Pretty", null);
  b.title = ui.prettyBody
    ? "Show the body exactly as it came off the wire"
    : "Indent the JSON body so it can be read";
  b.onclick = () => {
    ui.prettyBody = !ui.prettyBody;
    localStorage.setItem("ic.prettyBody", ui.prettyBody ? "1" : "0");
    // Nothing typed yet: re-derive from the wire bytes, which is exact both ways.
    // Otherwise keep the edit and reformat just its body -- switching views must
    // never be a way to lose a hand-written payload.
    if (ta.value === served || ta.value === prettify(served)) drafts.delete(key);
    else reformatBody(ta, key, ui.prettyBody);
    // Rebuild so the button label and the reformat note match the new state.
    $("#detail-body").dataset.key = "";
    refresh();
  };
  return b;
}

// A raw message is `start line\nheaders\n\nbody`. Only the body is reformatted --
// rewriting a header would change what is sent in a way the user did not ask for,
// and the blank-line split is what the engine's own parser looks for.
function splitRaw(raw) {
  const i = raw.indexOf("\n\n");
  return i < 0 ? null : { head: raw.slice(0, i + 2), body: raw.slice(i + 2) };
}

function prettyRaw(raw) {
  const parts = splitRaw(raw);
  if (!parts || !parts.body.trim()) return raw;
  const out = pretty(parts.body);
  return out === parts.body ? raw : parts.head + out;
}

// Reformats what is in the box right now rather than re-deriving from the served
// message, so a half-typed edit is never thrown away by toggling the view.
function reformatBody(ta, key, toPretty) {
  const parts = splitRaw(ta.value);
  if (!parts) return note("No body to reformat — this message is headers only.");
  let out;
  try {
    const v = JSON.parse(parts.body);
    out = toPretty ? JSON.stringify(v, null, 2) : JSON.stringify(v);
  } catch {
    return note("Body is not JSON, so there is nothing to reformat.");
  }
  ta.value = parts.head + out;
  drafts.set(key, ta.value);
}

function renderEditor(box, h) {
  box.classList.add("editing");
  box.append(el("p", "headline", `STOPPED · ${h.direction}`));
  const key = `${h.id}:${h.direction}`;
  let ta = null;

  // The textarea needs a flex parent to fill the pane; wrapping it keeps the
  // notes and the action row at their natural height.
  const fill = (node) => {
    const wrap = el("div", "editor-fill");
    wrap.append(node);
    return wrap;
  };

  if (h.direction === "websocket" && h.frame?.truncated) {
    box.append(el("p", "note",
      `Frame is ${fmtBytes(h.frame.size ?? 0)} — above the editable limit. Forward or drop it.`));
  } else if (h.direction === "websocket") {
    const raw = h.frame?.body ?? "";
    // A JSON frame is the common case on an app socket, and unformatted it is one
    // long line. Binary frames are spaced hex already -- never touch those.
    const shown = ui.prettyBody && !h.frame?.binary ? pretty(raw) : raw;
    ta = editorArea(key, shown);
    const dir = h.frame?.from_client ? "client → server" : "server → client";
    const head = el("div", "editor-head");
    head.append(el("p", "section",
      `frame #${h.frame?.seq ?? "?"} · ${dir} · ${fmtBytes(h.frame?.size ?? 0)}`));
    if (!h.frame?.binary) head.append(prettyToggle(ta, key, raw, pretty));
    box.append(head, fill(ta));
    if (shown !== raw) box.append(reformatNote());
  } else if (h.detail && h.detail.raw != null) {
    // Never reformat a CRLF body: its line endings are what make multipart
    // boundaries valid, and JSON.parse would not accept one anyway.
    const usePretty = ui.prettyBody && !h.detail.body_crlf;
    const shown = usePretty ? prettyRaw(h.detail.raw) : h.detail.raw;
    ta = editorArea(key, shown);
    const head = el("div", "editor-head");
    // Short: beside the Raw button in a narrow pane, the old wording wrapped to
    // two lines and ate height the editor needed. The detail is in the tooltip.
    const label = el("p", "section", "edit, then forward");
    label.title = "Content-Length is recomputed on forward — never edit it by hand.";
    head.append(label);
    if (!h.detail.body_crlf) head.append(prettyToggle(ta, key, h.detail.raw, prettyRaw));
    box.append(head, fill(ta));
    // Say it plainly: reformatting changes the bytes the server receives, which
    // matters for a signed or hashed payload.
    if (shown !== h.detail.raw) box.append(reformatNote());
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
  // The per-request version of the global "Stop replies" toggle. That toggle
  // stops *every* matching flow twice, which is why it defaults off and stays
  // off; this holds exactly one reply, the one in front of you, and disarms
  // itself as soon as it has been used.
  if (h.direction === "request") {
    const b = btn("Forward + stop reply", () => forwardId(h.id, false, true), "ok");
    b.title = "Send this request on, then stop its reply on the way back so you can "
            + "edit what the app receives. Applies to this request only.";
    actions.append(b);
  }
  if (ta) {
    actions.append(btn("Revert", () => {
      drafts.delete(key);
      box.dataset.key = "";
      refresh();
    }));
  }
  box.append(actions);
  if (ta) {
    ta.focus();
    // Assigning .value leaves the caret at the end, and focus() then scrolls
    // there -- so the editor opened showing the tail of the body instead of the
    // request line. Start at the top, where the method, path and headers are.
    ta.setSelectionRange(0, 0);
    ta.scrollTop = 0;
  }
}

export function forwardId(id, drop, stopReply) {
  const h = held.get(id);
  const key = h ? `${id}:${h.direction}` : null;
  const raw = !drop && key && drafts.has(key) ? drafts.get(key) : undefined;
  send({
    type: "resume", id, drop: !!drop, seq: h?.frame?.seq, raw,
    stop_reply: !!stopReply,
  });
}

// ------------------------------------------------------------------ repeater

function renderRepeat(box, f) {
  openRepeatTab(f.id);
  renderRepeatTabs(box, f);

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
      refresh();
    }),
  );
  box.append(actions);
  box.append(el("p", "section", "sends"), el("div", "sends"));
  refreshRepeatHistory(box, f);
}

// A strip of the requests you are iterating on. Without it the repeater held one
// request at a time and comparing two meant losing the first one's draft.
function renderRepeatTabs(box, f) {
  if (ui.repeatTabs.length < 2) return;
  const strip = el("div", "repeat-tabs");
  for (const id of ui.repeatTabs) {
    const t = getFlow(id);
    const tab = el("span", "repeat-tab" + (id === f.id ? " on" : ""));
    const label = el("button", "repeat-tab-label",
      t ? `${t.method} ${t.path}` : id.slice(0, 8));
    label.title = t ? `${t.host}${t.path}` : id;
    label.onclick = () => { select(id); ui.which = "repeat"; refresh(); };
    const x = el("button", "repeat-tab-close", "✕");
    x.title = "Close this repeater tab and discard its draft";
    x.onclick = (e) => {
      e.stopPropagation();
      closeRepeatTab(id);
      box.dataset.key = "";
      refresh();
    };
    tab.append(label, x);
    strip.append(tab);
  }
  box.append(strip);
}

// Every send of this request, so iterating is a list you can read rather than a
// single "last result" that the next send overwrites.
function refreshRepeatHistory(box, f) {
  const list = box.querySelector(".sends");
  if (!list) return;
  const sends = sendHistory(f.id);
  if (list.dataset.count === String(sends.length)) return;
  list.dataset.count = String(sends.length);
  list.textContent = "";
  if (!sends.length) {
    list.append(el("p", "hint", "No sends yet. Hit Send and each attempt is listed here."));
    return;
  }
  for (const [i, s] of sends.entries()) {
    const rowEl = el("div", "send-row");
    rowEl.onclick = () => select(s.id);
    rowEl.title = "Open this send in the Request/Response tabs";
    rowEl.append(
      el("span", "dim", `#${i + 1}`),
      el("span", `send-status ${statusClass(s)}`, statusText(s)),
      el("span", "dim", fmtBytes(s.resp_bytes || 0)),
      el("span", "dim", s.ms == null ? "—" : `${s.ms}ms`),
    );
    list.append(rowEl);
  }
}

function renderReplayDelta(box, f) {
  const orig = getFlow(f.replay_of);
  if (!orig) return;
  const bit = (a, b) => (a === b ? String(a ?? "—") : `${a ?? "—"} → ${b ?? "—"}`);
  box.append(el("p", "note",
    `replay · status ${bit(orig.status, f.status)}` +
    ` · body ${bit(fmtBytes(orig.resp_bytes || 0), fmtBytes(f.resp_bytes || 0))}` +
    ` · ${bit(orig.ms == null ? null : orig.ms + "ms", f.ms == null ? null : f.ms + "ms")}`));
}

// -------------------------------------------------------------------- frames

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
