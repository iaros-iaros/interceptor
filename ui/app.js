// Interceptor UI: wiring and the top-level render.
//
// The pieces live in their own modules -- state.js, transport.js, table.js,
// detail.js, rules.js, menu.js -- and bus.js carries "draw again" between them
// so nothing has to import this file back. This file owns the toolbar, the
// panels, the splitter and the order the renderers run in.
//
// Everything rendered here comes off the wire from sites under test, so text
// goes in via textContent only. Never innerHTML with captured data.

import { onRender } from "./bus.js";
import { currentTheme, toggleTheme } from "./theme.js";
import { RULES_DOC_HTML } from "./rules-doc.js";
import { $, btn, el, fmtBytes, when } from "./util.js";
import { getFlow, ui } from "./state.js";
import { connect, select, send } from "./transport.js";
import { passEverything, renderTable, runSearch, setRowFilter, setSearchBodies } from "./table.js";
import { forwardId, renderDetail } from "./detail.js";
import {
  addFaultRule, applyRules, loadRulesFromState, renderRawPreview, renderRules,
} from "./rules.js";

// -------------------------------------------------------------------- render

function render() {
  const state = ui.state;
  for (const b of document.querySelectorAll(".modes button")) {
    b.classList.toggle("on", b.dataset.mode === state.mode);
  }
  if (document.activeElement !== $("#scope") && state.scope != null) {
    $("#scope").value = state.scope;
  }
  $("#resp").classList.toggle("on", !!state.intercept_responses);
  $("#noise").classList.toggle("on", !!state.hide_noise);
  // The filter only decides what Intercept stops, so in Capture it is a control
  // that cannot do anything. Dimming it and captioning it "applies in Intercept
  // mode" was still a box asking to be typed into. Hide it instead; a stored
  // filter is not lost, it is named in the mode line below and comes back the
  // moment Intercept is armed.
  const intercepting = state.mode === "intercept";
  $(".scope-group").hidden = !intercepting;
  // The group's flex:1 is what pushes the other groups right, so something has to
  // take its place or they jump left every time the mode changes.
  $("#scope-spacer").hidden = intercepting;
  renderModeHint();
  renderProxyWarning();
  renderStats();
  renderQueue();
  renderTable();
  renderDetail();
  if (!$("#sessions").hidden) renderSessions();
}

onRender(render);

// One line, in plain words, for whatever is currently armed. "Stop replies"
// is not self-explanatory on a button, and a title attribute is only found by
// someone who already guessed there was something to find.
function renderModeHint() {
  const state = ui.state;
  const scoped = (state.scope || "").trim();
  const which = scoped ? `each request matching ${scoped}` : "every request";
  const allow = state.allow_hosts || [];
  let text;
  if (state.mode === "intercept" && state.intercept_responses) {
    text = `Intercept — ${which} stops so you can read or edit it, and its reply stops ` +
           "again on the way back. Each flow stops twice: once out, once in.";
  } else if (state.mode === "intercept") {
    text = `Intercept — ${which} stops so you can read or edit it before it goes on. ` +
           "Replies come back untouched (forward one with “Forward + stop reply” to " +
           "catch just its reply, or turn on “Stop replies” to catch them all).";
  } else {
    // The "everything" claim would contradict the allowlist clause below, so drop
    // it when one is in force rather than assert both.
    text = (allow.length
             ? "Capture — matching traffic is logged, nothing stops. "
             : "Capture — every request is logged, nothing stops. ") +
           "Switch to Intercept to stop flows for editing.";
    // The filter box is hidden here, so a filter set earlier would otherwise be
    // invisible until it suddenly started stopping things.
    if (scoped) {
      text += ` A stop filter is saved (${scoped}) and takes effect the moment you do.`;
    }
  }
  // An allowlist changes what the sentence above is even true of, so it is said
  // in the same breath rather than left to be discovered in a panel.
  if (passEverything(allow)) {
    text += " Nothing is being captured: the host list matches nothing, so all traffic"
          + " passes straight through. Sites load normally and none of it appears here."
          + " This is what the old Passthrough mode did.";
  } else if (allow.length) {
    text += ` Only ${allow.join(", ")} ${allow.length === 1 ? "is" : "are"} captured;`
          + " every other host still loads but never appears here.";
  }
  // Faults change what the app under test *sees*, so leaving them unmentioned
  // here is how someone spends a morning debugging a rule they set yesterday.
  const faults = (state.faults || []).length;
  if (faults) {
    text += ` ${faults} fault rule${faults === 1 ? " is" : "s are"} active: some traffic`
          + " is being delayed, failed or dropped on purpose. Affected rows are tagged"
          + " “fault”.";
  }
  $("#mode-hint").textContent = text;
}

// A machine whose egress needs a proxy client will 502 on every site behind it,
// and the only clue is a Cloudflare TLS reset in the log. Say it here: the person
// who clicked Launch Chrome is looking at this window, not at a terminal.
function renderProxyWarning() {
  const state = ui.state;
  const warn = !!state.env_proxy && !state.chained;
  const box = $("#proxy-warn");
  box.hidden = !warn;
  if (warn) {
    box.textContent =
      `This machine reaches the internet through ${state.env_proxy}, but Interceptor is ` +
      `connecting directly — anything that needs that proxy will fail with ` +
      `502 Bad Gateway. Relaunch it as:  interceptor --chain`;
  }
}

function renderStats() {
  const state = ui.state;
  const bits = [];
  bits.push(`${state.stored || 0} flows`, fmtBytes(state.bytes || 0));
  if (state.evicted) bits.push(`${state.evicted} evicted`);
  if (state.noise_hidden) bits.push(`${state.noise_hidden} noise hidden`);
  if (state.auto_forwarded) bits.push(`${state.auto_forwarded} auto-forwarded`);
  const n = (state.rules_body || []).length + (state.rules_headers || []).length;
  if (n) bits.push(`${n} rule${n === 1 ? "" : "s"} active`);
  const faults = (state.faults || []).length;
  if (faults) bits.push(`${faults} fault${faults === 1 ? "" : "s"} active`);
  // A forgotten allowlist reads as "the tool stopped capturing", so it is never
  // silent -- it says so here and again in the mode hint below the toolbar.
  const allow = (state.allow_hosts || []).length;
  if (allow) bits.push(`${allow} host${allow === 1 ? "" : "s"} only`);
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
  const state = ui.state;
  const q = state.queue || [];
  $("#queue").hidden = q.length === 0;
  if (!q.length) return;
  $("#queue-count").textContent = `${q.length} stopped — waiting for you`;
  const hosts = $("#queue-hosts");
  hosts.textContent = "";
  let stalled = false;
  for (const [h, n] of Object.entries(state.per_host || {})) {
    if (n > 1) stalled = true;
    const b = document.createElement("b");
    b.textContent = `${h}×${n}`;
    hosts.append(b, " ");
  }
  // Only when it is actually happening. Shown permanently it was 40px of advice
  // pushing the flow table down every time a single request stopped.
  $("#stall-note").hidden = !stalled;
  const list = $("#queue-list");
  list.textContent = "";
  for (const item of q) {
    const row = el("div", "q-item");
    if (item.id === ui.sel) row.classList.add("sel");
    const url = el("span", "url", `${item.host}${item.path}`);
    url.title = "Open in the editor";
    url.onclick = () => select(item.id);
    row.append(
      el("span", "dir", item.direction),
      url,
      // forwardId, not a bare resume: it pulls the draft for this flow, so a
      // change typed in the editor is never silently discarded by forwarding
      // from the queue instead of from the pane.
      btn("Forward", () => forwardId(item.id), "ok"),
      btn("Drop", () => forwardId(item.id, true), "danger"),
    );
    list.append(row);
  }
}

function renderSessions() {
  const list = $("#sessions-list");
  list.textContent = "";
  if (!ui.sessions.length) {
    list.append(el("p", "hint", "No saved sessions yet. Hit “Save session” to make one."));
    return;
  }
  for (const s of ui.sessions) {
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

// ------------------------------------------------------------------- wiring

for (const b of document.querySelectorAll(".modes button")) {
  b.onclick = () => {
    $("#scope").classList.remove("bad");
    send({ type: "mode.set", mode: b.dataset.mode, scope: $("#scope").value });
  };
}
for (const b of document.querySelectorAll("#detail-tabs button")) {
  b.onclick = () => {
    ui.which = b.dataset.which;
    render();
  };
}
function applyScope() {
  $("#scope").classList.remove("bad");
  $("#note").hidden = true;
  send({ type: "mode.set", mode: ui.state.mode || "capture", scope: $("#scope").value });
}
$("#scope").addEventListener("keydown", (e) => {
  if (e.key === "Enter") applyScope();
});
// change fires on blur when the value differs, so clicking away applies it too --
// pressing Enter was the only way to submit, and nothing said so.
$("#scope").addEventListener("change", applyScope);
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
    if (d.kind === "fault") {
      addFaultRule({
        url: d.url || "",
        delay_ms: Number(d.delay || 0),
        status: d.status ? Number(d.status) : null,
        drop: d.drop === "1",
      });
      return;
    }
    const rule = { where: d.where, url: d.url, find: d.find, repl: d.repl, raw: null };
    (d.kind === "header" ? ui.headerRules : ui.bodyRules).push(rule);
    renderRules();
  };
}
$("#add-body-rule").onclick = () => {
  ui.bodyRules.push({ where: "both", url: "", find: "", repl: "", raw: null });
  renderRules();
  $("#body-rules").querySelector(".rule-row:last-child .rule-input")?.focus();
};
$("#add-header-rule").onclick = () => {
  ui.headerRules.push({ where: "req", url: "", find: "", repl: "", raw: null });
  renderRules();
  $("#header-rules").querySelector(".rule-row:last-child .rule-input")?.focus();
};
$("#add-fault-rule").onclick = () => addFaultRule();
$("#rules-raw-toggle").onclick = () => {
  const pre = $("#rules-raw");
  pre.hidden = !pre.hidden;
  $("#rules-raw-toggle").textContent = pre.hidden
    ? "Show generated syntax" : "Hide generated syntax";
  $("#rules-raw-toggle").classList.toggle("on", !pre.hidden);
  renderRawPreview();
};

// Only one panel at a time. Three panels stacked above the workspace is the
// clutter this UI cannot afford -- and it is the same complaint the queue caused.
// Pass null to close everything. Returns whether `id` ended up open.
function openPanel(id) {
  let opened = false;
  for (const [panel, toggle] of [["#hosts-panel", "#hosts-toggle"],
                                 ["#rules", "#rules-toggle"],
                                 ["#sessions", "#open-session"]]) {
    const want = panel === id && $(panel).hidden;
    $(panel).hidden = !want;
    $(toggle).classList.toggle("on", want);
    if (want) opened = true;
  }
  return opened;
}

$("#hosts-toggle").onclick = () => {
  if (!openPanel("#hosts-panel")) return;
  // Show what is actually in force, not what was last typed here.
  $("#hosts-list").value = (ui.state.allow_hosts || []).join("\n");
  $("#hosts-list").focus();
};
$("#hosts-close").onclick = () => openPanel(null);
$("#hosts-apply").onclick = () => {
  const hosts = $("#hosts-list").value.split("\n").map((s) => s.trim()).filter(Boolean);
  send({ type: "hosts.set", hosts });
  $("#hosts-status").textContent = hosts.length
    ? `capturing ${hosts.length} host(s) only — TLS applies to new connections`
    : "capturing every host again";
  setTimeout(() => ($("#hosts-status").textContent = ""), 6000);
};
$("#hosts-clear").onclick = () => {
  $("#hosts-list").value = "";
  send({ type: "hosts.set", hosts: [] });
};

$("#rules-toggle").onclick = () => {
  if (openPanel("#rules")) loadRulesFromState();
};
$("#rules-close").onclick = () => openPanel(null);
$("#rules-apply").onclick = applyRules;
$("#resp").onclick = () =>
  send({ type: "opt.set", intercept_responses: !ui.state.intercept_responses });
$("#noise").onclick = () => send({ type: "opt.set", hide_noise: !ui.state.hide_noise });
$("#save-session").onclick = () => send({ type: "session.save" });
$("#open-session").onclick = () => {
  if (openPanel("#sessions")) send({ type: "sessions.list" });
};
$("#sessions-refresh").onclick = () => send({ type: "sessions.list" });
$("#sessions-close").onclick = () => openPanel(null);

// The filter box is two tools in one, switched by the button beside it: hide rows
// already on screen, or ask the server to search every stored body. Keeping them
// in one box is the whole reason this did not cost a second input.
$("#row-filter").addEventListener("input", (e) => {
  if (!ui.searchBodies) setRowFilter(e.target.value);
});
$("#row-filter").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && ui.searchBodies) runSearch();
});
// Same reason the scope box listens for `change`: Enter was the only way to
// submit and nothing said so, so clicking away looked like the search had run
// and returned everything.
$("#row-filter").addEventListener("change", () => {
  if (ui.searchBodies) runSearch();
});
$("#search-bodies").onclick = () => setSearchBodies(!ui.searchBodies);
$("#row-filter-clear").onclick = () => {
  $("#row-filter").value = "";
  if (ui.searchBodies) runSearch();
  else setRowFilter("");
  $("#row-filter").focus();
};

// ---------------------------------------------------------------- splitter

// Both panes stay usable at any width: below these the table loses its columns
// and the editor stops being an editor.
const DETAIL_MIN = 300;
const TABLE_MIN = 340;
const DETAIL_DEFAULT = 500;

function setDetailWidth(px) {
  const rect = $("#workspace").getBoundingClientRect();
  // Clamp against the actual workspace, not the window: the max depends on how
  // much room the table needs, and on a narrow window DETAIL_MIN has to win.
  const max = Math.max(DETAIL_MIN, rect.width - TABLE_MIN);
  const w = Math.round(Math.min(max, Math.max(DETAIL_MIN, px)));
  document.documentElement.style.setProperty("--detail-w", `${w}px`);
  return w;
}

const savedWidth = Number(localStorage.getItem("ic.detailWidth"));
if (savedWidth > 0) setDetailWidth(savedWidth);

function saveDetailWidth() {
  const cur = getComputedStyle(document.documentElement).getPropertyValue("--detail-w");
  localStorage.setItem("ic.detailWidth", String(parseInt(cur, 10) || DETAIL_DEFAULT));
}

$("#splitter").addEventListener("pointerdown", (e) => {
  e.preventDefault();
  const sp = $("#splitter");
  // Pointer capture, so the drag survives the cursor crossing the textarea or
  // leaving the window -- without it a fast drag simply stopped tracking.
  sp.setPointerCapture(e.pointerId);
  sp.classList.add("dragging");
  document.body.classList.add("resizing");

  const move = (ev) =>
    setDetailWidth($("#workspace").getBoundingClientRect().right - ev.clientX);
  const up = () => {
    sp.removeEventListener("pointermove", move);
    sp.removeEventListener("pointerup", up);
    sp.removeEventListener("pointercancel", up);
    sp.classList.remove("dragging");
    document.body.classList.remove("resizing");
    saveDetailWidth();
  };
  sp.addEventListener("pointermove", move);
  sp.addEventListener("pointerup", up);
  sp.addEventListener("pointercancel", up);
});

// Keyboard: a separator that only responds to a drag is unreachable without a
// mouse, and this one decides how much of the tool you can see.
$("#splitter").addEventListener("keydown", (e) => {
  const step = e.shiftKey ? 64 : 16;
  const cur = parseInt(
    getComputedStyle(document.documentElement).getPropertyValue("--detail-w"), 10,
  ) || DETAIL_DEFAULT;
  if (e.key === "ArrowLeft") setDetailWidth(cur + step);
  else if (e.key === "ArrowRight") setDetailWidth(cur - step);
  else if (e.key === "Home") setDetailWidth(DETAIL_DEFAULT);
  else return;
  e.preventDefault();
  saveDetailWidth();
});

$("#splitter").ondblclick = () => {
  setDetailWidth(DETAIL_DEFAULT);
  saveDetailWidth();
};

// A window that shrank can leave the pane wider than the clamp allows.
addEventListener("resize", () => {
  const cur = parseInt(
    getComputedStyle(document.documentElement).getPropertyValue("--detail-w"), 10,
  );
  if (cur) setDetailWidth(cur);
});

// ---------------------------------------------------------------- traffic tabs

for (const b of document.querySelectorAll("#traffic-tabs button")) {
  b.onclick = () => {
    if (ui.traffic === b.dataset.traffic) return;
    ui.traffic = b.dataset.traffic;
    // A selection from the other view would highlight nothing and read as a bug.
    if (ui.sel && !!getFlow(ui.sel)?.ws !== (ui.traffic === "ws")) ui.sel = null;
    render();
  };
}

$("#queue-collapse").onclick = () => {
  const q = $("#queue");
  q.classList.toggle("collapsed");
  const hidden = q.classList.contains("collapsed");
  $("#queue-collapse").textContent = hidden ? "Show list" : "Hide list";
  $("#queue-collapse").classList.toggle("on", hidden);
};

$("#launch").onclick = () => send({ type: "browser.launch" });
$("#clear").onclick = () => send({ type: "clear" });
$("#fwd-all").onclick = () => send({ type: "resume.all" });
$("#drop-all").onclick = () => send({ type: "resume.all", drop: true });

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
