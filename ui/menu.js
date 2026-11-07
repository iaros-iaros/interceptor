// Right-click menu for a flow row.
//
// This exists so the toolbar does not grow a button per feature. Everything that
// acts on *one* flow belongs to the row, not to a strip at the top of the window
// that is already four labelled groups deep -- and "select the row, then find the
// control" was the shape of every action in this UI until now.

import { $, copy, el, note } from "./util.js";
import { openRepeatTab, ui } from "./state.js";
import { select, send } from "./transport.js";
import { refresh } from "./bus.js";

let menu = null;

const esc = (s) => String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

// Anchored and escaped. A bare hostname is a regex in which every dot matches
// anything, so `api.example.com` also captured `api-example.com` and any host
// with that name inside it. The list matches host:port, hence the port.
export function hostPattern(f) {
  return `^${esc(f.host)}:${f.port}$`;
}

function close() {
  menu?.remove();
  menu = null;
}

function urlOf(f) {
  const port = f.port && f.port !== 80 && f.port !== 443 ? `:${f.port}` : "";
  return `${f.scheme}://${f.host}${port}${f.path}`;
}

export function openMenu(x, y, f) {
  close();
  menu = el("div", "ctx-menu");
  menu.setAttribute("role", "menu");

  const item = (label, fn, title) => {
    const b = el("button", null, label);
    if (title) b.title = title;
    b.onclick = () => { close(); fn(); };
    menu.append(b);
  };
  const sep = () => menu.append(el("div", "ctx-sep"));

  if (!f.ws) {
    item("Repeat this request", () => {
      openRepeatTab(f.id);
      select(f.id);
      ui.which = "repeat";
      refresh();
    }, "Open it in the repeater, edited if you like, without touching the original");
    sep();
    // Holding a single reply is deliberately NOT offered here. It only works on a
    // flow the stop filter already matches, so an entry on an arbitrary row would
    // do nothing on most of them. Its honest home is the held-request editor,
    // where the request is in front of you and the answer is always yes.
    item("Copy as curl", () => send({ type: "export", id: f.id, format: "curl" }),
         "A runnable command — the thing to paste into a ticket");
    item("Copy as raw request", () => send({ type: "export", id: f.id, format: "raw_request" }));
  }
  item("Copy URL", () => copy(urlOf(f), "URL"));
  sep();
  item(f.marked ? "Unmark" : "Mark", () => send({ type: "flow.mark", id: f.id, marked: !f.marked }),
       "Flag this flow — matchable in the stop filter as ~marked");
  item(f.comment ? "Edit comment…" : "Comment…", () => {
    // prompt is the laziest editor that works for a one-line note, and a comment
    // is exactly that; it is searchable and kept in a saved session.
    const text = window.prompt("Comment on this flow:", f.comment || "");
    if (text !== null) send({ type: "flow.comment", id: f.id, text });
  }, "Attach a note — searchable, and matchable as ~comment");
  sep();
  // Comparer: mark one flow, then diff a second against it. A dedicated mark
  // rather than "the selected flow" because right-clicking a row selects it, so
  // "selected" would always be this row by the time the menu opens.
  if (!f.ws) {
    item("Mark for compare", () => {
      ui.compareBase = f.id;
      note("Marked. Right-click another flow → “Compare with marked flow”.", true);
    }, "Pick this flow as one side of a diff");
    if (ui.compareBase && ui.compareBase !== f.id) {
      item("Compare with marked flow", () => {
        select(f.id);
        ui.which = "response";
        send({ type: "diff", a: ui.compareBase, b: f.id, which: "response" });
      }, "Diff this flow's response against the marked one");
    }
    sep();
  }
  item("Filter rows to this host", () => {
    // Through the box rather than table.js: menu.js importing table.js would be
    // the import cycle bus.js exists to prevent. Body search matches on bodies,
    // not on the row, so it is switched off first.
    if (ui.searchBodies) $("#search-bodies").click();
    const box = $("#row-filter");
    box.value = `\\s${esc(f.host)}(:\\d+)?\\s`;
    box.dispatchEvent(new Event("input"));
  }, "Hide every row from any other host — view only, nothing stops");
  item("Capture only this host", () => send({ type: "hosts.set", hosts: [hostPattern(f)] }),
       "Replaces the host list with this one host — everything else stops being captured");
  sep();
  item("Export everything as HAR…", () => send({ type: "har.save" }),
       "Writes every captured flow to a .har file in sessions/, for devtools or a colleague");

  document.body.append(menu);
  // Clamp: a right-click near the bottom right would otherwise open a menu that
  // runs off the window with no way to scroll to it.
  const r = menu.getBoundingClientRect();
  menu.style.left = `${Math.min(x, innerWidth - r.width - 8)}px`;
  menu.style.top = `${Math.min(y, innerHeight - r.height - 8)}px`;
  menu.querySelector("button")?.focus();
}

// Any click, any scroll, Escape: a context menu that outlives its context is a
// menu acting on a row you are no longer looking at.
addEventListener("pointerdown", (e) => {
  if (menu && !menu.contains(e.target)) close();
}, true);
addEventListener("scroll", close, true);
addEventListener("keydown", (e) => {
  if (e.key === "Escape" && menu) { e.stopPropagation(); close(); }
}, true);
