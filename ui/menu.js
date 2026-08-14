// Right-click menu for a flow row.
//
// This exists so the toolbar does not grow a button per feature. Everything that
// acts on *one* flow belongs to the row, not to a strip at the top of the window
// that is already four labelled groups deep -- and "select the row, then find the
// control" was the shape of every action in this UI until now.

import { copy, el } from "./util.js";
import { openRepeatTab, ui } from "./state.js";
import { select, send } from "./transport.js";
import { refresh } from "./bus.js";

let menu = null;

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
  item("Capture only this host", () => send({ type: "hosts.set", hosts: [f.host] }),
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
