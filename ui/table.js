// The flow table: traffic tabs, the filter/search strip, and the rows.

import { $, el, fmtBytes, statusClass, statusText } from "./util.js";
import { flows, searchFlows, ui, MAX_ROWS } from "./state.js";
import { select, send } from "./transport.js";
import { openMenu } from "./menu.js";

// The documented idiom for "open no host at all" -- the replacement for the
// Passthrough mode. Named rather than matched loosely: a pattern that happens to
// match nothing today (a typo) should still read as a narrow list, because that
// is what it is. Only the deliberate spelling gets the friendlier wording.
export const PASS_EVERYTHING = new Set(["^$", "(?!)"]);

export function passEverything(allow) {
  return allow.length > 0 && allow.every((p) => PASS_EVERYTHING.has(p.trim()));
}

function matchesRow(f) {
  if (!ui.rowFilter) return true;
  // Everything the row shows, so what you see is what you search.
  const port = f.port && f.port !== 80 && f.port !== 443 ? ":" + f.port : "";
  const hay = `${f.method} ${f.status ?? ""} ${f.host}${port} ${f.path} ${f.ctype || ""}`;
  return ui.rowFilterRe
    ? ui.rowFilterRe.test(hay)
    : hay.toLowerCase().includes(ui.rowFilter.toLowerCase());
}

// In search mode the rows come from the server and are already the answer, so
// the local text filter does not apply again -- it matched on what the row shows,
// and the search matched on bodies the row never shows.
function source() {
  return ui.searchBodies && ui.searchResults ? [...searchFlows.values()] : [...flows.values()];
}

export function renderTable() {
  const searching = ui.searchBodies && ui.searchResults !== null;
  const everything = source();
  // Two independent narrowings, kept separate so the counts mean what they say:
  // the tab picks the protocol, the filter box searches within it.
  const inView = everything.filter((f) => !!f.ws === (ui.traffic === "ws"));
  const all = searching ? inView : inView.filter(matchesRow);
  const shown = all.slice(-MAX_ROWS).reverse();
  const hiddenCount = all.length - shown.length;

  renderTrafficTabs(everything);
  renderFilterStrip(all.length, inView.length, searching);
  renderEmpty(inView.length, searching);

  $("#truncated").hidden = hiddenCount === 0;
  if (hiddenCount) {
    $("#truncated").textContent =
      `${hiddenCount} older matching flow(s) not rendered (newest ${MAX_ROWS} shown).`;
  }

  const body = document.createElement("tbody");
  for (const f of shown) body.append(row(f));
  $("#flows").tBodies[0].replaceWith(body);
}

function renderFilterStrip(matched, total, searching) {
  $("#row-filter-clear").hidden = !ui.rowFilter;
  $("#search-bodies").classList.toggle("on", ui.searchBodies);
  $("#row-filter-label").textContent = ui.searchBodies ? "Search bodies" : "Filter rows";
  $("#row-filter").placeholder = ui.searchBodies
    ? "text to find in any URL, header or body — press Enter to search"
    : "text or regex, e.g. /api/ or \\.(png|jpg) — hides rows only";
  const count = $("#row-filter-count");
  if (searching) {
    count.textContent = ui.searchResults.length
      ? `${matched} match${matched === 1 ? "" : "es"} in the store`
      : "no matches in the store";
  } else {
    count.textContent = ui.rowFilter ? `${matched} of ${total} shown` : "";
  }
}

function renderEmpty(count, searching) {
  $("#empty").hidden = count > 0;
  if (count) return;
  const ws = ui.traffic === "ws";
  const allow = ui.state.allow_hosts || [];
  if (searching) {
    $("#empty-title").textContent = "Nothing in the capture contains that.";
    $("#empty-hint").textContent =
      "Body search looks through every URL, header and body still in the store. "
      + "Streamed bodies are never buffered, so they cannot be searched.";
    return;
  }
  // An allowlist narrow enough to match nothing leaves an empty table that
  // looks like a broken tool. Passthrough used to cause exactly this and got
  // reported as such, so the explanation stays -- it just belongs to the list
  // now that the list is the only thing that can cause it.
  if (passEverything(allow)) {
    $("#empty-title").textContent = "Nothing is being captured — this is deliberate.";
    $("#empty-hint").textContent =
      "Your host list matches nothing, so all traffic passes straight through: sites "
      + "load normally and none of it is shown. Clear the list in Tools → Hosts to "
      + "capture everything again.";
  } else if (allow.length) {
    $("#empty-title").textContent = "Nothing captured — a host list is in force.";
    $("#empty-hint").textContent =
      `Only ${allow.join(", ")} would appear here. Every other host still loads `
      + "normally in the browser, it is simply not captured. Clear the list in "
      + "Tools → Hosts to capture everything again.";
  } else {
    $("#empty-title").textContent = ws ? "No WebSocket connections yet." : "No traffic yet.";
    // The context menu is the access path for everything that acts on one flow,
    // so it has to be discoverable somewhere. This is where a new user is
    // already looking, and it costs no chrome.
    $("#empty-hint").textContent = ws
      ? "A socket shows up here from its handshake onwards. Frames appear under the "
        + "Frames tab when you select it."
      : "Hit Launch Chrome above, or point any client at the proxy. Once rows appear, "
        + "right-click one for repeat, copy as curl, and HAR export.";
  }
}

// The count on each tab is the point of the split: "I don't see any WebSocket
// traffic" is answered by a number without having to switch views to check.
function renderTrafficTabs(everything) {
  let ws = 0, live = 0;
  for (const f of everything) {
    if (!f.ws) continue;
    ws++;
    // ws_open comes from the socket's own close timestamp. A 101 status cannot
    // stand in for it -- a long-closed connection still reports 101.
    if (f.ws_open) live++;
  }
  const counts = { http: everything.length - ws, ws };
  for (const b of document.querySelectorAll("#traffic-tabs button")) {
    const kind = b.dataset.traffic;
    b.classList.toggle("on", kind === ui.traffic);
    b.classList.toggle("has-live", kind === "ws" && live > 0);
    let badge = b.querySelector(".count");
    if (!badge) {
      badge = el("span", "count");
      b.append(badge);
    }
    badge.textContent = counts[kind] ? String(counts[kind]) : "";
  }
}

function row(f) {
  const tr = document.createElement("tr");
  if (f.id === ui.sel) tr.classList.add("sel");
  if (f.intercepted) tr.classList.add("held");
  if (f.faulted) tr.classList.add("faulted");
  tr.onclick = () => select(f.id);
  // Right-click is where everything that acts on one flow lives, so the toolbar
  // does not grow a button per feature.
  tr.oncontextmenu = (e) => {
    e.preventDefault();
    select(f.id);
    openMenu(e.clientX, e.clientY, f);
  };

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
  // Never silent: an unlabelled injected failure is an hour of debugging a rule
  // you armed yourself.
  if (f.faulted) {
    const tag = el("span", "tag tag-fault", "fault");
    tag.title = `Interceptor did this on purpose: ${f.faulted}`;
    tr.children[1].append(tag);
  }
  if (f.http_version && f.http_version.includes("2")) {
    tr.children[4].append(el("span", "tag tag-h2", "h2"));
  }
  return tr;
}

// ---------------------------------------------------------------- filter strip

export function setRowFilter(v) {
  ui.rowFilter = (v || "").trim();
  // Regex when it compiles, so /api/v\d+ works; plain text is a valid regex
  // anyway. A half-typed one like "api(" would throw on every keystroke, so it
  // falls back to a substring match instead of showing nothing.
  try {
    ui.rowFilterRe = ui.rowFilter ? new RegExp(ui.rowFilter, "i") : null;
  } catch {
    ui.rowFilterRe = null;
  }
  renderTable();
}

// Enter, not every keystroke: a body search is a scan of the whole store, and
// firing one per character typed would be a scan per character.
export function runSearch() {
  const q = $("#row-filter").value.trim();
  ui.searchQuery = q;
  if (!q) {
    ui.searchResults = null;
    searchFlows.clear();
    renderTable();
    return;
  }
  send({ type: "search", q });
}

export function setSearchBodies(on) {
  ui.searchBodies = on;
  ui.searchResults = null;
  searchFlows.clear();
  if (on) runSearch();
  else setRowFilter($("#row-filter").value);
  renderTable();
}
