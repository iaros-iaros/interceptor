// All mutable UI state in one place, so a feature that adds state adds it here
// rather than to a growing pile of module-level `let`s in the render code.

export const MAX_ROWS = 500; // ponytail: newest-N cap. Virtual scroll when it annoys.
// Retention, not just rendering. Without this the Map grew for the life of the
// tab and every render tick copied all of it -- tens of thousands of entries,
// ten times a second, after a morning of testing. The server evicts too.
export const MAX_KEPT = MAX_ROWS * 4;
// Repeater targets kept on the strip. More than this and it is a tab bar nobody
// can read; the drafts behind closed ones are dropped with them.
export const MAX_REPEAT_TABS = 8;

export const flows = new Map(); // id -> summary, insertion order = arrival
// Search hits, kept apart from `flows`. Merging them in would put flows from an
// hour ago at the end of an insertion-ordered map, i.e. at the top of a table
// that means "newest last" -- history masquerading as live traffic.
export const searchFlows = new Map();
export const frames = new Map(); // id -> [ws.message]
export const details = new Map(); // `${id}:${which}` -> detail | null
export const held = new Map(); // id -> flow.paused payload
export const drafts = new Map(); // `${id}:${direction}` -> edited raw, survives re-render
export const framesLoaded = new Set(); // flow ids whose frame history we backfilled

// Single mutable bag rather than exported `let`s: an ES module export binding is
// read-only from the importing side, so `sel = x` in another file silently would
// not work. One object everyone shares does.
export const ui = {
  state: {},          // last `state` push from the server
  sel: null,          // selected flow id
  which: "request",   // detail tab
  sessions: [],
  rowFilter: "",
  rowFilterRe: null,
  // "http" | "ws". A socket is one row that lives for minutes while frames
  // stream under it; mixed into hundreds of request rows it was invisible.
  traffic: "http",
  // Off: the filter box hides rows already on screen. On: it asks the server to
  // search bodies and headers across the whole store, which is a different
  // question and a different cost, so it is a deliberate switch rather than
  // something the same box does silently.
  searchBodies: false,
  searchResults: null,  // array of summaries, or null when not in a search
  searchQuery: "",
  // Flow ids open in the repeater strip, most recent last.
  repeatTabs: [],
  // Pretty-print JSON bodies in the held-flow editor. Sticky, because it is a
  // reading preference, not a per-flow decision.
  prettyBody: localStorage.getItem("ic.prettyBody") !== "0",
  // Rule forms, not raw specs. {where, url, find, repl, raw}
  // `raw` is set only for a spec the form cannot represent, so nothing is ever
  // silently dropped just because it is more complex than the form.
  bodyRules: [],
  headerRules: [],
  // {url, delay_ms, status, body, drop}
  faultRules: [],
};

// Everything keyed by flow id, so a forgotten flow does not leave its body,
// frames, draft or held entry behind. Clearing only `flows` leaked all four.
export function forgetAll() {
  flows.clear();
  frames.clear();
  details.clear();
  framesLoaded.clear();
  held.clear();
  drafts.clear();
  ui.sel = null;
  ui.repeatTabs = [];
  ui.searchResults = null;
}

export function forget(id) {
  flows.delete(id);
  frames.delete(id);
  framesLoaded.delete(id);
  held.delete(id);
  for (const w of ["request", "response"]) details.delete(`${id}:${w}`);
  for (const k of drafts.keys()) if (k.startsWith(id) || k === `repeat:${id}`) drafts.delete(k);
  ui.repeatTabs = ui.repeatTabs.filter((t) => t !== id);
  if (ui.sel === id) ui.sel = null;
}

export function trim() {
  while (flows.size > MAX_KEPT) {
    // Oldest first, but never the row being read, and never one open in the
    // repeater -- both are things the user is actively working on.
    let victim;
    for (const id of flows.keys()) {
      if (id !== ui.sel && !ui.repeatTabs.includes(id)) { victim = id; break; }
    }
    if (victim === undefined) break;
    forget(victim);
  }
}

export function openRepeatTab(id) {
  if (ui.repeatTabs.includes(id)) return;
  ui.repeatTabs.push(id);
  while (ui.repeatTabs.length > MAX_REPEAT_TABS) {
    const dropped = ui.repeatTabs.shift();
    drafts.delete(`repeat:${dropped}`);
  }
}

export function closeRepeatTab(id) {
  ui.repeatTabs = ui.repeatTabs.filter((t) => t !== id);
  drafts.delete(`repeat:${id}`);
}

// Every send of a given request, oldest first. The server tags each replay with
// `replay_of`, so the history is already in the data -- it was just never shown.
export function sendHistory(id) {
  return [...flows.values()].filter((f) => f.replay_of === id);
}

// A selected row can come from either table, so every reader goes through here.
export function getFlow(id) {
  if (id == null) return undefined;
  return flows.get(id) ?? searchFlows.get(id);
}
