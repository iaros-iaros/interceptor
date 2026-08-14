// The bridge socket: connect, send, and turn incoming pushes into state.
// Nothing here draws; it mutates state and asks for a frame.

import { refresh } from "./bus.js";
import { copy, note, setConn, $ } from "./util.js";
import {
  details, drafts, flows, frames, framesLoaded, getFlow, held, searchFlows,
  forgetAll, trim, ui,
} from "./state.js";

const RENDER_MS = 100; // ~10fps; the bridge already batches at 50ms
const token = new URLSearchParams(location.hash.slice(1)).get("token");

let ws = null;
let retryMs = 1000;
let pending = false;

export function send(msg) {
  if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(msg));
}

export function connect() {
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

function schedule() {
  if (pending) return;
  pending = true;
  setTimeout(() => {
    pending = false;
    refresh();
  }, RENDER_MS);
}

function handle(m) {
  switch (m.type) {
    case "snapshot":
      forgetAll();
      for (const f of m.flows) flows.set(f.id, f);
      break;
    case "flow": {
      flows.set(m.id, m);
      trim();
      // A response that arrived after we cached "no response yet" must refetch.
      if (m.id === ui.sel && m.status != null && details.get(`${m.id}:response`) === null) {
        details.delete(`${m.id}:response`);
        send({ type: "body.get", id: m.id, which: "response" });
      }
      break;
    }
    case "state": {
      ui.state = m;
      const live = new Set((m.queue || []).map((q) => q.id));
      for (const id of [...held.keys()]) {
        if (live.has(id)) continue;
        drafts.delete(`${id}:${held.get(id).direction}`);
        held.delete(id);
        if (id === ui.sel) {
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
      if (arr.length > 500) arr.shift();
      frames.set(m.id, arr);
      // Keep the row's frame count honest. The server only re-sends a flow
      // summary when the socket closes, so the table sat at "ws (0)" for the
      // whole life of a busy connection. seq is the server's own monotonic
      // index, so this counts frames the local buffer has already dropped.
      const f = flows.get(m.id);
      if (f && m.seq + 1 > (f.ws_frames || 0)) f.ws_frames = m.seq + 1;
      break;
    }
    case "frames":
      frames.set(m.id, m.frames);
      framesLoaded.add(m.id);
      // Force a rebuild: the backfill contains seqs the append cursor already
      // passed, so incremental append alone would skip them.
      if (m.id === ui.sel) $("#detail-body").dataset.key = "";
      break;
    case "body":
      details.set(`${m.id}:${m.which}`, m.detail);
      break;
    case "results":
      // Only adopt results for the query still in the box: two searches in
      // flight would otherwise land in whichever order the server finished them.
      if (m.q === ui.searchQuery) {
        ui.searchResults = m.flows || [];
        searchFlows.clear();
        for (const f of ui.searchResults) searchFlows.set(f.id, f);
      }
      break;
    case "export":
      copy(m.text, m.format === "curl" ? "curl command" : m.format);
      break;
    case "har":
      note(`HAR written to ${m.dir}/${m.name}`, true);
      break;
    case "cleared":
      forgetAll();
      break;
    case "sessions":
      ui.sessions = m.items || [];
      $("#sessions-dir").textContent = m.dir || "";
      break;
    case "saved":
      note(`saved ${m.flows} flow(s) to ${m.name}`, true);
      break;
    case "loaded":
      note(`loaded ${m.flows} flow(s) from ${m.name}`, true);
      ui.sel = null;
      framesLoaded.clear();
      break;
    case "error":
      note(m.message);
      if (/scope|filter/i.test(m.message)) $("#scope").classList.add("bad");
      break;
  }
}

// Selecting a row: state change plus the fetches it implies. Lives here rather
// than in the table so the queue list and the context menu can select too.
export function select(id) {
  const prev = getFlow(ui.sel);
  ui.sel = id;
  // Keep the open tab when the new flow can show it: clicking down a list while
  // reading responses used to throw you back to Request on every row.
  const f = getFlow(id);
  // Frames are the reason you opened a socket, so land there -- but only when
  // arriving from a non-socket row, so choosing Request on a socket sticks while
  // you click down the list.
  if (f?.ws && !prev?.ws) ui.which = "frames";
  if (ui.which === "frames" && !f?.ws) ui.which = "request";
  if (ui.which === "repeat" && f?.ws) ui.which = "request";
  for (const w of ["request", "response"]) {
    if (!details.has(`${id}:${w}`)) send({ type: "body.get", id, which: w });
  }
  refresh();
}
