// DOM and formatting helpers. No imports: this is the bottom of the stack.
//
// Everything rendered from captured traffic goes in via textContent only.
// Never innerHTML with data off the wire.

export const $ = (s) => document.querySelector(s);

export function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
}

export function btn(label, onclick, cls) {
  const b = el("button", cls, label);
  b.onclick = onclick;
  return b;
}

export function fmtBytes(n) {
  if (!n) return "0";
  const u = ["B", "K", "M", "G"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) {
    n /= 1024;
    i++;
  }
  return `${n < 10 && i > 0 ? n.toFixed(1) : Math.round(n)}${u[i]}`;
}

export function when(ts) {
  if (!ts) return "";
  const d = new Date(ts * 1000);
  return d.toLocaleString(undefined, { dateStyle: "short", timeStyle: "short" });
}

export function pretty(text) {
  try {
    return JSON.stringify(JSON.parse(text), null, 2);
  } catch {
    return text;
  }
}

export function statusText(f) {
  if (f.killed) return "killed";
  if (f.intercepted) return "stopped";
  return f.status == null ? "···" : String(f.status);
}

export function statusClass(f) {
  if (f.killed) return "err";
  if (f.status == null) return "pending";
  return `s${String(f.status)[0]}`;
}

export function setConn(on, label) {
  const n = $("#conn");
  n.className = on ? "on" : "off";
  n.textContent = label || (on ? "live" : "offline");
}

let noteTimer;
export function note(msg, ok) {
  const n = $("#note");
  n.textContent = msg;
  n.classList.toggle("ok", !!ok);
  n.hidden = false;
  clearTimeout(noteTimer);
  // Errors are worth reading twice; a confirmation is not.
  noteTimer = setTimeout(() => { n.hidden = true; }, ok ? 4000 : 12000);
}

// Clipboard needs a secure context, which http://127.0.0.1 counts as in every
// current browser -- but a stale one, or a denied permission, would otherwise
// fail silently and look like the menu item did nothing.
export async function copy(text, what) {
  try {
    await navigator.clipboard.writeText(text);
    note(`${what} copied to the clipboard`, true);
  } catch (e) {
    note(`Could not reach the clipboard (${e.message}). Nothing was copied.`);
  }
}
