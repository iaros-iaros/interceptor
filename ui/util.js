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

// ------------------------------------------------------------------ decoding
//
// Pure, DOM-free, so they run under node in the check suite. atob, TextDecoder
// and decodeURIComponent are all available in the browser and in node.

function b64urlToBytes(s) {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4 ? "=".repeat(4 - (b64.length % 4)) : "";
  const bin = atob(b64 + pad);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

// Decode as UTF-8, throwing on invalid bytes (fatal) -- that is how we tell "this
// base64 was text" from "this base64 was a gzip blob".
function bytesToText(bytes) {
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

// A string with no control characters other than tab/newline/CR is something
// worth showing; one with stray control bytes is a binary blob rendered as junk.
function isTextStr(s) {
  return !/[\u0000-\u0008\u000e-\u001f]/.test(s);
}

// Decode a JWT without verifying it -- this is a decoder, not a validator. Returns
// {header, payload, alg, exp, expired} or null when it is not three base64url
// JSON-bearing segments.
export function decodeJwt(token) {
  const parts = String(token || "").split(".");
  if (parts.length !== 3) return null;
  try {
    const header = JSON.parse(bytesToText(b64urlToBytes(parts[0])));
    const payload = JSON.parse(bytesToText(b64urlToBytes(parts[1])));
    const alg = String(header.alg ?? "");
    const exp = typeof payload.exp === "number" ? payload.exp : null;
    return { header, payload, alg, exp, expired: exp != null && exp * 1000 < Date.now() };
  } catch {
    return null;
  }
}

// Every way the given text plausibly decodes: base64/base64url, URL percent-
// encoding, hex, JWT. Only decodings that succeed, are text, and actually differ
// from the input are returned, so pasting plain text yields nothing.
export function decodings(input) {
  const text = (input || "").trim();
  const out = [];
  if (!text) return out;
  // base64 — reject length%4==1 (never valid) and very short strings (too many
  // false positives), and require the base64 alphabet.
  if (/^[A-Za-z0-9_+/-]+={0,2}$/.test(text) && text.length >= 8 && text.length % 4 !== 1) {
    try {
      const s = bytesToText(b64urlToBytes(text.replace(/=+$/, "")));
      if (s !== text && isTextStr(s)) out.push({ kind: "base64", text: s });
    } catch { /* not base64 after all */ }
  }
  if (/%[0-9a-fA-F]{2}/.test(text)) {
    try {
      const s = decodeURIComponent(text);
      if (s !== text) out.push({ kind: "url", text: s });
    } catch { /* malformed percent-encoding */ }
  }
  if (/^[0-9a-fA-F]+$/.test(text) && text.length % 2 === 0 && text.length >= 4) {
    try {
      const s = bytesToText(new Uint8Array(text.match(/../g).map((h) => parseInt(h, 16))));
      if (isTextStr(s)) out.push({ kind: "hex", text: s });
    } catch { /* not decodable text */ }
  }
  const jwt = decodeJwt(text);
  if (jwt) {
    out.push({ kind: "jwt",
      text: JSON.stringify({ header: jwt.header, payload: jwt.payload }, null, 2) });
  }
  return out;
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
