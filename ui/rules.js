// The Rules panel: rewrite rules (find/replace) and fault rules (break it on
// purpose). Both are "change matching traffic automatically, stop nothing", so
// they share one panel and one Apply rather than growing the toolbar.

import { $, btn, el } from "./util.js";
import { ui } from "./state.js";
import { send } from "./transport.js";

// mitmproxy wants one packed string per rewrite rule:
// <sep><filter><sep><find><sep><replace>. Nobody should have to type that, and a
// separator that also appears in the pattern is the most common way to get it
// wrong -- so the form owns the syntax and picks a separator that appears in
// neither the filter nor the find text. It may appear in the replacement:
// parse_spec splits with maxsplit=2, so the tail is taken whole.
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

export function composeRule(r) {
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
export function splitSpec(spec) {
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
export function ruleFromSpec(spec) {
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

export function loadRulesFromState() {
  ui.bodyRules = (ui.state.rules_body || []).map(ruleFromSpec);
  ui.headerRules = (ui.state.rules_headers || []).map(ruleFromSpec);
  ui.faultRules = (ui.state.faults || []).map((f) => ({ ...f }));
  renderRules();
}

export function renderRules() {
  renderRuleList($("#body-rules"), ui.bodyRules, "body");
  renderRuleList($("#header-rules"), ui.headerRules, "header");
  renderFaultList();
  renderRawPreview();
}

function renderRuleList(box, rules, kind) {
  box.textContent = "";
  if (!rules.length) {
    box.append(el("p", "hint", kind === "body" ? "No body rules yet." : "No header rules yet."));
    return;
  }
  rules.forEach((r, i) => box.append(ruleRow(r, i, rules, kind)));
}

function ruleInput(r, key, placeholder, cls, onInput) {
  const inp = document.createElement("input");
  inp.className = "rule-input" + (cls ? " " + cls : "");
  inp.placeholder = placeholder;
  inp.value = r[key] ?? "";
  inp.spellcheck = false;
  inp.oninput = () => { r[key] = inp.value; (onInput || renderRawPreview)(); };
  return inp;
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
      el("span", "rule-label", "URL has"), ruleInput(r, "url", "anything"),
      el("span", "rule-label", kind === "body" ? "find" : "header"),
      ruleInput(r, "find", kind === "body" ? "text to find" : "header name", "grow"),
      el("span", "rule-label", kind === "body" ? "replace with" : "set to"),
      ruleInput(r, "repl", kind === "body" ? "replacement" : "value (empty removes it)", "grow"),
    );
  }

  const rm = btn("✕", () => { rules.splice(i, 1); renderRules(); }, "icon");
  rm.title = "Remove this rule";
  row.append(rm);
  return row;
}

// ---------------------------------------------------------------- fault rules

function renderFaultList() {
  const box = $("#fault-rules");
  box.textContent = "";
  if (!ui.faultRules.length) {
    box.append(el("p", "hint", "No fault rules yet — traffic is left alone."));
    return;
  }
  ui.faultRules.forEach((r, i) => box.append(faultRow(r, i)));
}

function faultRow(r, i) {
  const row = el("div", "rule-row");
  const num = (key, placeholder, width) => {
    const inp = document.createElement("input");
    inp.className = "rule-input rule-num";
    inp.type = "number";
    inp.placeholder = placeholder;
    if (width) inp.style.width = width;
    inp.value = r[key] ?? "";
    inp.oninput = () => {
      const v = inp.value.trim();
      r[key] = v === "" ? (key === "delay_ms" ? 0 : null) : Number(v);
    };
    return inp;
  };

  const drop = btn("drop connection", null, "toggle");
  drop.classList.toggle("on", !!r.drop);
  drop.title = "Kill the connection instead of answering. The client sees a network "
             + "error, not an HTTP status.";
  drop.onclick = () => {
    r.drop = !r.drop;
    if (r.drop) r.status = null;   // the server rejects both together, so keep the
    renderFaultList();             // form from being able to ask for it
  };

  row.append(
    el("span", "rule-label", "when URL has"), ruleInput(r, "url", "anything", "", () => {}),
    el("span", "rule-label", "delay"), num("delay_ms", "0", "76px"),
    el("span", "rule-label", "ms"),
  );
  if (!r.drop) {
    row.append(el("span", "rule-label", "reply"), num("status", "e.g. 503", "92px"));
  }
  row.append(drop);

  const rm = btn("✕", () => { ui.faultRules.splice(i, 1); renderFaultList(); }, "icon");
  rm.title = "Remove this rule";
  row.append(rm);
  return row;
}

export function addFaultRule(preset) {
  ui.faultRules.push({ url: "", delay_ms: 0, status: null, body: "", drop: false, ...preset });
  renderFaultList();
  $("#fault-rules").querySelector(".rule-row:last-child .rule-input")?.focus();
}

// ------------------------------------------------------------------- applying

export function applyRules() {
  const specs = (rules) => rules.map(composeRule).filter(Boolean);
  const body = specs(ui.bodyRules), headers = specs(ui.headerRules);
  const skipped = (ui.bodyRules.length + ui.headerRules.length) - (body.length + headers.length);
  send({ type: "rules.set", body, headers });
  // Faults go as structured rules, not packed strings: that format exists only
  // because mitmproxy's own parser demands it, and this is our own code.
  send({ type: "faults.set", faults: ui.faultRules });
  // Say what went, and say what did not: an incomplete row silently doing nothing
  // is how the old textarea version lost people.
  const bits = [`applied ${body.length} body + ${headers.length} header rule(s)`];
  if (ui.faultRules.length) bits.push(`${ui.faultRules.length} fault rule(s)`);
  if (skipped) bits.push(`${skipped} incomplete row(s) skipped (nothing in "find")`);
  $("#rules-status").textContent = bits.join(" — ");
  setTimeout(() => ($("#rules-status").textContent = ""), 6000);
}

export function renderRawPreview() {
  const pre = $("#rules-raw");
  if (pre.hidden) return;
  const lines = [];
  for (const [label, rules] of [["body", ui.bodyRules], ["headers", ui.headerRules]]) {
    for (const r of rules) {
      const spec = composeRule(r);
      if (spec) lines.push(label.padEnd(9) + spec);
    }
  }
  for (const r of ui.faultRules) {
    const what = [];
    if (r.delay_ms) what.push(`delay ${r.delay_ms}ms`);
    if (r.drop) what.push("drop");
    else if (r.status) what.push(`reply ${r.status}`);
    if (what.length) lines.push("fault".padEnd(9) + `${r.url || "*"} -> ${what.join(", ")}`);
  }
  pre.textContent = lines.length
    ? lines.join("\n")
    : "(nothing yet -- the forms above generate these)";
}
