# Mini-Burp Features Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the gap between Interceptor and Burp's non-proxy tabs — Intruder, passive findings, Comparer, Decoder, annotations — and fix the five defects found in review, each with a check.

**Architecture:** Every feature reuses an engine primitive mitmproxy already ships (`flow.marked`/`flow.comment`, `~meta`, `replay.client`, `map_local`, `anticache`, the `tls_clienthello` hook, HAR reading in `FlowReader`) and extends the existing bridge protocol by a field or a command. Server logic that has a decision in it is a pure function with a `check.py` unit; UI logic with a decision in it is an exported pure function run under `node` by `check.py`, the way `clampRepeat` and `matchesRow` already are. A headless-Chrome smoke test over CDP (Task 5) finally covers the DOM.

**Tech Stack:** Python 3.13, mitmproxy 12.2.3, `websockets` 17 (also used as the CDP client), vanilla ES modules, SQLite. No new dependencies.

**Conventions (read before any task):**
- Tests live in `spike/check.py`: `check(name, ok, detail)` records a result; units use `taddons.context(addon, ...)` and `tflow.tflow()`; UI units extract a function from a `ui/*.js` file with `grab()` and run it under `node`. A fake bridge is `_Collect()` (records pushes, one client). Run the whole suite with `.venv/bin/python spike/check.py`; a single unit with `.venv/bin/python -c "import sys; sys.path.insert(0,'spike'); import check; check.units_x(); print(check.RESULTS)"`.
- Anything that changes the wire protocol changes `addon/`, `ui/` **and** `AGENT-API.md` (AGENTS.md rule).
- Non-obvious decisions get a comment at the point they matter. Deliberate shortcuts get a `ponytail:` comment naming the ceiling.
- One commit per task, on branch `claude/burp-features`. Run the suite before every commit.

**Order:** fixes first (Tasks 1–5), then features in value order (6–18).

---

## File map

| File | Responsibility added |
|---|---|
| `addon/interceptor.py` | clear semantics, HAR suffix, `edited`/`label`/`findings`/`marked`/`comment` summary fields, `flow.mark`/`flow.comment`/`diff` commands, `faults`+`passthrough_hosts` options, `tls_clienthello`, TLS detail, map_local/anticache plumbing |
| `addon/store.py` | frame text in the search index |
| `addon/bridge.py` | CSP header, `diff` in `REPLIES` |
| `addon/findings.py` (new) | passive checks: pure `passive(flow)` + `EXPLAIN` |
| `ui/menu.js` | `hostPattern`, filter-to-host, mark/comment, compare |
| `ui/table.js` | new tags (`edited`, `comment`, `finding`), row-filter hay |
| `ui/detail.js` | shortcuts, TLS section, JWT section, diff view, payload runner, labels in the send list |
| `ui/rules.js` | local-file rule block |
| `ui/util.js` | `decodeJwt`, `decodings` |
| `ui/app.js` | scope chips, anticache toggle, passthrough textarea, decoder panel |
| `ui/index.html`, `ui/style.css` | the markup and tag colours for all of the above |
| `spike/check.py` | one check per task; `ui_smoke()` |
| `README.md`, `AGENT-API.md` | every user-visible or protocol-visible change |

---

### Task 1: Clear keeps the flows that are still held

**Files:** Modify `addon/interceptor.py` (`_on_message`, `clear` branch), `ui/transport.js` (`cleared` case), `spike/check.py`, `AGENT-API.md` (`clear` row), `ui/index.html` (Clear button title).

- [ ] **Step 1: Write the failing check** (append after `units_stop_reply`, register in `main()` as `await units_clear_keeps_held()`)

```python
async def units_clear_keeps_held() -> None:
    """Clear empties the table. A flow still held is still waiting on a decision,
    so it cannot go with the table: wiping it from the store left a queue entry
    the table could not show."""
    import interceptor as I
    from mitmproxy.addons import modifybody, modifyheaders
    from mitmproxy.test import taddons, tflow

    addon = I.Interceptor()
    with taddons.context(addon, modifybody.ModifyBody(), modifyheaders.ModifyHeaders()) as tctx:
        tctx.configure(addon, hide_noise=False)
        addon.bridge = _Collect()
        held = tflow.tflow()            # no response: in flight
        held.intercept()
        addon.paused[held.id] = ("request", held)
        addon._remember(held)
        done = tflow.tflow(resp=True)
        addon._remember(done)
        await addon._on_message({"type": "clear"})
        kinds = [m["type"] for m in addon.bridge.sent]
        ok = (held.id in addon.store and done.id not in addon.store
              and held.id in addon.paused
              and "flow.paused" in kinds and kinds.index("cleared") < kinds.index("flow.paused"))
        addon.store.close()
    check("Clear keeps the flows still held and re-sends their holds", ok,
          f"held kept: {held.id in addon.store}, finished gone: {done.id not in addon.store}, "
          f"pushes: {kinds}")
```

- [ ] **Step 2: Run it, expect FAIL** (`held kept: False`).

- [ ] **Step 3: Implement.** In the `clear` branch, after `self.store.clear()` and the counter resets:

```python
            # A held flow is still waiting on a decision, so it cannot go with the
            # table: wiping it left a queue entry pointing at a row the table could
            # not show. Put the held ones back, and re-send their holds after
            # `cleared` -- the UI forgets everything on that message.
            for _direction, flow in self.paused.values():
                self._remember(flow)
            self.bridge.push("cleared")
            for direction, flow in self.paused.values():
                self.bridge.push("flow.paused", **self._paused_payload(direction, flow))
            self._push_state()
```
(and delete the old `self.bridge.push("cleared")` line above it). In `ui/transport.js`, the `cleared` case keeps drafts for held ids:

```js
    case "cleared": {
      // The server re-sends every hold right after this, so a half-typed edit on
      // a held flow must survive the Clear; everything else goes.
      const keep = [...drafts].filter(([k]) => held.has(k.split(":")[0]));
      forgetAll();
      for (const [k, v] of keep) drafts.set(k, v);
      break;
    }
```

- [ ] **Step 4: Run the suite, expect PASS.** Update the Clear button title in `index.html` ("Empty the table. Flows still stopped stay. Does not touch saved sessions.") and the `clear` row in AGENT-API.md.

- [ ] **Step 5: Commit** `fix: Clear keeps held flows and re-sends their holds`.

---

### Task 2: Row menu — anchored host pattern, and "Filter rows to this host"

**Files:** Modify `ui/menu.js`, `spike/check.py`, `README.md` (row-menu table).

- [ ] **Step 1: Failing check** (`units_host_pattern`, sync, registered after `units_row_filter`). It runs the shipped `hostPattern` under node and then matches the result the way `_off_list` does:

```python
def units_host_pattern() -> None:
    """"Capture only this host" used to send the bare hostname, i.e. a regex in
    which every dot matches anything and nothing is anchored."""
    import json as _json
    import re
    harness = r"""
      import { readFileSync } from "node:fs";
      const src = readFileSync("ui/menu.js", "utf8");
      const i = src.indexOf("function hostPattern(");
      let depth = 0, j = src.indexOf("{", i), end = -1;
      for (let k = j; k < src.length; k++) {
        if (src[k] === "{") depth++;
        else if (src[k] === "}" && --depth === 0) { end = k + 1; break; }
      }
      const fn = new Function(src.slice(i, end) + "; return hostPattern;")();
      console.log(JSON.stringify(JSON.parse(process.env.ROWS).map(fn)));
    """
    rows = [{"host": "api.example.com", "port": 443}, {"host": "10.0.0.1", "port": 8080}]
    out = subprocess.run(["node", "--input-type=module", "-e", harness], cwd=ROOT,
                         capture_output=True, text=True, timeout=60,
                         env={**os.environ, "ROWS": _json.dumps(rows)})
    if out.returncode != 0:
        return check("the row menu's host pattern is anchored and escaped", False,
                     f"node failed: {out.stderr.strip()[:200]}")
    p0, p1 = _json.loads(out.stdout)
    hit = lambda p, t: bool(re.search(p, t, re.IGNORECASE))  # noqa: E731
    notes = []
    if not hit(p0, "api.example.com:443"): notes.append("misses its own host")
    if hit(p0, "api-example.com:443"): notes.append("dot matched a dash")
    if hit(p0, "api.example.com.evil.net:443"): notes.append("not anchored at the end")
    if hit(p0, "xapi.example.com:443"): notes.append("not anchored at the start")
    if hit(p0, "api.example.com:8443"): notes.append("port not anchored")
    if not hit(p1, "10.0.0.1:8080") or hit(p1, "10x0y0z1:8080"): notes.append("IP not escaped")
    check("the row menu's host pattern is anchored and escaped", not notes,
          "; ".join(notes) or f"{p0}  {p1}")
```

- [ ] **Step 2: Run, expect FAIL** (`missing hostPattern` from node).

- [ ] **Step 3: Implement** in `ui/menu.js`:

```js
// Anchored and escaped. A bare hostname is a regex in which every dot matches
// anything, so `api.example.com` also captured `api-example.com` and any host
// with that name inside it. The list matches host:port, hence the port.
export function hostPattern(f) {
  const esc = String(f.host).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return `^${esc}:${f.port}$`;
}
```
Use it in "Capture only this host". Add, before it, **"Filter rows to this host"**: turns body search off if on (click `#search-bodies`), sets `#row-filter` to `\s${esc}(:\d+)?\s`-style pattern (host escaped) and dispatches an `input` event so app.js's listener applies it. No import from table.js — that would create the module cycle bus.js exists to prevent.

- [ ] **Step 4: Run, expect PASS.** README row-menu table gets the new item.
- [ ] **Step 5: Commit** `fix: anchor the row menu's host pattern; add filter-to-host`.

---

### Task 3: WebSocket frames in the search index

**Files:** Modify `addon/store.py` (`_search_text`), `spike/check.py` (`units_search`), `README.md`, `AGENT-API.md` (known limitations).

- [ ] **Step 1: Failing check** — in `units_search`, after the three HTTP flows:

```python
        wf = tflow.twebsocketflow()        # closed socket: frames "hello text", "it's me"
        store.put(wf, 10, I.summary(wf), 10 * 1024 * 1024)
        ...
        if found("it's me") != ["/ws"]:
            notes.append(f"frame match: {found(chr(105)+'t'+chr(39)+'s me')}")
```

- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement** at the end of `_search_text`, before the join:

```python
    if flow.websocket is not None:
        # Text frames only -- binary has nothing to substring -- and only once the
        # socket has closed, which is when a flow is final and this runs at all.
        parts += [m.content.decode(errors="replace")
                  for m in flow.websocket.messages if m.is_text]
```

- [ ] **Step 4: Run, expect PASS.** Docs: AGENT-API "Known limitations" first bullet becomes "search indexes the text frames of a *closed* socket; an open one is not indexed until it closes"; README "in bodies" bullet likewise.
- [ ] **Step 5: Commit** `feat: index WebSocket text frames for body search`.

---

### Task 4: Content-Security-Policy on the UI

**Files:** Modify `addon/bridge.py` (`_static`), `spike/check.py` (integration + `units_csp_safe_markup`).

- [ ] **Step 1: Failing checks.** In `integration()` after `static serving + token gate`, fetch the headers of `/`:

```python
def http_headers(path: str) -> dict:
    req = urllib.request.Request(UI + path)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=10) as r:
        return {k.lower(): v for k, v in r.headers.items()}
...
        csp = http_headers("/").get("content-security-policy", "")
        check("the UI is served with a CSP pinned to its own origin",
              "default-src 'self'" in csp and f"ws://127.0.0.1:{UI_PORT}" in csp
              and "frame-ancestors 'none'" in csp, csp or "no header")
```
And an offline unit proving the markup has nothing a CSP would block (inline scripts, `style=`, `on*=` handlers) in `index.html`, `rules.html` and `rules-doc.js`.

- [ ] **Step 2: Run, expect the integration check to FAIL** (`no header`).
- [ ] **Step 3: Implement** in `Bridge._static` headers:

```python
                # Everything this page renders comes off the wire from sites under
                # test. textContent-only rendering is the first line of defence;
                # this is the second: no inline script, no foreign origin, and no
                # page may frame the UI.
                "Content-Security-Policy": self.csp,
```
with `self.csp = (f"default-src 'self'; connect-src 'self' {origin ws}; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")` built in `__init__` from `self.origin`.

- [ ] **Step 4: Run, expect PASS.** Then open the UI in a browser and confirm the console is clean (Task 5 automates this).
- [ ] **Step 5: Commit** `feat: serve the UI with a Content-Security-Policy`.

---

### Task 5: Headless-Chrome smoke test over CDP

**Files:** Modify `spike/check.py` (`ui_smoke`, called from `integration()` once flows exist and before the "UI vanishes" check), `README.md` (Tests), `.github/workflows/check.yml` (comment only: Chrome is on both runner images).

- [ ] **Step 1: Write the check.** Chrome is found via `interceptor.CHROME_PATHS` + `shutil.which`; absent → `check(..., None, "Chrome not found")` (SKIP). Launch `--headless=new --disable-gpu --no-sandbox --no-first-run --disable-background-networking --user-data-dir=<tmp> --remote-debugging-port=0 about:blank`, read `DevTools listening on ws://…` from stderr, connect with `websockets`, then flat-mode CDP:
  1. `Target.createTarget {url: <UI url with token>}` → `targetId`; `Target.attachToTarget {targetId, flatten: true}` → `sessionId`.
  2. `Runtime.enable`, `Log.enable` on the session; collect `Runtime.exceptionThrown`, `Runtime.consoleAPICalled` (type `error`) and `Log.entryAdded` (level `error`).
  3. Poll `Runtime.evaluate` (`returnByValue`) up to 15s for `document.querySelectorAll('#flows tbody tr').length > 0 && document.querySelector('#conn').textContent === 'live'`.
  4. `document.querySelector('#flows tbody tr').click()`, then poll for `document.querySelector('#detail-body .headline')?.textContent` non-empty.
  5. `Browser.close`, kill the process, wait for exit (the bridge must see this client leave before the orphan check runs).
  Three checks: `the UI renders a captured row in a real browser`, `clicking a row opens the detail pane`, `no console or page errors while rendering` (detail lists them).

- [ ] **Step 2: Run** — expect PASS on this machine (Chrome present). Temporarily break `ui/app.js` with a duplicate `const` and confirm the first check FAILS with an exception in the detail; revert.
- [ ] **Step 3: README Tests section**: add the smoke test to "Covered", remove the "anything needing a DOM" gap sentence, keep the honest remainder (CSS layout, drag, keyboard).
- [ ] **Step 4: Commit** `test: headless-Chrome smoke test over CDP`.

---

### Task 6: Intruder-lite — payload markers in the Repeater

**Files:** Modify `ui/detail.js`, `ui/index.html` (none), `ui/style.css`, `addon/interceptor.py` (`repeat`, `summary`, `_on_message replay`), `spike/check.py`, `README.md`, `AGENT-API.md`.

- [ ] **Step 1: Failing checks.** (a) node unit `units_payloads` on the exported pure function:

```js
// §…§ marks the position; every marker takes the same payload (Burp's sniper
// with one position set). A function replacer, so a payload containing $& is
// inserted verbatim rather than expanded by String.replace.
export function expandPayloads(raw, payloads) {
  if (!/§[^§]*§/.test(raw)) return [];
  return payloads.map((p) => raw.replace(/§[^§]*§/g, () => p));
}
```
Cases: one marker → each payload substituted; two markers → both replaced with the same payload; payload `"$&x"` inserted literally; no marker → `[]`; empty payload list → `[]`.
(b) Python `units_replay_label`: register a fake `replay.client` with `tctx.master.commands.add("replay.client", fn)` that records its argument; `addon.repeat(fid, "", label="admin' --")` → recorded clone's `summary()["label"] == "admin' --"` and the original flow has no label.

- [ ] **Step 2: Run, expect FAIL** on both.
- [ ] **Step 3: Implement.** Server: `repeat(self, fid, raw="", label="")` sets `clone.metadata["label"] = label[:200]` when given; `summary()` gains `"label": flow.metadata.get("label")`; `_on_message` passes `msg.get("label") or ""`. UI (`renderRepeat`): under the editor a `payloads` block — textarea (one per line, draft key `payloads:${id}`), a **§ mark selection** button that wraps the editor's current selection in `§…§`, and a hint. `runRepeat`: when the payload list is non-empty, markers must exist (else `note()` and return); the sequence is `expandPayloads(raw, payloads)` and each send carries `label: payload`; the count field is ignored in payload mode and progress reads `3 / 12 payloads`. When markers exist but no payloads: refuse with a note (never send `§` to the server). Send list rows get a `label` column (`el("span", "send-label", s.label)`), empty when absent.

- [ ] **Step 4: Run, expect PASS.** Docs: README Repeater gets a "Payloads" subsection (markers, one position set, sequential, labels in the send list, caps unchanged); AGENT-API gets `replay.label` and the `label` summary field.
- [ ] **Step 5: Commit** `feat: payload markers in the repeater (intruder-lite)`.

---

### Task 7: Passive findings

**Files:** Create `addon/findings.py`; modify `addon/interceptor.py` (`response` hook, `clear`, `_load_session`, `summary`, `_snapshot`, `_push_state`), `ui/table.js`, `ui/detail.js`, `ui/transport.js`, `ui/state.js`, `ui/app.js` (stats), `ui/style.css`, `spike/check.py`, `README.md`, `AGENT-API.md`.

- [ ] **Step 1: Failing check** `units_findings`: build one `tflow.tflow(resp=True)` per rule and assert the exact code list; then two flows from the same host both missing HSTS and assert the second carries nothing (dedupe). Rules and keys (`passive(flow) -> list[tuple[code, key]]`, key dedupes across a capture):

| code | fires when | key |
|---|---|---|
| `missing-hsts` | https, 2xx/3xx, no `Strict-Transport-Security` | host |
| `missing-csp` | `text/html` 2xx without `Content-Security-Policy` | host |
| `missing-frame-protection` | `text/html` 2xx, no `X-Frame-Options` and no `frame-ancestors` in CSP | host |
| `missing-nosniff` | 2xx with a body and no `X-Content-Type-Options: nosniff` | host |
| `cookie-insecure` | https `Set-Cookie` without `Secure` | host:cookie |
| `cookie-no-httponly` | `Set-Cookie` without `HttpOnly` | host:cookie |
| `cookie-no-samesite` | `Set-Cookie` without `SameSite` | host:cookie |
| `cors-wildcard-credentials` | `ACAO: *` and `ACAC: true` | host |
| `cors-origin-reflected` | request has `Origin`, `ACAO` equals it, `ACAC: true` | host |
| `jwt-alg-none` | a JWT in request headers or `Set-Cookie` whose header part has `"alg":"none"` | first 16 chars of token |
| `secret-in-url` | query param named token/access_token/api_key/apikey/secret/password/passwd/auth/session/sid/jwt | host:param |
| `basic-auth` | `Authorization: Basic` | host |
| `plain-http-auth` | scheme http with `Authorization` or `Cookie` | host |
| `server-version` | `Server` or `X-Powered-By` containing `\d+\.\d+` | host:header |
| `directory-listing` | `text/html` body containing `Index of /` | host:path |

`EXPLAIN` maps each code to one sentence. Module docstring states why passive only (nothing is sent that the app did not send) and why first-sight dedupe (a page load is 300 flows from one host).

- [ ] **Step 2: Run, expect FAIL** (`ImportError: findings`).
- [ ] **Step 3: Implement.** `findings.py` as specified. In the addon: `self.findings_seen: set[tuple[str, str]] = set()`, reset in `clear` and `_load_session`; in `response()` before `_remember`:

```python
        new = [code for code, key in findings.passive(flow)
               if (code, key) not in self.findings_seen and not self.findings_seen.add((code, key))]
        if new:
            flow.metadata["findings"] = new
```
(the `not set.add(...)` idiom is the one-liner that records and keeps; comment it). `summary()` gains `"findings": flow.metadata.get("findings")`; `_push_state` gains `findings=len(self.findings_seen)`; the `snapshot` reply gains `findings_doc=findings.EXPLAIN` (sent once per `hello`, never in `state`). UI: `tag-finding` on the status cell (`2 findings`, title = explanations), `rowSig` and the row-filter hay include the codes plus the word `finding`, the stats strip shows `N findings`, the detail pane (either tab) lists `code — explanation` under a `findings` section. `ui.findingsDoc` is set from the snapshot.

- [ ] **Step 4: Run, expect PASS.** README: "Passive findings" section with the table and the dedupe rule; AGENT-API: `findings` summary field, `findings_doc` on `snapshot`, `findings` on `state`, and the note that `~meta <code>` matches tagged flows for a scope.
- [ ] **Step 5: Commit** `feat: passive findings tagged on the row`.

---

### Task 8: Comparer — `diff` command

**Files:** Modify `addon/interceptor.py` (`_diff_text`, `_diff`, `_on_message`), `addon/bridge.py` (`REPLIES`), `ui/detail.js`, `ui/transport.js`, `ui/state.js`, `ui/menu.js`, `ui/style.css`, `spike/check.py`, `AGENT-API.md`, `README.md`.

- [ ] **Step 1: Failing check** `units_diff`: two flows with responses `{"amount":100}` and `{"amount":1}` (`content-type: application/json`), `await addon._on_message({"type": "diff", "a": a.id, "b": b.id, "which": "response"})` → pushed `diff` text has a `-` line containing `100` and a `+` line containing `1`, and a missing id → `error`.
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement.** `_diff_text(flow, which)` builds from `detail()`: start line, `k: v` headers, blank, then `pretty` when present else `body` (so a one-line JSON body diffs field by field; `encoding` streamed/too-large → `None`). `_diff` resolves both flows from the store, uses `difflib.unified_diff(..., n=2, fromfile=f"{a[:8]} {which}", tofile=f"{b[:8]} {which}")`, pushes `diff` with `a`, `b`, `which`, `text` (`"(identical)"` when empty). Add `"diff"` to `REPLIES`. UI: `renderReplayDelta` gets a **Diff vs original** button (`a = replay_of`, `b = id`, `which = ui.which`); the row menu gets **Compare with the selected flow** when another row is selected (`a = ui.sel`, `b = f.id`). The reply lands in `ui.diff = {a, b, which, text}`; `renderMessage` renders it in place of the body when `ui.sel === b && ui.which === which`, one `<span>` per line with class `add`/`del`/`hunk`, plus a **Hide diff** button that clears `ui.diff`.
- [ ] **Step 4: Run, expect PASS.** Docs: AGENT-API `diff` command and reply; README "Comparer" paragraph under the Repeater.
- [ ] **Step 5: Commit** `feat: diff two flows (comparer)`.

---

### Task 9: Decoder — inline JWT and a Decoder panel

**Files:** Modify `ui/util.js` (`decodeJwt`, `decodings`), `ui/detail.js` (JWT section under headers), `ui/app.js` + `ui/index.html` (Decoder panel in Tools), `spike/check.py`, `README.md`.

- [ ] **Step 1: Failing check** `units_decoder` (node): `decodeJwt` on a token with `{"alg":"none"}` and `exp` in the past → `alg === "none"`, `expired === true`, payload round-trips; a two-part string → `null`. `decodings("aGVsbG8gd29ybGQ=")` includes `{kind: "base64", text: "hello world"}`; `decodings("a%20b%2Fc")` includes url `"a b/c"`; `decodings("68656c6c6f")` includes hex `"hello"`; `decodings("hello")` has no base64 entry (decodes to non-text).
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement** in `util.js`: `b64urlToBytes`, `isText(bytes)` (no control bytes except `\t\n\r`), `decodeJwt(token) -> {header, payload, alg, exp, expired} | null`, `decodings(text) -> [{kind, text}]` trying base64/base64url, URL, hex and JWT, keeping only decodings that succeed, are text, and differ from the input. UI: under the headers table, for every JWT-shaped token in a header value (dedupe), a `jwt in <header>` section with alg, exp (as a date, red `expired` when past), and the payload JSON; a **Decoder** panel (Tools → Decoder, same `openPanel` family) with one textarea and a live list of `<pre>` blocks labelled by kind.
- [ ] **Step 4: Run, expect PASS.** README: "Decoder" subsection.
- [ ] **Step 5: Commit** `feat: inline JWT decoding and a decoder panel`.

---

### Task 10: Annotations — mark and comment

**Files:** Modify `addon/interceptor.py` (`_annotate`, `_on_message`, `summary`), `ui/menu.js`, `ui/table.js`, `ui/detail.js`, `ui/style.css`, `spike/check.py`, `AGENT-API.md`, `README.md`.

- [ ] **Step 1: Failing check** `units_annotations` (async): store a finished flow, `flow.mark` → summary `marked` true and `flowfilter.parse("~marked")` matches; `flow.comment "suspicious"` → summary carries it and `~comment susp` matches; flush, drop the RAM cache, `store.get` → the annotation came back from disk; `flow.mark` with `marked: false` → cleared.
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement.** Commands `flow.mark {id, marked}` and `flow.comment {id, text}` → `_annotate(fid, marked=None, comment=None)`: `flow.marked = ":flag:" if marked else ""` (mitmproxy's own field, so `~marked` works as a scope and `.mitm` sessions keep it), `flow.comment = text[:2000]`, then `_remember` (re-stores the copy that came off disk) and `_push_flow`. `summary()` gains `marked: bool(...)`, `comment`. UI: row menu **Mark**/**Unmark** and **Comment…** (`window.prompt`, prefilled); `tr.marked` gets an accent left edge like `faulted` gets a red one; a comment shows as a `tag-comment` on the path cell (first 24 chars, full text in the title); `rowSig` and the row-filter hay include both; the detail headline shows the comment beneath it.
- [ ] **Step 4: Run, expect PASS.** Docs: AGENT-API commands + summary fields + "`~marked` and `~comment re` are valid scopes"; README row-menu table + a line in the filter cheat sheet.
- [ ] **Step 5: Commit** `feat: mark and comment flows`.

---

### Task 11: `edited` tag on hand-modified flows

**Files:** Modify `addon/interceptor.py` (`_apply_edits`, `repeat`, `summary`), `ui/table.js`, `ui/detail.js`, `ui/style.css`, `spike/check.py`, `AGENT-API.md`, `README.md`.

- [ ] **Step 1: Failing check** `units_edited_tag`: `_resume(id, raw=...)` on a held request → `summary()["edited"] == ["request"]`; a plain `_resume` → `None`; a rejected edit → still `None`; `repeat` (fake `replay.client`) of an edited flow with a new `raw` → the clone's tag is `["request"]` from the repeater edit only, and the original keeps its own.
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement.** At the successful end of each `_apply_edits` branch: `flow.metadata.setdefault("edited", []).append(what)` where `what` is `"request"`, `"response"` or `f"frame #{idx}"`. In `repeat`, `clone.metadata.pop("edited", None)` before applying `raw` — a copy inherits metadata, and "edited" on a replay must mean edited in the repeater. `summary()` gains `"edited"`. UI: `tag-edited` (warn colour) on the method cell with the list in its title; `rowSig`/hay include it; `renderMessage` notes "You edited this by hand before it was forwarded" when the current tab is in the list.
- [ ] **Step 4: Run, expect PASS.** Docs: summary field in AGENT-API; README "Editing a held flow" bullet.
- [ ] **Step 5: Commit** `feat: tag flows edited by hand`.

---

### Task 12: TLS details in the Response tab

**Files:** Modify `addon/interceptor.py` (`tls_info`, `detail`), `ui/detail.js`, `spike/check.py`, `AGENT-API.md`, `README.md`.

- [ ] **Step 1: Failing check** `units_tls_detail`: `tflow.tflow(resp=True)` has `server_conn.tls_version == "TLSv1.2"` and `sni == "address"` → `detail(f, "response")["tls"]` carries them and no `cert`; with `certificate_list = [certs.Cert.from_pem(<spike.selfsigned(tmp) cert.pem>)]` → `cert.cn == "127.0.0.1"`, `"127.0.0.1" in cert.altnames`, `cert.not_after` parses, `cert.sha256` is 64 hex chars; `tls_version = None` → no `tls` key.
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement** `tls_info(flow) -> dict | None` (server side only — that is the side a tester assesses): `version`, `cipher`, `alpn` (decoded), `sni`, and for the leaf certificate `cert: {cn, altnames (≤8), issuer ("CN=…, O=…"), not_before, not_after (ISO), sha256}`. Attach as `detail["tls"]` on responses. UI: a `tls` section with a kv table; `expired` in red when `not_after` is past, and the issuer shown as `issuer`.
- [ ] **Step 4: Run, expect PASS.** Docs: AGENT-API detail fields; README "Reading a body" gains a "TLS" paragraph.
- [ ] **Step 5: Commit** `feat: TLS version, cipher and certificate in the response tab`.

---

### Task 13: HAR import

**Files:** Modify `addon/interceptor.py` (`_session_path`, `_push_sessions`), `spike/check.py`, `README.md`, `AGENT-API.md`.

- [ ] **Step 1: Failing check** `units_har_import`: write a one-entry HAR into a temp dir, point `I.SESSIONS` at it, `FlowReader(...).stream()` yields a flow with path `/api/x`; `_session_path("devtools.har")` resolves; `_session_path("../x.har")` is `None`; restore `I.SESSIONS`.
- [ ] **Step 2: Run, expect FAIL** (`_session_path` rejects the suffix).
- [ ] **Step 3: Implement.** Accept `.har` in `_session_path` and list both suffixes in `_push_sessions` (`FlowReader` already sniffs HAR by its leading `{`). Comment: our own HAR exports land in the same folder, so they appear in the picker and reopen.
- [ ] **Step 4: Run, expect PASS.** Docs: README Sessions ("Open lists `.mitm` and `.har`"), AGENT-API `session.load`.
- [ ] **Step 5: Commit** `feat: open HAR files as sessions`.

---

### Task 14: TLS pass-through list

**Files:** Modify `addon/interceptor.py` (option `passthrough_hosts`, `configure`, `tls_clienthello`, `_passthrough`, `_set_hosts`, `_push_state`), `ui/app.js`, `ui/index.html`, `spike/check.py` (unit + e2e with a TLS target on `IC_TEST_TLS_PORT`, default 18083), `README.md`, `AGENT-API.md`.

- [ ] **Step 1: Failing checks.** Unit `units_passthrough`: `tctx.configure(addon, passthrough_hosts=[r"^pinned\.example:443$"])` → `_passthrough("pinned.example", ("1.2.3.4", 443))` true, `("other.example", ...)` false, `(None, ("pinned.example", 443))` true (no SNI: the address is the only name); a bad regex raises `OptionsError`. E2E: start `start_http(TLS_TARGET, tls=selfsigned(tmp))`; `curl -k -x PROXY https://127.0.0.1:<port>/` → `502` (the proxy opened the connection and refused the self-signed upstream); `hosts.set {hosts: [], passthrough: ["^127\\.0\\.0\\.1:<port>$"]}` and wait for `state.passthrough_hosts`; curl again → `200` and no new flow for that host in the store (`search` for the marker returns nothing new).
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement.**

```python
    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        # Burp's "TLS pass through": the connection is tunnelled, never opened, so
        # a certificate-pinned app keeps working and nothing of it is captured.
        # mitmproxy's own ignore_hosts cannot say this beside a Hosts list -- an
        # on-list host wins there -- so it is decided here, per connection.
        if self._passthrough(data.client_hello.sni, data.context.server.address):
            data.ignore_connection = True
```
`_passthrough(sni, address)` matches each pattern against `sni:port` and `host:port`, case-insensitive. `configure` compiles the option and raises `OptionsError` on a bad pattern. `hosts.set` accepts `passthrough`; `_set_hosts(hosts, passthrough=None)` validates and updates the option; `state` carries `passthrough_hosts`. UI: second textarea in the Hosts panel, "Don't decrypt these hosts", with the explanation (pinned apps, tunnelled, nothing captured, new connections only); Apply sends both lists; the stats strip shows `N not decrypted`.
- [ ] **Step 4: Run, expect PASS.** Docs: README Hosts section + Configuration table; AGENT-API `hosts.set` and `state`.
- [ ] **Step 5: Commit** `feat: TLS pass-through list beside the Hosts list`.

---

### Task 15: Map-local rules and an anticache toggle

**Files:** Modify `addon/interceptor.py` (`_set_rules`, `opt.set`, `_push_state`), `ui/rules.js`, `ui/index.html`, `ui/app.js`, `spike/check.py`, `README.md`, `AGENT-API.md`.

- [ ] **Step 1: Failing checks.** Unit `units_map_local`: `_set_rules([], [], local=[f"|/served|{tmpfile}"])` sets `ctx.options.map_local`; a missing file pushes an `error` and leaves the option unchanged. E2E: a local rule mapping `/served` to a temp file holding `served-by-map-local` → `curl /served` body equals it; `opt.set {anticache: true}` → `curl -H "If-None-Match: abc" /plain` → `body.get` request headers lack `if-none-match`.
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement.** `rules.set` gains `local`; each spec validated with `maplocal.parse_map_local_spec` (the file must exist — say so in the error); `ctx.options.update(map_local=local)`; `state.rules_local`. Comment: the UI can make the proxy serve any readable file to the client under test, which is the same trust the rewrite rules already carry. `opt.set` gains `anticache` → `ctx.options.update(anticache=…)`; `state.anticache`. UI: a third rule block **Serve a local file** (`when URL matches [regex] serve [path]`), composed by the existing `composeRule` with `where: "both", url: ""` so `find`/`repl` become `|regex|path`; `loadRulesFromState`/`applyRules`/`renderRawPreview` handle `ui.localRules`; the rules count in the stats strip includes them. Options group gets a **No cache** toggle.
- [ ] **Step 4: Run, expect PASS.** Docs: README Rules ("Serve a local file"), Options ("No cache"), Configuration table (`map_local`, `anticache`); AGENT-API `rules.set.local`, `opt.set.anticache`, state fields.
- [ ] **Step 5: Commit** `feat: map-local rules and a no-cache toggle`.

---

### Task 16: Intercept scope chips and editor shortcuts

**Files:** Modify `ui/index.html` (chips under the scope field), `ui/app.js` (chip wiring), `ui/detail.js` (keydown on the editor pane, button titles), `spike/check.py`, `README.md`.

- [ ] **Step 1: Failing check** `units_scope_chips`: read every `data-scope='…'` from `index.html` (html-unescaped), each must parse inside `~http & (<chip> )`; the static-assets chip must reject `/a.png?x=1`, `/x.js`, `/f.woff2` and accept `/api/users`, `/x.json`.
- [ ] **Step 2: Run, expect FAIL** (no chips).
- [ ] **Step 3: Implement.** Chips: **skip static assets** → `!~u "\\.(png|jpe?g|gif|svg|ico|css|js|map|woff2?|ttf)(\\?|$)"` (doubled backslashes: the filter's quoted string drops one level), **API only** → `~u /api/`, **POSTs** → `~m POST`. Click sets `#scope` and calls `applyScope()`. Shortcuts on `#detail-body` while a held flow is open: `Ctrl/⌘+Enter` Forward, `Ctrl/⌘+Shift+Enter` Forward + stop reply, `Ctrl/⌘+Shift+D` Drop; the button titles name them (⌘ on Mac, Ctrl elsewhere).
- [ ] **Step 4: Run, expect PASS.** Verify the shortcuts by hand in the browser. README: "Stop flows matching" gets the chips; "Editing a held flow" gets the shortcuts.
- [ ] **Step 5: Commit** `feat: scope chips and editor keyboard shortcuts`.

---

### Task 17: Faults as a mitmproxy option — rules survive restarts

**Files:** Modify `addon/interceptor.py` (`load`, `configure`, `_set_faults`), `spike/check.py` (`units_faults`, `restart_and_load`), `README.md` (Configuration + "Keeping rules across restarts"), `AGENT-API.md` (behaviour 4).

- [ ] **Step 1: Failing checks.** Unit: `tctx.configure(addon, faults=['{"url": "/x", "status": 503}'])` → one rule armed; `['{"url": "/x"}']` and `['nope']` raise `OptionsError`; `_set_faults([{...}])` writes the option back as JSON. E2E in `restart_and_load`: boot the second instance with `--set confdir=<tmp>` whose `config.yaml` holds one `faults` entry and one `modify_headers` entry; the first `state` carries both.
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement.** `loader.add_option("faults", Sequence[str], [], "...one JSON object per entry, the shape the UI sends; lives here so ~/.mitmproxy/config.yaml and --set carry rules across restarts")`. `configure`: on `"faults"`, `json.loads` each, `faultlib.parse_all`, `OptionsError` on failure, else `self.faults = parsed`. `_set_faults`: validate, then `ctx.options.update(faults=[json.dumps(f.to_spec()) for f in parsed])` — `configure` installs them — then log and push state.
- [ ] **Step 4: Run, expect PASS.** README: config table row; new "Keeping rules across restarts" subsection with a `~/.mitmproxy/config.yaml` example carrying `modify_body`, `modify_headers`, `map_local`, `allow_hosts`, `passthrough_hosts`, `faults`, `anticache`, `intercept_responses`, `hide_noise`.
- [ ] **Step 5: Commit** `feat: faults are an option, so config.yaml keeps every rule`.

---

### Task 18: Other clients — document `mitm.it`

**Files:** Modify `README.md` (Run → "Other clients"), `spike/check.py` (integration tail).

- [ ] **Step 1: Check**: after the orphan check, `curl -x PROXY http://mitm.it/` → `200` and the body mentions `mitmproxy` (the onboarding addon is in `default_addons`, so the page is served through this proxy).
- [ ] **Step 2: Run, expect PASS** (it is already true; the check pins the claim).
- [ ] **Step 3: README**: "Other clients: phones, curl, Electron" — point the client at the proxy, open `http://mitm.it` in it for the CA, `--set expose=true` + firewall for a device on the LAN, the loopback-bypass trap for curl/Node.
- [ ] **Step 4: Commit** `docs: how any other client trusts the proxy`.

---

### Wrap-up

- [ ] Update the check counts in README "Tests" and PLAN.md's status line; AGENT-API's "twenty commands" wording → the real count.
- [ ] Run `.venv/bin/python spike/check.py` one last time; all PASS, smoke test not SKIPped on this machine.
- [ ] Run `.venv/bin/python spike/spike.py --chrome --net` if the network allows, to confirm the launcher still works under the CSP.

## Self-review

- Spec coverage: fixes 1–5 ✔, Intruder (6), findings (7), Comparer (8), Decoder (9), annotations (10), edited tag (11), TLS (12), HAR (13), pass-through (14), map-local + anticache (15), chips + shortcuts (16), persistence (17), mitm.it (18) ✔. Not building: active scanner, crawler, plugin system, sitemap tree, virtual scrolling.
- Names used across tasks: `_Collect` (exists in check.py), `summary()` fields `label`/`findings`/`marked`/`comment`/`edited`, `state` fields `findings`/`passthrough_hosts`/`rules_local`/`anticache`, commands `flow.mark`/`flow.comment`/`diff`, options `faults`/`passthrough_hosts`. Consistent.
