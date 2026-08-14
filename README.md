<img width="1667" height="996" alt="ui" src="https://github.com/user-attachments/assets/772a8bf7-8ee2-478a-ad7e-989595bb623a" />

# Interceptor

A local, Burp-style network interception tool for testing. Capture HTTP/1.1, HTTP/2
and WebSocket traffic, pause it mid-flight, edit the request or the response by hand,
then forward or drop it.

mitmproxy engine, browser-based UI, one process, no cloud.

```bash
interceptor          # proxy on :8080, UI opens on :9000
```

---

## What it does

- **Captures everything** the proxy sees — HTTP/1.1, HTTP/2, WebSocket frames — with
  HTTP and WebSocket split into their own tabs, and a **Hosts** list to narrow the
  capture to the app under test when a page's CDNs are drowning it.
- **Pauses** any flow matching a scope filter, and holds it until you decide — with
  **Forward + stop reply** to catch a single response without stopping every flow twice.
- **Full edit** of a held request or response: request line, status line, every header,
  and the body — as raw text, the way Burp does it, with JSON indented for reading and
  a `Raw` toggle back to the exact bytes.
- **Reads any body**: JSON, form-encoded, multipart, XML, protobuf, gRPC, msgpack,
  GraphQL and a dozen more render as structured text instead of a wall of bytes.
- **WebSocket frames** can be edited, dropped, or **injected** in either direction on a
  live connection.
- **Repeater**: resend any captured HTTP request, edited if you like — once, or N times
  with a delay between them — with a tab per request you are iterating on and every send
  listed so you can compare them.
- **Rewrite rules**: automatic body and header rewrites that fire without pausing
  anything — for the changes you want on every request.
- **Fault rules**: make matching requests slow, fail, or die on purpose, then use the app
  and watch how it copes. Nothing stops; affected rows are tagged.
- **Search inside bodies**: find a token, a stack trace or a stray header anywhere in the
  capture, not just in what the table happens to show.
- **Gets things out**: copy any request as a runnable `curl` command, or export the whole
  capture as HAR for devtools and everyone else's tooling.
- **Sessions**: save the current capture to a file and reopen it later. Explicit only.
  The working store is a 0600 temp database, wiped on exit — see Storage.
- **Isolated Chrome** launcher: one click gives a throwaway profile wired to the proxy,
  with TLS interception working and **no CA installed anywhere** on your system.
- Dark and light themes, pink accent.

Because it is a proxy and not a browser extension, it also captures traffic from curl,
mobile devices, and any other client you point at it.

## Requirements

- **Python 3.13.** Not 3.14 — mitmproxy has no wheels for it yet.
- macOS or Linux. Chrome/Chromium for the launcher (optional; any HTTP client works).
- [`uv`](https://docs.astral.sh/uv/) for the venv, or use `python -m venv` and `pip`.

## Install

```bash
uv venv --python 3.13 .venv && uv pip install --python .venv/bin/python -r requirements.txt
```

Optionally put it on your `PATH` — `run.sh` walks its own symlink chain, so this works
from anywhere:

```bash
ln -s "$PWD/run.sh" /usr/local/bin/interceptor
```

## Run

```bash
interceptor
```

The proxy binds `127.0.0.1:8080`, the UI serves on `127.0.0.1:9000` and opens in your
default browser. The URL carries a per-run token in its fragment, and is also written to
`.ui-url` (mode `0600`) in case you launched with output redirected.

Then click **Launch Chrome**. That gives you a temporary-profile Chrome pointed at the
proxy, with `--disable-quic`, `--proxy-bypass-list=<-loopback>` and an SPKI pin for
mitmproxy's CA — so HTTPS is decrypted without installing a certificate into your system
keychain, your login keychain, or any profile's NSS store.

It also runs with **no HTTP cache** (`--disk-cache-size=1`, `--media-cache-size=1`).
That is not a detail: a warm profile serves most of a reload out of Chrome's own cache
without touching the network, so the proxy sees a fraction of the requests. Measured on
a real site, a reload dropped from 149 flows to 30 — and with Intercept armed, almost
nothing stopped, which reads as the tool being broken. This is the "Disable cache" box
every tester ticks in devtools; here it is simply always on. The profile directory is
wiped on a clean exit — it accumulates real session cookies, so if Interceptor is killed
outright (`SIGKILL`, a crash), check your temp directory for a leftover
`interceptor-profile-*`.

To use your own client instead, point it at `http://127.0.0.1:8080` and trust
`~/.mitmproxy/mitmproxy-ca-cert.pem`.

## The UI

The toolbar is grouped and labelled: the mode buttons, then **Stop flows matching**
(Intercept only), **Options**, **Tools**, **Session**. Controls look different according
to what they do —
the mode is a segmented control, on/off options are toggles with a filled dot,
*Launch Chrome* is green like the `live` badge because it is how you start, *Apply* and
*Instructions* are accent, and *Clear* is destructive. Under the toolbar, one line
restates in plain words what the current mode and toggles actually do, so you never have
to hover a control to find out.

**Modes** (top left):

| Mode | Behaviour |
|---|---|
| **Intercept** | Pause every flow matching the scope filter. |
| **Capture** | Log everything, pause nothing. |

A mode answers one question — *does a matching flow stop?* **What gets captured at all
is a separate axis and belongs to the Hosts list.** There used to be a third mode,
Passthrough, which conflated the two: it meant "capture nothing", so it left the table
empty while browsing worked, and it reliably read as the tool being broken. The Hosts
list says the same thing better, and can say the useful in-between as well.

### Hosts — capture only what you are testing

**Hosts** (in *Tools*) is the list of hosts worth looking at. Name them one per line, as
plain hostnames or regexes, and nothing else is captured:

```
app.example.com
api.example.com          # or one line:  .*\.example\.com
```

- Empty (the default) captures every host.
- **It means the same thing for HTTPS, plain HTTP and WebSockets.** Verified with all
  three against one on-list and one off-list host: on-list captured, off-list not, and
  every request still reached its server in both cases.
- A host left out is **not blocked** — it loads normally, it is simply not captured, not
  shown, and never stopped in Intercept. This is not a security boundary.
- Nothing off the list is ever **held**, either. A list that hid a host from the table
  while Intercept still paused its requests would stall the browser against a queue whose
  rows were filtered out — so the list is folded into the pause filter as well.
- To capture **nothing** — what Passthrough used to do — use a pattern that matches no
  host, such as `^$`. Verified equivalent: both leave zero flows captured while the
  request still returns 200.
- An active list is never silent: the toolbar says `2 hosts only` and the line under the
  mode buttons names them, because "why is my traffic missing?" is otherwise a long hunt.

It is also **the main speed control**, which is the other half of why it exists.

### What "capturing" costs

The proxy can only show you an HTTPS request if it breaks the encryption deliberately:
it answers your browser **pretending to be the site**, using a certificate it mints on
the spot, and opens its own TLS connection onward to the real server. Holding both keys
is what lets it print a URL, show a body, or let you edit one. Your browser accepts the
forged certificate only because of the SPKI pin the launcher passes — no CA is installed
anywhere.

Without that, a proxy sees only ciphertext: it knows *that* you reached
`example.com:443` and how many bytes moved, and nothing more. Plain `http://` has no
encryption in the first place, so it is always visible — there is nothing to open.

Terminating TLS costs two handshakes per connection (one with the browser using a forged
cert, one with the real server), and mitmproxy runs single-threaded, so all of it lands on
one core. Measured on loopback: **~170 new HTTPS connections/second with that core
saturated**, ~47ms each, versus ~10ms tunnelled. Bare `mitmdump` with no addon scores the
same (171 vs 158 req/s), so this is mitmproxy's cost, not this project's — the only way to
spend less is to decrypt fewer connections.

A page pulling from twenty hosts spends most of that budget on CDNs, fonts, analytics and
telemetry nobody is testing, and a host left off the list costs none of it.

The two halves apply on slightly different schedules: skipping TLS is decided when a
connection's next layer is chosen, so it takes effect for **new connections**, while the
capture half applies to every flow from the moment you press Apply.

**Stop flows matching** is the field under the mode buttons — mitmproxy's `flowfilter`
syntax. It decides which flows **Intercept** stops; it does not decide what gets captured.
Empty means everything stops.

Three things to know about it:

- **It applies on Enter, or when you click away.** Typing alone changes nothing.
- **It appears only in Intercept mode**, because it can only do anything there. It used
  to sit in the toolbar permanently, dimmed and captioned "applies in Intercept mode",
  which is still a box asking to be typed into for no effect. A filter set earlier is not
  lost when you leave Intercept — the line under the mode buttons names it, and it comes
  back the moment you arm Intercept again.
- **A bad filter is refused, not stored.** The field turns red, a message says why, and the
  filter that was already working stays in force. Note that filter syntax is *not* rules
  syntax: `~u /api/`, never `|~u /api/` — the leading separator belongs to rewrite rules.

The `?` beside the field opens the filter reference.

```
~u /api/ & ~m POST        POST requests with /api/ in the URL
~d api.example.com        one host
~u /checkout | ~u /pay    either path
~websocket                WebSocket flows only
```

Full cheat sheet in the in-app reference (**Rules → Instructions**, or the `?` beside the
field).

**Second toolbar row**: the filter field, then *Options* (*Stop replies*, off by
default — see below; *Hide noise*), *Tools* (*Rules*, *Hosts*, *Launch Chrome*) and *Session*
(*Save*, *Open*, *Clear*). The top right carries a live count of stored flows, bytes,
evictions, hidden noise, active rewrite and fault rules and any active host list, the
bridge connection badge, and the light/dark toggle.

The toolbar deliberately has no button for repeat, export, copy-as-curl or the reply hold.
Anything that acts on **one flow** lives in the row's right-click menu, and anything that
acts on **all matching traffic** lives in the *Rules* panel — so those two grew instead of
this row, which was already four labelled groups wide.

Only one panel is open at a time — *Rules*, *Hosts* and *Open session* replace each
other rather than stacking above the workspace.

**HTTP / WebSocket** tabs sit at the top of the table pane and split the capture by
protocol, the way Burp does. Each carries a count, so "is anything using a socket?" is
answered without switching views, and the WebSocket count turns green while a socket is
still open. A socket is one row that lives for minutes while frames stream under it —
mixed into several hundred request rows it was effectively invisible. Selecting one lands
on **Frames** directly, and its frame count now ticks up live rather than sitting at
`ws (0)` until the connection closes.

A socket is classified from its **handshake**, not from its upgrade. The handshake is
an ordinary GET carrying `Upgrade: websocket`, and `flow.websocket` stays empty until
the 101 lands — so classifying on that alone put the flow under HTTP first and moved it
to WebSocket once forwarded, which reads as one connection appearing twice. Most visible
in Intercept, which holds the flow at exactly that moment.

**Filter rows** sits above the table and is **view-only**: it hides rows that don't
match what you type, and changes nothing about capture, stopping, rewriting, or what a
saved session holds. It searches method, status, host, path and type, and shows
`3 of 6 shown` while active — counted within the current protocol tab. Plain text works,
and so does a regular expression —
`\.(png|jpg)`, `^POST`, `/api/v\d+/` — matched case-insensitively against the whole row;
a half-finished one like `(png` falls back to a substring match instead of blanking the
table. It is **not** the `~q ~u` filter syntax: this is the box to reach for when you
just want to find something in the list, and *Stop flows matching* in the toolbar is a
different thing entirely.

**in bodies** — the toggle beside that box — turns it into a search of the whole stored
capture rather than of the rows on screen. It looks inside every URL, every header and
every body the engine still holds, which is the question the row filter structurally
could not answer: *which response carried this token?* Headers are included deliberately —
"what still sends an `Authorization` header" and "which reply set this cookie" are the
same kind of hunt.

- **Press Enter, or click away, to run it.** It is a scan of the entire store, so it does
  not fire per keystroke.
- Results replace the table and are counted (`3 matches in the store`), including flows
  far older than the 500 rows the table renders. Toggle it off to go back to hiding rows.
- **Streamed bodies are never buffered**, so they are not searchable — the same limit that
  makes them uneditable.
- Text is matched literally, `%` and `_` included. This box is a substring search, not a
  regex; the row filter is the one that takes a regex.

**Flow table** streams in as traffic arrives, batched on a 50ms tick — a single page
load is easily 300–500 flows. Only the newest 500 rows are rendered, with a line under the
table counting the rest, and the tab drops flows past 2000 to keep a long session from
growing without bound. The engine keeps its own, much larger store on disk (see
Storage and `store_bytes`).
Click a row for the detail pane: **Request**, **Response**, **Frames** (WebSocket only)
and **Repeat**.

**The detail pane is resizable.** Drag the divider between the table and the pane, or
focus it and use the arrow keys (`Shift` for bigger steps, `Home` to reset); double-click
resets it too. The width is clamped so neither side can be squeezed out, and it is
remembered across restarts.

**Queue panel** appears whenever something is held. It shows per-host depth, because
browsers open ~6 connections per host — holding 6 requests stalls that entire host, not
just those requests. **Forward all** and **Drop all** are the panic buttons. The list is
height-capped and scrolls, so a deep queue can never push the flow table and the editor
off the screen, and **Hide list** collapses it to just the counts and those two buttons.

### The row menu

**Right-click any row.** Everything that acts on a single flow lives there, which is why
the toolbar has not grown a button for any of it:

| Item | What it does |
|---|---|
| **Repeat this request** | Opens it in the Repeater — a copy, never the original |
| **Copy as curl** | A runnable command, straight to the clipboard |
| **Copy as raw request** | The request as raw text |
| **Copy URL** | Just the URL |
| **Capture only this host** | Replaces the Hosts list with this one host |
| **Export everything as HAR…** | Writes the whole capture to `sessions/<timestamp>.har` |

**Copy as curl** is the handoff: a captured request becomes something a developer can run,
without retyping it. **HAR** is the same handoff for the whole session — devtools, most
performance tooling and most other proxies read it, so a capture outlives this tool.

A HAR is written to a file rather than downloaded, and for the same reason a session dump
is: it is full request and response bodies in plaintext, and the UI's static-file route
carries no token. It lands in `sessions/` at mode `0600`, alongside saved sessions, and
the UI tells you the path. **Treat it like a credentials file.**

### Four ways to change traffic

Easy to conflate, so: they are not interchangeable.

| | What it changes | Scope | Reaches the browser? |
|---|---|---|---|
| **Intercept** + edit | Anything: method, URL, status, headers, body | One flow, by hand | Yes — the client waits for your version |
| **Rewrite rules** | Body text, headers | Every matching flow, automatic | Yes |
| **Fault rules** | Timing, status, the connection itself | Every matching flow, automatic | Yes |
| **Repeat** | A copy of a request | One flow, by hand | No — the reply lands in a new row |

Selecting a finished row shows **Request** and **Response** read-only: those bytes were
delivered already, so there is nothing left to change. **Repeat** is the tab that gives
you an editor, and it says so — *edits apply to the copy, not the original*. Use it to
probe the server (change a field, resend, compare `replay · status 200 → 403`); use
Intercept or a rule to change what the app itself receives.

### Reading a body

Bodies are rendered through mitmproxy's own content views, so what you get is structured
text rather than bytes: JSON, form-encoded, multipart, XML and HTML, protobuf, gRPC,
msgpack, GraphQL, Socket.IO, MQTT, zip listings, images and more. The section header names
the one that was used —

```
body · 412B · shown as protobuf
```

— and stays silent for plain text, where there is nothing to add.

**This is display only, and that distinction matters.** The editor, the Repeater and the
raw view all still hold the exact bytes off the wire. A protobuf rendering cannot be
turned back into bytes, so it is never what gets forwarded, and every guarantee in
*Editing a held flow* below is unaffected by it.

### The Repeater

**Repeat** resends a copy of a captured request. Reach it from the detail tabs or from
the row menu.

- **A tab per request.** Open a second request in the Repeater and a strip appears above
  the editor; switch between them and each keeps its own draft. Closing a tab discards its
  draft, and eight is the cap — beyond that it stops being readable.
- **Every send is listed** under the editor with its status, size and time, so iterating
  is a list you can compare rather than one result the next send overwrites. Click any
  send to open it in Request/Response.
- Edits apply to the copy. The original row keeps its own response, so the comparison you
  are making stays intact.

**Repeating it N times.** The action row reads as a sentence:

```
[Send]  ×  [10]  delay  [250]  ms     [Reset]
```

Leave the count at `1` and it behaves exactly as it always did — one send, nothing else
changes. Above that it repeats.

**Sends never overlap.** Each one waits for its own reply, *then* waits the delay, then the
next goes out. That is what makes it a repeat with a delay rather than a fixed-rate burst:
firing on a timer without waiting lets sends pile up whenever the server is slower than the
delay, which puts the send list out of order and quietly turns "10 requests, 250ms apart"
into load. A delay of `0` therefore means back-to-back, one at a time — not all at once.

- **Send turns into Stop** for the duration. The counter beside it tracks both halves of
  each step — `3 / 10 · waiting for reply`, then `3 / 10 done` — so a slow endpoint looks
  slow rather than looking stuck.
- **Stop takes effect between sends**, not mid-flight: a request already on the wire runs
  to completion. You get `4 of 10 sent — stopped` rather than a silent halt.
- **The run survives switching tabs.** Move to another flow and back and the Stop button
  and counter are still there; it is a real run, not a property of the view.
- **One run at a time.** Two runs interleaving into the same send list would make that
  list unreadable, which is the thing it exists to prevent.
- **A reply that never comes stops the run** after 60 seconds, saying which send stalled,
  rather than hanging on Stop forever.
- **If the bridge drops mid-run it stops and says so**, rather than counting sends that
  never left the browser.
- Count is capped at **1000** and the delay at **60,000ms**, both far above any hand-driven
  use. These are foot-gun guards, not policy: a mistyped `1000` in a field meant for `10`
  is a thousand real requests at a real service.

One caveat that is the browser's and not this tool's: a **backgrounded tab** has its timers
clamped to roughly one second, so a run left in a hidden tab paces itself at about 1s per
step regardless of the delay you set. Keep the tab visible if the interval matters.

### Editing a held flow

The editor gives you the whole message as raw text. Change the method, the path, the
status, any header, the body. It fills the height of the detail pane and scrolls inside
itself, and **Forward** / **Drop** stay pinned to the bottom of the pane whatever the
message length — so a long request never puts them out of reach.

A JSON body is **indented for reading** by default; `Raw` switches to the exact bytes off
the wire and back. Two things worth knowing about that:

- Forwarding a flow you have not typed into sends the **original bytes**, indentation or
  not — so viewing a signed or hashed body cannot break its signature.
- Once you edit anything, what is in the box is what goes on the wire, indentation
  included. Press `Raw` first if the payload's exact bytes matter.

Only the body is ever reformatted; the header block is untouched byte-for-byte, and a
CRLF body (multipart) is left alone entirely. The choice is remembered.

On forward:

- Bodies are `decode()`d first, so a gzipped body is editable as text.
- `Content-Length` is recomputed for you — never edit it by hand.
- A malformed edit is rejected with an error rather than being half-applied.
- Bodies over 5MB are streamed and cannot be edited. The UI labels them. The same
  applies to uploads and to chunked responses, which declare no length — those are cut
  off by size instead.
- Binary bodies (an image, protobuf, `application/octet-stream`) *are* editable, and
  round-trip byte-for-byte if you don't touch them — mitmproxy decodes them as latin-1,
  which maps every byte. What isn't editable is a body whose declared encoding its bytes
  contradict: `application/json` holding binary, an explicit `charset=` that doesn't
  match, or a corrupt `Content-Encoding: gzip`. Those show as not editable.
- A multipart body comes back byte-for-byte when you edit only the headers — its CRLFs
  are what make the boundaries valid. Editing the **body** of a CRLF message does convert
  them to LF: a browser textarea cannot hold a CRLF. The editor warns when that applies.

**Stop replies is off by default.** Left off, only the request stops and the reply
comes back untouched. Turned on, the reply stops as well on its way to the browser, so a
matching flow stops twice — once out, once in. That reads as the tool being broken if you
were not expecting it, which is why it is off, as it is in Burp. The option is
`intercept_responses`.

**To catch one reply, use the button instead of the toggle.** A held request has a third
action, **Forward + stop reply**: the request goes on its way and only *that* reply comes
back to you. The global toggle stays off, nothing else stops twice, and the arm is
one-shot — it is spent on the reply it was set for and does not carry to the next request.
This is the version worth reaching for, because "hold the reply to *this*" is almost
always the actual intent; the toggle exists for when you genuinely want every reply.

It only offers itself on a held request, and deliberately not from the row menu: holding a
reply works by way of the flow already matching the stop filter, so an entry on an
arbitrary row would do nothing on most of them.

### Rewrite rules

For changes you want applied automatically to every matching flow, with nothing stopping.
Each rule is a row of fields that reads as a sentence:

```
in [requests ▾]   URL has [/api/]   find ["amount":100]   replace with ["amount":1]
```

Add rows with **+ Add a body rule** / **+ Add a header rule**, press **Apply**. Empty
*URL has* means every URL; an empty *replace with* deletes the matched text, or removes
the header for a header rule.

Under the hood mitmproxy takes one packed string per rule
(`|filter|find|replace`), and choosing a separator that also occurs in your pattern is
the classic way to break one. **The form generates that string and picks a safe
separator**, so you never type it — press **Show generated syntax** to see what it built.

Anything the form cannot express — a status code, a content type, a header condition —
appears as an **advanced** row holding the raw string, editable as text. Nothing you
write by hand is ever rewritten into a form.

**What rules cannot do.** They are mitmproxy's `modify_body` and `modify_headers`, so
they reach the body text and the headers — nothing else. No changing the method, the URL
or the response status, and no dropping a flow; that needs Intercept. The replacement is
also literal: `\1` and `$1` backreferences do not expand, because `modify_body` passes a
constant to `re.sub`. Match with a regex as wide as you like, but write the result out
verbatim.

Press **Instructions** in the Rules panel for the full reference in a modal: what each
field means, a table of every filter symbol, **a table of every regex symbol with a worked
example**, header-rule semantics, ten worked examples given as field values, the escape
traps (`\b` is a backspace here, `\1` backreferences don't work), and a "my rule did not
fire" checklist.
The same content is a standalone page at [ui/rules.html](ui/rules.html) — both render
[ui/rules-doc.js](ui/rules-doc.js), so they cannot disagree.

### Fault rules — break things on purpose

The third block in the **Rules** panel. Make matching requests slow, fail, or die, then
use the app normally and watch how it copes.

```
when URL has [/api/checkout]   delay [5000] ms   reply [503]   ○ drop connection
```

Add rows with **+ Add a fault rule**, press **Apply** — the same Apply as the rewrite
rules above, since they are the same kind of thing: change matching traffic automatically,
stop nothing.

**What it is for.** *Does the app show an error or spin forever when checkout fails? Does
it time out cleanly, or does the user press the button five more times and create five
orders? Does token refresh actually fire on a 401? Does the retry logic exist?* Every one
of those is an ordinary test case, and none of them could be produced on demand before.

**Why the other two paths could not do it.** Intercept *can* type a 500 into a held
reply, but it catches one flow at a time by hand, and cannot produce a timeout at all —
you would be the stopwatch while the held flow stalls that host's other connections. And
it is not repeatable: "I did it with my mouse last sprint" is not a test you can run
again. Rewrite rules run automatically, which is the right shape, but
`modify_body`/`modify_headers` only substitute text inside a body or a header — no status
code, no delay, no dropped connection. One path is unrepeatable, the other structurally
cannot express failure.

**A faulted flow is never quiet.** It carries a red `fault` tag and a red edge in the
table, the detail pane says *"Interceptor produced this on purpose"* and names the rule,
the toolbar counts active rules, and the line under the mode buttons spells out that
traffic is being broken. An injected 503 is indistinguishable from a real one, and an
unlabelled one is a morning lost to debugging your own rule — so this is the part of the
feature that is not optional.

Rules worth knowing:

- **First match wins**, top to bottom. Two rules never compound into a delay nobody
  predicted.
- **A request you stopped by hand is skipped.** With it held in front of you, you are
  already the fault injector — and a hook returns before the flow reaches the queue, so a
  delay would land *before* the row appeared rather than after.
- **Replays are skipped.** Repeating a request to compare it against the original is not
  the moment to have it broken underneath you.
- **A rule that would do nothing is refused**, as is one asking to both drop the
  connection and send a reply. One bad row rejects the whole list rather than arming part
  of it, so what you see applied is what is applied.
- **Delay is capped at two minutes**, which is past every client timeout worth testing,
  and holds a real connection open for its duration.
- **A delay suspends only its own flow.** Measured: three 250ms faults running together
  take 252ms, not 750ms. It never blocks the proxy.
- **Browsers open ~6 connections per host**, so a long delay on a busy path stalls that
  whole host, not only the requests you targeted — the same arithmetic as the hold queue.

`drop connection` kills the connection instead of answering, so the client sees a network
error rather than an HTTP status. A synthesized reply is JSON with an
`x-interceptor-fault: 1` header, so an automated client can tell too.

Deliberately not built: truncated bodies and probabilistic firing. Both are real, neither
has been asked for, and each costs a column in a row that currently reads as a sentence.

### Sessions

**Save session** writes every flow the engine still has stored — which can be more than
the rows on screen — to `sessions/<timestamp>.mitm`. **Open session** lists that folder and
loads one back, replacing what is on screen.

No session is ever written for you. The `sessions/` folder isn't created until your first
save, and closing Interceptor mid-session discards the capture — a fresh instance always
starts empty. This is deliberate: a `.mitm` file is every captured request in plaintext,
cookies and bearer tokens included, so keeping one has to be a decision rather than a
default.

Files are created `0600` and the folder `0700` — from the first byte, not after the
write finishes. Both `sessions/` and `*.mitm` are gitignored. **Treat a
saved session like a credentials file.**

**HAR export** (row menu → *Export everything as HAR…*) writes to the same folder with the
same permissions, and carries the same warning. The difference is who reads it: a `.mitm`
file is for reopening here, a `.har` is for handing to devtools, a colleague, or another
tool entirely.

### Storage

The working capture lives in a SQLite file, not in memory: completed flows are serialised
to disk and only an index — ids, sizes, arrival order, roughly a hundred bytes a flow —
stays in RAM. Measured over 23,000 flows and 200MB of traffic, resident memory grew 12MB,
about **0.5KB per flow**, against the ~8KB per flow it used to cost to keep every body
resident. That is what stops a morning of testing being evicted to make room for the
current page.

**This file is decrypted traffic, so it is treated like one.** It is created `0600` in
your temp directory (`interceptor-store-*/flows.db`), and it is deleted when Interceptor
shuts down — so an ordinary quit leaves nothing behind, and only a `SIGKILL` or a crash
can leave it, in the same way the Chrome profile can. It is never in the project
directory, and `sessions/` remains the only place anything is kept on purpose.

Some flows cannot go to disk while they are in use, and are held in memory by reference
instead: anything still in flight, anything **held** in the queue, and any **open
WebSocket**. That is not an optimisation — `resume()` and frame injection act on the
exact object the proxy is awaiting, so handing back a copy rehydrated from the database
would look correct, release nothing, and strand the client.

One consequence worth knowing: a **reconnecting UI is sent the newest 2000 summaries**,
not the whole store. Memory no longer bounds the capture, so without that cap a reload
would try to push an entire session down one WebSocket message — and the browser discards
everything past its own 2000-row limit anyway. Older flows are still on disk and still go
into a saved session; they simply aren't re-listed in the table after a reload.

The cost is about **15% of peak store throughput** (1330 → 1132 flows/second on the same
loopback workload), because each finalised flow is serialised and written once. That
ceiling sits roughly 6× above the ~170 new HTTPS connections/second that TLS termination
itself allows, so it is not the binding constraint on anything you will actually do.

**Serialisation happens on the flush tick, not in the hook.** `get_state()` deep-copies a
whole flow, bodies included, and extracting its searchable text decodes both bodies again
— doing either per flow inside the `response` hook would put that work on the same event
loop that is terminating TLS. `_pending` therefore holds the flow itself and the row is
built once per 100ms batch instead. A worker thread would buy little on top of that and
would trade a measured non-problem for concurrent access to flow objects.

Each stored flow also keeps up to **256KB of searchable text** — its URL, headers and both
bodies — which is what **in bodies** searches. That duplicates part of what the serialised
blob already holds, and it is a deliberate disk-for-answers trade: the store held every
body from the start and nothing could query them. The search is a `LIKE` scan with no
index, because `LIKE '%x%'` cannot use one and a tokenising index would break the
substring matches that make it useful for hunting a token. At a few thousand rows that
scan is milliseconds.

Loaded flows can be edited and re-sent through the Repeater, so yesterday's request can
be replayed today.

### WebSockets

Sockets live under the **WebSocket** tab of the flow table, separate from HTTP. Select one
and its frames appear under the **Frames** tab; they can be edited or dropped individually
while held, and a held JSON frame is indented like any other body.

Ordering is safe: while one frame is held, mitmproxy processes no further data for
that connection, in either direction — so a held frame cannot be overtaken by a later one.
This is guaranteed by the proxy's own structure, not by anything in this addon.

You can also **inject** a frame in either direction on a live connection. Note that an
injected frame is itself subject to interception, so with intercept armed it lands in the
queue like any other frame.

Repeat is hidden for WebSocket flows — mitmproxy's client replay refuses them.

## Configuration

`run.sh` already passes six options, so those are changed by **environment variable** —
passing `--set` for one of them again is a hard error (`Received multiple values for
listen_port`), not a silent override. Five have env vars; the sixth is `flow_detail=0`,
which silences mitmdump's own per-flow console output and has no override:

| Variable | Default | Meaning |
|---|---|---|
| `IC_LISTEN_HOST` / `IC_LISTEN_PORT` | `127.0.0.1` / `8080` | Proxy bind. Loopback only — see Security. |
| `IC_UI_PORT` | `9000` | UI port (static files and WebSocket share it). |
| `IC_URL_FILE` | `.ui-url` | Where the UI URL + token is written. |
| `IC_OPEN_UI` | `true` | Open the browser at startup. |

```bash
IC_LISTEN_PORT=8888 interceptor
```

Everything else is a `--set` flag after `interceptor`:

| Option | Default | Meaning |
|---|---|---|
| `ui_host` | `127.0.0.1` | UI bind host. |
| `store_bytes` | `2GB` | Flow store cap **in bytes of captured traffic**. Bodies dominate, so the cap is bytes, not flow count; oldest flows are evicted and the count is shown in the UI. This caps the **store file**, not memory — see Storage. The file runs about half again larger than the cap (serialisation, index and WAL). |
| `hide_noise` | `true` | Hide browser background chatter (Google telemetry, safebrowsing, gstatic). Counted and reported, never silently dropped. |
| `allow_hosts` | *(empty)* | The **Hosts** list, presettable from the command line: capture only these. Empty captures everything. |
| `ignore_hosts` | *(empty)* | The inverse, and the one thing the Hosts list cannot express: tunnel *these* hosts and capture everything else — mitmproxy's equivalent of Burp's TLS pass through, for a certificate-pinned host that breaks under interception. Command line only; nothing in the UI writes it, so a value set here survives every mode switch. |
| `intercept_responses` | `false` | Also stop replies. Same as the *Stop replies* toggle. |
| `expose` | `false` | Permit binding off loopback. Without it, that is refused outright — see Security. |
| `ssl_insecure` | `false` | Accept self-signed/expired certs on upstream targets. Commented out in `run.sh`. |

### Behind a proxy or VPN client

If your machine reaches the internet through a proxy client — Clash, Surge, a corporate
proxy — Interceptor must be chained through it, or it dials out directly and anything
behind the proxy fails with a bare 502 (see Troubleshooting). Opt in with one flag:

```bash
interceptor --chain
```

It reads the proxy configured *right now* and adopts it as upstream, saying which way it
went:

```
interceptor: chaining upstream to http://127.0.0.1:7897 (--chain)
```

Detection is `scutil --proxy` on macOS first, then `HTTPS_PROXY`/`HTTP_PROXY`. `scutil`
comes first because a shell you opened *before* toggling the client still carries the old
environment variable, so the environment is the less trustworthy of the two.

Chaining is a flag, never automatic: `scutil` is macOS-only, Linux and WSL expose only the
environment variables, and a VPN that installs a route or TUN interface rather than a proxy
setting is invisible to both. Passing the flag always means the same thing on every
platform.

`--chain` refuses in two cases rather than doing something useless, and says why:

| Situation | What happens |
|---|---|
| The configured proxy *is* this proxy | Refuses — it would be its own upstream, forever |
| A loopback proxy is configured but not answering | Warns the client looks switched off, connects directly |
| Nothing detected | Says so, and points at `--mode upstream:…` for a proxy it cannot see |

Chaining changes nothing about capture: traffic is still decrypted and editable on the way
past, and the toolbar shows `127.0.0.1:8080 → 127.0.0.1:7897` so the route is never a
guess. When a proxy is configured and you did *not* chain, a warning strip appears under
the toolbar — the 502 explains itself.

To pin a specific upstream by hand — a VPS, useful when staging allowlists a fixed IP:

```bash
interceptor --mode upstream:http://your-vps:8080
```

The engine always stays local — only egress moves. Interception, storage and the CA private
key never leave your machine.

## Security

The UI bridge carries every captured request, cookie and bearer token, and accepts
commands that rewrite traffic. It is protected by two independent gates:

1. **`Origin` check.** Any web page you visit can open `ws://127.0.0.1:9000` — browsers
   do not apply CORS to WebSocket connections. Connections whose `Origin` isn't ours are
   rejected.
2. **A random per-run token**, compared with `hmac.compare_digest`. It travels in the URL
   **fragment** (`#token=…`), which is never sent in `Referer` headers and never written
   to server logs.

Also:

- **Binding off loopback is refused.** The proxy port has no authentication at all, so
  a non-loopback bind publishes an open MITM proxy. `IC_LISTEN_HOST=0.0.0.0 interceptor`
  exits `2` without starting anything, and so does `--set listen_host=`,
  `--set ui_host=`, mitmproxy's own `--listen-host`, and a bind address hidden inside a
  mode spec — `--mode regular@0.0.0.0:8080`, `--mode=…`, `--set mode=…` and the `-m`
  alias, all of which would otherwise be public while `listen_host` still read
  `127.0.0.1`. Anything not provably loopback counts as
  public, including the empty host that mitmproxy itself defaults to.

  To do it anyway — a phone on your LAN, say — add `--set expose=true` and firewall the
  port. The run then logs a loud `EXPOSED:` line. Note that the UI's `Origin` check is
  built from its bind address, so reaching the UI over a LAN IP is rejected even with a
  valid token; only the proxy port is usable that way.

  The check lives in `run.sh`, before it launches anything, because mitmproxy brings the
  proxy listener up *before* any script addon loads — so no amount of addon code can
  stop a public bind. The addon carries the same check for `mitmdump -s` used directly.
- The CA private key lives in `~/.mitmproxy/` at mode `0600` and never leaves the machine.
- `.ui-url` is a credential. It's gitignored and deleted on shutdown.
- The proxy port itself (`8080`) has no authentication — it relies on being bound to
  loopback.
- Saved `.mitm` files are decrypted traffic. See Sessions above.
- **The working store is decrypted traffic too.** It is a SQLite file created `0600` in
  your temp directory and deleted on shutdown, so an ordinary quit leaves nothing behind
  — but a `SIGKILL` or a crash can leave an `interceptor-store-*` directory, exactly as
  it can leave an `interceptor-profile-*`. Check for both if the process died hard. See
  Storage.
- The **Hosts** list is not a security boundary. A host left off it is not blocked or
  isolated in any way; it simply isn't captured.

## Tests

```bash
.venv/bin/python spike/spike.py --chrome --net    # browser + network reality   4/4
.venv/bin/python spike/check.py                   # units + end-to-end        69/69
```

Both are safe to run while a real instance is up — separate ports (`18xxx`/`19000`), their
own URL file, and neither kills stray processes. `check.py` deletes the session it saves,
so it leaves your `sessions/` folder as it found it.

They test different things, which is why they are separate commands. `check.py` runs
offline against a loopback target and proves this project's own logic. `spike.py` needs a
real browser and real internet, and proves the four assumptions underneath it that no
amount of local testing can: an HTTP flow can be held and resumed out-of-band, WebSocket
frame order survives a held frame, Chrome decrypts HTTPS through an SPKI pin with **no CA
installed anywhere**, and an HTTP/2 request body round-trips edited. Those are the things a
mitmproxy or Chrome upgrade breaks silently. It also holds the shared test harness
(`start_http`, `ws_echo`) that `check.py` imports.

**Covered:** both bridge auth gates, static serving and path-traversal refusal, capture,
pause → forward / drop, request and response editing, `Content-Length` recompute,
multipart bodies surviving the editor byte-for-byte, malformed-edit rejection,
force-forward on UI disconnect, the flow store's SQLite round trip and its refusal to
hand back a copy of a live flow, byte accounting and eviction (WebSocket frames
included, each counted exactly once so a long-lived socket stays O(1) per frame rather
than O(n²)), the streaming cutoff, WebSocket frame editing, truncation refusal and
injection, a socket being classified from its handshake rather than its upgrade (and an
`h2c` upgrade not being dragged in with it), body and header rewrite rules, the host list
(validation, and that it covers HTTP, HTTPS and WebSocket alike and reaches the pause
filter), the repeater, session save/open including a
full-restart round trip, file modes at creation time under a permissive umask, and the
loopback guard — every entry path including `--mode` specs, without ever opening a public
socket to prove it.

Also: **fault rules** (malformed rules refused, one bad row rejecting the whole list, a
synthesized reply answering the request while a non-matching URL is left untouched, first
match winning, and a timing assertion that three concurrent 250ms delays finish in ~250ms
rather than ~750ms — i.e. that the delay is awaited rather than blocking the loop);
**body search** across bodies, headers and URLs, including a literal `%` not matching
everything; **content views** producing a rendering *beside* the exact bytes with `body`
and `raw` untouched; **copy as curl** producing a command carrying method, URL, header and
body; and the **one-shot reply hold** arming, holding exactly one reply, and disarming.

Four units also run shipped frontend functions under `node`: the rule form's compose/parse
pair from `ui/rules.js` (every spec it generates is fed to mitmproxy's real
`parse_modify_spec`), the row filter from `ui/table.js` (text, regex, case-insensitivity,
invalid-regex fallback), the editor's pretty-printer from `ui/util.js` and `ui/detail.js`
(headers byte-identical, non-JSON and CRLF bodies untouched, and a blank line inside a
body never mistaken for the header separator), and the repeater's burst clamp from
`ui/detail.js` (negatives, blanks, junk and absurd numbers all landing somewhere sane, and
a count that can never clamp to zero — a Send that sends nothing reads as broken).

**Not covered:** anything needing a DOM — `index.html`, `style.css` and every rendering
path across the `ui/` modules; `node --check` is syntax-only. Also the `error`-hook queue
cleanup, the noise counter, `launch_chrome`'s flags, and concurrent held flows.

Neither suite talks to the internet through a real browser, and that gap has cost real
bugs: a WebSocket handshake showing under HTTP until it upgraded, and Chrome's own cache
hiding four requests in five on a reload. Both were invisible to loopback echo servers
and only appeared when driving the launcher's Chrome against a live site. Check that by
hand after changing anything about modes, classification or the launcher.

## Layout

```
addon/
  interceptor.py   # hooks, mode switch, host list, pause queue, sessions, launcher
  store.py         # flows in SQLite; live and held ones held in RAM by identity
  bridge.py        # WebSocket + static files on one port, token + Origin gates
  faults.py        # delay / fail / drop rules, and why neither other path can do it
  views.py         # body rendering via mitmproxy's content views — display only
  exporters.py     # curl / httpie / raw and HAR, plus their file permissions
ui/
  index.html
  app.js           # toolbar, panels, splitter, wiring, the top-level render
  bus.js           # "draw again" — what keeps the modules below acyclic
  state.js         # every piece of mutable UI state, in one place
  transport.js     # the bridge socket and message handling
  table.js         # flow table, row filter, body search
  detail.js        # detail pane, held-flow editor, frames, repeater
  rules.js         # rewrite-rule and fault-rule forms
  menu.js          # the row context menu
  util.js          # DOM and formatting helpers
  style.css        # every colour a CSS custom property, defined for both themes
  theme.js         # light/dark, shared by app and docs
  rules-doc.js     # rule reference — one source for the modal and the page
  rules.html       # renders rules-doc.js standalone
  icon.png         # app icon and favicon
sessions/          # created on first save or HAR export; gitignored, dir 0700, files 0600
spike/
  spike.py         # browser/network assumptions + the shared test harness
  check.py         # units + end-to-end
run.sh             # entry point, symlink-safe
```

Interception itself is mitmproxy's built-in `Intercept` addon — this project sets
`ctx.options.intercept` and owns the half that's actually ours: what to store, what to
show, and how to resume with edits. Note that `mitmdump` doesn't load `Intercept` on its
own, so it's registered explicitly.

## Troubleshooting

**A request never appears.** In order of likelihood:

1. **QUIC.** Chrome bypasses HTTP proxies over QUIC entirely. The launcher passes
   `--disable-quic`; if you're using your own browser, disable it there.
2. **Loopback bypass.** Every HTTP client silently bypasses proxies for `localhost`.
   Chrome needs `--proxy-bypass-list=<-loopback>`, curl ≥7.86 needs `--noproxy ""`, Node
   reads `NO_PROXY`. Nothing errors — the request just isn't there.
3. **Hide noise** is on and the host is on the noise list. The count is in the toolbar.

**502 Bad Gateway — "connection closed".** The proxy reached the site's IP but the server
dropped the TLS handshake. Almost always this means your machine only reaches the internet
through a local proxy or VPN client, and Interceptor dialled out directly instead. Check for
one:

```bash
env | grep -i proxy
```

Relaunch it chained through that proxy — capture is unaffected:

```bash
interceptor --chain
```

If detection finds nothing (a route-based VPN, or a platform without `scutil`), name the
upstream yourself:

```bash
interceptor --mode upstream:http://127.0.0.1:7897
```

When Interceptor sees a proxy it is *not* chained to, it says so in two places: a line at
startup, and a warning strip under the toolbar in the UI — which is where you are when you
press *Launch Chrome* and hit the 502. It never adopts that proxy on its own: silently rerouting a QA session is
worse than a clear error. The proxy log names the real cause — look for
`Server TLS handshake failed` next to the host.

**Every flow stops twice.** *Stop replies* is on. Turn it off, and use **Forward + stop
reply** on a held request when you want one particular reply.

**A request failed, or was slow, and the server is fine.** Check for a fault rule you left
armed: the toolbar shows `1 fault active`, the line under the mode buttons says traffic is
being broken on purpose, and the row carries a red `fault` tag. Open **Rules** and remove
it. This is exactly the confusion the tagging exists to prevent, so if a failure is *not*
tagged, it is real.

**A body shows as `shown as raw`, or not structured at all.** Nothing recognised it, which
is normal for plain text and for formats without a view. It changes nothing about editing:
the exact bytes are always what the editor and the Repeater hold.

**A body won't edit.** It's over 5MB and streamed, or its bytes contradict the encoding it
declares (`application/json` holding binary, a wrong `charset=`, corrupt gzip). Binary
bodies themselves *are* editable. The detail pane says which case applies. A WebSocket frame over 5MB is refused the same way. Separately, the frame
*log* shortens any preview past 4KB and tags it `preview` — that tag is about the view, not
about editability.

**Durations look too long.** A held flow's `ms` spans request start to response end, so
your editing time is inside the number.

**Chrome won't quit.** Its `clients2.google.com` time-service request keeps it alive
through a proxy. Known; kill it.

**HTTP/3 is not intercepted.** QUIC is disabled in the launched browser rather than
decrypted; a client that insists on HTTP/3 will bypass the proxy.
