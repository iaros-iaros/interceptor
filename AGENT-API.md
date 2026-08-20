# Driving Interceptor from an agent

Everything the UI can do, an agent can do. There is no privileged path: the browser
UI is a WebSocket client like any other, and the twenty commands below are the whole
surface. This document is that surface, written for a program rather than a person.

Every command and payload here was exercised against a running instance — see
[Verifying](#verifying) at the end.

---

## Start it headless

```bash
IC_OPEN_UI=false interceptor
```

Proxy on `127.0.0.1:8080`, control server on `127.0.0.1:9000`, no browser. To run
alongside an instance a human is using, move all three ports:

```bash
IC_OPEN_UI=false IC_LISTEN_PORT=8899 IC_UI_PORT=9099 IC_URL_FILE=.ui-url-agent interceptor
```

Point the client under test at `http://127.0.0.1:8080` and trust
`~/.mitmproxy/mitmproxy-ca-cert.pem`. Two client-side traps that are not this tool's
doing: HTTP/3 bypasses a proxy entirely (disable QUIC), and every HTTP client silently
bypasses proxies for `localhost` (curl needs `--noproxy ""`).

## Connect

The URL and its token are written to `.ui-url` (mode `0600`) in the project directory:

```
http://127.0.0.1:9000/#token=gvcZjKCm35EOlXEApY0ej0jKy3B1n_mU
```

Split on `/#token=`, and connect to `ws://<host:port>/ws?token=<token>`.

**You must send an `Origin` header equal to the UI's own origin.** This is not
optional and it is the single most common reason an agent client fails to start:

| `Origin` sent | Result |
|---|---|
| *(none)* | `403` |
| `http://127.0.0.1:9000` | connected |
| anything else | `403` |

```python
import json, websockets

url = open(".ui-url").read().strip()
origin, _, token = url.partition("/#token=")
ws = await websockets.connect(
    origin.replace("http://", "ws://") + f"/ws?token={token}",
    additional_headers={"Origin": origin},
    max_size=20 * 1024 * 1024,          # see Size limits
)
await ws.send(json.dumps({"type": "hello"}))
```

Both gates exist because any page the user visits can open a WebSocket to loopback —
WebSockets are not subject to CORS — and this socket carries decrypted traffic with
cookies and bearer tokens in it. Treat the token as a credential: it is one.

---

## Five things that will bite you

Read these before writing a client. Each one has cost someone an hour.

### 1. Messages arrive batched, as JSON arrays

Every frame is a JSON **array** of messages, flushed on a 50 ms tick. One `recv()` can
carry the reply to your command plus twenty unrelated flow events. A client that reads
one message per `recv()` silently drops the rest.

Buffer the batch, then scan the buffer:

```python
class Client:
    def __init__(self, ws): self.ws, self.pending = ws, []

    async def send(self, **msg):
        # `state` is also pushed on a timer -- see #2
        self.pending = [m for m in self.pending if m["type"] != "state"]
        await self.ws.send(json.dumps(msg))

    async def until(self, kind, timeout=15):
        while True:
            for i, m in enumerate(self.pending):
                if m["type"] == kind:
                    del self.pending[i]
                    return m
            self.pending += json.loads(await asyncio.wait_for(self.ws.recv(), timeout))
```

### 2. There are no correlation IDs, and `state` is also pushed on a timer

Nothing echoes back a request id. You match replies by `type`, and for flow-specific
replies by the `id` field inside them.

`state` is the trap: it is pushed after most commands **and** once a second whenever
traffic is flowing. "The next `state` I see" is not "the reply to my command" — it may
be a stale one that was already in flight. Discarding buffered `state` messages before
sending, as the snippet above does, narrows that window but does not close it: a timer
push can still land between your send and the server handling it.

So **confirm by content, not by arrival order**. After `mode.set`, keep reading until a
`state` actually carries the scope you asked for:

```python
await c.send(type="mode.set", mode="intercept", scope="~websocket")
while (st := await c.until("state"))["scope"] != "~websocket":
    pass
```

The same goes for `rules_body`, `faults` and `allow_hosts` — check the field, not the
message. An `error` arriving instead means the command was rejected and nothing changed.

### 3. Disconnecting force-forwards every held flow

When the last client drops, every paused flow is released unedited and counted as
auto-forwarded. This is a deliberate safety valve — a closed browser tab must never
wedge traffic forever — but it means **an agent must hold one socket open for the whole
session**. A connect / command / disconnect pattern loses every pause, and while nothing
is connected, Intercept holds nothing at all: flows sail through and are counted in
`auto_forwarded`.

### 4. Server-side settings outlive your connection

`rules.set`, `faults.set`, `hosts.set`, `mode.set` and `opt.set` live on the server.
They survive your disconnect and apply to whatever connects next — including the human's
browser. An agent that sets a 503 fault and crashes leaves that fault armed.

Reset what you set, in a `finally`:

```python
await c.send(type="faults.set", faults=[])
await c.send(type="rules.set", body=[], headers=[])
await c.send(type="hosts.set", hosts=[])
await c.send(type="mode.set", mode="capture", scope="")
```

### 5. A rejected edit keeps the flow held

If `resume` carries a `raw` that will not parse, you get an `error` and **the flow stays
paused** — deliberately, so a typo never loses a hand-crafted payload. Your client must
handle that: fix and resend, or resume without `raw`. Ignoring the error leaves the
client under test hanging.

```
error  {"message": "edit rejected: line 2 is not a header: 'nope'", "id": "..."}
```

---

## Commands

Every message is `{"type": ..., ...}`. Unknown types are logged and ignored — they do
not close the connection.

### Session

| Command | Payload | Effect |
|---|---|---|
| `hello` | — | Server replies `snapshot` + `state`. Send it first, and again any time you want a fresh snapshot. |
| `clear` | — | Wipe the store. Replies `cleared` + `state`. Also resets the noise and auto-forward counters. |

### Mode and scope

| Command | Payload | Effect |
|---|---|---|
| `mode.set` | `mode`: `"capture"` \| `"intercept"`, `scope`: filter string | `capture` records only. `intercept` also *pauses* flows matching `scope`. |

`scope` is a [mitmproxy flow filter](https://docs.mitmproxy.org/stable/concepts-filters/):
`~u /api/`, `~d example.com & ~m POST`, `~m POST & ~u /checkout`. An empty scope in
intercept mode stops everything. Argument-less filters work too — `~websocket` for every
frame, `~q` for every request, `~s` for every response.

A bad filter is rejected with an `error` and the previous scope is kept — the mode never
changes to something you did not ask for. Note that a rejection pushes **no `state`**, so
a client that blocks waiting for one will sit until its timeout: treat `error` as a
possible reply to `mode.set`, not just as background noise.

### Intercept: holding, editing, forwarding

When a flow is held you receive `flow.paused`. Release it with `resume`:

| Field | Type | Meaning |
|---|---|---|
| `id` | string | The flow id, from `flow.paused`. Required. |
| `raw` | string | Edited message text. Omit to forward unchanged. |
| `drop` | bool | Kill the flow instead of forwarding. Ignores `raw`. |
| `stop_reply` | bool | Request only: also hold *this flow's* response when it comes back. Self-disarming. |
| `seq` | int | WebSocket only: which frame. Take it from `frame.seq`. |

`resume.all` releases everything held; add `drop: true` to kill instead.

`stop_reply` is how you catch one response without stopping every flow twice. The
alternative — `opt.set` with `intercept_responses: true` — holds *every* matching
response, which doubles your loop's work.

### The `raw` edit format

`detail.raw` is the whole message as one editable blob, Burp-style, and what you send
back in `resume`/`replay` must be the same shape:

```
POST /pay HTTP/1.1
Host: api.example.com
Content-Type: application/json

{"amount":100}
```

Start line, headers, **one blank line**, body. Responses use `HTTP/1.1 200 OK` as the
start line. Rules:

- The **body is written back exactly as you send it**, byte for byte. Only the header
  block is newline-normalised, so a multipart body's CRLFs survive.
- The separator is whichever of `\r\n\r\n` or `\n\n` comes first.
- `Content-Encoding` is stripped from `raw` on the way out, because the body you are
  shown is already decoded. Do not add it back.
- `Content-Length` is recomputed from the body you send. **Do not hand-edit it** — the
  header block is applied before the body, so your value is overwritten anyway, and
  editing it is how you desync it.
- **An absolute URL in the request line retargets the flow.** `POST /pay HTTP/1.1` edits
  the path; `POST https://other.example.com/pay HTTP/1.1` sends the request to a
  different host and port entirely. Useful, and easy to do by accident.
- A line that is not `name: value` is a hard error, and the flow stays held.
- `detail.raw` is `null` when the message is not safely round-trippable: streamed, over
  5 MB, or bytes that contradict a declared text encoding. Check for `null` — do not
  send an edit you did not receive a `raw` for.

`detail.body_crlf` tells you the body contains CRLFs. Editing headers is always safe;
rewriting such a body by hand risks corrupting it.

One heuristic to know about, because it silently discards an edit: if the body you send
back differs from the one you were served **only** by CRLF→LF, the original bytes are
restored. It exists because an HTML textarea rewrites CRLF to LF on its own and would
otherwise destroy every multipart upload. It means an agent that normalises line endings
wholesale will find those edits reverted — send the body byte-exact, or change something
other than the line endings.

### Reading traffic

| Command | Payload | Reply |
|---|---|---|
| `body.get` | `id`, `which`: `"request"` \| `"response"` | `body` with a `detail` object |
| `frames.get` | `id` | `frames` — the full WebSocket frame history |
| `search` | `q` | `results` — flows whose URL, headers or bodies contain `q` |
| `export` | `id`, `format`: `curl` \| `httpie` \| `raw_request` \| `raw` | `export` with `text` |

`snapshot` and `flow` pushes carry **summaries only**. Bodies never arrive unasked —
call `body.get` for the flow you care about. Held flows are the exception: `flow.paused`
already includes `detail`, so no round trip is needed to edit one.

`search` is a substring scan over URL, headers and both bodies, capped at 2000 results.
It is the only way to ask "which response carried this token".

### Rewrite rules — no pausing

Automatic rewrites, applied without holding anything. This is usually what an agent
wants: set rules, drive the app, read the results.

```json
{"type": "rules.set",
 "body":    ["/~u /api/pay/amount/AMT"],
 "headers": ["/~u /api/x-agent/1"]}
```

Spec syntax is `<sep><flow-filter><sep><pattern><sep><replacement>`, where `<sep>` is
any character absent from the pattern (`/` above). Body patterns are **regexes**; header
patterns are **literal header names**. Both lists are replaced wholesale — send both
every time, and send `[]` to clear. An invalid spec is rejected with an `error` and
*none* of the rules are applied.

Rules cannot touch a streamed body, because a streamed body is never buffered.

### Fault injection — no pausing

Make matching requests slow, fail, or die.

```json
{"type": "faults.set",
 "faults": [{"url": "/checkout", "delay_ms": 5000, "status": 503, "body": "nope"},
            {"url": "/api/", "drop": true}]}
```

| Field | Type | Notes |
|---|---|---|
| `url` | string | A `~u` regex. Empty matches everything. |
| `delay_ms` | int | 0–120000. |
| `status` | int\|null | 100–599. |
| `body` | string | Reply body, used with `status`. |
| `drop` | bool | Kill the connection. Mutually exclusive with `status`. |

Effects apply in order: delay, then drop, then reply. A rule that does nothing at all is
rejected. The first matching rule wins. Every rule is validated before any is armed, so
a typo in the third never leaves the first two live.

Faulted responses carry an **`x-interceptor-fault: 1`** header and a `faulted` field in
the summary — so a client under test, and your own assertions, can tell an injected 503
from a real one.

### Repeater

```json
{"type": "replay", "id": "<flow id>", "raw": "<edited request, or omitted>"}
```

Replays a **copy**, so the original row is preserved for comparison. The new flow's
summary carries `replay_of: "<original id>"` and `is_replay: true`. There is no reply
message — watch for the new `flow` push, or search for it.

Rejected for WebSocket flows: mitmproxy's client replay refuses them.

### WebSocket frames

A held frame arrives as `flow.paused` with `direction: "websocket"` and a `frame`
object instead of `detail`. Edit it by sending `raw` as the **frame payload alone** —
not a start line and headers — along with `seq`.

If `frame.binary` is true, the payload was rendered as hex and your edit must come back
as hex; anything else is rejected. If `frame.truncated` is true the frame is above the
editable limit and you were only shown a prefix — the edit is refused outright rather
than sending a truncated frame, so forward or drop it instead.

Injection needs no pause:

```json
{"type": "ws.inject", "id": "<flow id>", "to_client": true,
 "text": "hello", "is_text": true}
```

`is_text: false` reads `text` as hex (whitespace ignored). `to_client: false` sends it
to the server instead. The socket must still be open.

Note that a scope matching a WebSocket flow matches **both directions**. If you edit a
frame going out and the server answers, that answer is held too — release it, or your
client under test waits forever.

### Hosts, options, sessions

| Command | Payload | Effect |
|---|---|---|
| `hosts.set` | `hosts`: list of regexes | Capture only these. `[]` captures everything. No double quotes in a pattern. |
| `opt.set` | `intercept_responses`: bool, `hide_noise`: bool | Either or both. |
| `session.save` | — | Dump the capture to `sessions/<timestamp>.mitm`. Replies `saved`. |
| `session.load` | `name` | Replace the capture with a saved one. Replies `loaded`. |
| `sessions.list` | — | Replies `sessions`. |
| `har.save` | — | Write the whole capture as HAR into `sessions/`. Replies `har`. |
| `browser.launch` | — | Launch throwaway-profile Chrome wired to the proxy. Rarely what a headless agent wants. |

`hosts.set` is not a security control — an unlisted host still reaches the client, it is
simply not captured. It is a performance and noise control, and a big one: TLS is not
terminated for hosts off the list.

HAR and sessions are written to disk at mode `0600`, never served over the bridge, and
the reply tells you the directory. That is deliberate: the static route is not
token-gated, so serving a capture there would publish it to any page the user has open.

---

## Messages from the server

| Type | When | Key fields |
|---|---|---|
| `snapshot` | After `hello` | `flows` — up to 2000 newest summaries, oldest first |
| `state` | After most commands, and once a second under traffic | see below |
| `flow` | A flow was recorded or updated | the summary fields, inline |
| `flow.paused` | A flow is held | `id`, `direction`, `summary`, and `detail` (HTTP) or `frame` (WebSocket) |
| `body` | Reply to `body.get` | `id`, `which`, `detail` |
| `frames` | Reply to `frames.get` | `id`, `frames` |
| `results` | Reply to `search` | `q`, `flows` |
| `export` | Reply to `export` | `id`, `format`, `text` |
| `har` / `saved` / `loaded` / `sessions` / `cleared` | their commands | `name`, `bytes`, `flows`, `items`, `dir` |
| `error` | Anything rejected | `message`, sometimes `id` |

**`state`** is the whole control-panel picture and the thing to poll for confirmation:
`mode`, `scope`, `queue` (what is held right now, with `id`/`direction`/`host`/`path`),
`per_host`, `stored`, `bytes`, `evicted`, `noise_hidden`, `hide_noise`,
`intercept_responses`, `auto_forwarded`, `rules_body`, `rules_headers`, `faults`,
`allow_hosts`, `proxy`, `env_proxy`, `chained`, `sessions_dir`.

`auto_forwarded` climbing is your signal that flows are escaping unheld — usually
because nothing was connected, or an edit was too large and closed the socket.

**Summary** fields, on every row: `id`, `method`, `scheme`, `host`, `port`, `path`,
`http_version`, `status`, `ctype`, `req_bytes`, `resp_bytes`, `start`, `ms`, `ws`,
`ws_frames`, `ws_open`, `streamed`, `intercepted`, `killed`, `replay_of`, `is_replay`,
`faulted`.

**Detail** fields: `headers` (list of `[name, value]` pairs, duplicates preserved),
`body`, `encoding`, `size`, `body_crlf`, `raw`, plus `method`/`url`/`http_version` on a
request or `status`/`reason` on a response. `pretty` and `pretty_view` appear when the
body is something mitmproxy can render structurally — protobuf, gRPC, msgpack, XML,
GraphQL and a dozen more. **`pretty` is display only and is not round-trippable — never
send it back as `raw`.**

`encoding` is one of `text`, `base64` (bytes that contradict a declared encoding),
`streamed`, or `too-large`. Only `text` is editable.

**Frame** entries: `seq`, `from_client`, `size`, `preview`, `binary`, `truncated`,
`injected`, `dropped`.

---

## Three working shapes

**Passive.** Set `hosts.set` to the app under test, drive it, then `search` for what you
care about or `har.save` and read the file. No socket babysitting beyond staying
connected.

**Rules and faults.** `rules.set` / `faults.set`, drive the app, assert on what came
back. Nothing pauses, so there is no loop to run and no risk of stranding a client. This
is the right default for an agent — reach for intercept only when the decision genuinely
depends on the content of a specific in-flight message.

**Intercept loop.** `mode.set` to `intercept` with the narrowest scope that works, then:

```python
while True:
    held = await c.until("flow.paused")
    raw = held["detail"]["raw"]
    if raw is None:                                  # not editable
        await c.send(type="resume", id=held["id"])
        continue
    await c.send(type="resume", id=held["id"], raw=decide(raw))
```

Keep the scope tight. A broad scope in intercept mode stops page loads dead at a few
hundred flows, and every one waits on your loop.

---

## Known limitations

**`search` does not index WebSocket frames.** The search index is built from URL,
headers and HTTP bodies. A frame payload is not in it. Find the flow another way — the
summary's `ws` and `ws_frames` fields — and call `frames.get`.

**Streamed bodies are invisible.** Anything over 5 MB streams, which means it is never
buffered: no `raw`, no rewrite rules, nothing in the search index. `summary.streamed`
and `detail.encoding == "streamed"` tell you when this is why you are seeing nothing.

**Size limits.** Editable bodies cap at 5 MB; the socket accepts messages up to 20 MB
(hex-encoded binary frames arrive at ~3× their byte size). Exceeding the socket limit
closes the connection — which force-forwards every held flow. Set `max_size` on your
client accordingly.

**`snapshot` and `search` cap at 2000 rows.** For a bigger capture, use `har.save` and
read the file.

---

## Notes for an agent operating this

- The proxy port has **no authentication**. Binding it off loopback is refused unless
  `expose=true` is passed explicitly, and that refusal is load-bearing — do not work
  around it to make something reachable.
- Captured traffic is decrypted and contains live cookies and bearer tokens. Session
  dumps, HAR files and `export` output all carry them. Treat that output as credentials:
  do not paste it into a ticket, a log, or anywhere outside the machine without the
  user's say-so.
- `.ui-url` holds the control token. Same rule.
- Faults and rules change what a real application receives. On anything that is not a
  local or explicitly-designated test target, confirm before arming them.
- Always clear faults and rules when you are done, even on an error path.

---

## Verifying

Every command and payload above was exercised against a headless instance on a throwaway
port — HTTP capture, rewrite rules, fault injection, search, body fetch, curl export,
repeater, intercept edit/drop/`stop_reply`, rejected-edit handling, sessions, HAR, and
the WebSocket path including `frames.get`, injection in both directions, and frame
edit/drop.

If you change the protocol, re-run that exercise rather than trusting this file.
