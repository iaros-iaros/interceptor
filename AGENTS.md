# Interceptor

A local, Burp-style intercepting proxy: capture HTTP/1.1, HTTP/2 and WebSocket traffic,
pause it mid-flight, edit it, forward or drop it. mitmproxy engine, browser UI, one
process. See README.md.

## Driving it programmatically

**If you are here to *use* Interceptor rather than change it — to capture, rewrite, fault
or intercept traffic from a script or an agent — read [AGENT-API.md](AGENT-API.md)
first.** It is the whole control protocol: how to start headless, how to authenticate,
the twenty commands, the payload shapes, and the five behaviours that will otherwise cost
you an hour each. Do not reverse-engineer the protocol from `ui/`.

Start: `IC_OPEN_UI=false interceptor`, read the token from `.ui-url`, connect to
`ws://127.0.0.1:9000/ws?token=…` with an `Origin` header matching the UI's origin.

## Working on the code

Python 3.13 only — mitmproxy has no 3.14 wheels. Everything runs out of `.venv`.

```bash
.venv/bin/python spike/check.py                   # units + end-to-end, offline
.venv/bin/python spike/spike.py --chrome --net    # needs a real browser and internet
```

Both use their own ports (`18xxx`/`19000`) and their own URL file, so they are safe to run
while an instance is up, and neither kills stray processes. Run `check.py` before claiming
anything works.

- `addon/` is the proxy addon (mitmproxy hooks, store, bridge, faults, exporters).
  `ui/` is the browser client. `spike/` is the test harness.
- Anything that changes the wire protocol between them changes both sides *and*
  AGENT-API.md.
- Non-obvious decisions are explained in comments at the point they matter. When a fix
  looks like a typo — a stray space, an odd ordering — check for the comment before
  tidying it away; several of them are load-bearing.
