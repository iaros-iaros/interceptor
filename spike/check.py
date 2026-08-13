#!/usr/bin/env python3
"""End-to-end check. Boots the real run.sh and drives it like the UI does.

Covers: static serving, path-traversal refusal, the two bridge auth gates,
capture, pause -> forward, pause -> drop, and force-forward when the UI vanishes.

Run:  .venv/bin/python spike/check.py
"""

from __future__ import annotations

import asyncio
import gzip
import json
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import websockets

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "spike"))
sys.path.insert(0, str(ROOT / "addon"))

from spike import WS_RECEIVED, start_http, ws_echo  # noqa: E402


def _port(env: str, default: int) -> int:
    return int(os.environ.get(env, default))


# The suite runs on its own ports and its own URL file, so it can never collide
# with -- or clobber the state of -- an instance you already have running. That
# is also why there is no `pkill mitmdump` here: it would shoot down your proxy.
PROXY_PORT = _port("IC_TEST_PROXY_PORT", 18080)
UI_PORT = _port("IC_TEST_UI_PORT", 19000)
TARGET = ("127.0.0.1", _port("IC_TEST_TARGET_PORT", 18081))
WS_TARGET = ("127.0.0.1", _port("IC_TEST_WS_PORT", 18082))
URL_FILE = ".ui-url.test"

UI = f"http://127.0.0.1:{UI_PORT}"
PROXY = f"http://127.0.0.1:{PROXY_PORT}"

RESULTS: list[tuple[str, bool | None, str]] = []
SAVED_NAME: str | None = None


def check(name: str, ok: bool | None, detail: str = "") -> None:
    """ok=None records a SKIP -- inconclusive, not a failure."""
    RESULTS.append((name, ok, detail))


def port_free(port: int) -> bool:
    with socket.socket() as s:
        # SO_REUSEADDR so a socket lingering in TIME_WAIT from a previous run does
        # not read as "in use" -- servers set this too, so this matches what
        # run.sh will actually manage to bind. An active listener still fails.
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


# --------------------------------------------------------------- offline units


def units() -> None:
    import interceptor as I
    from mitmproxy import flowfilter
    from mitmproxy.test import taddons, tflow

    filt = flowfilter.parse(I.NOISE_FILTER)
    cases = {
        "clients2.google.com": True,
        "fonts.gstatic.com": True,
        "safebrowsing.googleapis.com": True,
        "api.example.com": False,
        "localhost": False,
    }
    wrong = []
    for host, want_noise in cases.items():
        f = tflow.tflow()
        f.request.host = host
        f.request.headers["Host"] = host
        if (not filt(f)) is not want_noise:
            wrong.append(host)
    check("noise filter classifies browser chatter vs real targets", not wrong,
          f"misclassified: {wrong}" if wrong else f"{len(cases)} hosts correct")

    # _compose() must produce a parseable expression in every combination --
    # "~all" refusing to compose with "&" is exactly the trap here.
    addon = I.Interceptor()
    bad = []
    with taddons.context(addon) as tctx:
        for hide in (True, False):
            for scope in ("", "~u /api/ & ~m POST", "~d example.com"):
                tctx.options.hide_noise = hide
                addon.scope = scope
                expr = addon._compose()
                try:
                    flowfilter.parse(expr)
                except ValueError as e:
                    bad.append((hide, scope, str(e)))
    check("_compose() yields a parseable filter in all combinations", not bad,
          f"failures: {bad}" if bad else "6 combinations parse")

    units_raw()
    units_store()
    units_private_files()
    units_frames()
    units_paused_payload()
    units_nonlive()
    units_bridge_guard()


def units_raw() -> None:
    """parse_raw / raw_text edge cases. These corrupt payloads when wrong, and
    the integration checks only ever exercise the happy path."""
    import interceptor as I
    from mitmproxy.test import tflow

    bad = []
    cases = 0

    def want(label, got, expect):
        nonlocal cases
        cases += 1
        if got != expect:
            bad.append(f"{label}: got {got!r} want {expect!r}")

    # CRLF must normalise; a colon inside a value must not split the header.
    start, hdrs, body = I.parse_raw(
        "POST /p HTTP/1.1\r\nX-Time: 12:30:45\r\nHost: h\r\n\r\n{}"
    )
    want("crlf start", start, "POST /p HTTP/1.1")
    want("colon in value", hdrs, [("X-Time", "12:30:45"), ("Host", "h")])
    want("crlf body", body, "{}")

    # A CRLF-only header block still parses: "\r\n\r\n" contains no "\n\n", so
    # the separator has to be found before any normalising.
    start, hdrs, body = I.parse_raw("GET /p HTTP/1.1\r\nHost: h\r\n\r\nbody")
    want("crlf-only separator start", start, "GET /p HTTP/1.1")
    want("crlf-only separator headers", hdrs, [("Host", "h")])
    want("crlf-only separator body", body, "body")

    # The body's own CRLFs must survive. Rewriting them to LF corrupts every
    # multipart upload: RFC 7578 requires CRLF before each boundary delimiter.
    mp = '--X\r\nContent-Disposition: form-data; name="a"\r\n\r\nv\r\n--X--\r\n'
    _s, _h, body = I.parse_raw(f"POST /u HTTP/1.1\nHost: h\n\n{mp}")
    want("multipart body kept byte-for-byte", body, mp)

    # What the browser actually sends back: a <textarea> normalises CRLF to LF in
    # its own value, per the HTML spec's value-sanitisation step, so an untouched
    # multipart body arrives LF-only. _apply_edits must recognise that as "not
    # edited" and restore the original bytes -- otherwise fixing parse_raw fixed
    # nothing for the one client that exists.
    flow = tflow.tflow()
    flow.request.headers["content-type"] = "multipart/form-data; boundary=X"
    flow.request.content = mp.encode()
    served = I.raw_text(flow, "request")
    as_textarea_returns_it = served.replace("\r\n", "\n")   # what the browser does
    addon = I.Interceptor()
    addon._apply_edits(flow, "request", as_textarea_returns_it)
    want("textarea-normalised body is restored, not sent as LF",
         flow.request.content, mp.encode())

    # A body the user genuinely changed must still go through as typed. Edit inside
    # the body, not the headers -- tflow's default header value contains "value".
    flow2 = tflow.tflow()
    flow2.request.content = mp.encode()
    edited = I.raw_text(flow2, "request").replace("\r\n\r\nv\r\n", "\r\n\r\nCHANGED\r\n")
    addon._apply_edits(flow2, "request", edited)
    want("a real body edit still applies", b"CHANGED" in flow2.request.content, True)

    # No blank line: everything is headers, body empty.
    _s, hdrs, body = I.parse_raw("GET / HTTP/1.1\nHost: h")
    want("no blank line headers", hdrs, [("Host", "h")])
    want("no blank line body", body, "")

    # Empty body after a blank line stays empty, not None.
    _s, _h, body = I.parse_raw("GET / HTTP/1.1\nHost: h\n\n")
    want("empty body", body, "")

    # Duplicate headers survive as separate entries.
    _s, hdrs, _b = I.parse_raw("GET / HTTP/1.1\nX-D: 1\nX-D: 2\n\n")
    want("duplicate headers", hdrs, [("X-D", "1"), ("X-D", "2")])

    rejected = []
    rejected_cases = (
        ("no colon", "GET / HTTP/1.1\nBadHeader\n\n"),
        ("empty start line", "\nHost: h\n\n"),
    )
    for label, text in rejected_cases:
        try:
            I.parse_raw(text)
            rejected.append(f"{label} was accepted")
        except ValueError:
            pass
    check("parse_raw: CRLF, colons in values, no blank line, duplicates, malformed",
          not bad and not rejected,
          "; ".join(bad + rejected) or f"{cases + len(rejected_cases)} cases correct")

    # ---- raw_text refusals and Content-Encoding stripping
    notes = []
    f = tflow.tflow(resp=True)
    f.response.headers["content-encoding"] = "gzip"
    f.response.raw_content = gzip.compress(b'{"z":9}')
    raw = I.raw_text(f, "response")
    if raw is None or "content-encoding" in raw.lower():
        notes.append("content-encoding not stripped from editor view")
    if raw and '{"z":9}' not in raw:
        notes.append("body not shown decoded")

    f2 = tflow.tflow()
    f2.request.raw_content = b"\xff\xfe\x00binary"
    if I.raw_text(f2, "request") is not None:
        notes.append("binary body offered as editable text")

    f3 = tflow.tflow()
    f3.request.raw_content = b"x" * (I.MAX_EDITABLE_BODY + 1)
    if I.raw_text(f3, "request") is not None:
        notes.append("oversized body offered as editable text")

    f4 = tflow.tflow(resp=True)
    f4.response.stream = True
    if I.raw_text(f4, "response") is not None:
        notes.append("streamed body offered as editable text")
    if (I.detail(f4, "response") or {}).get("encoding") != "streamed":
        notes.append("streamed body not labelled 'streamed' for the UI")
    check("raw_text refuses binary/oversized/streamed and strips Content-Encoding",
          not notes, "; ".join(notes) or "5 refusals correct")

    # ---- full edit round trip through _apply_edits
    notes = []
    addon = I.Interceptor()
    f = tflow.tflow()
    f.request.headers["content-length"] = "999"  # stale on purpose
    edited = 'POST /new?q=1 HTTP/1.1\nHost: h\nX-D: 1\nX-D: 2\n\n{"unicode":"héllo ☂"}'
    addon._apply_edits(f, "request", edited)
    if f.request.method != "POST" or f.request.path != "/new?q=1":
        notes.append(f"start line not applied: {f.request.method} {f.request.path}")
    if list(f.request.headers.items(True)).count(("X-D", "1")) != 1:
        notes.append("duplicate headers lost")
    expect_len = len('{"unicode":"héllo ☂"}'.encode())
    if f.request.headers.get("content-length") != str(expect_len):
        notes.append(f"Content-Length {f.request.headers.get('content-length')} != {expect_len}")
    if f.request.text != '{"unicode":"héllo ☂"}':
        notes.append(f"unicode body mangled: {f.request.text!r}")

    # An absolute target retargets host and port.
    addon._apply_edits(f, "request", "GET https://other.example:8443/abs HTTP/1.1\nHost: h\n\n")
    if (f.request.host, f.request.port) != ("other.example", 8443):
        notes.append(f"absolute URL did not retarget: {f.request.host}:{f.request.port}")

    # Malformed status line must raise, leaving the flow untouched.
    fr = tflow.tflow(resp=True)
    try:
        addon._apply_edits(fr, "response", "HTTP/1.1 NOTANUMBER OK\n\n")
        notes.append("non-numeric status accepted")
    except ValueError:
        pass
    check("edit round trip: multibyte body, duplicate headers, CL recompute, retarget",
          not notes, "; ".join(notes) or "7 assertions correct")


def units_store() -> None:
    """Flow-store byte accounting and the streaming cutoff. Neither has ever run:
    the cap is 512MB in real use and nothing in the integration suite goes near it."""
    import interceptor as I
    from mitmproxy.test import taddons, tflow

    notes = []
    addon = I.Interceptor()
    with taddons.context(addon) as tctx:
        tctx.options.hide_noise = False
        tctx.options.store_bytes = 400

        for i in range(10):
            f = tflow.tflow(resp=True)
            f.request.host = f"h{i}.example.com"
            f.request.raw_content = b"x" * 100
            addon._remember(f)

        if addon.evicted == 0:
            notes.append("nothing evicted despite a 400 byte cap")
        if addon.bytes > tctx.options.store_bytes and len(addon.store) > 1:
            notes.append(f"cap exceeded: {addon.bytes}B held")
        # The invariant that a bad pop/re-add would break.
        if addon.bytes != sum(addon.sizes.values()):
            notes.append(f"accounting drift: bytes={addon.bytes} sizes={sum(addon.sizes.values())}")
        if set(addon.store) != set(addon.sizes):
            notes.append("store and sizes maps disagree")

        # Re-remembering one flow (request hook, then response hook) must not
        # double-count it -- this is what the pop-before-add exists for.
        addon2 = I.Interceptor()
        tctx.options.store_bytes = 512 * 1024 * 1024
        f = tflow.tflow(resp=True)
        f.request.raw_content = b"y" * 50
        addon2._remember(f)
        once = addon2.bytes
        addon2._remember(f)
        if addon2.bytes != once:
            notes.append(f"double counted on re-remember: {once} -> {addon2.bytes}")
        if len(addon2.store) != 1:
            notes.append(f"re-remember duplicated the entry: {len(addon2.store)}")
    check("flow store evicts by bytes and never double-counts", not notes,
          "; ".join(notes) or f"evicted {addon.evicted}, kept {len(addon.store)}, accounting exact")

    # ---- streaming cutoff
    notes = []
    addon = I.Interceptor()
    with taddons.context(addon):
        big = tflow.tflow(resp=True)
        big.response.headers["content-length"] = str(I.MAX_EDITABLE_BODY + 1)
        addon.responseheaders(big)
        if not getattr(big.response, "stream", False):
            notes.append("oversized response not streamed")

        small = tflow.tflow(resp=True)
        small.response.headers["content-length"] = "100"
        addon.responseheaders(small)
        if getattr(small.response, "stream", False):
            notes.append("small response streamed unnecessarily")

        junk = tflow.tflow(resp=True)
        junk.response.headers["content-length"] = "not-a-number"
        try:
            addon.responseheaders(junk)
        except ValueError:
            notes.append("non-numeric Content-Length raised instead of being ignored")
    check("streaming cutoff: oversized streams, small does not, junk CL is safe",
          not notes, "; ".join(notes) or "3 cases correct")

    units_bind()


def units_bind() -> None:
    """The loopback guard. Tested without opening a socket -- the failure mode
    here is an open MITM proxy on the LAN, so it must not be checked by trying
    it. run.sh's half of the guard is checked separately in guard_refuses()."""
    import interceptor as I
    from mitmproxy import exceptions
    from mitmproxy.test import taddons

    wrong = [h for h, want in {
        "127.0.0.1": True, "127.0.0.2": True, "::1": True, "localhost": True,
        "0.0.0.0": False, "": False, "192.168.1.10": False, "::": False,
        "example.com": False,  # unresolved name: not positively loopback
    }.items() if I._is_loopback(h) is not want]
    check("_is_loopback treats anything unproven as public", not wrong,
          f"misclassified: {wrong}" if wrong else "9 hosts correct")

    addon = I.Interceptor()
    notes = []
    with taddons.context(addon) as tctx:
        # Assign, not configure(): mitmproxy's own default for listen_host is ""
        # (every interface), which the guard rightly refuses, and a configure()
        # rollback would restore it and raise from inside the rollback. These
        # assignments give the context a clean loopback baseline to vary from.
        tctx.options.listen_host = "127.0.0.1"
        tctx.options.ui_host = "127.0.0.1"
        for host_opt in ("listen_host", "ui_host"):
            try:
                tctx.configure(addon, **{host_opt: "0.0.0.0", "expose": False})
                notes.append(f"{host_opt}=0.0.0.0 was accepted without expose")
            except exceptions.OptionsError:
                pass
            tctx.options.update(**{host_opt: "127.0.0.1"})
        try:
            tctx.configure(addon, listen_host="0.0.0.0", expose=True)
        except exceptions.OptionsError:
            notes.append("expose=true was still refused")
        tctx.options.update(listen_host="127.0.0.1", expose=False)

        # A mode spec carries its own bind address and proxyserver prefers it over
        # listen_host, so the option check alone left an open proxy one flag away.
        for spec, want_refused in (("regular@0.0.0.0:8080", True),
                                   ("reverse:http://x@0.0.0.0:9999", True),
                                   ("regular@8080", False),              # bare port
                                   ("upstream:http://vps:8080", False),  # not a bind
                                   ("regular@127.0.0.1:9999", False)):
            try:
                tctx.configure(addon, mode=[spec])
                if want_refused:
                    notes.append(f"{spec} was accepted")
            except exceptions.OptionsError:
                if not want_refused:
                    notes.append(f"{spec} was wrongly refused")
            tctx.options.update(mode=[])
    check("binding off loopback is refused unless expose is set, mode specs included",
          not notes, "; ".join(notes) or "2 hosts + 5 mode specs classified, expose overrides")


def units_private_files() -> None:
    """Files holding credentials must be 0600 from creation, not after the write.
    Checked under a permissive umask, which is the only way the old chmod-after
    ordering shows up at all."""
    import interceptor as I

    old = os.umask(0o000)
    try:
        probe = ROOT / ".mode-probe.tmp"
        fd = I._open_private(probe)
        with os.fdopen(fd, "w") as fh:
            mode_during = oct(os.stat(probe).st_mode & 0o777)
            fh.write("x")
        mode_after = oct(probe.stat().st_mode & 0o777)
        probe.unlink()
    finally:
        os.umask(old)
    check("_open_private creates 0600 with a permissive umask, not just at the end",
          mode_during == "0o600" and mode_after == "0o600",
          f"during write {mode_during}, after {mode_after} (umask was 000)")


def units_frames() -> None:
    """Frame rendering and the WebSocket edit path."""
    import interceptor as I
    from mitmproxy.test import taddons, tflow
    from mitmproxy.websocket import WebSocketMessage

    notes = []
    # The text/binary call must be made on the whole frame. "€" is 3 bytes and
    # 4096 % 3 == 1, so decoding only the first 4096 bytes splits a sequence and
    # reports a plain text frame as binary.
    _r, binary, truncated = I._frame_view(("€" * 2000).encode(), 4096)
    if binary:
        notes.append("multibyte text frame classified as binary")
    if truncated:
        notes.append("2000 chars reported as truncated at 4096")

    # Truncation must be reported: the editor writes this string back to the wire.
    rendered, _b, truncated = I._frame_view(b"A" * 5000, 4096)
    if not truncated or len(rendered) != 4096:
        notes.append(f"5000B frame: truncated={truncated}, rendered={len(rendered)}B")

    small, binary2, trunc2 = I._frame_view(b"hi", 4096)
    if trunc2 or binary2 or small != "hi":
        notes.append("small text frame mis-rendered")

    _hx, binary3, _t = I._frame_view(b"\xff\xfe\x00\x01", 4096)
    if not binary3:
        notes.append("binary frame not detected")
    check("_frame_view reports truncation and judges binary on the whole frame",
          not notes, "; ".join(notes) or "4 cases correct")

    # An oversized frame must be refused, not silently written back as a prefix.
    addon = I.Interceptor()
    wf = tflow.twebsocketflow()
    wf.websocket.messages.clear()
    huge = b"A" * (I.MAX_EDITABLE_BODY + 10)
    wf.websocket.messages.append(WebSocketMessage(1, True, huge))
    view, _, _ = I._frame_view(wf.websocket.messages[-1].content)
    try:
        addon._apply_edits(wf, "websocket", view)
        outcome = f"accepted, frame now {len(wf.websocket.messages[-1].content)}B"
    except ValueError as e:
        outcome = f"refused: {e}"
    check("editing a frame larger than the editable limit is refused",
          wf.websocket.messages[-1].content == huge,
          f"{outcome}; frame intact: {wf.websocket.messages[-1].content == huge}")

    # _apply_edits must act on the frame the caller resolved, not on the last one.
    wf2 = tflow.twebsocketflow()
    wf2.websocket.messages.clear()
    for payload in (b"f0", b"f1", b"f2"):
        wf2.websocket.messages.append(WebSocketMessage(1, True, payload))
    addon._apply_edits(wf2, "websocket", "EDITED", 0)
    got = [m.content for m in wf2.websocket.messages]
    check("an edit lands on the frame the caller named, not the newest",
          got == [b"EDITED", b"f1", b"f2"], f"frames now {got}")

    # WebSocket frames must count against the store cap.
    addon2 = I.Interceptor()
    with taddons.context(addon2) as tctx:
        tctx.configure(addon2, hide_noise=False, store_bytes=512 * 1024 * 1024)
        wf3 = tflow.twebsocketflow()
        wf3.websocket.messages.clear()
        addon2._remember(wf3)
        base = addon2.bytes
        for _ in range(50):
            wf3.websocket.messages.append(WebSocketMessage(1, True, b"P" * 10_000))
        addon2._remember(wf3)
    frame_bytes = sum(len(m.content) for m in wf3.websocket.messages)
    check("WebSocket frames count against the memory cap",
          addon2.bytes - base == frame_bytes,
          f"accounted {addon2.bytes - base}B of {frame_bytes}B in frames")

    # ...and it must count each frame ONCE. Re-summing the whole list per arriving
    # frame is O(n) per frame and O(n^2) over a connection, and it runs on the
    # proxy's own event loop: measured 0.72ms/frame at 2.5k frames rising to
    # 9.9ms at 30k, which slowed every other request through the proxy. Counting
    # reads of .content is the direct, non-flaky way to assert that -- a timing
    # assertion on the same thing would be a flake generator.
    reads = [0]

    class CountedFrame:
        """A frame that records every read of its payload. Delegates get_state to a
        real message, because the store serialises a finalised flow."""

        def __init__(self, data: bytes) -> None:
            self._data = data
            self._real = WebSocketMessage(1, True, data)
            self.from_client = True
            self.injected = False
            self.dropped = False

        @property
        def content(self) -> bytes:
            reads[0] += 1
            return self._data

        def get_state(self):
            return self._real.get_state()

    addon3 = I.Interceptor()
    n_frames = 200
    with taddons.context(addon3) as tctx:
        tctx.configure(addon3, hide_noise=False, store_bytes=512 * 1024 * 1024)
        wf4 = tflow.twebsocketflow()
        wf4.websocket.messages.clear()
        addon3._remember(wf4)
        reads[0] = 0
        # One _remember per arriving frame, exactly as websocket_message does.
        for _ in range(n_frames):
            wf4.websocket.messages.append(CountedFrame(b"Q" * 100))
            addon3._remember(wf4)
    quadratic = n_frames * (n_frames + 1) // 2      # what re-summing would cost
    check("WebSocket byte accounting reads each frame once, not once per frame",
          reads[0] == n_frames,
          f"{reads[0]} payload reads for {n_frames} frames "
          f"(re-summing would be {quadratic}); "
          f"accounted {addon3.sizes[wf4.id] - len(wf4.request.raw_content or b'')}B")

    # The WebSocket tab marks sockets that are still up. A 101 status cannot say
    # that -- a closed connection keeps its handshake status forever -- so
    # summary() reads the socket's own close timestamp instead.
    wf6 = tflow.twebsocketflow()
    wf6.websocket.timestamp_end = None
    open_now = I.summary(wf6)["ws_open"]
    wf6.websocket.timestamp_end = time.time()
    closed_now = I.summary(wf6)["ws_open"]
    plain = I.summary(tflow.tflow(resp=True))["ws_open"]
    check("ws_open tracks the socket's close timestamp, not its 101 status",
          open_now is True and closed_now is False and plain is False,
          f"live={open_now}, closed={closed_now}, plain HTTP flow={plain}")

    # A loaded session replaces the message list wholesale, so the cursor from a
    # previous life must not make the recount skip frames.
    addon4 = I.Interceptor()
    with taddons.context(addon4) as tctx:
        tctx.configure(addon4, hide_noise=False, store_bytes=512 * 1024 * 1024)
        wf5 = tflow.twebsocketflow()
        wf5.websocket.messages.clear()
        for _ in range(20):
            wf5.websocket.messages.append(WebSocketMessage(1, True, b"R" * 1_000))
        addon4._remember(wf5)
        before = addon4.bytes
        # Same flow id, shorter list: exactly what FlowReader hands back.
        wf5.websocket.messages.clear()
        for _ in range(5):
            wf5.websocket.messages.append(WebSocketMessage(1, True, b"R" * 1_000))
        addon4._remember(wf5)
    check("a stale frame cursor recounts instead of under-counting",
          addon4.bytes < before and addon4.bytes - len(wf5.request.raw_content or b"") == 5_000,
          f"{before}B for 20 frames -> {addon4.bytes}B for 5 frames")


def units_paused_payload() -> None:
    """A reconnecting UI must get the same payload the live push sent. The
    snapshot used to send a held frame's HTTP handshake as `detail`, so the
    editor came up blank and anything typed in replaced the real frame."""
    import interceptor as I
    from mitmproxy.addons import modifybody, modifyheaders
    from mitmproxy.test import taddons, tflow

    class Collect:
        def __init__(self):
            self.clients = {"x"}
            self.sent = []

        def push(self, type_, **payload):
            self.sent.append({"type": type_, **payload})

    addon = I.Interceptor()
    wf = tflow.twebsocketflow()
    with taddons.context(addon, modifybody.ModifyBody(), modifyheaders.ModifyHeaders()) as tctx:
        tctx.configure(addon, hide_noise=False)
        addon.bridge = Collect()
        addon.paused[wf.id] = ("websocket", wf)
        addon._snapshot()
    paused = [m for m in addon.bridge.sent if m["type"] == "flow.paused"]
    frame = (paused[0].get("frame") or {}) if paused else {}
    real = wf.websocket.messages[-1].content.decode()
    check("a reconnecting UI gets the held frame, not the handshake",
          frame.get("body") == real,
          f"snapshot frame body {frame.get('body')!r} vs real frame {real!r}")


def units_nonlive() -> None:
    """A flow loaded from a session is marked intercepted by the built-in Intercept
    addon. If the flag is left set, every loaded row renders as held with an empty
    queue and no way to clear it."""
    import interceptor as I
    from mitmproxy.addons import modifybody, modifyheaders
    from mitmproxy.test import taddons, tflow

    addon = I.Interceptor()
    with taddons.context(addon, modifybody.ModifyBody(), modifyheaders.ModifyHeaders()) as tctx:
        tctx.configure(addon, hide_noise=False)
        addon.bridge = None
        dead = tflow.tflow(resp=True)
        dead.live = False
        dead.intercept()
        addon._maybe_pause(dead, "request")
    check("a loaded flow is not left marked held",
          not dead.intercepted and dead.id not in addon.paused,
          f"intercepted={dead.intercepted}, queued={dead.id in addon.paused}, "
          f"summary says held: {I.summary(dead)['intercepted']}")


def units_bridge_guard() -> None:
    """The proxy port is bound before this script loads, so a request can reach
    the hooks while the bridge is still None."""
    import interceptor as I
    from mitmproxy.addons import modifybody, modifyheaders
    from mitmproxy.test import taddons, tflow

    addon = I.Interceptor()
    with taddons.context(addon, modifybody.ModifyBody(), modifyheaders.ModifyHeaders()) as tctx:
        tctx.configure(addon, hide_noise=False)
        addon.bridge = None
        try:
            addon.request(tflow.tflow())
            addon.websocket_message(tflow.twebsocketflow())
            outcome = "survived"
        except Exception as e:
            outcome = f"{type(e).__name__}: {e}"
    check("hooks survive a request arriving before the bridge exists",
          outcome == "survived", outcome)


# ------------------------------------------------------------------- helpers


def http_code(path: str) -> int:
    req = urllib.request.Request(UI + path)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except OSError:
        return 0


def curl_full(path: str, body: str | None = None, timeout: int = 25):
    """Returns (rc, response_body, status_code, elapsed)."""
    cmd = ["curl", "-s", "--max-time", str(timeout), "--noproxy", "", "-x", PROXY,
           "-w", "\n__CODE__%{http_code}"]
    if body is not None:
        cmd += ["-X", "POST", "-H", "content-type: application/json",
                "--data-binary", body]
    cmd.append(f"http://{TARGET[0]}:{TARGET[1]}{path}")
    t0 = time.monotonic()
    r = subprocess.run(cmd, capture_output=True, text=True)
    out, _, code = r.stdout.rpartition("\n__CODE__")
    return r.returncode, out, code.strip(), time.monotonic() - t0


def curl_bytes(path: str, body: str, timeout: int = 25) -> tuple[int, bytes]:
    """Like curl_full but byte-exact. subprocess's text=True applies universal
    newlines to stdout, which rewrites CRLF to LF -- fine everywhere else, fatal
    for a check whose whole point is that the body's CRLFs survived."""
    cmd = ["curl", "-s", "--max-time", str(timeout), "--noproxy", "", "-x", PROXY,
           "-X", "POST", "-H", "content-type: multipart/form-data; boundary=BOUND",
           "--data-binary", body, f"http://{TARGET[0]}:{TARGET[1]}{path}"]
    r = subprocess.run(cmd, capture_output=True)
    return r.returncode, r.stdout


def curl(path: str, timeout: int = 25) -> tuple[int, float]:
    rc, _out, _code, secs = curl_full(path, None, timeout)
    return rc, secs


async def arm(conn, scope: str, responses: bool | None = None) -> None:
    """Put the proxy in intercept mode with a scope, and wait until it took."""
    if responses is not None:
        await say(conn, type="opt.set", intercept_responses=responses)
        await recv_until(
            conn,
            lambda m: m.get("type") == "state" and m.get("intercept_responses") is responses,
        )
    await say(conn, type="mode.set", mode="intercept", scope=scope)
    await recv_until(
        conn,
        lambda m: m.get("type") == "state" and m.get("mode") == "intercept"
        and m.get("scope") == scope,
    )


async def wait_url(deadline: float) -> str | None:
    f = ROOT / URL_FILE
    while time.monotonic() < deadline:
        if f.exists():
            text = f.read_text().strip()
            if "#token=" in text:
                return text
        await asyncio.sleep(0.2)
    return None


async def recv_until(conn, pred, timeout: float = 15, collect: list | None = None):
    """Waits for a matching message. Pass `collect` to also keep everything seen --
    without it, messages scanned past are discarded, which silently breaks any
    later search for something that arrived before the match."""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            raw = await asyncio.wait_for(conn.recv(), timeout=max(0.1, end - time.monotonic()))
        except (TimeoutError, asyncio.TimeoutError):
            return None
        for m in json.loads(raw):
            if collect is not None:
                collect.append(m)
            if pred(m):
                return m
    return None


async def say(conn, **msg) -> None:
    await conn.send(json.dumps(msg))


async def forward_until_done(conn, fut, first_drop: bool = False) -> None:
    """In intercept mode a matching flow pauses twice (request, then response).
    Keep releasing until the client call actually returns."""
    dropped = False
    while not fut.done():
        m = await recv_until(conn, lambda m: m.get("type") == "flow.paused", timeout=8)
        if m is None:
            return
        drop = first_drop and not dropped
        dropped = dropped or drop
        await say(conn, type="resume", id=m["id"], drop=drop)
        await asyncio.sleep(0.1)


# --------------------------------------------------------------- integration


async def integration() -> None:
    busy = {
        name: port
        for name, port in (("proxy", PROXY_PORT), ("ui", UI_PORT),
                           ("target", TARGET[1]), ("ws-target", WS_TARGET[1]))
        if not port_free(port)
    }
    if busy:
        return check(
            "test ports are free", False,
            f"in use: {busy} -- override with IC_TEST_PROXY_PORT / IC_TEST_UI_PORT / "
            "IC_TEST_TARGET_PORT, or stop whatever is listening",
        )

    (ROOT / URL_FILE).unlink(missing_ok=True)
    start_http(*TARGET)
    ws_srv = await websockets.serve(ws_echo, *WS_TARGET)

    proc = subprocess.Popen(
        # No --chain: chaining is opt-in, so an instance booted plainly always goes
        # direct, whatever proxy client this machine happens to be running.
        ["./run.sh"], cwd=ROOT, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, start_new_session=True,
        env={**os.environ, "IC_LISTEN_PORT": str(PROXY_PORT),
             "IC_UI_PORT": str(UI_PORT), "IC_URL_FILE": URL_FILE,
             "IC_OPEN_UI": "false"},
    )
    try:
        url = await wait_url(time.monotonic() + 30)
        if not url:
            return check("run.sh publishes its UI URL and token", False,
                         f"no {URL_FILE} after 30s")
        token = url.split("#token=", 1)[1]
        check("run.sh publishes its UI URL and token", True, url.split("#")[0] + "#token=…")

        codes = {
            "/": http_code("/"),
            "/app.js": http_code("/app.js"),
            "/theme.js": http_code("/theme.js"),
            # The app imports rules-doc.js and shows icon.png; a 404 on either is
            # a blank modal or a missing favicon, both silent in the Python suite.
            "/rules-doc.js": http_code("/rules-doc.js"),
            "/icon.png": http_code("/icon.png"),
            "/rules.html": http_code("/rules.html"),
            "/style.css": http_code("/style.css"),
            "/nope": http_code("/nope"),
            "/ws (no token)": http_code("/ws"),
        }
        check("static serving + token gate",
              all(codes[k] == 200 for k in ("/", "/app.js", "/theme.js",
                                            "/rules-doc.js", "/icon.png",
                                            "/rules.html", "/style.css"))
              and codes["/nope"] == 404 and codes["/ws (no token)"] == 403,
              ", ".join(f"{k}={v}" for k, v in codes.items()))

        # Gate 1: Origin. websockets rejects a mismatched Origin for us.
        rejected = False
        try:
            async with websockets.connect(
                f"ws://127.0.0.1:{UI_PORT}/ws?token={token}", origin="http://evil.example",
                open_timeout=10,
            ):
                pass
        except Exception:
            rejected = True
        check("WebSocket with foreign Origin is rejected", rejected,
              "any page you visit can open ws:// to loopback; Origin must match")

        # Gate 2: token.
        rejected = False
        try:
            async with websockets.connect(
                f"ws://127.0.0.1:{UI_PORT}/ws?token=wrong", origin=UI, open_timeout=10
            ):
                pass
        except Exception:
            rejected = True
        check("WebSocket with bad token is rejected", rejected)

        async with websockets.connect(
            f"ws://127.0.0.1:{UI_PORT}/ws?token={token}", origin=UI, open_timeout=10
        ) as conn:
            await say(conn, type="hello")
            st = await recv_until(conn, lambda m: m.get("type") == "state")
            # The UI can only warn about an unchained proxy if state carries the two
            # fields it needs. run.sh fills env_proxy in from scutil or the
            # environment, so its value depends on the host -- assert the field is
            # present and that this unchained instance says so.
            check("state carries the proxy fields the UI warns with",
                  st is not None and "env_proxy" in st and st.get("chained") is False,
                  f"env_proxy={(st or {}).get('env_proxy')!r}, chained={(st or {}).get('chained')!r}")
            check("snapshot/state on hello", st is not None and st.get("mode") == "capture",
                  f"mode={st.get('mode') if st else None}")

            # --- capture
            fut = asyncio.create_task(asyncio.to_thread(curl, "/captured"))
            got = await recv_until(
                conn, lambda m: m.get("type") == "flow" and m.get("path") == "/captured"
            )
            await fut
            check("capture mode records a flow", got is not None,
                  f"status={got.get('status') if got else None}")

            # --- intercept then forward
            await say(conn, type="mode.set", mode="intercept", scope="~u /hold")
            await recv_until(conn, lambda m: m.get("type") == "state" and m.get("mode") == "intercept")
            fut = asyncio.create_task(asyncio.to_thread(curl, "/hold"))
            first = await recv_until(conn, lambda m: m.get("type") == "flow.paused")
            still_waiting = first is not None and not fut.done()
            if first:
                await say(conn, type="resume", id=first["id"])
                await forward_until_done(conn, fut)
            rc, secs = await fut
            check("intercept holds the request, then forward completes it",
                  still_waiting and rc == 0,
                  f"held={still_waiting}, curl rc={rc} in {secs:.2f}s")

            # A bad filter must be refused in every mode, not silently stored until
            # the mode changes -- and the filter in force must not be replaced by the
            # broken one. "|~u /api/" is the case that matters: it parses on its own,
            # and only fails once composed with the noise filter.
            await arm(conn, "~u /hold")
            await say(conn, type="mode.set", mode="capture", scope="|~u /api/")
            err = await recv_until(conn, lambda m: m.get("type") == "error", timeout=8)
            # A refusal returns before pushing state, so ask for one rather than
            # waiting for a push that is not coming.
            await say(conn, type="hello")
            st = await recv_until(conn, lambda m: m.get("type") == "state", timeout=8)
            check("a bad scope filter is refused and the working one is kept",
                  err is not None and "bad filter" in (err.get("message") or "")
                  and (st or {}).get("scope") == "~u /hold",
                  f"error={(err or {}).get('message', '')[:60]!r}, "
                  f"scope still {(st or {}).get('scope')!r}")

            # --- drop
            fut = asyncio.create_task(asyncio.to_thread(curl, "/hold-drop", 8))
            first = await recv_until(conn, lambda m: m.get("type") == "flow.paused")
            if first:
                await say(conn, type="resume", id=first["id"], drop=True)
            rc, secs = await fut
            # rc 52/56 = server closed with no reply, which is what a drop is.
            # rc 28 would mean the paused flow was stranded and the client hung.
            check("drop kills the held flow without stranding the client",
                  rc not in (0, 28) and secs < 6,
                  f"curl rc={rc} in {secs:.2f}s (28 would mean a hang)")

            # ---------------------------------------------------- P2 editors
            # Edit the body but deliberately leave the now-stale Content-Length
            # in the headers. The echo target reads exactly Content-Length bytes,
            # so a truncated echo proves the header was not recomputed.
            await arm(conn, "~u /edit-ok")
            fut = asyncio.create_task(asyncio.to_thread(curl_full, "/edit-ok", '{"orig":true}'))
            m = await recv_until(conn, lambda m: m.get("type") == "flow.paused")
            raw = (m or {}).get("detail", {}).get("raw") or ""
            head, _, _ = raw.partition("\n\n")
            payload = json.dumps({"edited": True, "pad": "x" * 300})
            had_stale_cl = "content-length" in head.lower()
            await say(conn, type="resume", id=m["id"], raw=f"{head}\n\n{payload}")
            rc, out, code, _ = await fut
            check("editing a held request rewrites the body upstream",
                  rc == 0 and out == payload,
                  f"target echoed {len(out)}B, expected {len(payload)}B")
            check("Content-Length is recomputed, not trusted from the editor",
                  had_stale_cl and out == payload,
                  f"stale CL present in editor text: {had_stale_cl}; echo intact: {out == payload}")

            # A multipart body must survive the editor byte-for-byte. The editor
            # round-trip used to rewrite every CRLF in the body to LF, which breaks
            # the boundary delimiters RFC 7578 requires -- silently, so the failure
            # looked like a bug in the application under test.
            await arm(conn, "~u /edit-mp")
            mp = ('--BOUND\r\nContent-Disposition: form-data; name="a"\r\n\r\n'
                  'value\r\n--BOUND--\r\n')
            fut = asyncio.create_task(asyncio.to_thread(curl_bytes, "/edit-mp", mp))
            m = await recv_until(conn, lambda m: m.get("type") == "flow.paused")
            raw = (m or {}).get("detail", {}).get("raw") or ""
            # Forward the editor text exactly as served -- what the UI sends when
            # the user touched the buffer but changed nothing in the body.
            await say(conn, type="resume", id=m["id"], raw=raw)
            rc, out = await fut
            crlf = b"\r\n"
            check("a multipart body survives the editor byte-for-byte",
                  rc == 0 and out == mp.encode(),
                  f"target received {out.count(crlf)}/{mp.encode().count(crlf)} CRLFs"
                  + ("" if out == mp.encode() else f"; got {out!r}"))

            # A malformed edit must be refused without losing the flow.
            await arm(conn, "~u /edit-bad")
            fut = asyncio.create_task(asyncio.to_thread(curl_full, "/edit-bad", '{"a":1}'))
            m = await recv_until(conn, lambda m: m.get("type") == "flow.paused")
            await say(conn, type="resume", id=m["id"],
                      raw="GET /x HTTP/1.1\nBadHeaderWithNoColon\n\n")
            err = await recv_until(conn, lambda m: m.get("type") == "error", timeout=8)
            survived = err is not None and not fut.done()
            await say(conn, type="resume", id=m["id"])  # retry, unedited
            rc, out, code, _ = await fut
            check("a malformed edit is rejected and the flow stays held", survived and rc == 0,
                  f"error={(err or {}).get('message')!r}, recovered rc={rc}")

            # Response editing, which also exercises the +resp toggle.
            await arm(conn, "~u /edit-resp", responses=True)
            fut = asyncio.create_task(asyncio.to_thread(curl_full, "/edit-resp", '{"a":1}'))
            m1 = await recv_until(
                conn, lambda m: m.get("type") == "flow.paused" and m.get("direction") == "request")
            await say(conn, type="resume", id=m1["id"])
            m2 = await recv_until(
                conn, lambda m: m.get("type") == "flow.paused" and m.get("direction") == "response")
            raw = (m2 or {}).get("detail", {}).get("raw") or ""
            head, _, body = raw.partition("\n\n")
            lines = head.split("\n")
            lines[0] = "HTTP/1.1 418 I am a teapot"
            await say(conn, type="resume", id=m2["id"], raw="\n".join(lines) + "\n\n" + body)
            rc, out, code, _ = await fut
            check("editing a held response changes what the client sees",
                  rc == 0 and code == "418", f"client saw status {code!r}")
            await say(conn, type="opt.set", intercept_responses=False)
            await recv_until(
                conn, lambda m: m.get("type") == "state" and not m.get("intercept_responses"))

            # ------------------------------------------------------- sessions
            # Save must be explicit, and a saved session must survive a full
            # restart -- that is the whole point of the feature.
            await say(conn, type="mode.set", mode="capture", scope="")
            await recv_until(conn, lambda m: m.get("type") == "state" and m.get("mode") == "capture")
            await asyncio.to_thread(curl_full, "/session-marker", '{"keep":"me"}')
            await recv_until(
                conn, lambda m: m.get("type") == "flow" and m.get("path") == "/session-marker")
            await say(conn, type="session.save")
            saved = await recv_until(conn, lambda m: m.get("type") == "saved", timeout=15)
            on_disk = saved and (ROOT / "sessions" / saved["name"]).is_file()
            mode = oct((ROOT / "sessions" / saved["name"]).stat().st_mode & 0o777) if on_disk else "?"
            check("save session writes a file to sessions/, mode 0600",
                  on_disk and mode == "0o600",
                  f"{(saved or {}).get('name')} holding {(saved or {}).get('flows')} flow(s), mode {mode}")

            listed = None
            if saved:
                await say(conn, type="sessions.list")
                got = await recv_until(conn, lambda m: m.get("type") == "sessions")
                listed = any(i["name"] == saved["name"] for i in (got or {}).get("items", []))
            check("the saved session appears in the picker", bool(listed))

            # Path traversal must be refused: the name arrives over the bridge.
            await say(conn, type="session.load", name="../requirements.txt")
            err = await recv_until(conn, lambda m: m.get("type") == "error", timeout=8)
            check("session.load refuses a traversal path", err is not None,
                  f"rejected with {(err or {}).get('message')!r}")
            global SAVED_NAME
            SAVED_NAME = saved["name"] if saved else None

            # ------------------------------------------------- P4 rules + repeater
            # Rules rewrite with nobody watching: no pause, no queue, no clicking.
            await say(conn, type="mode.set", mode="capture", scope="")
            await recv_until(conn, lambda m: m.get("type") == "state" and m.get("mode") == "capture")
            # '|' separator: the pattern contains slashes and quotes, and the
            # separator must not appear anywhere in the pattern.
            await say(conn, type="rules.set",
                      body=['|~u /ruled|"amount":100|"amount":31337'],
                      headers=["|~q|X-Injected-By|interceptor"])
            await recv_until(conn, lambda m: m.get("type") == "state" and m.get("rules_body"))
            rc, out, code, _ = await asyncio.to_thread(
                curl_full, "/ruled", '{"amount":100,"currency":"EUR"}')
            body_ok = '"amount":31337' in out and '"amount":100' not in out
            check("a body rule rewrites in flight with nothing paused",
                  rc == 0 and body_ok, f"target echoed {out.strip()[:70]}")
            # The echo target only returns the body, so the header has to be read
            # back from the proxy's own view of the request it forwarded.
            ruled = await recv_until(
                conn, lambda m: m.get("type") == "flow" and m.get("path") == "/ruled")
            hdrs: dict[str, str] = {}
            if ruled:
                await say(conn, type="body.get", id=ruled["id"], which="request")
                b = await recv_until(
                    conn, lambda m: m.get("type") == "body" and m.get("id") == ruled["id"])
                hdrs = {k.lower(): v for k, v in ((h[0], h[1]) for h in
                                                  ((b or {}).get("detail") or {}).get("headers", []))}
            check("a header rule adds a header to the forwarded request",
                  hdrs.get("x-injected-by") == "interceptor",
                  f"proxy-side request headers show x-injected-by={hdrs.get('x-injected-by')!r}"
                  if ruled else "flow for /ruled never arrived")
            await say(conn, type="rules.set", body=[], headers=[])
            await recv_until(conn, lambda m: m.get("type") == "state" and not m.get("rules_body"))

            # Repeater: resend a captured request with an edit, and confirm the
            # original row is untouched (replay.client mutates what it is given).
            rc, out, code, _ = await asyncio.to_thread(
                curl_full, "/repeat-me", '{"n":1}')
            orig = await recv_until(
                conn, lambda m: m.get("type") == "flow" and m.get("path") == "/repeat-me"
                and m.get("status") is not None)
            if orig is None:
                check("repeater resends an edited copy", False, "original flow never seen")
            else:
                raw = None
                await say(conn, type="body.get", id=orig["id"], which="request")
                bod = await recv_until(conn, lambda m: m.get("type") == "body")
                raw = ((bod or {}).get("detail") or {}).get("raw")
                head, _, _ = (raw or "").partition("\n\n")
                await say(conn, type="replay", id=orig["id"],
                          raw=f"{head}\n\n" + json.dumps({"n": 2, "via": "repeater"}))
                rep = await recv_until(
                    conn, lambda m: m.get("type") == "flow"
                    and m.get("replay_of") == orig["id"] and m.get("status") is not None,
                    timeout=20)
                check("repeater resends an edited copy as a new flow",
                      rep is not None and rep["id"] != orig["id"],
                      f"new flow {'yes' if rep else 'no'}, "
                      f"replay_of set: {(rep or {}).get('replay_of') == orig['id']}")
                # replay.client clears response/error on the flow it is handed, so
                # ask the server for the ORIGINAL's response again: if we had
                # replayed the original instead of a copy, this comes back empty.
                await say(conn, type="body.get", id=orig["id"], which="response")
                b = await recv_until(
                    conn, lambda m: m.get("type") == "body" and m.get("id") == orig["id"]
                    and m.get("which") == "response", timeout=10)
                intact = bool((b or {}).get("detail"))
                check("repeating does not blank the original flow's response", intact,
                      "replay.client mutates its argument, so a copy is replayed"
                      if intact else "original lost its response — a copy was NOT used")

            # ------------------------------------------- P3 WebSocket edit+inject
            # The handshake is an HTTP request on the same flow, so it gets held
            # too; forward it, then tamper with the first frame the client sends.
            await arm(conn, "~u /")
            got: list[str] = []
            WS_RECEIVED.clear()

            async def ws_client() -> None:
                async with websockets.connect(
                    f"ws://{WS_TARGET[0]}:{WS_TARGET[1]}/", proxy=PROXY, open_timeout=25
                ) as c:
                    await c.send("hello")
                    got.append(await asyncio.wait_for(c.recv(), 25))  # echo of the tampered frame
                    got.append(await asyncio.wait_for(c.recv(), 25))  # the injected frame

            client = asyncio.create_task(ws_client())
            fid, tampered = None, False
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline and not tampered:
                m = await recv_until(conn, lambda m: m.get("type") == "flow.paused", timeout=10)
                if m is None:
                    break
                fid = m["id"]
                if m.get("direction") == "websocket":
                    await say(conn, type="resume", id=fid, raw="tampered",
                              seq=(m.get("frame") or {}).get("seq"))
                    tampered = True
                else:
                    await say(conn, type="resume", id=fid)

            # Stop intercepting, or the injected frame gets held as well.
            await say(conn, type="mode.set", mode="capture", scope="")
            await recv_until(conn, lambda m: m.get("type") == "state" and m.get("mode") == "capture")
            await say(conn, type="ws.inject", id=fid, to_client=True, text="injected-frame")
            try:
                await asyncio.wait_for(client, timeout=30)
            except (TimeoutError, asyncio.TimeoutError):
                client.cancel()

            check("editing a held WebSocket frame changes what the server receives",
                  tampered and WS_RECEIVED == ["tampered"],
                  f"client sent 'hello', server received {WS_RECEIVED}")
            check("injecting a frame delivers it to the client, unsent by the server",
                  got[1:] == ["injected-frame"] and "injected-frame" not in WS_RECEIVED,
                  f"client received {got}, server never saw it: "
                  f"{'injected-frame' not in WS_RECEIVED}")

            # --- UI vanishes with a flow still held
            await arm(conn, "~u /hold")
            fut = asyncio.create_task(asyncio.to_thread(curl, "/hold-orphan", 20))
            first = await recv_until(conn, lambda m: m.get("type") == "flow.paused")
            orphaned = first is not None and not fut.done()
            await conn.close()
        rc, secs = await fut
        check("closing the UI force-forwards held flows instead of hanging",
              orphaned and rc == 0, f"curl rc={rc} in {secs:.2f}s")
    finally:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        ws_srv.close()
        (ROOT / URL_FILE).unlink(missing_ok=True)


async def restart_and_load() -> None:
    """Boot a completely fresh instance and open the session the first one saved.
    Nothing survives in memory across this, so a pass means the file is real."""
    if not SAVED_NAME:
        return check("a saved session survives a restart", None, "nothing was saved to load")
    for _ in range(20):
        if all(port_free(p) for p in (PROXY_PORT, UI_PORT)):
            break
        await asyncio.sleep(0.5)
    (ROOT / URL_FILE).unlink(missing_ok=True)
    proc = subprocess.Popen(
        # No --chain: chaining is opt-in, so an instance booted plainly always goes
        # direct, whatever proxy client this machine happens to be running.
        ["./run.sh"], cwd=ROOT, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, start_new_session=True,
        env={**os.environ, "IC_LISTEN_PORT": str(PROXY_PORT),
             "IC_UI_PORT": str(UI_PORT), "IC_URL_FILE": URL_FILE,
             "IC_OPEN_UI": "false"},
    )
    try:
        url = await wait_url(time.monotonic() + 30)
        if not url:
            return check("a saved session survives a restart", False, "second instance never came up")
        token = url.split("#token=", 1)[1]
        async with websockets.connect(
            f"ws://127.0.0.1:{UI_PORT}/ws?token={token}", origin=UI, open_timeout=10
        ) as conn:
            await say(conn, type="hello")
            fresh = await recv_until(conn, lambda m: m.get("type") == "snapshot")
            started_empty = fresh is not None and not fresh.get("flows")

            await say(conn, type="session.load", name=SAVED_NAME)
            seen: list = []
            loaded = await recv_until(
                conn, lambda m: m.get("type") == "loaded", timeout=25, collect=seen)
            marker = next((m for m in seen if m.get("type") == "flow"
                           and m.get("path") == "/session-marker"), None)
            check("a fresh instance starts empty and nothing auto-loads", started_empty,
                  f"snapshot had {len((fresh or {}).get('flows', []))} flow(s)")
            check("opening a saved session restores its flows after a restart",
                  loaded is not None and marker is not None,
                  f"loaded {(loaded or {}).get('flows')} flow(s); marker flow present: {marker is not None}")
    finally:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        (ROOT / URL_FILE).unlink(missing_ok=True)


def guard_refuses() -> None:
    """run.sh must refuse before exec'ing mitmdump. Safe to run for real: a pass
    means no process started, and the addon-level guard cannot help here -- the
    proxy listener is up before scripts load."""
    cases = {
        "IC_LISTEN_HOST env": (["./run.sh"], {"IC_LISTEN_HOST": "0.0.0.0"}),
        "--set listen_host": (["./run.sh", "--set", "listen_host=0.0.0.0"], {}),
        "--set ui_host": (["./run.sh", "--set", "ui_host=0.0.0.0"], {}),
        "--listen-host": (["./run.sh", "--listen-host", "10.0.0.5"], {}),
        # mitmproxy documents "--mode, -m", and a mode spec's own bind address wins
        # over listen_host. Every spelling has to be covered or the guard is theatre.
        "--mode": (["./run.sh", "--mode", "regular@0.0.0.0:8080"], {}),
        "--mode=": (["./run.sh", "--mode=regular@0.0.0.0:8080"], {}),
        "-m separated": (["./run.sh", "-m", "regular@0.0.0.0:8080"], {}),
        "-m attached": (["./run.sh", "-mregular@0.0.0.0:8080"], {}),
        # Short flags cluster, and both spellings of that reached the bind before
        # the guard walked clusters instead of matching "-m" literally.
        "-qm clustered": (["./run.sh", "-qm", "regular@0.0.0.0:8080"], {}),
        "-qm attached": (["./run.sh", "-qmregular@0.0.0.0:8080"], {}),
        "--set mode=": (["./run.sh", "--set", "mode=regular@0.0.0.0:8080"], {}),
    }
    bad = []
    for label, (argv, env) in cases.items():
        p = subprocess.run(argv, cwd=ROOT, env={**os.environ, **env},
                           capture_output=True, text=True, timeout=30)
        if p.returncode != 2 or "refusing to bind off loopback" not in p.stderr:
            bad.append(f"{label} -> rc={p.returncode}")
    check("run.sh refuses to launch bound off loopback", not bad,
          f"not refused: {bad}" if bad else f"{len(cases)} entry paths refused, rc=2")

    # 192.0.2.1 is TEST-NET-1: non-loopback, so the guard must decide about it, but
    # not an address this machine owns, so the bind fails and nothing is ever
    # published -- true even if this suite were run as root.
    # The guard must not over-refuse: a value-taking short flag swallows the rest of
    # its cluster, so the m in `-pm 8080` is part of -p's value, not a mode.
    benign = subprocess.run(["./run.sh", "-pm", "8080", "--set", "listen_port=1"],
                            cwd=ROOT, env={**os.environ, "IC_URL_FILE": URL_FILE,
                                           "IC_UI_PORT": str(UI_PORT), "IC_OPEN_UI": "false"},
                            capture_output=True, text=True, timeout=60)
    (ROOT / URL_FILE).unlink(missing_ok=True)
    check("the guard does not mistake a short flag's value for a mode",
          "refusing to bind off loopback" not in benign.stderr,
          "-pm 8080 reached mitmproxy" if "refusing" not in benign.stderr
          else "wrongly refused")

    p = subprocess.run(["./run.sh", "--set", "listen_host=192.0.2.1", "--set", "expose=true"],
                       cwd=ROOT, env={**os.environ, "IC_URL_FILE": URL_FILE,
                                      "IC_UI_PORT": str(UI_PORT), "IC_OPEN_UI": "false"},
                       capture_output=True, text=True, timeout=60)
    (ROOT / URL_FILE).unlink(missing_ok=True)
    check("expose=true gets past the guard", "refusing to bind off loopback" not in p.stderr,
          "reached mitmproxy's own bind, which then failed as intended"
          if "refusing" not in p.stderr else "still refused")


def units_row_filter() -> None:
    """The row filter takes a regex, and a half-typed one must not blank the table.
    Both branches run under node against the shipped matchesRow."""
    import json as _json

    harness = r"""
      import { readFileSync } from "node:fs";
      const src = readFileSync("ui/app.js", "utf8");
      const grab = (name) => {
        const i = src.indexOf(`function ${name}(`);
        if (i < 0) throw new Error(`missing ${name}`);
        let depth = 0, j = src.indexOf("{", i);
        for (let k = j; k < src.length; k++) {
          if (src[k] === "{") depth++;
          else if (src[k] === "}" && --depth === 0) return src.slice(i, k + 1);
        }
        throw new Error(`unbalanced ${name}`);
      };
      const code = ['let rowFilter = ""; let rowFilterRe = null;',
                    "function renderTable() {}",      // matchesRow's caller needs a DOM
                    grab("setRowFilter"), grab("matchesRow")].join("\n");
      const fns = new Function(code + "; return {setRowFilter, matchesRow};")();
      const rows = JSON.parse(process.env.ROWS);
      console.log(JSON.stringify(JSON.parse(process.env.PATTERNS).map((p) => {
        fns.setRowFilter(p);
        return rows.filter(fns.matchesRow).map((r) => r.path);
      })));
    """

    rows = [
        {"method": "GET", "status": 200, "host": "h", "port": 443, "path": "/api/users", "ctype": "application/json"},
        {"method": "POST", "status": 500, "host": "h", "port": 443, "path": "/api/orders", "ctype": "application/json"},
        {"method": "GET", "status": 200, "host": "h", "port": 443, "path": "/static/logo.png", "ctype": "image/png"},
        {"method": "GET", "status": 304, "host": "h", "port": 8080, "path": "/health", "ctype": ""},
    ]
    patterns = [
        "",                 # everything
        "/api/",            # plain text, also a valid regex
        r"\.(png|jpg)",     # a real regex
        "PNG",              # case-insensitive
        "^POST",            # anchored at the start of the row
        "(png",             # invalid regex -> substring, matches nothing
        "8080",             # the port is searchable because the row shows it
    ]
    want = [
        ["/api/users", "/api/orders", "/static/logo.png", "/health"],
        ["/api/users", "/api/orders"],
        ["/static/logo.png"],
        ["/static/logo.png"],
        ["/api/orders"],
        [],
        ["/health"],
    ]
    out = subprocess.run(
        ["node", "--input-type=module", "-e", harness], cwd=ROOT,
        capture_output=True, text=True, timeout=60,
        env={**os.environ, "ROWS": _json.dumps(rows), "PATTERNS": _json.dumps(patterns)},
    )
    if out.returncode != 0:
        return check("the row filter matches text and regex", False,
                     f"node failed: {out.stderr.strip()[:200]}")
    got = _json.loads(out.stdout)
    bad = [f"{p!r} -> {g} want {w}" for p, g, w in zip(patterns, got, want) if g != w]
    check("the row filter takes text or regex and survives a half-typed one",
          not bad, "; ".join(bad) or f"{len(patterns)} patterns correct, bad regex falls back")


def units_flow_store() -> None:
    """The store keeps completed flows on disk and in-flight ones in RAM. Two
    things must hold or it is worse than the OrderedDict it replaced:

    * a flow read back from SQLite has to be usable -- body, raw editable text
    * a flow still in flight, or held, or on an open socket, must come back as the
      *same object*, because resume() and inject.websocket act on identity. A
      rehydrated copy would look right, release nothing, and strand the client.
    """
    import interceptor as I
    from mitmproxy.test import tflow
    from mitmproxy.websocket import WebSocketMessage

    store = I.FlowStore()
    notes = []
    CAP = 512 * 1024 * 1024
    try:
        # Completed flow -> serialised, released, and readable again.
        done = tflow.tflow(resp=True)
        done.request.raw_content = b'{"q":1}'
        done.response.raw_content = b'{"a":2}'
        store.put(done, 14, I.summary(done), CAP)
        fid = done.id
        store.flush()
        # Drop every RAM reference the store holds, so a hit can only come from disk.
        store._cache.clear()
        back = store.get(fid)
        if back is None:
            notes.append("completed flow could not be read back from disk")
        else:
            if back is done:
                notes.append("cache was not actually cleared; disk path untested")
            if (back.response.raw_content or b"") != b'{"a":2}':
                notes.append(f"body corrupted on round trip: {back.response.raw_content!r}")
            if I.raw_text(back, "request") is None:
                notes.append("rehydrated flow has no editable raw text")

        # In flight (no response yet) -> same object, never serialised away.
        flight = tflow.tflow(resp=False)
        store.put(flight, 10, I.summary(flight), CAP)
        store.flush()
        store._cache.clear()
        if store.get(flight.id) is not flight:
            notes.append("an in-flight flow did not come back as the same object")

        # Held -> same object, or resume() would act on a copy.
        held = tflow.tflow(resp=True)
        held.intercepted = True
        store.put(held, 10, I.summary(held), CAP)
        store.flush()
        store._cache.clear()
        if store.get(held.id) is not held:
            notes.append("a held flow did not come back as the same object")

        # Open socket -> same object, or inject.websocket would hit a copy.
        ws = tflow.twebsocketflow()
        ws.websocket.timestamp_end = None
        store.put(ws, 10, I.summary(ws), CAP)
        store.flush()
        store._cache.clear()
        if store.get(ws.id) is not ws:
            notes.append("an open WebSocket did not come back as the same object")
        # ...and once it closes it may be released.
        ws.websocket.timestamp_end = 1.0
        ws.websocket.messages.append(WebSocketMessage(1, True, b"last"))
        store.put(ws, 14, I.summary(ws), CAP)
        store.flush()
        store._cache.clear()
        reread = store.get(ws.id)
        if reread is None or len(reread.websocket.messages) != len(ws.websocket.messages):
            notes.append("a closed socket's frames did not survive the round trip")

        # Summaries come back newest-last, which is the order the UI appends in.
        got = [s["id"] for s in store.summaries()]
        if got[-1] != ws.id:
            notes.append(f"summaries are not in last-updated order: {got[-1][:8]}")
        if len(got) != len(store):
            notes.append(f"summaries {len(got)} != index {len(store)}")
    finally:
        store.close()
    check("the flow store round-trips through SQLite and keeps live flows by identity",
          not notes, "; ".join(notes) or "disk read intact; in-flight, held and open "
                                        "sockets kept by identity")


def units_decrypt_scope() -> None:
    """The decrypt allowlist is mitmproxy's `allow_hosts`, so the part that is ours
    is validation: a bad pattern must be refused with the working list left in
    force, exactly like the scope filter. A rejected pattern that still got stored
    would silently stop decrypting the host under test."""
    import interceptor as I
    from mitmproxy.addons import modifybody, modifyheaders
    from mitmproxy.test import taddons

    class Collect:
        def __init__(self):
            self.clients = {"x"}
            self.sent = []

        def push(self, type_, **payload):
            self.sent.append({"type": type_, **payload})

    addon = I.Interceptor()
    notes = []
    # _push_state reads modify_body/modify_headers, so their owners must be loaded.
    with taddons.context(addon, modifybody.ModifyBody(),
                         modifyheaders.ModifyHeaders()) as tctx:
        tctx.configure(addon, hide_noise=False)
        addon.bridge = Collect()

        addon._set_decrypt(["app.example.com", " api.example.com "])
        if list(ctx_opt(tctx, "allow_hosts")) != ["app.example.com", "api.example.com"]:
            notes.append(f"good patterns not stored/trimmed: {ctx_opt(tctx, 'allow_hosts')}")

        # A bad regex must be refused outright, keeping what already worked.
        addon.bridge.sent.clear()
        addon._set_decrypt(["ok.example.com", "*nope(("])
        errs = [m for m in addon.bridge.sent if m["type"] == "error"]
        if not errs:
            notes.append("bad pattern accepted without an error")
        if list(ctx_opt(tctx, "allow_hosts")) != ["app.example.com", "api.example.com"]:
            notes.append(f"bad batch clobbered the working list: {ctx_opt(tctx, 'allow_hosts')}")

        # Empty means decrypt everything again -- the documented way back.
        addon._set_decrypt([])
        if list(ctx_opt(tctx, "allow_hosts")) != []:
            notes.append("empty list did not clear the allowlist")

        # And it has to reach the UI, or an active allowlist is invisible.
        addon._set_decrypt(["only.example.com"])
        addon.bridge.sent.clear()
        addon._push_state()
        state = next((m for m in addon.bridge.sent if m["type"] == "state"), {})
        if state.get("allow_hosts") != ["only.example.com"]:
            notes.append(f"state does not carry allow_hosts: {state.get('allow_hosts')}")

    check("the decrypt allowlist validates and never half-applies",
          not notes, "; ".join(notes) or "trimmed, bad regex refused, clearable, in state")


def ctx_opt(tctx, name):
    return getattr(tctx.options, name)


def units_pretty_body() -> None:
    """The editor indents a JSON body for reading, and what it produces can be
    forwarded. So the header block must come back byte-identical, a non-JSON body
    must be left completely alone, and the blank-line split must land on the
    header separator and not on a blank line inside the body -- anything else
    silently corrupts an outgoing request."""
    import json as _json

    harness = r"""
      import { readFileSync } from "node:fs";
      const src = readFileSync("ui/app.js", "utf8");
      const grab = (name) => {
        const i = src.indexOf(`function ${name}(`);
        if (i < 0) throw new Error(`missing ${name}`);
        let depth = 0, j = src.indexOf("{", i);
        for (let k = j; k < src.length; k++) {
          if (src[k] === "{") depth++;
          else if (src[k] === "}" && --depth === 0) return src.slice(i, k + 1);
        }
        throw new Error(`unbalanced ${name}`);
      };
      const code = [grab("pretty"), grab("splitRaw"), grab("prettyRaw")].join("\n");
      const fns = new Function(code + "; return {prettyRaw, splitRaw};")();
      console.log(JSON.stringify(JSON.parse(process.env.CASES).map((raw) => {
        const out = fns.prettyRaw(raw);
        const parts = fns.splitRaw(raw);
        return { out, headKept: parts ? out.startsWith(parts.head) : out === raw };
      })));
    """

    head = "POST /pay HTTP/1.1\nHost: h\ncontent-type: application/json\n\n"
    cases = [
        head + '{"a":1,"b":[2,3]}',                 # JSON: indented
        head + "not json at all",                   # left alone
        head + "",                                  # empty body
        "GET /x HTTP/1.1\nHost: h\n",               # no blank line at all
        # A blank line inside a text body must not be mistaken for the separator.
        "POST /x HTTP/1.1\nHost: h\n\nline1\n\nline3",
        # multipart: CRLF boundaries must survive untouched
        "POST /u HTTP/1.1\nHost: h\n\n--B\r\nContent-Disposition: form-data\r\n\r\nv\r\n--B--\r\n",
    ]
    out = subprocess.run(
        ["node", "--input-type=module", "-e", harness], cwd=ROOT,
        capture_output=True, text=True, timeout=60,
        env={**os.environ, "CASES": _json.dumps(cases)},
    )
    if out.returncode != 0:
        return check("the editor's pretty-print only touches the body", False,
                     f"node failed: {out.stderr.strip()[:200]}")
    got = _json.loads(out.stdout)
    bad = []
    if got[0]["out"] != head + '{\n  "a": 1,\n  "b": [\n    2,\n    3\n  ]\n}':
        bad.append(f"JSON body not indented: {got[0]['out']!r}")
    for i, label in ((1, "non-JSON body"), (2, "empty body"), (3, "no blank line"),
                     (4, "blank line inside body"), (5, "multipart CRLF body")):
        if got[i]["out"] != cases[i]:
            bad.append(f"{label} was modified: {got[i]['out']!r}")
    if not all(g["headKept"] for g in got):
        bad.append("header block did not survive byte-for-byte")
    check("the editor's pretty-print only touches the body",
          not bad, "; ".join(bad) or f"{len(cases)} cases correct, headers byte-identical")


def units_rule_builder() -> None:
    """The rule form composes and parses mitmproxy specs. A wrong separator or a
    bad round-trip silently rewrites someone's rule, so both directions are checked
    against the real parser -- node builds the spec, mitmproxy parses it."""
    import json as _json
    from mitmproxy.addons.modifyheaders import parse_modify_spec

    # Drive the browser's own compose/parse code under node, so the check exercises
    # the shipped functions rather than a Python restatement of them.
    harness = r"""
      import { readFileSync } from "node:fs";
      const src = readFileSync("ui/app.js", "utf8");
      // Pull just the pure helpers; the rest of app.js needs a DOM.
      const grab = (name) => {
        const i = src.indexOf(`function ${name}(`);
        if (i < 0) throw new Error(`missing ${name}`);
        let depth = 0, j = src.indexOf("{", i);
        for (let k = j; k < src.length; k++) {
          if (src[k] === "{") depth++;
          else if (src[k] === "}" && --depth === 0) return src.slice(i, k + 1);
        }
        throw new Error(`unbalanced ${name}`);
      };
      const seps = src.match(/const SEP_CANDIDATES = \[[\s\S]*?\];/)[0];
      const code = [seps, grab("pickSep"), grab("filterFor"), grab("composeRule"),
                    grab("splitSpec"), grab("ruleFromSpec")].join("\n");
      const fns = new Function(code + "; return {composeRule, ruleFromSpec};")();
      const cases = JSON.parse(process.env.CASES);
      console.log(JSON.stringify(cases.map((c) =>
        c.kind === "compose" ? fns.composeRule(c.rule) : fns.ruleFromSpec(c.spec))));
    """

    cases = [
        # compose: the separator must avoid the filter and the find text
        {"kind": "compose", "rule": {"where": "req", "url": "/api/", "find": "a", "repl": "b", "raw": None}},
        {"kind": "compose", "rule": {"where": "both", "url": "", "find": "x|y", "repl": "z", "raw": None}},
        {"kind": "compose", "rule": {"where": "resp", "url": "", "find": "a:b|c#d@e", "repl": "q", "raw": None}},
        {"kind": "compose", "rule": {"where": "both", "url": "", "find": "a", "repl": "keep|the|pipes", "raw": None}},
        {"kind": "compose", "rule": {"where": "both", "url": "", "find": "  ", "repl": "z", "raw": None}},
        # parse: simple shapes become forms, anything else stays raw
        {"kind": "parse", "spec": "|~q & ~u /api/|a|b"},
        {"kind": "parse", "spec": "|~s|a|b"},
        {"kind": "parse", "spec": "|a|b"},
        {"kind": "parse", "spec": "|~c 500 & ~t json|a|b"},
    ]
    out = subprocess.run(["node", "--input-type=module", "-e", harness],
                         cwd=ROOT, capture_output=True, text=True, timeout=60,
                         env={**os.environ, "CASES": _json.dumps(cases)})
    if out.returncode != 0:
        return check("the rule form composes and parses specs correctly", False,
                     f"node failed: {out.stderr.strip()[:160]}")
    got = _json.loads(out.stdout)

    notes = []
    # 1-4: every composed spec must parse, and mean what the form said
    for i in range(4):
        spec = got[i]
        if not spec:
            notes.append(f"case {i} composed nothing")
            continue
        try:
            parse_modify_spec(spec, True)
        except Exception as e:
            notes.append(f"case {i} spec {spec!r} rejected by mitmproxy: {e}")
    # the find text containing every obvious separator must still work
    if got[2] and got[2][0] in "a:b|c#d@e":
        notes.append(f"case 2 picked a separator present in the find text: {got[2]!r}")
    # a replacement may contain the separator -- it is the untouched tail
    if got[3] and not got[3].endswith("keep|the|pipes"):
        notes.append(f"case 3 mangled the replacement: {got[3]!r}")
    # an empty find is not a rule
    if got[4] is not None:
        notes.append(f"case 4 built a rule from an empty find: {got[4]!r}")
    # 5-8: parse results
    want = [
        {"where": "req", "url": "/api/", "raw": None},
        {"where": "resp", "url": "", "raw": None},
        {"where": "both", "url": "", "raw": None},
        {"raw": "|~c 500 & ~t json|a|b"},
    ]
    for i, w in enumerate(want, start=5):
        g = got[i]
        for k, v in w.items():
            if g.get(k) != v:
                notes.append(f"parse case {i}: {k}={g.get(k)!r} want {v!r}")

    check("the rule form composes specs mitmproxy accepts and parses them back",
          not notes, "; ".join(notes) or f"{len(cases)} cases correct, separators avoided")


def units_chain_flag() -> None:
    """--chain turns whatever proxy is configured into an upstream mode. Checked at
    the shell level, without launching: it must chain when a proxy is present, run
    direct when none is, and never smuggle a public bind past the loopback guard."""
    probe = r'''
set -uo pipefail
eval "$(sed -n '/^detect_proxy()/,/^}/p' ./run.sh)"
case "${1:-}" in
  env)  command() { if [ "${2:-}" = "scutil" ]; then return 1; fi; builtin command "$@"; }
        export HTTPS_PROXY=http://127.0.0.1:9999 ;;
  none) command() { if [ "${2:-}" = "scutil" ]; then return 1; fi; builtin command "$@"; }
        unset HTTPS_PROXY https_proxy HTTP_PROXY http_proxy ;;
esac
printf '%s' "$(detect_proxy)"
'''
    def detect(mode: str) -> str:
        return subprocess.run(["bash", "-c", probe, "bash", mode], cwd=ROOT,
                              capture_output=True, text=True, timeout=30).stdout.strip()

    notes = []
    if not detect("env").startswith("http://127.0.0.1:9999"):
        notes.append(f"env fallback did not resolve: {detect('env')!r}")
    if detect("none") != "":
        notes.append(f"no proxy anywhere should resolve empty, got {detect('none')!r}")
    check("--chain resolves a proxy when there is one and nothing when there is not",
          not notes, "; ".join(notes) or "env fallback and empty case both correct")

    # Chaining must not become a way around the loopback guard, in either spelling.
    for label, argv in (("--chain", ["./run.sh", "--chain", "-qm", "regular@0.0.0.0:8080"]),
                        ("default", ["./run.sh", "-qm", "regular@0.0.0.0:8080"])):
        p = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, timeout=30)
        if p.returncode != 2 or "refusing to bind off loopback" not in p.stderr:
            notes.append(f"{label} did not refuse: rc={p.returncode}")
    check("chaining does not smuggle a public bind past the guard", not notes,
          "; ".join(notes) or "both spellings refused with rc=2")

    # is_self: a system proxy pointing at this very listener must not become our own
    # upstream. Checked at the shell level; a real run would just loop.
    self_probe = r'''
set -uo pipefail
eval "$(sed -n '/^proxy_hostport()/,/^}/p;/^is_self()/,/^}/p' ./run.sh)"
IC_LISTEN_PORT=8080
is_self "http://127.0.0.1:8080" && printf 'self ' || printf 'notself '
is_self "http://localhost:8080" && printf 'self ' || printf 'notself '
is_self "http://127.0.0.1:7897" && printf 'self' || printf 'notself'
'''
    got = subprocess.run(["bash", "-c", self_probe], cwd=ROOT,
                         capture_output=True, text=True, timeout=30).stdout.strip()
    check("a system proxy pointing at this listener is not adopted as upstream",
          got == "self self notself", f"got {got!r} (want 'self self notself')")


def cleanup_saved_session() -> None:
    """The suite writes a real file into the user's sessions/ folder to prove the
    save path. Leaving it there would clutter the picker a little more every run."""
    if not SAVED_NAME:
        return
    path = ROOT / "sessions" / SAVED_NAME
    path.unlink(missing_ok=True)
    sessions = ROOT / "sessions"
    if sessions.is_dir() and not any(sessions.iterdir()):
        # It did not exist before the first save, so do not leave it behind either.
        sessions.rmdir()


async def main() -> int:
    units()
    guard_refuses()
    units_chain_flag()
    units_rule_builder()
    units_row_filter()
    units_pretty_body()
    units_flow_store()
    units_decrypt_scope()
    await integration()
    await restart_and_load()
    cleanup_saved_session()
    print()
    width = max(len(n) for n, _, _ in RESULTS)
    for name, ok, detail in RESULTS:
        label = "SKIP" if ok is None else "PASS" if ok else "FAIL"
        print(f"  {label}  {name.ljust(width)}  {detail}")
    failed = [n for n, ok, _ in RESULTS if ok is False]
    skipped = [n for n, ok, _ in RESULTS if ok is None]
    tail = f", {len(skipped)} skipped" if skipped else ""
    print(f"\n  {len(RESULTS) - len(failed) - len(skipped)}/{len(RESULTS)} passed{tail}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
