"""Interceptor: flow store, mode switch, pause queue, UI bridge, Chrome launcher.

Run:  ./run.sh          (mitmdump -s addon/interceptor.py)

Interception itself is the built-in `Intercept` addon's job -- we set
`ctx.options.intercept` to a filter expression and it handles HTTP requests and
responses, WebSocket messages, TCP, UDP and DNS, including the `is_replay`
guard. This addon owns the half that is actually ours: what to store, what to
show, and how to resume with edits.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import webbrowser
from collections import Counter, OrderedDict
from datetime import datetime
from pathlib import Path

from mitmproxy import command, ctx, exceptions, flowfilter, http
from mitmproxy.addons import intercept
from mitmproxy.log import ALERT
from mitmproxy.proxy.mode_specs import ProxyMode

sys.path.insert(0, str(Path(__file__).resolve().parent))
import faults as faultlib  # noqa: E402
import views  # noqa: E402
from bridge import Bridge  # noqa: E402
from exporters import FORMATS as EXPORT_FORMATS, export_text, write_har  # noqa: E402
from store import FlowStore  # noqa: E402

# Two modes, because a mode only answers one question: does a matching flow stop?
# What gets opened up is a separate axis, and it belongs to the Decrypt list.
# Passthrough used to conflate the two -- it was "open nothing", which the Decrypt
# list expresses as a pattern matching no host, so the mode was one concept too
# many and read as "the tool is broken" whenever it was left on.
MODES = ("intercept", "capture")

# Saved sessions live here. Nothing is ever written without an explicit click:
# a .mitm file is every captured request in plaintext, cookies and bearer tokens
# included, so it must be a deliberate act rather than a default.
SESSIONS = Path(__file__).resolve().parent.parent / "sessions"

# Chrome talks to these entirely on its own. They drown a QA session and are
# never the thing under test. Counted and reported in the UI, never silently
# dropped -- a hidden flow the user does not know about is a bug report.
# Telemetry subdomains only, never the googleapis.com apex: Firebase, Firestore,
# Cloud Storage, Maps and Identity Platform all live under it, so hiding the apex
# hides the application under test -- the exact failure this comment warns about.
NOISE_DOMAINS = (
    r"clients[0-9]*\.google\.com|.*\.gstatic\.com|"
    r"safebrowsing\.googleapis\.com|sb-ssl\.google\.com|"
    r"optimizationguide-pa\.googleapis\.com|content-autofill\.googleapis\.com|"
    r"update\.googleapis\.com|play\.googleapis\.com|"
    r"accounts\.google\.com|.*\.doubleclick\.net"
)
# Quoted so the regex's own parentheses are not read as filter grouping.
NOISE_FILTER = f'!~d "{NOISE_DOMAINS}"'

# Bodies past this are streamed, which means they are never buffered and cannot
# be edited. The UI labels them so non-editability is never a silent surprise.
MAX_EDITABLE_BODY = 5 * 1024 * 1024

CHROME_PATHS = (
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    "google-chrome",
    "google-chrome-stable",
    "chromium",
    "chromium-browser",
)


def _is_loopback(host: str) -> bool:
    """Anything we cannot positively identify as loopback counts as public --
    including "" (mitmproxy's own default, which binds every interface) and any
    hostname, whose resolution we are not going to vouch for here."""
    if host in ("localhost", "localhost."):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _frame_view(data: bytes, n: int = 4096) -> tuple[str, bool, bool]:
    """Returns (rendered, is_binary, truncated). Binary frames render as spaced
    hex, which is also the format the inject box accepts back.

    The text/binary decision is made on the *whole* frame, never on the first n
    bytes: a UTF-8 sequence straddling the cut would otherwise make a plain text
    frame render as hex. `truncated` exists because the editor writes this string
    back onto the wire -- a silently cut view means a silently cut payload.
    """
    try:
        text = data.decode()
    except UnicodeDecodeError:
        return data[:n].hex(" "), True, len(data) > n
    return text[:n], False, len(text) > n


def _open_private(path: Path) -> int:
    """Create a file that is 0600 from the first byte. write_text()-then-chmod()
    leaves it world-readable (0644 under the usual umask) for the whole write --
    for a session dump that window spans every captured request."""
    return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)


def is_ws_handshake(flow: http.HTTPFlow) -> bool:
    """A WebSocket flow starts life as an ordinary GET carrying `Upgrade:
    websocket`, and `flow.websocket` stays None until the 101 completes.

    Reading only `flow.websocket` meant a socket appeared under HTTP while its
    handshake was in flight -- most visibly in Intercept, where the handshake is
    held right at that moment -- and then vanished and reappeared under WebSocket
    once forwarded. Same flow, two tabs, looking like a duplicate. The Upgrade
    header is there from the first byte, so classify on that instead.
    """
    return "websocket" in flow.request.headers.get("upgrade", "").lower()


def summary(flow: http.HTTPFlow) -> dict:
    r, resp = flow.request, flow.response
    ms = None
    if resp and resp.timestamp_end and r.timestamp_start:
        ms = round((resp.timestamp_end - r.timestamp_start) * 1000)
    return {
        "id": flow.id,
        "method": r.method,
        "scheme": r.scheme,
        "host": r.host,
        "port": r.port,
        "path": r.path,
        "http_version": r.http_version,
        "status": resp.status_code if resp else None,
        "ctype": resp.headers.get("content-type", "").split(";")[0] if resp else "",
        "req_bytes": len(r.raw_content or b""),
        "resp_bytes": len(resp.raw_content or b"") if resp else 0,
        "start": r.timestamp_start,
        "ms": ms,
        # True from the handshake onwards, so a socket never starts under HTTP and
        # then hops tabs once it upgrades.
        "ws": flow.websocket is not None or is_ws_handshake(flow),
        "ws_frames": len(flow.websocket.messages) if flow.websocket else 0,
        # Whether the socket is still up, which a 101 status cannot tell you --
        # a closed connection keeps its handshake status forever.
        "ws_open": flow.websocket is not None and flow.websocket.timestamp_end is None,
        "streamed": bool(getattr(r, "stream", False))
        or bool(resp and getattr(resp, "stream", False)),
        "intercepted": flow.intercepted,
        "killed": bool(flow.error),
        "replay_of": flow.metadata.get("replay_of"),
        "is_replay": flow.is_replay,
        # A 503 you injected is indistinguishable from a real one without this.
        # Never omit it: an unlabelled fault is an hour spent debugging your own
        # rule, which is the one way this feature can cost more than it gives.
        "faulted": flow.metadata.get("faulted"),
    }


def raw_text(flow: http.HTTPFlow, which: str) -> str | None:
    """The whole message as one editable blob, Burp-style: start line, headers,
    blank line, body. None when the message is not safely round-trippable.

    Content-Encoding is deliberately omitted: the body below it is shown decoded,
    so leaving the header in would desync what the user sees from what is sent.
    """
    msg = flow.request if which == "request" else flow.response
    if msg is None or getattr(msg, "stream", False):
        return None
    raw = msg.raw_content or b""
    if len(raw) > MAX_EDITABLE_BODY:
        return None
    try:
        body = msg.get_text(strict=True) or ""
    except (ValueError, UnicodeDecodeError):
        # Not "binary" -- mitmproxy falls back to latin-1 for content types that
        # imply no encoding, so a PNG or protobuf body decodes and edits fine. This
        # fires when the bytes contradict a *declared* text encoding (JSON holding
        # binary, a wrong charset=) or when decompression fails.
        return None
    if which == "request":
        start = f"{msg.method} {msg.path} {msg.http_version}"
    else:
        start = f"{msg.http_version} {msg.status_code} {msg.reason}"
    lines = [start]
    lines += [
        f"{k}: {v}"
        for k, v in msg.headers.items(True)
        if k.lower() != "content-encoding"
    ]
    return "\n".join(lines) + "\n\n" + body


def parse_raw(text: str) -> tuple[str, list[tuple[str, str]], str]:
    """Split an edited raw message back into start line, headers and body.

    The body comes back exactly as typed. Only the header block is newline-
    normalised: normalising the whole message rewrote CRLF to LF inside the body
    too, which corrupts every multipart/form-data upload (RFC 7578 requires CRLF
    before each boundary) and any body where the bytes are the point.

    The separator is whichever of CRLFCRLF / LFLF comes first, so a pasted
    CRLF-only header block still parses -- "\\r\\n\\r\\n" contains no "\\n\\n",
    which is why the old code normalised before splitting.
    """
    crlf, lf = text.find("\r\n\r\n"), text.find("\n\n")
    if crlf != -1 and (lf == -1 or crlf < lf):
        head, body = text[:crlf], text[crlf + 4:]
    elif lf != -1:
        head, body = text[:lf], text[lf + 2:]
    else:
        head, body = text, ""  # no blank line: all headers, empty body
    lines = head.replace("\r\n", "\n").split("\n")
    if not lines or not lines[0].strip():
        raise ValueError("missing start line")
    headers = []
    for n, line in enumerate(lines[1:], start=2):
        if not line.strip():
            continue
        name, sep, value = line.partition(":")
        if not sep or not name.strip():
            raise ValueError(f"line {n} is not a header: {line[:60]!r}")
        headers.append((name.strip(), value.strip()))
    return lines[0].strip(), headers, body


def detail(flow: http.HTTPFlow, which: str) -> dict | None:
    msg = flow.request if which == "request" else flow.response
    if msg is None:
        return None
    raw = msg.raw_content or b""
    body, encoding = "", "text"
    if getattr(msg, "stream", False):
        encoding = "streamed"
    elif len(raw) > MAX_EDITABLE_BODY:
        encoding = "too-large"
    else:
        try:
            body = msg.get_text(strict=True) or ""
        except (ValueError, UnicodeDecodeError):
            body, encoding = base64.b64encode(raw).decode(), "base64"
    out = {
        "headers": list(msg.headers.items(True)),
        "body": body,
        "encoding": encoding,
        "size": len(raw),
        # A textarea cannot hold CRLF, so the UI's copy of the body is already
        # normalised and it cannot detect this for itself. Editing the headers is
        # safe (the original body is restored on the way back), editing the body
        # is not, and the editor needs to be able to say which.
        "body_crlf": "\r\n" in body,
    }
    out["raw"] = raw_text(flow, which)
    # Display only, and strictly additive: `body` and `raw` above are still the
    # exact bytes, because those are what the editor writes back onto the wire.
    # A protobuf rendering is not round-trippable and must never be mistaken for
    # one, so it travels in its own field and the UI never edits it.
    if encoding == "text":
        pretty = views.prettify(flow, msg)
        if pretty:
            out["pretty"], out["pretty_view"] = pretty
    if which == "request":
        out |= {"method": msg.method, "url": msg.url, "http_version": msg.http_version}
    else:
        out |= {"status": msg.status_code, "reason": msg.reason}
    return out


class Interceptor:
    def __init__(self) -> None:
        self.bridge: Bridge | None = None
        # Completed flows on disk, in-flight ones in RAM -- see store.py. Bodies
        # dominated memory, so the cap used to evict a morning's capture to make
        # room for the current page; now only the index is in RAM.
        self.store = FlowStore()
        # id -> (frames already counted, their total bytes). Frame bytes are
        # accumulated incrementally; re-summing the whole list per frame made
        # frame handling O(n^2) -- see _remember.
        self.ws_seen: dict[str, tuple[int, int]] = {}
        self.noise_hidden = 0
        self.auto_forwarded = 0
        self.paused: OrderedDict[str, tuple[str, http.HTTPFlow]] = OrderedDict()
        # Armed from the held-request editor: hold *this* flow's reply too, without
        # turning on the global toggle that makes every matching flow stop twice.
        self.stop_reply: set[str] = set()
        self.faults: list[faultlib.Fault] = []
        self.mode = "capture"
        self.scope = ""
        self.url_file: Path | None = None
        self.browsers: list[subprocess.Popen] = []
        self.tmpdirs: list[tempfile.TemporaryDirectory] = []
        self._noise = flowfilter.parse(NOISE_FILTER)
        self._state_pushed_at = 0.0  # throttles counter-only state pushes
        self._writer: asyncio.Task | None = None

    def load(self, loader) -> None:
        loader.add_option("ui_host", str, "127.0.0.1",
                          "UI bind host. Loopback only -- binding publicly exposes an open MITM proxy.")
        loader.add_option("ui_port", int, 9000, "UI port (static files and WebSocket share it).")
        loader.add_option("store_bytes", int, 2 * 1024 * 1024 * 1024,
                          "Flow store cap in BYTES of captured traffic. Bodies dominate, so the "
                          "cap is bytes rather than flow count. This is a cap on the store file, "
                          "not on memory -- only the index lives in RAM now -- so it is far more "
                          "generous than the 512MB it had to be when every body was resident. "
                          "The file itself runs larger than the cap by roughly half again "
                          "(serialisation, index and WAL overhead).")
        loader.add_option("hide_noise", bool, True,
                          "Hide browser background chatter from the flow table (counted, not silent).")
        loader.add_option("open_ui", bool, True,
                          "Open the UI in your default browser at startup. Automation "
                          "should set this false (the check suite does).")
        loader.add_option("url_file", str, ".ui-url",
                          "Where to write the UI URL. Tests override it so a run never "
                          "clobbers the file belonging to a real instance.")
        loader.add_option("intercept_responses", bool, False,
                          "Also hold responses. Off by default: a matching flow otherwise pauses "
                          "twice (once each way), which reads as the tool being broken.")
        loader.add_option("expose", bool, False,
                          "Permit binding off loopback. Refused without this: it publishes an "
                          "open MITM proxy and a UI that rewrites traffic to the whole network.")

    def configure(self, updated) -> None:
        # Startup passes every option through here, so this fires before the UI
        # bridge binds in running(); a later `set listen_host=...` re-triggers it.
        # It cannot save the *proxy* port, which mitmproxy binds before any script
        # addon even loads -- that is run.sh's job, see the note there.
        if {"listen_host", "ui_host", "mode", "expose"} & set(updated):
            self._check_bind()

    @staticmethod
    def _check_bind() -> None:
        public = {
            name: host
            for name, host in (("listen_host", ctx.options.listen_host),
                               ("ui_host", ctx.options.ui_host))
            if not _is_loopback(host)
        }
        # A mode spec carries its own bind address -- `regular@0.0.0.0:8080` -- and
        # proxyserver takes it over the listen_host option, so checking only the
        # option leaves an open proxy one flag away.
        for spec in ctx.options.mode:
            try:
                host = ProxyMode.parse(spec).listen_host("")
            except Exception:
                continue  # mitmproxy reports its own malformed specs
            if host and not _is_loopback(host):
                public[f"mode {spec}"] = host
        if not public:
            return
        where = ", ".join(f"{k}={v or '* (all interfaces)'}" for k, v in sorted(public.items()))
        if not ctx.options.expose:
            # Raise only. Rewriting the option back to loopback from here was tried
            # and is worse: ctx.options.update() inside load() swallows this very
            # exception, and the run then continues bound to 0.0.0.0 -- exactly the
            # outcome the guard exists to prevent. run.sh refuses before exec for
            # that reason; see the note there.
            raise exceptions.OptionsError(
                f"refusing to bind off loopback: {where}. The proxy port has no "
                f"authentication at all, so this publishes an open MITM proxy -- anyone "
                f"who can reach it can route traffic through you and read it decrypted. "
                f"Pass --set expose=true if you mean it, and firewall the port."
            )
        logging.log(ALERT,
                    f"EXPOSED: {where}. The proxy port is unauthenticated -- firewall it. "
                    f"The UI's Origin check is built from its bind address, so reaching it "
                    f"over a LAN IP will be rejected even with the right token.")

    async def running(self) -> None:
        if self.bridge:
            return
        # Chunked bodies declare no Content-Length, so the per-message check in
        # _maybe_stream cannot see their size. This is mitmproxy's own size-based
        # cutoff and it does cover them. Note that a streamed body is never
        # buffered, so rewrite rules cannot touch one either -- _set_rules says so.
        ctx.options.update(stream_large_bodies=str(MAX_EDITABLE_BODY))
        ui_dir = Path(__file__).resolve().parent.parent / "ui"
        self.bridge = Bridge(
            ctx.options.ui_host, ctx.options.ui_port, ui_dir,
            self._on_message, self._on_ui_gone,
            # Hex-encoded binary frames arrive at ~3x their byte size, so the
            # inbound cap is sized off the same constant the editor enforces --
            # under it, a large edit closed the socket and force-forwarded the lot.
            max_message_bytes=4 * MAX_EDITABLE_BODY,
        )
        await self.bridge.start()
        self._writer = asyncio.create_task(self._flush_loop())
        self._set_mode("capture")
        # mitmproxy's log stream is buffered when stdout is not a tty, so the URL
        # can vanish entirely when run.sh is redirected. Print unbuffered, and
        # also drop it in a file for scripts. The token is a credential: 0600.
        self.url_file = Path(__file__).resolve().parent.parent / ctx.options.url_file
        with os.fdopen(_open_private(self.url_file), "w") as fh:
            fh.write(self.bridge.url + "\n")  # 0600 from the first byte: it is a token
        print(f"\n  interceptor UI -> {self.bridge.url}\n", flush=True)
        logging.log(ALERT, f"interceptor UI -> {self.bridge.url}")
        self._warn_env_proxy()
        if ctx.options.open_ui:
            # Non-blocking, and it carries the token so there is nothing to copy.
            webbrowser.open(self.bridge.url)

    async def _flush_loop(self) -> None:
        """Batch flow writes off the hot path. One transaction per tick beats one
        per flow by three orders of magnitude at page-load rates, and the store's
        readers flush on demand so nothing is ever stale."""
        while True:
            await asyncio.sleep(0.1)
            self.store.flush()

    @staticmethod
    def _detected_proxy() -> str:
        """The proxy this machine is configured to use, as resolved by run.sh (which
        asks scutil first, so it sees a Clash/Surge toggle rather than a stale shell
        env). Falls back to this process's own environment when run directly."""
        return (os.environ.get("IC_DETECTED_PROXY")
                or next((os.environ[k] for k in ("HTTPS_PROXY", "https_proxy",
                                                 "HTTP_PROXY", "http_proxy")
                         if os.environ.get(k)), "")).strip()

    @staticmethod
    def _chained() -> bool:
        return any(m.startswith("upstream:") for m in ctx.options.mode)

    @staticmethod
    def _warn_env_proxy() -> None:
        """If this machine only reaches the internet through a local proxy or VPN
        client, connecting straight out fails -- and the symptom is a bare
        `502 Bad Gateway / connection closed`, which reads like the tool is broken.
        The environment usually says so; say it back at startup rather than leaving
        someone to work it out from a Cloudflare TLS reset.

        Deliberately not adopted automatically: silently routing a QA session
        through whatever proxy an env var names would change where the traffic goes
        without anyone asking for it.
        """
        env = Interceptor._detected_proxy()
        if not env or Interceptor._chained():
            return  # no proxy to speak of, or already chained through it
        logging.log(ALERT,
                    f"note: this machine has a proxy configured ({env}) but interceptor is "
                    f"dialling out directly. If a site returns '502 Bad Gateway / "
                    f"connection closed', relaunch as:  interceptor --chain")

    async def done(self) -> None:
        # The token dies with the process, so leaving the file behind is both
        # useless and a credential-shaped thing lying around.
        try:
            if self._writer:
                self._writer.cancel()
            # The store file is decrypted traffic, so closing it is also deleting
            # it. In the finally block, because a leftover must not depend on the
            # browser cleanup below succeeding.
            if self.url_file:
                self.url_file.unlink(missing_ok=True)
            for proc in self.browsers:
                proc.kill()
                try:
                    # Wait, or the profile below is still being flushed when we
                    # try to delete it -- and that profile holds real cookies.
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    logging.warning("interceptor: browser did not exit; profile may remain")
            for tdir in self.tmpdirs:
                try:
                    tdir.cleanup()
                except OSError as e:
                    logging.warning(f"interceptor: could not wipe {tdir.name}: {e}")
        finally:
            # Whatever went wrong above, the port has to be released and the
            # decrypted-traffic file has to go.
            self.store.close()
            if self.bridge:
                await self.bridge.stop()

    # ------------------------------------------------------------ flow store

    def _is_noise(self, flow) -> bool:
        # NOISE_FILTER is a negation, so a flow that does NOT match it is noise.
        return bool(ctx.options.hide_noise) and not self._noise(flow)

    @staticmethod
    def _off_list(flow) -> bool:
        """True when a host list is set and this flow is not on it.

        The list has to mean the same thing for every protocol or its name is a
        lie. mitmproxy's `allow_hosts` only governs TLS -- it decides what gets
        terminated -- so plain HTTP and `ws://` sailed past it and kept appearing
        from hosts the user had excluded. This is the other half: what gets kept.
        Matched the way mitmproxy matches it, against `host:port`.
        """
        hosts = ctx.options.allow_hosts
        if not hosts or not isinstance(flow, http.HTTPFlow):
            return False
        target = f"{flow.request.host}:{flow.request.port}"
        return not any(re.search(h, target, re.IGNORECASE) for h in hosts if h.strip())

    # The store owns the byte accounting now. These stay so the rest of the addon,
    # the UI payload and the checks read the same names they always did.
    @property
    def bytes(self) -> int:
        return self.store.bytes

    @property
    def evicted(self) -> int:
        return self.store.evicted

    @property
    def sizes(self):
        return self.store.sizes

    def _remember(self, flow) -> bool:
        if not isinstance(flow, http.HTTPFlow) or self._is_noise(flow):
            return False
        if self._off_list(flow):
            return False
        size = len(flow.request.raw_content or b"")
        if flow.response:
            size += len(flow.response.raw_content or b"")
        if flow.websocket:
            # Frames are the whole point of a long-lived socket and they never
            # stop arriving. Counting only the handshake froze a chat or telemetry
            # flow at a few hundred bytes, so the cap could never evict it and the
            # frames piled up in RAM for as long as the connection lasted.
            #
            # Count only frames not counted before. Re-summing the whole list ran
            # once per arriving frame, which is O(n) per frame and O(n^2) over a
            # connection: measured 0.72ms/frame at 2.5k frames rising to 9.9ms at
            # 30k. That cost lands on the proxy's own event loop, so one chatty
            # socket slowed every other request through the proxy -- HTTP p50
            # doubled at 25k frames and got worse from there.
            msgs = flow.websocket.messages
            counted, total = self.ws_seen.get(flow.id, (0, 0))
            if counted > len(msgs):
                # A session load replaces the list wholesale, so a stale cursor
                # would silently under-count. Recount from scratch.
                counted, total = 0, 0
            if counted < len(msgs):
                total += sum(len(m.content) for m in msgs[counted:])
                self.ws_seen[flow.id] = (len(msgs), total)
            size += total
        before = set(self.store) if self.ws_seen else None
        self.store.put(flow, size, summary(flow), ctx.options.store_bytes)
        # Frame cursors for flows the store just evicted would otherwise leak for
        # the life of the process, and a recycled id would resume mid-count.
        if before is not None:
            for gone in before - set(self.store):
                self.ws_seen.pop(gone, None)
        return True

    def _push_flow(self, flow) -> None:
        # The proxy port is bound before this script even loads, so a request can
        # reach the hooks while the bridge is still None. Unguarded, that raised
        # out of request() before the flow was ever queued.
        if self.bridge is None:
            return
        if isinstance(flow, http.HTTPFlow) and flow.id in self.store:
            self.bridge.push("flow", **summary(flow))

    # ------------------------------------------------------------ hooks

    def requestheaders(self, flow: http.HTTPFlow) -> None:
        self._maybe_stream(flow.request)

    def responseheaders(self, flow: http.HTTPFlow) -> None:
        self._maybe_stream(flow.response)

    @staticmethod
    def _maybe_stream(msg) -> None:
        """Never buffer what could not be edited anyway. Uploads need this as much
        as downloads did -- without a requestheaders hook a large POST body was
        buffered whole, with no cap at all."""
        try:
            declared = int(msg.headers.get("content-length", 0))
        except ValueError:
            declared = 0
        if declared > MAX_EDITABLE_BODY:
            msg.stream = True
        # A chunked message declares no length, so the check above cannot see it.
        # stream_large_bodies (set in running()) is mitmproxy's own size-based
        # cutoff and covers exactly that case.

    def _push_state_soon(self) -> None:
        """Every stored flow moves the toolbar's counters (flows, bytes, evicted,
        noise hidden), but a full state payload per flow was hundreds of
        queue/per_host/rule dumps per page load. Not pushing at all left the
        counters frozen for a whole session of curl-only traffic, which is how
        "4 flows" ended up under a table showing eight. Once a second."""
        now = time.monotonic()
        if now - self._state_pushed_at >= 1.0:
            self._state_pushed_at = now
            self._push_state()

    async def request(self, flow: http.HTTPFlow) -> None:
        # Async because a fault may delay this flow. mitmproxy awaits coroutine
        # hooks, so the sleep suspends this one flow and nothing else -- the same
        # shape the pause queue relies on. A sync `time.sleep` here would stop the
        # whole proxy, which is the trap this comment exists to prevent.
        if self._is_noise(flow):
            self.noise_hidden += 1
            self._push_state_soon()
            return
        if self._remember(flow):
            self._push_flow(flow)
            self._push_state_soon()
        await self._maybe_fault(flow)
        self._maybe_pause(flow, "request")

    async def _maybe_fault(self, flow: http.HTTPFlow) -> None:
        """Break this flow on purpose, if a rule says so.

        Skipped when the flow is already held for hand editing: a human with the
        flow stopped in front of them *is* the fault injector, and the hook returns
        before `wait_for_resume` runs, so a delay here would land before the row
        ever reached the queue -- five seconds of nothing, then the editor.

        Skipped for replays too. Repeating a request to compare it against the
        original is not the moment to have it broken underneath you.
        """
        if not self.faults or flow.intercepted or flow.is_replay:
            return
        if self._off_list(flow):
            return
        try:
            what = await faultlib.apply(self.faults, flow)
        except Exception as e:  # a bad rule costs its flow, never the proxy
            logging.warning(f"interceptor: fault failed: {e!r}")
            return
        if not what:
            return
        flow.metadata["faulted"] = what
        # Re-store and re-push explicitly rather than leaving it to the response
        # hook: a short-circuited flow never goes upstream, so the table has to be
        # corrected from here or the row sits at "···" forever.
        self._remember(flow)
        self._push_flow(flow)

    def response(self, flow: http.HTTPFlow) -> None:
        if self._remember(flow):
            self._push_flow(flow)
            self._push_state_soon()
        self._maybe_pause(flow, "response")

    def websocket_start(self, flow: http.HTTPFlow) -> None:
        if self._remember(flow):
            self._push_flow(flow)
            self._push_state_soon()

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        # Frames are pushed straight to the UI rather than through _remember, so
        # the host list has to be honoured here too or an excluded `ws://` socket
        # would keep streaming rows into a table that claims to show one host.
        if self._is_noise(flow) or self._off_list(flow):
            return
        msg = flow.websocket.messages[-1]
        self._remember(flow)
        self._push_state_soon()  # frames move the byte counter
        if self.bridge is not None:
            rendered, binary, truncated = _frame_view(msg.content)
            self.bridge.push(
                "ws.message", id=flow.id, seq=len(flow.websocket.messages) - 1,
                from_client=msg.from_client, size=len(msg.content),
                preview=rendered, binary=binary, truncated=truncated,
                injected=msg.injected,
            )
        self._maybe_pause(flow, "websocket")

    def websocket_end(self, flow: http.HTTPFlow) -> None:
        self._push_flow(flow)

    def error(self, flow) -> None:
        # A killed or timed-out flow must not linger in the queue as a phantom.
        self.paused.pop(flow.id, None)
        # Its reply is never coming, so a pending arm would outlive the flow.
        self.stop_reply.discard(flow.id)
        # Re-store it: the error is part of the flow, and this is also the point at
        # which a flow that never got a response becomes safe to persist and drop.
        self._remember(flow)
        self._push_flow(flow)
        self._push_state()

    # ------------------------------------------------------------ pause queue

    def _maybe_pause(self, flow, direction: str) -> None:
        if not flow.intercepted:
            return

        # Two cases where holding would strand the client forever, so release
        # immediately instead. Both are counted and surfaced in the UI.
        #
        # 1. Nothing is listening. With no UI there is nobody to decide, and the
        #    built-in Intercept addon happily re-intercepts the *response* of a
        #    flow whose request we just force-forwarded on disconnect.
        # 2. Response interception is off (the default).
        if not flow.live:
            # A flow read from a saved session is dispatched straight to the hooks,
            # never through the proxy's wait_for_resume path. Queueing it would
            # park an entry nothing can ever release -- but the built-in Intercept
            # has already set .intercepted on it, and summary() feeds that straight
            # to the table, so every loaded row rendered as "held" with an empty
            # queue. Clear the flag on the way out; resume() on a flow with no
            # waiter is a no-op.
            flow.resume()
            return
        listening = self.bridge is not None and bool(self.bridge.clients)
        # `stop_reply` is the per-request opt-in armed from the held-request
        # editor. The global toggle stops every matching flow twice, which is why
        # it defaults off and stays off -- this holds one reply, the one you asked
        # for, and disarms itself immediately after.
        wanted = (direction != "response"
                  or bool(ctx.options.intercept_responses)
                  or flow.id in self.stop_reply)
        if direction == "response":
            self.stop_reply.discard(flow.id)
        if not listening or not wanted:
            if not listening:
                self.auto_forwarded += 1
            self.paused[flow.id] = (direction, flow)
            self._resume(flow.id)
            return

        self.paused[flow.id] = (direction, flow)
        self.bridge.push("flow.paused", **self._paused_payload(direction, flow))
        self._push_state()

    @staticmethod
    def _paused_payload(direction: str, flow) -> dict:
        """One builder for both the live push and the snapshot a reconnecting UI
        gets. They used to be written separately, and the snapshot sent a held
        WebSocket frame as `detail` -- the HTTP handshake -- so the editor came up
        blank after a reload and anything typed in replaced the real frame."""
        payload = {"id": flow.id, "direction": direction, "summary": summary(flow)}
        if direction == "websocket":
            msg = flow.websocket.messages[-1]
            # Editable view, not the 4KB preview: whatever this string holds is
            # what gets written back to the wire on forward.
            rendered, binary, truncated = _frame_view(msg.content, MAX_EDITABLE_BODY)
            payload["frame"] = {
                "seq": len(flow.websocket.messages) - 1,
                "from_client": msg.from_client,
                "body": rendered,
                "binary": binary,
                "truncated": truncated,
                "size": len(msg.content),
            }
        else:
            payload["detail"] = detail(
                flow, "response" if direction == "response" else "request"
            )
        return payload

    def _apply_edits(self, flow, direction: str, raw: str, idx: int | None = None) -> None:
        """Write an edited raw message back onto the flow. Raises ValueError on
        anything malformed, which keeps the flow held so the user can fix it.

        `idx` is the frame the caller decided on, passed in rather than recomputed:
        this used to edit msgs[-1] while _resume dropped msgs[seq], two different
        notions of "the frame in hand" that agreed only because mitmproxy holds at
        most one frame per flow."""
        if direction == "websocket":
            msgs = flow.websocket.messages
            if not msgs:
                raise ValueError("no frame to edit")
            if idx is None:
                idx = len(msgs) - 1
            if not 0 <= idx < len(msgs):
                raise ValueError(f"no frame #{idx}")
            target = msgs[idx]
            # The editor showed a binary frame as hex, so it must come back as hex.
            _, was_binary, was_truncated = _frame_view(target.content, MAX_EDITABLE_BODY)
            if was_truncated:
                # The editor only ever held a prefix, so writing it back would send
                # a truncated frame and call it an edit. Refuse, exactly as
                # raw_text() refuses an oversized HTTP body.
                raise ValueError(
                    f"frame is {len(target.content)} bytes — above the editable limit"
                )
            if was_binary:
                try:
                    target.content = bytes.fromhex(raw.replace(" ", "").replace("\n", ""))
                except ValueError as e:
                    raise ValueError(f"binary frame must stay valid hex: {e}") from e
            else:
                target.content = raw.encode()
            return

        which = "response" if direction == "response" else "request"
        msg = flow.response if which == "response" else flow.request
        if msg is None:
            raise ValueError(f"no {which} to edit")
        start, headers, body = parse_raw(raw)

        if which == "request":
            parts = start.split()
            if len(parts) < 2:
                raise ValueError(f"bad request line: {start[:60]!r}")
            msg.method = parts[0]
            target = parts[1]
            if target.startswith(("http://", "https://")):
                msg.url = target  # absolute target also retargets host/port
            else:
                msg.path = target
        else:
            parts = start.split(None, 2)
            if len(parts) < 2 or not parts[1].isdigit():
                raise ValueError(f"bad status line: {start[:60]!r}")
            msg.status_code = int(parts[1])
            msg.reason = parts[2] if len(parts) > 2 else ""

        # An HTML <textarea> rewrites CRLF to LF in its own value -- that is the
        # spec's value-sanitisation step, not something the UI can opt out of. So a
        # body that came back LF-only, and is otherwise identical to what we served,
        # was not edited: the browser did that. Put the original bytes back, or
        # every multipart upload loses its boundary CRLFs the moment the user
        # touches the headers. A body the user really did edit keeps LF, which a
        # textarea cannot avoid -- the editor says so when the body has CRLFs.
        try:
            served = msg.get_text(strict=True) or ""
        except (ValueError, UnicodeDecodeError):
            served = ""
        if served and body != served and body == served.replace("\r\n", "\n"):
            body = served

        # Order matters. decode() first so raw_content becomes the plaintext the
        # user was editing; then headers; then the body, whose setter recomputes
        # Content-Length. Hand-editing that header instead would desync it.
        if msg.headers.get("content-encoding"):
            msg.decode()
        msg.headers.clear()
        for name, value in headers:
            msg.headers.add(name, value)
        msg.text = body

    def _resume(self, fid: str | None, drop: bool = False, seq: int | None = None,
                raw: str | None = None, stop_reply: bool = False) -> None:
        entry = self.paused.get(fid)
        if entry is None:
            return
        direction, flow = entry
        # Armed before the flow goes back on the wire, so the reply is already
        # spoken for by the time it comes back. Only meaningful on a request --
        # asking to hold the reply to a reply is not a thing.
        if stop_reply and direction == "request":
            self.stop_reply.add(fid)
        # Resolve the frame once, here, and hand it to both the edit and the drop.
        idx = None
        if direction == "websocket":
            msgs = flow.websocket.messages
            idx = seq if seq is not None else len(msgs) - 1
        if raw is not None and not drop:
            try:
                self._apply_edits(flow, direction, raw, idx)
            except (ValueError, UnicodeEncodeError) as e:
                # Stay held. Losing someone's hand-crafted payload to a typo is
                # far worse than making them fix the typo.
                self.bridge.push("error", message=f"edit rejected: {e}", id=fid)
                return
        self.paused.pop(fid, None)
        if direction == "websocket":
            msgs = flow.websocket.messages
            if drop and idx is not None and 0 <= idx < len(msgs):
                msgs[idx].drop()  # killing here would tear down the whole socket
            flow.resume()
        else:
            if drop:
                if flow.killable:
                    flow.kill()
                # kill() clears .intercepted, which makes resume() a no-op and
                # strands the coroutine awaiting wait_for_resume() -- the client
                # then hangs forever. (mitmweb's own kill path has this bug;
                # verified in spike/spike.py.) Re-arm the public flag, then resume.
                flow.intercepted = True
            flow.resume()
        # An edited flow has to be re-stored, or a read after forwarding would hand
        # back the bytes as they arrived rather than as they were sent -- and this
        # is where a held flow stops being intercepted, so it is also where it
        # becomes safe to persist and release.
        self._remember(flow)
        self._push_flow(flow)
        self._push_state()

    def _on_ui_gone(self) -> None:
        if not self.paused:
            return
        n = len(self.paused)
        for fid in list(self.paused):
            self._resume(fid)
        # Counted like any other force-forward -- this is the case users actually
        # hit (closed tab, oversized edit), so leaving it out of the stat made the
        # toolbar undercount exactly when it mattered.
        self.auto_forwarded += n
        logging.log(ALERT, f"UI disconnected with {n} paused flow(s) -- force-forwarded all")

    # ------------------------------------------------------------ mode

    @staticmethod
    def _host_filter() -> str:
        """The host list as a flow filter, so Intercept stops nothing outside it.

        Without this the list would hide a host from the table while still holding
        its requests -- a browser stalled on a queue you cannot see, because the
        rows explaining it were filtered out. Quoted for the same reason the noise
        filter is: the regex's own parentheses must not read as filter grouping.
        """
        hosts = [h.strip() for h in ctx.options.allow_hosts if h.strip()]
        return f'~d "({"|".join(hosts)})"' if hosts else ""

    def _compose(self) -> str:
        # "~all" refuses to compose with "&" in mitmproxy's filter grammar, so an
        # empty scope degrades to whatever other terms exist, or to ~all alone.
        #
        # The space before the closing paren is load-bearing, not a typo. An
        # argument-less filter is built as `Literal("~websocket") + WordEnd()`, and
        # pyparsing's WordEnd defaults its word characters to `printables` -- which
        # contains ")". So "(~websocket)" fails to parse while "~websocket" alone is
        # fine, and every argument-less filter (~q ~s ~a ~e ~all ~http ~websocket
        # ~tcp ~udp ~dns ~marked ~replay) was unusable as a scope. A space is enough
        # to satisfy WordEnd. The parens themselves have to stay: "&" binds tighter
        # than "|", so an ungrouped "~u /a | ~u /b" would put the noise and host
        # filters on the second branch only. units_scope_atoms covers both halves.
        terms = [
            f"({self.scope} )" if self.scope else "",
            NOISE_FILTER if ctx.options.hide_noise else "",
            self._host_filter(),
        ]
        return " & ".join(t for t in terms if t) or "~all"

    def _set_mode(self, mode: str, scope: str | None = None) -> None:
        if mode not in MODES:
            logging.warning(f"interceptor: unknown mode {mode!r}")
            return
        if scope is not None:
            candidate = scope.strip()
            # Validate in every mode, not just on the way into intercept: a typo used
            # to sit in the box looking accepted until the mode changed. And validate
            # the *composed* expression, because some filters parse alone and only
            # break once combined -- "|~u /api/" is one, mitmproxy accepts the stray
            # leading "|" until it is wrapped in parentheses.
            previous, self.scope = self.scope, candidate
            try:
                flowfilter.parse(self._compose())
            except ValueError as e:
                self.scope = previous   # never leave a broken filter stored
                self.bridge.push(
                    "error",
                    # mitmproxy appends the whole composed expression, noise regex
                    # included, which is unreadable in a toast. Keep the reason only.
                    message=f"bad filter {candidate!r}: {str(e).split(':')[0].lower()}. "
                            f"This box takes filter syntax such as  ~u /api/  or "
                            f"~d example.com & ~m POST  -- a leading | is rules syntax, "
                            f"not filter syntax. Press ? for the full reference.")
                return
        if mode == "intercept":
            expr = self._compose()
            try:
                flowfilter.parse(expr)
            except ValueError as e:
                self.bridge.push("error", message=f"bad scope filter: {e}")
                return
            ctx.options.update(intercept=expr)
        else:
            # Capture: stop nothing, and release anything already held so switching
            # out of Intercept never strands a waiting client.
            ctx.options.update(intercept=None)
            for fid in list(self.paused):
                self._resume(fid)
        # `ignore_hosts` is deliberately not touched here any more. Passthrough used
        # to set it to ".*" and every other mode reset it to [], which meant a mode
        # switch silently discarded a hand-set `--set ignore_hosts=...`. Nothing in
        # the UI owns that option now, so a per-host tunnel list passed on the
        # command line survives -- mitmproxy's own equivalent of Burp's TLS pass
        # through, for the case the Decrypt allowlist cannot express.
        self.mode = mode
        self._push_state()

    # ------------------------------------------------------------ UI protocol

    def _report(self, message: str) -> bool:
        """Surface a problem to the UI, or to the log when there is no UI.

        The `@command.command` methods below are reachable from mitmproxy's own
        command interface, which can call them before `running()` has built the
        bridge -- an unguarded `self.bridge.push` there is an AttributeError, not
        an error message. Returns False so callers can `return self._report(...)`.
        """
        if self.bridge is not None:
            self.bridge.push("error", message=message)
        else:
            logging.warning(f"interceptor: {message}")
        return False

    def _push_state(self) -> None:
        if not self.bridge:
            return
        queue, hosts = [], Counter()
        for fid, (direction, flow) in self.paused.items():
            host = flow.request.host if isinstance(flow, http.HTTPFlow) else "?"
            hosts[host] += 1
            queue.append({"id": fid, "direction": direction, "host": host,
                          "path": flow.request.path if isinstance(flow, http.HTTPFlow) else ""})
        self.bridge.push(
            "state", mode=self.mode, scope=self.scope, queue=queue,
            per_host=dict(hosts), stored=len(self.store), bytes=self.bytes,
            evicted=self.evicted, noise_hidden=self.noise_hidden,
            hide_noise=bool(ctx.options.hide_noise),
            intercept_responses=bool(ctx.options.intercept_responses),
            auto_forwarded=self.auto_forwarded,
            sessions_dir=str(SESSIONS),
            rules_body=list(ctx.options.modify_body),
            rules_headers=list(ctx.options.modify_headers),
            faults=[f.to_spec() for f in self.faults],
            allow_hosts=list(ctx.options.allow_hosts),
            proxy=f"{ctx.options.listen_host or '127.0.0.1'}:{ctx.options.listen_port}",
            # So the UI can explain a 502 before the user has to ask anyone.
            env_proxy=self._detected_proxy(),
            chained=self._chained(),
        )

    def _snapshot(self) -> None:
        # Summaries come off disk already built, and only the newest page of them:
        # the store is no longer bounded by memory, but a snapshot still has to fit
        # in one message and the browser caps its own table anyway.
        self.bridge.push("snapshot", flows=self.store.summaries())
        for direction, flow in self.paused.values():
            self.bridge.push("flow.paused", **self._paused_payload(direction, flow))
        self._push_state()

    async def _on_message(self, msg: dict) -> None:
        kind = msg.get("type")
        if kind == "hello":
            self._snapshot()
        elif kind == "mode.set":
            self._set_mode(msg.get("mode", "capture"), msg.get("scope"))
        elif kind == "resume":
            self._resume(msg.get("id"), drop=bool(msg.get("drop")),
                         seq=msg.get("seq"), raw=msg.get("raw"),
                         stop_reply=bool(msg.get("stop_reply")))
        elif kind == "resume.all":
            drop = bool(msg.get("drop"))
            for fid in list(self.paused):
                self._resume(fid, drop=drop)
        elif kind == "body.get":
            flow = self.store.get(msg.get("id"))
            which = msg.get("which", "request")
            if flow is not None:
                self.bridge.push("body", id=flow.id, which=which,
                                 detail=detail(flow, which))
        elif kind == "frames.get":
            # Frame history otherwise exists only in whatever live pushes a client
            # happened to be connected for, so a reload showed "no frames" next to
            # a flow labelled "ws (4)". The server has the whole list; serve it.
            flow = self.store.get(msg.get("id"))
            if isinstance(flow, http.HTTPFlow) and flow.websocket:
                out = []
                for seq, fm in enumerate(flow.websocket.messages):
                    rendered, binary, truncated = _frame_view(fm.content)
                    out.append({
                        "seq": seq, "from_client": fm.from_client,
                        "size": len(fm.content), "preview": rendered,
                        "binary": binary, "truncated": truncated,
                        "injected": fm.injected, "dropped": fm.dropped,
                    })
                self.bridge.push("frames", id=flow.id, frames=out)
        elif kind == "search":
            # Server-side, because the browser only ever held summaries -- the
            # bodies live in the store and were until now unqueryable.
            self.bridge.push("results", q=msg.get("q", ""),
                             flows=self.store.search(msg.get("q", "")))
        elif kind == "export":
            self._export(msg.get("id"), msg.get("format", "curl"))
        elif kind == "har.save":
            self._save_har()
        elif kind == "faults.set":
            self._set_faults(list(msg.get("faults") or []))
        elif kind == "clear":
            self.store.clear()
            self.ws_seen.clear()
            self.noise_hidden = 0
            # Counters describe what is in the table, so they go with it. Leaving
            # this behind showed "12 auto-forwarded" above an empty capture.
            self.auto_forwarded = 0
            self.stop_reply.clear()
            self.bridge.push("cleared")
            self._push_state()
        elif kind == "opt.set":
            if "intercept_responses" in msg:
                ctx.options.update(intercept_responses=bool(msg["intercept_responses"]))
            if "hide_noise" in msg:
                ctx.options.update(hide_noise=bool(msg["hide_noise"]))
                if self.mode == "intercept":
                    self._set_mode("intercept")  # noise is baked into the filter
            self._push_state()
        elif kind == "sessions.list":
            self._push_sessions()
        elif kind == "session.save":
            self._save_session()
        elif kind == "session.load":
            await self._load_session(msg.get("name", ""))
        elif kind == "replay":
            self.repeat(msg.get("id"), msg.get("raw") or "")
        elif kind == "rules.set":
            self._set_rules(list(msg.get("body") or []), list(msg.get("headers") or []))
        elif kind == "hosts.set":
            self._set_hosts(list(msg.get("hosts") or []))
        elif kind == "ws.inject":
            self.inject_frame(msg.get("id"), bool(msg.get("to_client")),
                              msg.get("text", ""), bool(msg.get("is_text", True)))
        elif kind == "browser.launch":
            self.launch_chrome()
        else:
            logging.warning(f"interceptor: unknown UI message {kind!r}")

    # ------------------------------------------------------------ sessions

    @staticmethod
    def _session_path(name: str) -> Path | None:
        """Resolve a client-supplied name to a file inside sessions/, or None.
        The name comes over the bridge, so it is never trusted as a path."""
        if not name or "/" in name or "\\" in name or name.startswith("."):
            return None
        path = (SESSIONS / name).resolve()
        if not path.is_relative_to(SESSIONS.resolve()) or path.suffix != ".mitm":
            return None
        return path

    def _push_sessions(self) -> None:
        items = []
        if SESSIONS.is_dir():
            for path in sorted(SESSIONS.glob("*.mitm"), reverse=True):
                stat = path.stat()
                items.append({"name": path.name, "bytes": stat.st_size,
                              "mtime": stat.st_mtime})
        self.bridge.push("sessions", items=items, dir=str(SESSIONS))

    def _save_session(self) -> None:
        from mitmproxy import io as mitm_io

        if not self.store:
            self.bridge.push("error", message="nothing to save yet")
            return
        SESSIONS.mkdir(mode=0o700, exist_ok=True)
        if SESSIONS.stat().st_mode & 0o077:
            SESSIONS.chmod(0o700)  # mkdir(exist_ok) does not touch an existing dir
        name = f"{datetime.now().strftime('%Y-%m-%d_%H%M%S')}.mitm"
        path = SESSIONS / name
        # 0600 before the first flow lands, not after the last one: this is
        # decrypted traffic with cookies and bearer tokens in it, and chmod-after
        # left the whole dump readable by any local user while it was being written.
        with os.fdopen(_open_private(path), "wb") as fh:
            writer = mitm_io.FlowWriter(fh)
            # Streamed one at a time: the store can hold far more than fits in RAM.
            for flow in self.store.iter_flows():
                writer.add(flow)
        logging.log(ALERT, f"saved {len(self.store)} flow(s) -> sessions/{name}")
        self.bridge.push("saved", name=name, flows=len(self.store))
        self._push_sessions()

    async def _load_session(self, name: str) -> None:
        from mitmproxy import io as mitm_io

        path = self._session_path(name or "")
        if path is None or not path.is_file():
            self.bridge.push("error", message=f"no such session: {name!r}")
            return
        # Opening a session replaces what is on screen rather than merging, so a
        # historical capture is never mixed up with live traffic.
        self.store.clear()
        self.ws_seen.clear()
        self.noise_hidden = 0
        self.bridge.push("cleared")

        count = 0
        try:
            with path.open("rb") as fh:
                for flow in mitm_io.FlowReader(fh).stream():
                    # load_flow replays the whole lifecycle, so our own hooks fire
                    # and the store fills exactly as it would from live traffic.
                    await ctx.master.load_flow(flow)
                    count += 1
        except Exception as e:
            self.bridge.push("error", message=f"could not read {name}: {e}")
            return
        logging.log(ALERT, f"loaded {count} flow(s) from sessions/{name}")
        self.bridge.push("loaded", name=name, flows=count)
        self._push_state()

    # ------------------------------------------------------------ export

    def _export(self, fid: str | None, fmt: str) -> None:
        """One flow as a runnable command. The UI puts it on the clipboard.

        Sent over the bridge rather than written to a file: the whole point is
        pasting it into a terminal or a ticket, and a path to open first would be
        one step more than the thing is worth.
        """
        flow = self.store.get(fid)
        if flow is None:
            self.bridge.push("error", message="that flow is no longer in the store")
            return
        try:
            text = export_text(flow, fmt)
        except Exception as e:
            self.bridge.push("error", message=f"export failed: {e}")
            return
        self.bridge.push("export", id=fid, format=fmt, text=text)

    def _save_har(self) -> None:
        """Every captured flow as a HAR file in sessions/.

        A file rather than a download: a HAR of a real session is tens of
        megabytes of decrypted traffic, and the bridge's static route is not
        token-gated -- serving it there would publish the capture to any page the
        user has open. Same destination and same 0600 treatment as a session dump.
        """
        try:
            name, size = write_har(self.store.iter_flows(), SESSIONS, _open_private)
        except Exception as e:
            self.bridge.push("error", message=f"HAR export failed: {e}")
            return
        logging.log(ALERT, f"exported HAR -> sessions/{name}")
        self.bridge.push("har", name=name, bytes=size, dir=str(SESSIONS))

    # ------------------------------------------------------------ faults

    def _set_faults(self, specs: list[dict]) -> None:
        """Rules that break traffic on purpose. See faults.py for why neither
        Intercept nor the rewrite rules can express this."""
        try:
            parsed = faultlib.parse_all(specs)
        except ValueError as e:
            # Nothing is armed on a bad rule: a half-applied fault list is worse
            # than none, because you would be testing against rules you cannot see.
            self.bridge.push("error", message=str(e))
            return
        self.faults = parsed
        logging.log(ALERT, f"{len(parsed)} fault rule(s) active"
                           + (f": {'; '.join(f.describe() for f in parsed)}" if parsed else ""))
        self._push_state()

    # ------------------------------------------------------------ repeater

    @command.command("interceptor.repeat")
    def repeat(self, fid: str, raw: str = "") -> None:
        """Repeater: resend a captured request, optionally edited first.

        Always replays a *copy* -- `replay.client` mutates the flow it is given
        (clears response and error, sets is_replay), so replaying the original
        would blank the row you were comparing against.
        """
        # These are `@command.command`s: mitmproxy asserts the return value against
        # the annotation (command.py), so a `-> None` command must return nothing
        # at all -- `return self._report(...)` would hand it False and blow up.
        flow = self.store.get(fid)
        if not isinstance(flow, http.HTTPFlow):
            self._report("not an HTTP flow")
            return
        clone = flow.copy()
        clone.metadata["replay_of"] = fid
        if raw:
            try:
                self._apply_edits(clone, "request", raw)
            except (ValueError, UnicodeEncodeError) as e:
                self._report(f"repeat rejected: {e}")
                return
        try:
            ctx.master.commands.call("replay.client", [clone])
        except Exception as e:  # command errors are surfaced, not swallowed
            self._report(f"replay failed: {e}")

    # ------------------------------------------------------------ rewrite rules

    def _set_rules(self, body: list[str], headers: list[str]) -> None:
        """Rule-based auto-rewrite with no human in the loop. Both the spec syntax
        and the rewriting are mitmproxy's own `modify_body` / `modify_headers`,
        which are already in default_addons -- we only validate and set them.

        Spec: `<sep><flow-filter><sep><pattern><sep><replacement>`, separator being
        any character NOT present in the pattern. Body patterns are regexes;
        header patterns are literal header names.
        """
        from mitmproxy.addons.modifyheaders import parse_modify_spec

        for specs, is_regex, label in ((body, True, "body"), (headers, False, "header")):
            for spec in specs:
                try:
                    parse_modify_spec(spec, is_regex)
                except ValueError as e:
                    self.bridge.push("error", message=f"bad {label} rule {spec!r}: {e}")
                    return
        try:
            ctx.options.update(modify_body=body, modify_headers=headers)
        except Exception as e:
            self.bridge.push("error", message=f"rules rejected: {e}")
            return
        # A streamed body is never buffered, so no rule can touch it.
        streamed_note = " (rules cannot touch streamed bodies)" if body else ""
        logging.log(ALERT, f"{len(body)} body + {len(headers)} header rule(s) active{streamed_note}")
        self._push_state()

    # ------------------------------------------------------------ decrypt scope

    def _set_hosts(self, hosts: list[str]) -> None:
        """Capture only these hosts. One list, three effects:

        * mitmproxy's `allow_hosts` stops terminating TLS for anything else, which
          is where the speed comes from -- two handshakes per connection on a
          single-threaded loop, measured ~170 new HTTPS connections/second with
          one core saturated. A page pulling from twenty hosts spends most of that
          budget on CDNs, fonts and telemetry nobody is testing.
        * `_off_list` keeps unlisted flows out of the store, so plain HTTP and
          `ws://` obey the list too. `allow_hosts` alone governs TLS only, which
          made the list a half-truth for everything unencrypted.
        * `_host_filter` folds it into the intercept expression, so nothing off
          the list is ever held. Filtering the table while still pausing those
          requests would stall the browser against an invisible queue.

        Not a security control. An unlisted host is not blocked -- it reaches the
        client untouched, it is merely not shown here.
        """
        cleaned = [h.strip() for h in hosts if h.strip()]
        for pattern in cleaned:
            # The pattern is embedded in a quoted flowfilter term, so a quote of
            # its own would break out of it and compose something else entirely.
            if '"' in pattern:
                self.bridge.push(
                    "error",
                    message=f"host pattern {pattern!r} cannot contain a double quote.")
                return
            try:
                re.compile(pattern)
            except re.error as e:
                self.bridge.push(
                    "error",
                    message=f"bad host pattern {pattern!r}: {e}. This box takes a "
                            f"hostname such as  app.example.com  or a regular "
                            f"expression such as  .*\\.example\\.com  -- one per line.")
                return
        previous = list(ctx.options.allow_hosts)
        try:
            ctx.options.update(allow_hosts=cleaned)
            # The list also becomes part of the intercept expression, so a pattern
            # that parses as a regex but not as a filter term must not be stored.
            if self.mode == "intercept":
                flowfilter.parse(self._compose())
        except Exception as e:
            ctx.options.update(allow_hosts=previous)
            self.bridge.push("error", message=f"host list rejected: {e}")
            return
        if self.mode == "intercept":
            self._set_mode("intercept")   # the filter has to be re-armed
        # TLS termination is chosen when a connection's next layer is picked, so
        # the tunnelling half applies to new connections only; the storage half
        # applies to every flow from here on.
        logging.log(ALERT,
                    f"capturing {cleaned} only (new connections for TLS)"
                    if cleaned else "capturing every host again")
        self._push_state()

    # ------------------------------------------------------------ ws injection

    @command.command("interceptor.inject")
    def inject_frame(self, fid: str, to_client: bool, text: str,
                     is_text: bool = True) -> None:
        """Send a frame neither peer sent. The thing Burp is weakest at, and it
        costs nothing here: mitmproxy already ships the `inject.websocket`
        command, we only have to validate and route."""
        flow = self.store.get(fid)
        if not isinstance(flow, http.HTTPFlow) or not flow.websocket:
            self._report("not a WebSocket flow")
            return
        if not flow.live:
            self._report("WebSocket already closed — cannot inject")
            return
        if is_text:
            data = text.encode()
        else:
            try:
                data = bytes.fromhex(text.replace(" ", "").replace("\n", ""))
            except ValueError as e:
                self._report(f"invalid hex payload: {e}")
                return
        ctx.master.commands.call("inject.websocket", flow, to_client, data, is_text)
        logging.info(f"injected {len(data)}B frame -> {'client' if to_client else 'server'}")

    # ------------------------------------------------------------ launcher

    def _chrome_exe(self) -> str | None:
        for cand in CHROME_PATHS:
            if Path(cand).exists():
                return cand
            found = shutil.which(cand)
            if found:
                return found
        return None

    def _ca_pin(self) -> str | None:
        """base64(sha256(SubjectPublicKeyInfo)) of mitmproxy's CA.

        Lets Chrome trust the proxy without installing anything into the system
        store, the login keychain, or the profile's NSS DB. Verified by
        spike/spike.py --chrome.
        """
        pem = Path(ctx.options.confdir).expanduser() / "mitmproxy-ca-cert.pem"
        if not pem.exists():
            return None
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        cert = x509.load_pem_x509_certificate(pem.read_bytes())
        der = cert.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return base64.b64encode(hashlib.sha256(der).digest()).decode()

    @command.command("interceptor.browser")
    def launch_chrome(self) -> None:
        """Isolated Chrome wired to this proxy. Forked from mitmproxy's own
        browser addon, which is missing the three flags that matter."""
        exe = self._chrome_exe()
        if not exe:
            self.bridge.push("error", message="Chrome not found")
            return
        tdir = tempfile.TemporaryDirectory(prefix="interceptor-profile-")
        self.tmpdirs.append(tdir)
        host = ctx.options.listen_host or "127.0.0.1"
        ui_port = ctx.options.ui_port
        args = [
            exe,
            f"--user-data-dir={tdir.name}",
            f"--proxy-server=http://{host}:{ctx.options.listen_port}",
            # Chrome bypasses proxies for loopback by default, which makes
            # staging-on-localhost invisible. <-loopback> removes that bypass --
            # then re-exclude our own UI, or we capture our own bridge traffic
            # in a feedback loop.
            f"--proxy-bypass-list=<-loopback>;127.0.0.1:{ui_port};localhost:{ui_port}",
            # QUIC sidesteps HTTP proxies entirely: the #1 cause of a missing flow.
            "--disable-quic",
            # The #2 cause: Chrome's own cache. A warm profile serves most of a
            # reload from disk without touching the network, so the proxy sees a
            # fraction of the requests and the table looks broken -- measured on a
            # real site, a reload dropped from 149 flows to 30, and with Intercept
            # armed almost nothing stopped. A capture tool that shows you four
            # requests in five is worse than useless, so the throwaway profile runs
            # with no cache at all. This is why testers reach for "Disable cache"
            # in devtools; here it is simply always on.
            "--disk-cache-size=1",
            "--media-cache-size=1",
            # Background chatter pollutes the table and keeps Chrome alive forever.
            "--disable-background-networking",
            "--disable-component-update",
            "--disable-sync",
            "--disable-default-apps",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-extensions",
        ]
        pin = self._ca_pin()
        if pin:
            args.append(f"--ignore-certificate-errors-spki-list={pin}")
        args.append("about:blank")
        # Never wait on this process: its background requests keep it alive
        # indefinitely when routed through a proxy.
        self.browsers.append(
            subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        )
        logging.log(ALERT, f"launched isolated Chrome (CA pin {'set' if pin else 'MISSING'})")


# Intercept must come first: it sets flow.intercepted, which our hooks read.
# mitmdump does not load it by default -- only mitmweb and the console tool do --
# so it is registered here explicitly, along with the `intercept` option it owns.
addons = [intercept.Intercept(), Interceptor()]
