#!/usr/bin/env python3
"""P0 spike — prove the four risky primitives before building anything.

Q1  flow.intercept() from the request hook holds the flow; resume() from a
    *separate* asyncio task releases it, and a body edit round-trips.
Q2  One WebSocket frame can be held for editing while later frames on the same
    flow queue behind it (order preserved), and msg.drop() is honoured.
Q3  Chrome with --proxy-bypass-list=<-loopback> and
    --ignore-certificate-errors-spki-list intercepts an HTTPS *localhost*
    target with no CA installed anywhere on the system.
Q4  An HTTP/2 request body edit round-trips.

Run:
    .venv/bin/python spike/spike.py             # Q1, Q2      (offline)
    .venv/bin/python spike/spike.py --chrome    # + Q3        (headless Chrome)
    .venv/bin/python spike/spike.py --net       # + Q4        (needs internet)
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import websockets
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster

def _port(env: str, default: int) -> int:
    return int(os.environ.get(env, default))


# Deliberately NOT the app's own 8080/9000: the spike must be runnable while a
# real instance is up. Override via IC_SPIKE_*_PORT if these clash too.
PROXY = ("127.0.0.1", _port("IC_SPIKE_PROXY_PORT", 18090))
HTTP_T = ("127.0.0.1", _port("IC_SPIKE_HTTP_PORT", 18091))
WS_T = ("127.0.0.1", _port("IC_SPIKE_WS_PORT", 18092))
TLS_T = ("127.0.0.1", _port("IC_SPIKE_TLS_PORT", 18443))
PROXY_URL = f"http://{PROXY[0]}:{PROXY[1]}"

CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
CA_PEM = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"

# Paths whose request body the spike addon rewrites. Must cover every Q4
# endpoint: nghttp2 serves /httpbin/post, postman-echo serves /post.
EDIT_PATHS = ("/q1", "/httpbin/post", "/post")

WS_RECEIVED: list[str] = []  # what the *target server* actually received, in order
RESULTS: list[tuple[str, bool | None, str]] = []

# curl exit codes that mean "the network let us down", not "the tool is wrong".
TRANSPORT_FAIL = {6, 7, 28, 35, 52, 56}


def check(name: str, ok: bool | None, detail: str = "") -> None:
    """ok=None records a SKIP -- inconclusive, not a failure."""
    RESULTS.append((name, ok, detail))


# ---------------------------------------------------------------- target servers


class Echo(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, body: bytes) -> None:
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        self._send(self.rfile.read(int(self.headers.get("content-length", 0))))

    def do_GET(self) -> None:
        self._send(json.dumps({"marker": "spike-target-ok"}).encode())

    def log_message(self, *a) -> None:  # silence
        pass


def start_http(host: str, port: int, tls: Path | None = None) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer((host, port), Echo)
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(tls / "cert.pem", tls / "key.pem")
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


async def ws_echo(conn) -> None:
    async for msg in conn:
        WS_RECEIVED.append(msg)
        await conn.send(msg)


def selfsigned(dst: Path) -> Path:
    """Self-signed cert for 127.0.0.1. Chrome requires a SAN, not just CN."""
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-keyout", str(dst / "key.pem"), "-out", str(dst / "cert.pem"),
         "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1"],
        check=True, capture_output=True,
    )
    return dst


def spki_pin(ca_pem: Path) -> str:
    """base64(sha256(SubjectPublicKeyInfo)) — the value Chrome's
    --ignore-certificate-errors-spki-list expects."""
    cert = x509.load_pem_x509_certificate(ca_pem.read_bytes())
    der = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(hashlib.sha256(der).digest()).decode()


# ---------------------------------------------------------------- spike addon


class Spike:
    """Uses the out-of-band pattern the real tool needs: the hook calls
    intercept() and returns immediately; a separate task calls resume() later.
    That is what a UI round trip looks like."""

    def __init__(self) -> None:
        self.flows: list[dict] = []
        self.responses: list[dict] = []
        self.hook_order: list[str] = []  # frames as the addon saw them
        self.q1_held = 0.0

    def response(self, flow) -> None:
        self.responses.append({
            "host": flow.request.host,
            "port": flow.request.port,
            "path": flow.request.path,
            "status": flow.response.status_code,
        })

    # ---- Q1 / Q4: HTTP request body edit -------------------------------
    def request(self, flow) -> None:
        self.flows.append({
            "host": flow.request.host,
            "port": flow.request.port,
            "path": flow.request.path,
            "http_version": flow.request.http_version,
        })
        if flow.request.path in EDIT_PATHS:
            flow.intercept()
            asyncio.create_task(self._edit_and_resume(flow))

    async def _edit_and_resume(self, flow) -> None:
        t0 = time.monotonic()
        await asyncio.sleep(0.25)  # stand-in for a human editing in the UI
        flow.request.decode()  # strip Content-Encoding before touching the body
        flow.request.text = json.dumps({"edited": True})
        self.q1_held = time.monotonic() - t0
        flow.resume()

    # ---- Q2: WebSocket frame hold, ordering, drop ----------------------
    def websocket_message(self, flow) -> None:
        msg = flow.websocket.messages[-1]
        if not msg.from_client:
            return  # leave server->client echoes untouched
        body = msg.content.decode()
        self.hook_order.append(body)
        flow.intercept()
        asyncio.create_task(self._ws_resume(flow, msg, body))

    async def _ws_resume(self, flow, msg, body: str) -> None:
        # Hold m1 far longer than its neighbours. If the proxy does NOT queue
        # later frames behind a held one, the target sees m2 before m1.
        await asyncio.sleep(0.5 if body == "m1" else 0.0)
        if body == "m3":
            msg.drop()
        else:
            msg.content = f"{body}-edited".encode()
        flow.resume()


# ---------------------------------------------------------------- drivers


def curl(url: str, body: str | None = None, *extra: str) -> tuple[int, str, str]:
    # --noproxy "" is mandatory: curl >=7.86 silently bypasses proxies for
    # loopback destinations. Same class of bug as Chrome needing <-loopback>.
    cmd = ["curl", "-s", "--max-time", "25", "--noproxy", "", "-x", PROXY_URL, *extra]
    if body is not None:
        cmd += ["-X", "POST", "-H", "content-type: application/json",
                "--data-binary", body]
    cmd.append(url)
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr


def q1(addon: Spike) -> None:
    t0 = time.monotonic()
    rc, out, err = curl(f"http://{HTTP_T[0]}:{HTTP_T[1]}/q1", '{"orig":true}')
    elapsed = time.monotonic() - t0
    if rc != 0:
        return check("Q1 intercept+resume+body edit", False, f"curl rc={rc} {err.strip()}")
    try:
        got = json.loads(out)
    except json.JSONDecodeError:
        return check("Q1 intercept+resume+body edit", False, f"non-json: {out[:120]!r}")
    ok = got == {"edited": True} and elapsed >= 0.25 and addon.q1_held >= 0.25
    check("Q1 intercept+resume+body edit", ok,
          f"target echoed {got}, flow held {addon.q1_held:.2f}s, total {elapsed:.2f}s")


async def q2(addon: Spike) -> None:
    WS_RECEIVED.clear()
    sent = [f"m{i}" for i in range(6)]
    echoes: list[str] = []
    try:
        async with websockets.connect(
            f"ws://{WS_T[0]}:{WS_T[1]}/", proxy=PROXY_URL, open_timeout=10
        ) as conn:
            for m in sent:
                await conn.send(m)
            for _ in range(len(sent) - 1):  # m3 is dropped, so one fewer echo
                echoes.append(await asyncio.wait_for(conn.recv(), timeout=10))
    except Exception as e:
        return check("Q2 WS hold / order / drop", False, f"{type(e).__name__}: {e}")

    expect = ["m0-edited", "m1-edited", "m2-edited", "m4-edited", "m5-edited"]
    order_ok = WS_RECEIVED == expect
    drop_ok = "m3-edited" not in WS_RECEIVED and "m3" not in WS_RECEIVED
    check("Q2 WS frame hold, order preserved, drop honoured",
          order_ok and drop_ok and echoes == expect,
          f"target received {WS_RECEIVED} (m1 was held 0.5s; expected {expect})")


def q3(addon: Spike, tls_dir: Path) -> None:
    if not Path(CHROME).exists():
        return check("Q3 Chrome localhost HTTPS, no CA installed", False, "Chrome not found")
    if not CA_PEM.exists():
        return check("Q3 Chrome localhost HTTPS, no CA installed", False, f"missing {CA_PEM}")
    pin = spki_pin(CA_PEM)
    url = f"https://{TLS_T[0]}:{TLS_T[1]}/q3"
    # Do NOT wait for Chrome to exit. It keeps background requests (the
    # clients2.google.com time service) in flight through the proxy and never
    # terminates. Assert from the proxy's own observations instead, then kill it.
    # A *completed 200* to :8443 proves both halves at once: the proxy was used
    # (bypass-list) and Chrome accepted our CA (SPKI pin) — a rejected cert
    # fails the Chrome->mitmproxy handshake, so no HTTP flow would exist at all.
    with tempfile.TemporaryDirectory() as profile:
        proc = subprocess.Popen(
            [CHROME, "--headless=new", f"--user-data-dir={profile}",
             f"--proxy-server={PROXY_URL}",
             "--proxy-bypass-list=<-loopback>",
             "--disable-quic",
             f"--ignore-certificate-errors-spki-list={pin}",
             "--no-first-run", "--no-default-browser-check", "--disable-extensions",
             "--disable-background-networking", "--disable-component-update",
             "--disable-sync", "--disable-default-apps",
             url],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
        )
        try:
            deadline = time.monotonic() + 25
            hit: dict | None = None
            while time.monotonic() < deadline:
                hit = next((r for r in addon.responses if r["port"] == TLS_T[1]), None)
                if hit:
                    break
                time.sleep(0.25)
        finally:
            proc.kill()
            proc.wait(timeout=10)

    saw = [f for f in addon.flows if f["port"] == TLS_T[1]]
    ok = hit is not None and hit["status"] == 200
    check("Q3 Chrome localhost HTTPS via proxy, no CA installed", ok,
          f"proxy saw {len(saw)} request(s) to :{TLS_T[1]}, "
          f"decrypted response: {hit['status'] if hit else 'none'}")


def q4(addon: Spike) -> None:
    """Needs a third-party h2 endpoint that echoes the request body, so a dead
    host must degrade to SKIP -- otherwise an outage looks like a regression."""
    label = "Q4 HTTP/2 request body edit"
    attempts = []
    for url in ("https://nghttp2.org/httpbin/post", "https://postman-echo.com/post"):
        path = "/" + url.split("/", 3)[3]
        # --cacert (not -k): validates the mitmproxy-signed chain, so a broken
        # MITM cert still fails loudly.
        rc, out, err = curl(url, '{"orig":true}', "--http2", "--cacert", str(CA_PEM))
        if rc in TRANSPORT_FAIL:
            attempts.append(f"{url} unreachable (curl rc={rc})")
            continue
        if rc != 0:
            return check(label, False, f"curl rc={rc} {err.strip()[:160]}")
        try:
            echoed = json.loads(out).get("json")
        except (json.JSONDecodeError, AttributeError):
            return check(label, False, f"unexpected body: {out[:160]!r}")
        versions = [f["http_version"] for f in addon.flows if f["path"] == path]
        return check(label, echoed == {"edited": True} and any("2" in v for v in versions),
                    f"upstream saw {echoed}, negotiated {versions}")
    check(label, None, "; ".join(attempts) + " -- network, not the tool")


# ---------------------------------------------------------------- harness


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--chrome", action="store_true", help="also run Q3 (headless Chrome)")
    ap.add_argument("--net", action="store_true", help="also run Q4 (needs internet)")
    args = ap.parse_args()

    tmp = Path(tempfile.mkdtemp(prefix="spike-tls-"))
    servers = [start_http(*HTTP_T)]
    if args.chrome:
        selfsigned(tmp)
        servers.append(start_http(*TLS_T, tls=tmp))
    ws_srv = await websockets.serve(ws_echo, *WS_T)

    addon = Spike()
    opts = options.Options(listen_host=PROXY[0], listen_port=PROXY[1])
    master = DumpMaster(opts, with_termlog=False, with_dumper=False)
    master.addons.add(addon)
    # ssl_insecure: our Q3 target is self-signed, so the proxy must accept it.
    master.options.update(ssl_insecure=True, http2=True)
    run = asyncio.create_task(master.run())
    await asyncio.sleep(1.5)  # let the listener bind and the CA get generated

    async def guard(label: str, coro):
        """One check crashing must not lose the other checks' results."""
        try:
            await coro
        except Exception as e:
            check(label, False, f"{type(e).__name__}: {e}")

    try:
        await guard("Q1 intercept+resume+body edit", asyncio.to_thread(q1, addon))
        await guard("Q2 WS frame hold, order preserved, drop honoured", q2(addon))
        if args.chrome:
            await guard("Q3 Chrome localhost HTTPS via proxy, no CA installed",
                        asyncio.to_thread(q3, addon, tmp))
        if args.net:
            await guard("Q4 HTTP/2 request body edit", asyncio.to_thread(q4, addon))
    finally:
        master.shutdown()
        run.cancel()
        ws_srv.close()
        for s in servers:
            s.shutdown()
        shutil.rmtree(tmp, ignore_errors=True)

    print()
    width = max(len(n) for n, _, _ in RESULTS)
    for name, ok, detail in RESULTS:
        verdict = "SKIP" if ok is None else ("PASS" if ok else "FAIL")
        print(f"  {verdict}  {name.ljust(width)}  {detail}")
    not_run = []
    if not args.chrome:
        not_run.append("Q3 (--chrome)")
    if not args.net:
        not_run.append("Q4 (--net)")
    if not_run:
        print(f"\n  NOT RUN: {', '.join(not_run)}")
    failed = [n for n, ok, _ in RESULTS if ok is False]
    passed = [n for n, ok, _ in RESULTS if ok is True]
    skipped = [n for n, ok, _ in RESULTS if ok is None]
    line = f"\n  {len(passed)}/{len(passed) + len(failed)} passed"
    if skipped:
        line += f", {len(skipped)} skipped (inconclusive)"
    print(line)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
