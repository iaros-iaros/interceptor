"""Static-file + WebSocket bridge for the UI. One port, loopback only.

Security. This socket carries every captured request, cookie and bearer token,
and it accepts commands that rewrite live traffic. Any page the user visits can
open a WebSocket to 127.0.0.1 -- WebSockets are not subject to CORS -- so there
are two independent gates:

  * Origin must equal our own origin (enforced by websockets' `origins=`; a
    request with no Origin header at all is rejected too).
  * A random per-run token must appear on the /ws query string.

The token reaches the page through the URL *fragment*, which browsers never put
in a Referer header and which never lands in a server log.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import secrets
from collections.abc import Awaitable, Callable
from pathlib import Path
from urllib.parse import parse_qs

from websockets.asyncio.server import ServerConnection, serve
from websockets.datastructures import Headers
from websockets.http11 import Response

# One batched frame per tick. A single page load is 300-500 flows; one WS frame
# each melts the UI.
FLUSH_INTERVAL = 0.05

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
}


class Bridge:
    def __init__(
        self,
        host: str,
        port: int,
        ui_dir: Path,
        on_message: Callable[[dict], Awaitable[None]],
        on_last_client_gone: Callable[[], None],
        max_message_bytes: int = 1024 * 1024,
    ) -> None:
        self.host = host
        self.port = port
        self.max_message_bytes = max_message_bytes
        self.ui_dir = Path(ui_dir).resolve()
        self.token = secrets.token_urlsafe(24)
        self.on_message = on_message
        self.on_last_client_gone = on_last_client_gone
        self.clients: set[ServerConnection] = set()
        self._out: list[dict] = []
        self._server = None
        self._flusher: asyncio.Task | None = None

    @property
    def origin(self) -> str:
        return f"http://{self.host}:{self.port}"

    @property
    def url(self) -> str:
        return f"{self.origin}/#token={self.token}"

    async def start(self) -> None:
        self._server = await serve(
            self._handle,
            self.host,
            self.port,
            origins=[self.origin],
            process_request=self._process_request,
            # websockets defaults this to 1 MiB, which is smaller than the body the
            # editor will happily hand back. Exceeding it closes the connection,
            # and a closed UI force-forwards every held flow unedited -- so the
            # user's edit vanished and the original went upstream.
            max_size=self.max_message_bytes,
        )
        self._flusher = asyncio.create_task(self._flush_loop())

    async def stop(self) -> None:
        if self._flusher:
            self._flusher.cancel()
        if self._server:
            self._server.close()
            # Without this, stop() can return before the port is actually free --
            # which is why restarting on the same port needed a retry loop.
            await self._server.wait_closed()

    # ------------------------------------------------------------ handshake

    def _process_request(self, conn: ServerConnection, request) -> Response | None:
        route, _, query = request.path.partition("?")
        if route == "/ws":
            token = parse_qs(query).get("token", [""])[0]
            if not hmac.compare_digest(token, self.token):
                logging.warning("bridge: rejected /ws (bad or missing token)")
                return conn.respond(403, "forbidden\n")
            return None  # continue into the WebSocket handshake
        return self._static(conn, route)

    def _static(self, conn: ServerConnection, route: str) -> Response:
        name = "index.html" if route in ("", "/") else route.lstrip("/")
        path = (self.ui_dir / name).resolve()
        # resolve() then containment check: no ../ escape out of ui/.
        if not path.is_relative_to(self.ui_dir) or not path.is_file():
            return conn.respond(404, "not found\n")
        body = path.read_bytes()
        return Response(
            200,
            "OK",
            Headers({
                "Content-Type": CONTENT_TYPES.get(path.suffix, "application/octet-stream"),
                "Content-Length": str(len(body)),
                "Cache-Control": "no-store",
                # This origin is reachable from any page the user visits, so do not
                # let the browser guess a type we did not declare.
                "X-Content-Type-Options": "nosniff",
            }),
            body,
        )

    # ------------------------------------------------------------ messaging

    async def _handle(self, conn: ServerConnection) -> None:
        self.clients.add(conn)
        try:
            async for raw in conn:
                try:
                    msg = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if isinstance(msg, dict):
                    try:
                        await self.on_message(msg)
                    except Exception as e:
                        # One bad command costs one command. Letting it reach the
                        # outer handler ended the connection, and a gone UI means
                        # every held flow is force-forwarded unedited.
                        logging.warning(f"bridge: {msg.get('type')!r} failed: {e!r}")
                        self.push("error", message=f"{msg.get('type')} failed: {e}")
        except Exception as e:  # transport-level: a UI bug must not take the proxy down
            logging.warning(f"bridge: client error: {e!r}")
        finally:
            self.clients.discard(conn)
            if not self.clients:
                # A closed UI must never leave flows paused forever.
                self.on_last_client_gone()

    def push(self, type_: str, **payload) -> None:
        self._out.append({"type": type_, **payload})

    async def _flush_loop(self) -> None:
        while True:
            await asyncio.sleep(FLUSH_INTERVAL)
            if not self._out:
                continue
            batch, self._out = self._out, []
            if not self.clients:
                continue  # nothing listening; a fresh client gets a full snapshot
            try:
                data = json.dumps(batch, default=str)
            except (TypeError, ValueError) as e:
                logging.warning(f"bridge: undeliverable batch dropped: {e}")
                continue
            await asyncio.gather(
                *(c.send(data) for c in tuple(self.clients)), return_exceptions=True
            )
