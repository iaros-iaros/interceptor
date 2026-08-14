"""Pretty-printing for message bodies, via mitmproxy's own contentviews.

The UI could only indent JSON (`JSON.parse` in app.js), so every other body type
-- protobuf, gRPC, form-encoded, multipart, XML, msgpack, GraphQL -- rendered as
an undifferentiated wall of latin-1. mitmproxy ships eighteen prettifiers and the
engine already imports them; this is the two-line adapter.

**Display only.** The prettified text never feeds the editor. `detail()` keeps
sending `body` and `raw` exactly as before, because those are what get written
back onto the wire and they have to stay byte-exact -- the CRLF/multipart
handling in `_apply_edits` depends on it. A protobuf rendering is not
round-trippable and must never be mistaken for one.
"""

from __future__ import annotations

import logging

from mitmproxy import contentviews, http

# Prettifying is a parse of the whole body, so it is not free. Past this the pane
# would be unreadable anyway and the cost lands on the proxy's event loop.
MAX_PRETTY = 1 * 1024 * 1024

# Views whose output is just the bytes back. Reporting them would put "shown as
# raw" under every plain-text body, which is noise -- the absence of a label
# already means "nothing was interpreted".
PLAIN_VIEWS = {"raw", "hex dump"}


def prettify(flow: http.HTTPFlow, msg: http.Message) -> tuple[str, str] | None:
    """Returns (text, view_name), or None when there is nothing to add.

    None means "the UI should show the body as it already has it" -- either
    prettifying failed, or the chosen view is a passthrough, or the result is
    identical to the plain body and would only cost bandwidth.
    """
    raw = msg.raw_content or b""
    if not raw or len(raw) > MAX_PRETTY:
        return None
    try:
        result = contentviews.prettify_message(msg, flow)
    except Exception as e:
        # A malformed body is the normal case here, not an exception worth
        # surfacing: the pane falls back to the plain rendering.
        logging.debug(f"interceptor: contentview failed: {e}")
        return None
    name = (result.view_name or "").lower()
    if not result.text or name in PLAIN_VIEWS:
        return None
    try:
        if result.text == (msg.get_text(strict=True) or ""):
            return None  # identical to what the UI already has
    except (ValueError, UnicodeDecodeError):
        pass  # undecodable plain body, so the prettified form is strictly better
    return result.text, result.view_name or "?"
