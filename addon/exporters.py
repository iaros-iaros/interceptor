"""Getting a captured flow back out of the tool.

Until now the only exit was a `.mitm` session file, which nothing but this tool
reads -- so the moment a tester actually cares about ("hand a developer something
they can run") meant retyping the request by hand.

Both halves are mitmproxy's own, already loaded by `mitmdump`: the `export`
addon (curl / httpie / raw) and the `savehar` addon. This module only routes to
them and owns the file permissions, which matter -- both outputs are decrypted
traffic with cookies and bearer tokens in them.
"""

from __future__ import annotations

import asyncio
import itertools
import json
import os
from datetime import datetime
from pathlib import Path

from mitmproxy import ctx, http

# What the row context menu offers. `raw` is the whole exchange, `raw_request`
# just the request -- the two people actually paste somewhere.
FORMATS = ("curl", "httpie", "raw_request", "raw")


def export_text(flow: http.HTTPFlow, fmt: str) -> str:
    """One flow as a runnable command or as raw bytes. Raises ValueError on an
    unknown format so the caller can report it rather than pushing None."""
    if fmt not in FORMATS:
        raise ValueError(f"unknown export format {fmt!r}")
    if not isinstance(flow, http.HTTPFlow):
        raise ValueError("not an HTTP flow")
    # Via the command rather than the formats dict: the command layer also
    # resolves surrogate escapes, which a raw body will otherwise carry into the
    # clipboard as undecodable bytes.
    return ctx.master.commands.call("export", fmt, flow)


async def write_har(flows, directory: Path, open_private) -> tuple[str, int]:
    """Every flow as a HAR file in `directory`. Returns (filename, bytes).

    HAR is the interchange format devtools, performance tooling and most other
    proxies all read, so this is what makes a capture outlive Interceptor.

    Streamed: each entry is built, written and dropped in turn, and the event loop
    gets a turn every 50 flows. make_har() on the whole capture held it three times
    over -- flows, dict, JSON string -- several GB at the default store cap, all
    while the proxy waited.

    `open_private` is the addon's 0600 opener, passed in rather than imported so
    this module does not reach back into interceptor.py. A HAR holds full request
    and response bodies in plaintext -- it gets the same treatment as a session
    dump, 0600 from the first byte rather than chmod-after.
    """
    savehar = ctx.master.addons.get("savehar")
    if savehar is None:  # pragma: no cover -- default_addons always provides it
        raise ValueError("HAR export unavailable: savehar addon not loaded")

    # Only HTTP flows: make_har logs and skips anything else, and a HAR of zero
    # entries is a confusing thing to hand someone.
    flows = (f for f in flows if isinstance(f, http.HTTPFlow))
    first = next(flows, None)
    if first is None:
        raise ValueError("nothing to export yet")

    directory.mkdir(mode=0o700, exist_ok=True)
    if directory.stat().st_mode & 0o077:
        directory.chmod(0o700)  # mkdir(exist_ok) does not touch an existing dir
    name = f"{datetime.now().strftime('%Y-%m-%d_%H%M%S')}.har"
    # make_har([]) is the envelope -- version, creator, pages -- with the entries
    # written into it by hand: its JSON minus the closing "}}", then the list.
    log = savehar.make_har([])["log"]
    del log["entries"]
    servers_seen: set = set()
    with os.fdopen(open_private(directory / name), "w", encoding="utf-8") as fh:
        fh.write(json.dumps({"log": log})[:-2] + ', "entries": [')
        for i, f in enumerate(itertools.chain([first], flows)):
            fh.write(("," if i else "") + json.dumps(savehar.flow_entry(f, servers_seen)))
            if i % 50 == 49:
                await asyncio.sleep(0)
        fh.write("]}}")
    return name, (directory / name).stat().st_size
