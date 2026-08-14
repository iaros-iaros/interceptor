"""Breaking traffic on purpose: delay it, answer it with an error, or drop it.

**Why this is not covered by anything already here.** Intercept can produce a 500
-- hold the response and type one -- but it catches one flow at a time, by hand,
and it cannot produce a *timeout* at all (you would be the stopwatch, while the
held flow stalls that host's other connections). Rewrite rules run automatically,
which is the right shape, but `modify_body`/`modify_headers` only substitute text
inside a body or a header: no status code, no delay, no dropped connection. So
the manual path is unrepeatable and the automatic path cannot express failure.

**Why the delay does not block the proxy.** mitmproxy awaits coroutine hooks
(`addonmanager.invoke_addon`), so `await asyncio.sleep()` inside a hook suspends
that one flow and nothing else -- the same shape the pause queue already relies
on when it parks a flow in `wait_for_resume`.

Deliberately not here: truncated bodies and probabilistic firing. Both are real,
neither has been asked for, and each needs its own UI column.
"""

from __future__ import annotations

import asyncio
import logging

from mitmproxy import flowfilter, http

# An unbounded delay is a hang, not a test, and it holds a real client connection
# open for the whole time. Two minutes is past every client timeout worth testing.
MAX_DELAY_MS = 120_000

# What a synthesized reply says when the rule does not name a body. JSON because
# the client under test is almost always parsing one, and an empty body makes
# "did my error handling run" ambiguous with "did the parse fail".
DEFAULT_BODY = '{"error": "injected by interceptor"}'


class Fault:
    """One rule. Effects apply in order: delay, then drop, then reply."""

    __slots__ = ("url", "delay_ms", "status", "body", "drop", "_filter")

    def __init__(self, spec: dict) -> None:
        self.url = str(spec.get("url") or "").strip()
        self.delay_ms = int(spec.get("delay_ms") or 0)
        status = spec.get("status")
        self.status = int(status) if status not in (None, "", False) else None
        self.body = str(spec.get("body") or "")
        self.drop = bool(spec.get("drop"))

        if self.delay_ms < 0 or self.delay_ms > MAX_DELAY_MS:
            raise ValueError(
                f"delay must be between 0 and {MAX_DELAY_MS}ms (got {self.delay_ms})"
            )
        if self.status is not None and not 100 <= self.status <= 599:
            raise ValueError(f"status must be between 100 and 599 (got {self.status})")
        if self.drop and self.status is not None:
            raise ValueError(
                "a rule cannot both drop the connection and send a reply — "
                "drop leaves the client with nothing, a reply is something"
            )
        if not (self.delay_ms or self.drop or self.status is not None):
            raise ValueError("rule does nothing: set a delay, a status, or drop")

        expr = f"~u {self.url}" if self.url else "~all"
        try:
            self._filter = flowfilter.parse(expr)
        except ValueError as e:
            raise ValueError(f"bad URL pattern {self.url!r}: {e}") from e

    def matches(self, flow) -> bool:
        return bool(self._filter(flow))

    def describe(self) -> str:
        """Human-readable, and it lands on the flow so the table can say where a
        failure came from. A 503 you injected is indistinguishable from a real
        one without this."""
        bits = []
        if self.delay_ms:
            bits.append(f"delayed {self.delay_ms}ms")
        if self.drop:
            bits.append("dropped")
        if self.status is not None:
            bits.append(f"replied {self.status}")
        return ", ".join(bits)

    def to_spec(self) -> dict:
        return {"url": self.url, "delay_ms": self.delay_ms, "status": self.status,
                "body": self.body, "drop": self.drop}


def parse_all(specs: list[dict]) -> list[Fault]:
    """Validates every rule before accepting any, so a typo in the third row can
    never leave the first two armed and the user believing all three are."""
    out = []
    for i, spec in enumerate(specs, start=1):
        try:
            out.append(Fault(spec))
        except (ValueError, TypeError) as e:
            raise ValueError(f"fault rule {i}: {e}") from e
    return out


async def apply(faults: list[Fault], flow: http.HTTPFlow) -> str | None:
    """Apply the first matching rule. Returns its description, or None.

    First match wins rather than all matches composing: two rules each adding a
    delay to the same request is a number nobody predicted, and a rule list is
    read top to bottom.
    """
    for fault in faults:
        if not fault.matches(flow):
            continue
        if fault.delay_ms:
            await asyncio.sleep(fault.delay_ms / 1000)
            # The client may have given up, or the flow may have been killed,
            # while we slept. Touching .response on a dead flow is not an edit,
            # it is an exception on the proxy's own event loop.
            if not flow.live or flow.error is not None:
                return fault.describe()
        if fault.drop:
            if flow.killable:
                flow.kill()
        elif fault.status is not None:
            # Setting a response in the request hook means mitmproxy never dials
            # the server -- the reply is entirely ours.
            flow.response = http.Response.make(
                fault.status,
                fault.body or DEFAULT_BODY,
                {"content-type": "application/json", "x-interceptor-fault": "1"},
            )
        logging.debug(f"interceptor: fault {fault.describe()} -> {flow.request.pretty_url}")
        return fault.describe()
    return None
