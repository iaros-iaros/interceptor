"""Flow storage: completed flows in SQLite, in-flight flows in RAM.

**Why hybrid.** A flow the proxy is still working on cannot round-trip through the
database. `resume()`, `.intercepted` and `.live` only mean anything on the exact
object the proxy is awaiting -- rehydrating a copy from a blob gives you something
that looks identical and releases nothing. So anything in flight is held by
reference, which costs no extra memory because the proxy holds it anyway, and only
its summary is written. The body blob is written once, when the flow finalises.

**Why the index stays in RAM.** Every invariant the addon depends on -- the byte
total, eviction order, "do we already have this id" -- has to be exact and
synchronous. Answering those from SQLite would put blocking I/O on the proxy's
event loop, which is the one thing this file must not do. So RAM holds ids, sizes
and order (about a hundred bytes a flow) and disk holds the payloads.

**Why writes are batched.** At a few thousand flows a second, one transaction per
flow would be thousands of fsync-adjacent calls on the event loop. Upserts
accumulate and flush on a timer, in a single transaction, exactly like the UI
bridge batches its own pushes. A read that needs a payload flushes first, so a
pending write is never invisible.

**Why serialisation happens in flush(), not put().** `get_state()` deep-copies the
whole flow, bodies included, and `tnetstring.dumps` then walks that copy -- and
`put()` is called from the `response` hook, i.e. on the same event loop that is
terminating TLS. Building the search text costs another decode of both bodies on
top. Doing either per flow at hook time is the one cost in this file that scales
with body size; doing both once per 100ms tick, off the hook, does not. `_pending`
therefore holds the flow itself and the row is built at flush time.

The file is created 0600 in the temp dir and unlinked on exit: it holds decrypted
traffic, cookies and bearer tokens included. `sessions/` stays explicit-only.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import tempfile
from collections import OrderedDict
from collections.abc import Iterator, Mapping
from pathlib import Path

from mitmproxy import http
from mitmproxy.io import tnetstring

# Flows kept as live Python objects after they finalise, so clicking a recent row
# does not go to disk. Bounded by count, not bytes: these are the only flows whose
# memory is genuinely ours (the proxy has let go of them).
CACHE_ROWS = 200

# A reconnecting UI gets the newest N summaries, not the whole table. With an
# unbounded store the snapshot would otherwise grow without limit, and the browser
# discards everything past its own cap anyway.
SNAPSHOT_ROWS = 2000

# Per flow, how much searchable text is kept. This duplicates part of the body
# that `state` already holds, so it is a disk cost paid for being able to ask
# "which response carried this token" -- the question the store existed to answer
# and could not. 256KB covers an API response many times over; past that a body is
# a bundle or an image and substring search is not what anyone wants from it.
SEARCH_TEXT_MAX = 256 * 1024

SCHEMA = """
CREATE TABLE IF NOT EXISTS flow (
    id      TEXT PRIMARY KEY,
    seq     INTEGER NOT NULL,
    size    INTEGER NOT NULL DEFAULT 0,
    summary TEXT    NOT NULL,
    state   BLOB,
    text    TEXT
);
CREATE INDEX IF NOT EXISTS flow_seq ON flow(seq);
"""

# LIKE's own wildcards, plus the escape character itself. Without this a search
# for "100%" matches every flow and a search for "a_b" matches "axb".
_LIKE_ESCAPE = str.maketrans({"\\": r"\\", "%": r"\%", "_": r"\_"})


def _search_text(flow: http.HTTPFlow) -> str:
    """URL, headers and both bodies as one blob to match against.

    Headers are in deliberately: "which response set this cookie" and "what still
    sends an Authorization header" are the same question as a body search, and
    excluding them would make the feature feel arbitrarily half-done.
    """
    parts = [flow.request.pretty_url]
    for msg in (flow.request, flow.response):
        if msg is None or getattr(msg, "stream", False):
            continue  # a streamed body was never buffered; there is nothing to index
        parts.append("\n".join(f"{k}: {v}" for k, v in msg.headers.items(True)))
        # strict=False: a body whose bytes contradict its declared encoding is
        # exactly the kind of thing worth finding, so index it surrogate-escaped
        # rather than skipping it.
        try:
            parts.append(msg.get_text(strict=False) or "")
        except (ValueError, TypeError):
            pass  # decompression failed; the rest of the flow is still indexed
    return "\n".join(parts)[:SEARCH_TEXT_MAX]


class FlowStore:
    """Dict-ish over flow ids. Iterating yields ids in last-updated order."""

    def __init__(self, path: Path | None = None) -> None:
        # id -> size, in last-updated order. This is the authoritative index:
        # membership, byte total and eviction order all come from here.
        self._index: OrderedDict[str, int] = OrderedDict()
        self.bytes = 0
        self.evicted = 0

        self._live: dict[str, http.HTTPFlow] = {}          # in flight, by reference
        self._cache: OrderedDict[str, http.HTTPFlow] = OrderedDict()
        self._pending: dict[str, tuple] = {}               # id -> row awaiting write
        self._deleted: list[str] = []
        self._seq = 0
        self._tmp: tempfile.TemporaryDirectory | None = None

        if path is None:
            self._tmp = tempfile.TemporaryDirectory(prefix="interceptor-store-")
            path = Path(self._tmp.name) / "flows.db"
        self.path = Path(path)
        # 0600 from the first byte, like the session writer: this file is every
        # captured request in plaintext.
        if str(self.path) != ":memory:":
            os.close(os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600))
        self.db = sqlite3.connect(str(self.path), isolation_level=None)
        self.db.executescript(
            # WAL so a reader never blocks the writer; NORMAL because losing the
            # last few flows to a power cut is not worth an fsync per batch.
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;" + SCHEMA
        )

    # ------------------------------------------------------------ mapping-ish

    @property
    def sizes(self) -> Mapping[str, int]:
        return self._index

    def __len__(self) -> int:
        return len(self._index)

    def __iter__(self) -> Iterator[str]:
        return iter(self._index)

    def __contains__(self, fid: str) -> bool:
        return fid in self._index

    # ------------------------------------------------------------ writing

    def put(self, flow: http.HTTPFlow, size: int, summary: dict, cap_bytes: int) -> None:
        """Insert or update, then evict oldest until under the cap."""
        self.bytes -= self._index.pop(flow.id, 0)
        self._index[flow.id] = size
        self._index.move_to_end(flow.id)
        self.bytes += size
        self._seq += 1

        # Can this flow still change, or still be acted on by identity? Each clause
        # guards a specific hazard, and `flow.live` cannot stand in for any of them:
        # it is still True inside the response hook (the HTTP layer clears it later,
        # when it drops the stream), so trusting it would mean nothing was ever
        # persisted and no memory was ever released.
        #
        #  * no response and no error -> the response hook will still fill it in
        #  * intercepted -> resume() acts on this exact object; a rehydrated copy
        #    would release nothing and strand the client
        #  * websocket still open -> inject.websocket acts on this exact object,
        #    and frames are still arriving
        final = (
            (flow.response is not None or flow.error is not None)
            and not flow.intercepted
            and not (flow.websocket is not None
                     and flow.websocket.timestamp_end is None)
        )
        if final:
            self._live.pop(flow.id, None)
            self._cache[flow.id] = flow
            self._cache.move_to_end(flow.id)
            while len(self._cache) > CACHE_ROWS:
                self._cache.popitem(last=False)
        else:
            self._live[flow.id] = flow

        # The flow itself, not its serialised form -- see the module docstring.
        # A flow that changes again before the next tick simply re-enters here and
        # overwrites this entry, which is the same last-write-wins the old code had.
        self._pending[flow.id] = (flow, self._seq, size, json.dumps(summary), final)
        self._evict(cap_bytes)

    def _evict(self, cap_bytes: int) -> None:
        while self.bytes > cap_bytes and len(self._index) > 1:
            fid, size = self._index.popitem(last=False)
            self.bytes -= size
            self.evicted += 1
            self._forget(fid)

    def _forget(self, fid: str) -> None:
        self._live.pop(fid, None)
        self._cache.pop(fid, None)
        self._pending.pop(fid, None)
        self._deleted.append(fid)

    def flush(self) -> None:
        """One transaction for the whole batch. Safe to call at any time.

        Serialisation and search-text extraction happen here rather than in put(),
        so neither lands on the proxy's event loop per flow.
        """
        if not self._pending and not self._deleted:
            return
        pending, gone = list(self._pending.values()), self._deleted
        self._pending, self._deleted = {}, []

        rows = []
        for flow, seq, size, summary, final in pending:
            blob = text = None
            if final:
                try:
                    blob = tnetstring.dumps(flow.get_state())
                    text = _search_text(flow)
                except Exception as e:
                    # One unserialisable flow must not cost the whole batch: the
                    # rest of the tick is still good, and the row's summary (which
                    # is what the table draws) does not depend on either of these.
                    logging.warning(f"interceptor: could not serialise flow: {e}")
                    blob = text = None
            rows.append((flow.id, seq, size, summary, blob, text))

        try:
            self.db.execute("BEGIN")
            if rows:
                # COALESCE keeps a blob already written from being nulled by a
                # later summary-only update.
                self.db.executemany(
                    "INSERT INTO flow (id, seq, size, summary, state, text) "
                    "VALUES (?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(id) DO UPDATE SET seq=excluded.seq, "
                    "size=excluded.size, summary=excluded.summary, "
                    "state=COALESCE(excluded.state, flow.state), "
                    "text=COALESCE(excluded.text, flow.text)",
                    rows,
                )
            if gone:
                self.db.executemany("DELETE FROM flow WHERE id = ?",
                                    [(g,) for g in gone])
            self.db.execute("COMMIT")
        except sqlite3.Error as e:
            # Never take the proxy down over storage. The in-RAM index is still
            # correct, so the table keeps working; only history is at risk.
            logging.warning(f"interceptor: flow store write failed: {e}")
            try:
                self.db.execute("ROLLBACK")
            except sqlite3.Error:
                pass

    # ------------------------------------------------------------ reading

    def get(self, fid: str | None) -> http.HTTPFlow | None:
        """The live object when we have one, else rehydrated from disk."""
        if fid is None or fid not in self._index:
            return None
        flow = self._live.get(fid) or self._cache.get(fid)
        if flow is not None:
            return flow
        self.flush()   # a pending write must not read as absent
        row = self.db.execute("SELECT state FROM flow WHERE id = ?", (fid,)).fetchone()
        if row is None or row[0] is None:
            return None
        try:
            flow = http.HTTPFlow.from_state(tnetstring.loads(row[0]))
        except Exception as e:
            logging.warning(f"interceptor: could not read flow {fid}: {e}")
            return None
        self._cache[fid] = flow
        self._cache.move_to_end(fid)
        while len(self._cache) > CACHE_ROWS:
            self._cache.popitem(last=False)
        return flow

    def summaries(self, limit: int = SNAPSHOT_ROWS) -> list[dict]:
        """Newest `limit` summaries, oldest first -- the order the UI appends in."""
        self.flush()
        rows = self.db.execute(
            "SELECT summary FROM flow ORDER BY seq DESC LIMIT ?", (limit,)
        ).fetchall()
        return [json.loads(r[0]) for r in reversed(rows)]

    def search(self, needle: str, limit: int = SNAPSHOT_ROWS) -> list[dict]:
        """Summaries of flows whose URL, headers or bodies contain `needle`.

        The question this answers -- "which response carried this token" -- was
        previously unaskable: the row filter only ever saw what the table drew.

        ponytail: a LIKE scan, no index. `LIKE '%x%'` cannot use one, and FTS
        tokenises, which would stop the substring matches that make this useful
        for hunting a token or a fragment of a stack trace. At a few thousand rows
        the scan is milliseconds. If a capture ever gets big enough for this to
        drag, the upgrade is FTS5 as a *second* column beside this one, not
        instead of it.
        """
        needle = (needle or "").strip()
        if not needle:
            return []
        self.flush()
        pattern = f"%{needle.translate(_LIKE_ESCAPE)}%"
        try:
            rows = self.db.execute(
                "SELECT summary FROM flow WHERE text LIKE ? ESCAPE '\\' "
                "ORDER BY seq DESC LIMIT ?",
                (pattern, limit),
            ).fetchall()
        except sqlite3.Error as e:
            logging.warning(f"interceptor: search failed: {e}")
            return []
        return [json.loads(r[0]) for r in reversed(rows)]

    def iter_flows(self) -> Iterator[http.HTTPFlow]:
        """Every flow we still hold, for a session write. Streams rather than
        materialising: the store can now be far larger than memory."""
        self.flush()
        for (fid,) in self.db.execute("SELECT id FROM flow ORDER BY seq").fetchall():
            flow = self.get(fid)
            if flow is not None:
                yield flow

    # ------------------------------------------------------------ lifecycle

    def clear(self) -> None:
        self._index.clear()
        self._live.clear()
        self._cache.clear()
        self._pending.clear()
        self._deleted.clear()
        self.bytes = 0
        self.evicted = 0
        try:
            self.db.execute("DELETE FROM flow")
        except sqlite3.Error as e:
            logging.warning(f"interceptor: could not clear flow store: {e}")

    def close(self) -> None:
        try:
            self.flush()
            self.db.close()
        except sqlite3.Error as e:
            logging.warning(f"interceptor: closing flow store: {e}")
        finally:
            # The file is decrypted traffic; it does not outlive the process.
            if self._tmp is not None:
                try:
                    self._tmp.cleanup()
                except OSError as e:
                    logging.warning(f"interceptor: could not wipe {self._tmp.name}: {e}")
