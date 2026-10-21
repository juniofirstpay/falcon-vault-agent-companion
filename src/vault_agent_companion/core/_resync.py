"""Shared plumbing for event-driven watching backed by a periodic resync.

``watchfiles`` events are a fast-path HINT, not a guarantee: a render that lands before the
watch arms is never reported, and an event can be lost outright (inotify queue overflow,
some overlay / bind-mounted volumes). So both watchers also resync on a timer — compare each
registered file's content fingerprint against the last one handled, and act on a mismatch.

The timer rides on ``awatch`` itself (``yield_on_timeout``): an idle watch yields an empty
batch every tick, so events and resyncs run in ONE task — no lock, no concurrent reloads.
The first batch (event or tick) is only yielded once the watch is armed, so the first
resync doubles as the "sync once after arming" pass.
"""

from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Optional

# Re-check every registered file this often (seconds). A failed load / handler keeps the
# previous state, so a spurious resync is harmless; a missed one is a stale cert.
DEFAULT_RESYNC_INTERVAL = 300.0

# Upper bound on the awatch idle tick: how late the post-arm sync can land, and the
# granularity of the resync timer. Matches watchfiles' own default async timeout.
_MAX_TICK_MS = 5_000


def fingerprint(path: str) -> Optional[bytes]:
    """sha256 of the file's bytes, or ``None`` if it can't be read right now.

    Content, not mtime/size: re-issued leaves are routinely the same size, and some volumes
    have coarse mtimes. The rendered files are a few KB, so hashing is cheap.
    """
    try:
        return hashlib.sha256(Path(path).read_bytes()).digest()
    except OSError:
        return None


def tick_ms(resync_interval: Optional[float]) -> int:
    """``rust_timeout`` for awatch: the resync interval, capped at :data:`_MAX_TICK_MS`."""
    if not resync_interval or resync_interval <= 0:
        return _MAX_TICK_MS
    return max(1, min(_MAX_TICK_MS, int(resync_interval * 1000)))


class ResyncClock:
    """``due()`` is True on the first call (the post-arm sync), then once per interval.

    A falsy / non-positive interval disables the periodic part; the first call still fires.
    """

    def __init__(self, interval: Optional[float]) -> None:
        self._interval = interval if interval and interval > 0 else None
        self._last: Optional[float] = None

    def due(self) -> bool:
        now = time.monotonic()
        if self._last is None or (
            self._interval is not None and now - self._last >= self._interval
        ):
            self._last = now
            return True
        return False
