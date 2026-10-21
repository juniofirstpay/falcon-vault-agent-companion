"""One filesystem watcher per process.

A service that watches the rendered secrets file AND a rotating leaf (for the server
context + client contexts) does NOT need a watch loop per file. The Vault Agent renders
everything under one shared root (e.g. ``/shared``); ``watchfiles.awatch`` is recursive,
so a SINGLE ``awatch(root)`` sees every rendered file. This ``Watcher`` runs that one loop
and dispatches each change to the handlers registered for that path.

Reload DEPTH stays the app's concern — the watcher only fires the handlers it's given
(e.g. ``settings.reload()``; ``CertRotator.reload``; a client-lib ``reload_cert``).
"""

from __future__ import annotations

import asyncio
import inspect
from pathlib import Path
from typing import Awaitable, Callable, Dict, List, Optional, Union

from watchfiles import awatch

from vault_agent_companion.core._resync import (
    DEFAULT_RESYNC_INTERVAL,
    ResyncClock,
    fingerprint,
    tick_ms,
)

Handler = Callable[[], Optional[Awaitable[None]]]
# Invoked with (exception, path) when a handler raises. May be sync or async.
ErrorHandler = Callable[[BaseException, str], Optional[Awaitable[None]]]


async def _maybe_await(result: object) -> None:
    if inspect.isawaitable(result):
        await result


class Watcher:
    """Single ``awatch`` over a root dir; fires the handlers registered for each changed file.

    Handlers may be sync or async, and several may be registered for one path (they fire in
    registration order — e.g. reload the server ctx AND the client libs on a leaf change).

    A handler that raises MUST NOT kill the watch loop — otherwise one transient reload error
    (a half-rendered file, a downstream rebuild hiccup) silently stops ALL future rotations
    until the process restarts. So :meth:`watch` isolates each handler: an exception is routed
    to the optional ``on_error`` callback (or swallowed) and the loop carries on. Only
    ``asyncio.CancelledError`` propagates, so cancelling the task still stops the watcher.

    Events alone can miss a render (one that lands before the watch arms, or a dropped
    event), so :meth:`watch` also resyncs: each path's content fingerprint is compared with
    the one last handled (baseline: when it was registered with :meth:`on`) and its handlers
    fire on a mismatch. A path only counts as handled once ALL its handlers succeeded, so a
    failed handler is retried on the next resync instead of waiting for the next render.

    The ``on()`` baseline leaves one gap: a render between the app's OWN initial read and
    ``on()``. For a rotating cert that's an outage once the in-memory leaf expires, so pass
    ``sync_on_arm=True`` there — the path then has no baseline and its handlers fire once
    the watch is armed. Leave it off where a needless boot-time fire is costly (a secrets
    reload that rebuilds pools).
    """

    def __init__(self, root: Union[str, Path]) -> None:
        self._root = Path(root).resolve()
        self._handlers: Dict[str, List[Handler]] = {}
        # path -> fingerprint of the content its handlers last ALL succeeded on
        self._synced: Dict[str, Optional[bytes]] = {}

    def on(
        self, path: Union[str, Path], handler: Handler, *, sync_on_arm: bool = False
    ) -> "Watcher":
        """Register ``handler`` for changes to ``path`` (must live under the root). Chainable.

        By default the file's current content is the resync baseline: the app is assumed to
        have read it already, so only a later change fires the handler. With
        ``sync_on_arm=True`` the path has no baseline, so ALL its handlers fire once after the
        watch arms (and are retried on later resyncs until they all succeed) — use it for a
        cert whose initial load happened before ``on()``.
        """
        key = str(Path(path).resolve())
        self._handlers.setdefault(key, []).append(handler)
        if sync_on_arm:
            self._synced[key] = None  # never handled: the post-arm resync fires it
        else:
            self._synced.setdefault(key, fingerprint(key))
        return self

    async def _dispatch(
        self, path: str, on_error: Optional[ErrorHandler], fp: Optional[bytes] = None
    ) -> None:
        """Fire every handler for ``path``, isolating failures; mark it synced if all passed."""
        # Fingerprint BEFORE firing: a render mid-dispatch then shows up on the next resync.
        if fp is None:
            fp = fingerprint(path)
        ok = True
        for handler in self._handlers[path]:
            try:
                await _maybe_await(handler())
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 — one bad handler must not stop rotations
                ok = False
                if on_error is not None:
                    try:
                        await _maybe_await(on_error(exc, path))
                    except Exception:  # noqa: BLE001 — never let error reporting kill the loop
                        pass
        if ok:
            self._synced[path] = fp

    async def resync(self, *, on_error: Optional[ErrorHandler] = None) -> None:
        """Fire the handlers of every path whose content changed since it was last handled.

        Unreadable (e.g. missing) files are skipped. :meth:`watch` calls this once after
        arming and then periodically; it's also safe to call directly.
        """
        for path in list(self._handlers):
            fp = fingerprint(path)
            if fp is not None and fp != self._synced.get(path):
                await self._dispatch(path, on_error, fp)

    async def watch(
        self,
        *,
        stop_event: Optional[object] = None,
        debounce: int = 200,
        step: int = 50,
        on_error: Optional[ErrorHandler] = None,
        resync_interval: Optional[float] = DEFAULT_RESYNC_INTERVAL,
        force_polling: Optional[bool] = None,
        poll_delay_ms: int = 300,
    ) -> None:
        """Run the single watch loop until cancelled / stopped.

        A handler that raises never breaks the loop: the exception goes to ``on_error`` (if
        given) and the next change is still processed. ``asyncio.CancelledError`` is left to
        propagate so the task can be cancelled.

        Once armed, the loop calls :meth:`resync`, then again every ``resync_interval``
        seconds (``None`` keeps only the post-arm pass). ``force_polling`` /
        ``poll_delay_ms`` go to ``watchfiles.awatch`` (``None`` defers to the
        ``WATCHFILES_FORCE_POLLING`` env var), for volumes that don't deliver events.
        """
        clock = ResyncClock(resync_interval)
        async for changes in awatch(
            self._root,
            stop_event=stop_event,
            debounce=debounce,
            step=step,
            rust_timeout=tick_ms(resync_interval),
            yield_on_timeout=True,
            force_polling=force_polling,
            poll_delay_ms=poll_delay_ms,
        ):
            touched = {str(Path(p).resolve()) for _, p in changes} & self._handlers.keys()
            for path in touched:
                await self._dispatch(path, on_error)
            if clock.due():
                await self.resync(on_error=on_error)

    def spawn(self, **kwargs: object) -> "asyncio.Task[None]":
        """Start :meth:`watch` as a background task. Cancel the task to stop watching."""
        return asyncio.ensure_future(self.watch(**kwargs))  # type: ignore[arg-type]
