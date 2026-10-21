"""Hot-reload rotating mTLS leaf certs into live SSLContexts.

``SSLContext.load_cert_chain`` is re-callable: it swaps the cert used for NEW handshakes
while in-flight connections keep the old one, and it leaves ``verify_mode`` /
``load_verify_locations`` (the trust root) untouched. So rotating a leaf is just
re-loading the chain — no restart, no monkey-patching.

Both roles register here: the inbound server context (uvicorn's ``config.ssl``) AND any
outbound http-client context the service presents on east-west calls.
"""

from __future__ import annotations

import logging
import ssl
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

from watchfiles import awatch

from vault_agent_companion.core._resync import (
    DEFAULT_RESYNC_INTERVAL,
    ResyncClock,
    fingerprint,
    tick_ms,
)

logger = logging.getLogger(__name__)

_Target = Tuple[ssl.SSLContext, str, str]  # (context, cert_path, key_path)


class CertRotator:
    """Registry of (SSLContext, cert file) pairs, reloaded when the file changes."""

    def __init__(self) -> None:
        self._targets: List[_Target] = []
        # cert path -> fingerprint of the content last loaded into EVERY context for it
        self._loaded: Dict[str, bytes] = {}

    def register(
        self,
        ctx: ssl.SSLContext,
        cert_path: Union[str, Path],
        key_path: Optional[Union[str, Path]] = None,
    ) -> "CertRotator":
        """Register a context. ``key_path`` defaults to ``cert_path`` (the sidecar renders
        cert+key into one PEM). Chainable."""
        cert = str(Path(cert_path).resolve())
        key = str(Path(key_path or cert_path).resolve())
        self._targets.append((ctx, cert, key))
        return self

    def _certs(self) -> List[str]:
        """Distinct registered cert paths, in registration order."""
        return list(dict.fromkeys(cert for _, cert, _ in self._targets))

    def _load(self, cert: str, fp: Optional[bytes] = None) -> None:
        """Re-load ``cert`` into every context registered for it; record its fingerprint
        only if all of them succeeded (otherwise the next resync retries)."""
        # Fingerprint BEFORE loading: a swap mid-load leaves a stale fingerprint, which
        # costs one extra reload on the next resync — never a missed rotation.
        if fp is None:
            fp = fingerprint(cert)
        ok = True
        for ctx, c, key in self._targets:
            if c != cert:
                continue
            try:
                ctx.load_cert_chain(certfile=cert, keyfile=key)
                logger.info("mtls cert reloaded: %s", cert)
            except (ssl.SSLError, OSError) as exc:
                ok = False
                logger.warning("mtls cert reload failed for %s: %s", cert, exc)
        if ok and fp is not None:
            self._loaded[cert] = fp

    def reload(self, only_cert: Optional[str] = None) -> None:
        """Re-load the chain for every registered context (or just ``only_cert``).

        A failed load (e.g. a half-written file) is logged and skipped, never raised —
        the context keeps serving the previous cert until the next good render.
        """
        for cert in self._certs():
            if only_cert is None or cert == only_cert:
                self._load(cert)

    def resync(self) -> None:
        """Reload every cert whose file content differs from what was last loaded.

        Never-loaded certs count as differing, so the first call reloads everything. Cheap
        when nothing changed (one small file read + hash per cert); :meth:`watch` calls it
        once after arming and then periodically, to recover renders the watch never saw.
        """
        for cert in self._certs():
            fp = fingerprint(cert)
            if fp is not None and fp != self._loaded.get(cert):
                self._load(cert, fp)

    async def watch(
        self,
        *,
        stop_event: Optional[object] = None,
        debounce: int = 200,
        step: int = 50,
        resync_interval: Optional[float] = DEFAULT_RESYNC_INTERVAL,
        force_polling: Optional[bool] = None,
        poll_delay_ms: int = 300,
    ) -> None:
        """Watch every registered cert file; reload the affected context(s) on change.

        Events are the fast path. Once the watch is armed it also calls :meth:`resync` (so a
        render that landed before arming is picked up), then every ``resync_interval``
        seconds (so a dropped event costs minutes, not a whole cert lifetime). Pass
        ``resync_interval=None`` to keep only the post-arm sync. ``force_polling`` /
        ``poll_delay_ms`` go to ``watchfiles.awatch`` (``None`` defers to the
        ``WATCHFILES_FORCE_POLLING`` env var), for volumes that don't deliver events.
        """
        certs = set(self._certs())
        dirs = {str(Path(cert).parent) for cert in certs}
        clock = ResyncClock(resync_interval)
        async for changes in awatch(
            *dirs,
            stop_event=stop_event,
            debounce=debounce,
            step=step,
            rust_timeout=tick_ms(resync_interval),
            yield_on_timeout=True,
            force_polling=force_polling,
            poll_delay_ms=poll_delay_ms,
        ):
            touched = {str(Path(p).resolve()) for _, p in changes} & certs
            for cert in touched:
                self.reload(only_cert=cert)
            if clock.due():
                self.resync()
