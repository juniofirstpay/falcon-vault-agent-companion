"""Issue #6: a render the watch never reports (before arming, or a dropped event) must still
be picked up — by the post-arm sync and the periodic resync."""

from __future__ import annotations

import asyncio
import ssl
from pathlib import Path

import pytest

from tests.conftest import make_self_signed
from tests.test_tls import _FakeCtx, _served_serial
from vault_agent_companion.core import tls, watcher
from vault_agent_companion.core._resync import ResyncClock, fingerprint, tick_ms
from vault_agent_companion.core.tls import CertRotator
from vault_agent_companion.core.watcher import Watcher


def _deaf_awatch(seen_kwargs: dict):
    """An ``awatch`` stand-in that never reports a change — every event is "dropped" — but
    yields the idle ticks that ``yield_on_timeout`` asks for."""

    async def fake(*paths, **kwargs):
        seen_kwargs.update(kwargs, paths=paths)
        assert kwargs["yield_on_timeout"] is True
        while True:
            await asyncio.sleep(kwargs["rust_timeout"] / 1000)
            yield set()

    return fake


async def _wait_for(pred, timeout: float = 3.0) -> bool:
    for _ in range(int(timeout / 0.02)):
        if pred():
            return True
        await asyncio.sleep(0.02)
    return pred()


async def _drain(task: asyncio.Task) -> None:
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


def _rotate(path: Path, serial: int) -> None:
    cert_pem, key_pem = make_self_signed("svc.internal", serial)
    path.write_bytes(cert_pem + key_pem)


# --- pure pieces --------------------------------------------------------------------------


def test_fingerprint_tracks_content_not_metadata(tmp_path):
    f = tmp_path / "leaf.pem"
    f.write_text("a")
    first = fingerprint(str(f))
    f.write_text("a")  # same bytes, new mtime
    assert fingerprint(str(f)) == first
    f.write_text("b")  # same size, new bytes
    assert fingerprint(str(f)) != first
    assert fingerprint(str(tmp_path / "missing.pem")) is None


@pytest.mark.parametrize(
    "interval, expected",
    [
        pytest.param(300.0, 5_000, id="capped-at-5s"),
        pytest.param(0.2, 200, id="short-interval"),
        pytest.param(None, 5_000, id="disabled"),
    ],
)
def test_tick_ms(interval, expected):
    assert tick_ms(interval) == expected


def test_resync_clock_fires_first_then_per_interval(monkeypatch):
    now = [100.0]
    monkeypatch.setattr("vault_agent_companion.core._resync.time.monotonic", lambda: now[0])
    clock = ResyncClock(10.0)
    assert clock.due()  # post-arm sync
    now[0] += 9.9
    assert not clock.due()
    now[0] += 0.2
    assert clock.due()

    disabled = ResyncClock(None)
    assert disabled.due()
    now[0] += 1e6
    assert not disabled.due()


# --- CertRotator --------------------------------------------------------------------------


def test_cert_resync_reloads_only_on_content_change(write_leaf):
    leaf = write_leaf("leaf", "svc.internal", 1)
    ctx = _FakeCtx()
    rotator = CertRotator().register(ctx, leaf)

    rotator.resync()
    assert len(ctx.calls) == 1, "never-loaded cert must be loaded on the first resync"
    rotator.resync()
    assert len(ctx.calls) == 1, "unchanged content must not reload"
    _rotate(leaf, 2)
    rotator.resync()
    assert len(ctx.calls) == 2


def test_cert_resync_retries_after_failed_load(tmp_path, write_leaf):
    leaf = write_leaf("leaf", "svc.internal", 1)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(leaf), keyfile=str(leaf))
    rotator = CertRotator().register(ctx, leaf)
    rotator.resync()

    leaf.write_text("half-written")
    rotator.resync()  # fails, logged — previous cert still served
    assert _served_serial(ctx) == 1
    _rotate(leaf, 2)
    rotator.resync()
    assert _served_serial(ctx) == 2


async def test_cert_render_before_arming_is_loaded(monkeypatch, write_leaf):
    """Arming gap: the app loaded serial 1, then serial 2 rendered before the watch armed.
    No event will ever arrive; the post-arm sync must still swap the served leaf."""
    leaf = write_leaf("leaf", "svc.internal", 1)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(leaf), keyfile=str(leaf))
    rotator = CertRotator().register(ctx, leaf)
    _rotate(leaf, 2)  # lands in the gap

    monkeypatch.setattr(tls, "awatch", _deaf_awatch({}))
    task = asyncio.ensure_future(rotator.watch(resync_interval=None))
    try:
        assert await _wait_for(lambda: _served_serial(ctx) == 2, timeout=7.0)
    finally:
        await _drain(task)


async def test_cert_dropped_event_recovered_by_periodic_resync(monkeypatch, write_leaf):
    leaf = write_leaf("leaf", "svc.internal", 1)
    ctx = _FakeCtx()
    rotator = CertRotator().register(ctx, leaf)
    monkeypatch.setattr(tls, "awatch", _deaf_awatch({}))
    task = asyncio.ensure_future(rotator.watch(resync_interval=0.1))
    try:
        assert await _wait_for(lambda: len(ctx.calls) == 1)  # post-arm sync
        await asyncio.sleep(0.3)
        assert len(ctx.calls) == 1, "idle resyncs must not reload unchanged content"
        _rotate(leaf, 2)  # its event is "dropped"
        assert await _wait_for(lambda: len(ctx.calls) == 2)
    finally:
        await _drain(task)


async def test_cert_watch_passes_polling_options(monkeypatch, write_leaf):
    leaf = write_leaf("leaf", "svc.internal", 1)
    seen: dict = {}
    monkeypatch.setattr(tls, "awatch", _deaf_awatch(seen))
    rotator = CertRotator().register(_FakeCtx(), leaf)
    task = asyncio.ensure_future(
        rotator.watch(resync_interval=0.1, force_polling=True, poll_delay_ms=75)
    )
    try:
        assert await _wait_for(lambda: bool(seen))
        assert seen["force_polling"] is True
        assert seen["poll_delay_ms"] == 75
        assert seen["rust_timeout"] == 100
    finally:
        await _drain(task)


async def test_cert_watch_real_polling_mode(write_leaf):
    """End-to-end with real watchfiles in polling mode (the fallback for volumes that don't
    deliver inotify events)."""
    leaf = write_leaf("leaf", "svc.internal", 1)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(leaf), keyfile=str(leaf))
    rotator = CertRotator().register(ctx, leaf)
    task = asyncio.ensure_future(
        rotator.watch(
            debounce=50, step=10, resync_interval=None, force_polling=True, poll_delay_ms=50
        )
    )
    try:
        # the poller compares whole-second mtimes; rotate in a later second so the
        # EVENT path (not the resync) is what's under test here
        await asyncio.sleep(1.2)
        _rotate(leaf, 2)
        assert await _wait_for(lambda: _served_serial(ctx) == 2)
    finally:
        await _drain(task)


async def test_cert_real_polling_miss_recovered_by_resync(write_leaf):
    """A real dropped event: the poller misses a same-size rewrite within the same second as
    the previous write. The resync must recover it."""
    leaf = write_leaf("leaf", "svc.internal", 1)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(leaf), keyfile=str(leaf))
    rotator = CertRotator().register(ctx, leaf)
    task = asyncio.ensure_future(
        rotator.watch(
            debounce=50, step=10, resync_interval=0.2, force_polling=True, poll_delay_ms=50
        )
    )
    try:
        await asyncio.sleep(0.1)
        _rotate(leaf, 2)
        assert await _wait_for(lambda: _served_serial(ctx) == 2)
    finally:
        await _drain(task)


# --- Watcher ------------------------------------------------------------------------------


async def test_watcher_dropped_event_recovered_by_resync(monkeypatch, tmp_path):
    f = tmp_path / "vault-secrets.yaml"
    f.write_text("password: v1\n")
    calls: list[int] = []
    w = Watcher(tmp_path).on(f, lambda: calls.append(1))

    monkeypatch.setattr(watcher, "awatch", _deaf_awatch({}))
    task = w.spawn(resync_interval=0.1)
    try:
        await asyncio.sleep(0.3)
        assert calls == [], "content unchanged since on(): no spurious fire at startup"
        f.write_text("password: v2\n")  # its event is "dropped"
        assert await _wait_for(lambda: len(calls) == 1)
        await asyncio.sleep(0.3)
        assert len(calls) == 1, "handled content must not re-fire"
    finally:
        await _drain(task)


async def test_watcher_render_before_arming_fires(monkeypatch, tmp_path):
    f = tmp_path / "vault-secrets.yaml"
    f.write_text("password: v1\n")
    calls: list[int] = []
    w = Watcher(tmp_path).on(f, lambda: calls.append(1))
    f.write_text("password: v2\n")  # lands between on() and arming

    monkeypatch.setattr(watcher, "awatch", _deaf_awatch({}))
    task = w.spawn(resync_interval=None)
    try:
        assert await _wait_for(lambda: len(calls) == 1, timeout=7.0)
    finally:
        await _drain(task)


async def test_watcher_failed_handler_retried_on_resync(monkeypatch, tmp_path):
    f = tmp_path / "vault-secrets.yaml"
    f.write_text("password: v1\n")
    calls: list[int] = []
    errors: list[str] = []

    def flaky() -> None:
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("transient rebuild hiccup")

    w = Watcher(tmp_path).on(f, flaky)
    monkeypatch.setattr(watcher, "awatch", _deaf_awatch({}))
    task = w.spawn(resync_interval=0.1, on_error=lambda exc, path: errors.append(path))
    try:
        f.write_text("password: v2\n")
        assert await _wait_for(lambda: len(calls) == 2), "failed handler must be retried"
        await asyncio.sleep(0.3)
        assert len(calls) == 2, "once it succeeds, it must not re-fire"
        assert errors == [str(f.resolve())]
    finally:
        await _drain(task)


@pytest.mark.parametrize(
    "sync_on_arm, fires",
    [
        pytest.param(True, 1, id="sync-on-arm-fires-once"),
        pytest.param(False, 0, id="default-baseline-at-on"),
    ],
)
async def test_watcher_sync_on_arm_covers_render_before_on(
    monkeypatch, tmp_path, sync_on_arm, fires
):
    """The services' gap: the app loads the cert, the sidecar re-renders, THEN on() runs. With
    the default baseline the render is invisible; sync_on_arm fires the handler once."""
    leaf = tmp_path / "leaf.pem"
    leaf.write_text("leaf v1")  # the app's own initial load reads this
    leaf.write_text("leaf v2")  # re-rendered before on()
    secrets = tmp_path / "vault-secrets.yaml"
    secrets.write_text("password: v1\n")
    cert_calls: list[int] = []
    secrets_calls: list[int] = []
    w = (
        Watcher(tmp_path)
        .on(secrets, lambda: secrets_calls.append(1))
        .on(leaf, lambda: cert_calls.append(1), sync_on_arm=sync_on_arm)
    )

    monkeypatch.setattr(watcher, "awatch", _deaf_awatch({}))
    task = w.spawn(resync_interval=0.1)
    try:
        await asyncio.sleep(0.5)
        assert len(cert_calls) == fires
        assert secrets_calls == [], "sync_on_arm is per path: the secrets handler must not fire"
    finally:
        await _drain(task)


async def test_watcher_sync_on_arm_retries_until_success(monkeypatch, tmp_path):
    leaf = tmp_path / "leaf.pem"
    leaf.write_text("leaf v1")
    calls: list[int] = []

    def flaky() -> None:
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("reload failed")

    w = Watcher(tmp_path).on(leaf, flaky, sync_on_arm=True)
    monkeypatch.setattr(watcher, "awatch", _deaf_awatch({}))
    task = w.spawn(resync_interval=0.1)
    try:
        assert await _wait_for(lambda: len(calls) == 2)
        await asyncio.sleep(0.3)
        assert len(calls) == 2, "once it succeeds, it must not re-fire"
    finally:
        await _drain(task)
