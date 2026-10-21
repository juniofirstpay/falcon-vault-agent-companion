# vault-agent-companion — Architecture & Design

## The contract this package consumes

A Vault Agent sidecar (separate container) authenticates to Vault via AppRole and renders
files to a shared volume. This package is the **app-side half**: it watches those files and
hot-reloads them. The two halves only agree on the **rendered files** — that's the
language-agnostic standard (a Go service re-implements the same file-watch natively; this
package is the Python convenience).

```
Vault Agent ──renders──▶ /shared/vault-secrets.yaml ──▶ [secrets.watch] ──▶ on_change()
            ──renders──▶ /shared/certs/<svc>-leaf.pem ─▶ [CertRotator]   ──▶ load_cert_chain()
```

## Why a standalone package (not folded into svcplane)

`falcon-svcplane` owns mTLS **termination** + the peer-CN allow-list (authz). Secret/cert
**reload** is a different concern with a different release cadence:

- Bundling it would force `dynaconf` + `watchfiles` onto every svcplane consumer.
- Cert rotation must also reload the **outbound** http-client context, which svcplane doesn't
  own — so it doesn't cleanly belong inside svcplane.
- svcplane keeps building the initial `ssl_kwargs`; this package reloads the live context it
  produced. Clean handoff, no coupling.

## Agnostic core + adapters

```
core/                        # deps: watchfiles only
  secrets.py   watch(path, on_change) / spawn ; pure _touches_target predicate
  tls.py       CertRotator.register(ctx, cert_path[, key_path]).watch() / resync()
  watcher.py   Watcher(root).on(path, handler).watch() / resync()  — one awatch per process
  _resync.py   content fingerprint + resync clock shared by tls/watcher
adapters/                    # optional extras
  dynaconf.py  make_reload(settings, re_resolve=None)
  uvicorn.py   attach(rotator, server_or_config, cert_path)
```

The core takes **generic hooks** (a callback; a `register(SSLContext, path)`), so it's usable
by any config lib, any ASGI server, with or without svcplane. Adapters are thin translations.

## Design decisions, and why

### Watch the parent directory, not the file
The Vault Agent renders atomically: write a temp file, then **rename** it into place. That
changes the inode. A watch on the file path would end up watching a stale, unlinked inode and
miss every rotation. So both `secrets.watch` and `CertRotator.watch` watch the file's
**parent directory** and filter for the target path. (The `_touches_target` predicate is pure
so it's unit-tested without the filesystem — macOS fsevents can replay a file's own creation
at watcher startup, which makes real-fs negative tests flaky.)

### Events are a hint; the resync is the guarantee
A watch driven only by filesystem events can miss a rotation, and a missed leaf rotation is
a TLS outage once the in-memory leaf expires (~22 h later for a 24 h leaf re-issued at
~90%). Two ways to miss one:

1. **Arming gap.** `awatch` arms on its first loop turn. A render between the app's initial
   `load_cert_chain` and arming is never reported.
2. **Dropped events.** inotify queue overflow; overlay / bind-mounted volumes; and polling
   mode itself, which compares whole-second mtimes and so misses a same-size rewrite within
   the same second (re-issued leaves are usually the same size).

So `CertRotator.watch` and `Watcher.watch` also **resync**: compare each registered file's
sha256 with the one last handled, and act on a mismatch. Content, not mtime/size, for the
reasons above; the files are a few KB, so hashing them every few minutes is free.

- The timer rides on `awatch(yield_on_timeout=True, rust_timeout=…)`: an idle watch yields an
  empty batch every tick (≤ 5 s), so events and resyncs share **one task** — no lock, no
  concurrent reloads of the same context.
- The first batch is only yielded once the watch is armed, so the **first resync is the
  post-arm sync** (lands within 5 s of start). `CertRotator` has no baseline, so it reloads
  every cert then (idempotent); `Watcher` baselines at `on()` time, so it only fires
  handlers whose file changed since registration (no spurious `settings.reload()` /
  pool rebuild at boot).
- Then every `resync_interval` seconds (default 300; `None` keeps only the post-arm sync).
- A fingerprint is recorded only once **every** context / handler for that file succeeded,
  and is taken *before* loading — so a failed load or handler is retried next resync, and a
  render mid-load costs at most one extra reload, never a miss.
- Events still reload unconditionally (unchanged behaviour); they just also update the
  fingerprint, so the next resync doesn't repeat the work.

### Single-issuance cert, cert+key in one file
The naïve approach renders the cert and the key from **two separate** template blocks — two
`pki/issue` calls — producing a cert and key that don't match. The correct pattern renders
both from **one** issuance into one PEM, so `cert_path == key_path`. `load_cert_chain` reads
the key from the same file. The trust root is read separately (from `pki/cert/ca`, no
issuance), so the leaf render and the CA render never interfere.

### `SSLContext.load_cert_chain` for cert rotation
`load_cert_chain` is re-callable on a live context. It updates the cert used for **new**
handshakes; existing connections keep the cert they negotiated; `verify_mode` and the trust
root (`load_verify_locations`) are untouched. So rotating a leaf is just re-loading the chain
— no restart, no monkey-patching. Register **both** the inbound (server) context and any
outbound http-client context; a rotated leaf must refresh both.

### Reload depth is the app's concern
The core only fires the callback. What to re-resolve after a secrets change is the app's call,
because it depends on *how each consumer captured the secret*:

| Consumer | Rotates by |
|---|---|
| values read live from settings per use | `settings.reload()` alone |
| provider/client instances that captured a secret at construction | rebuild the instances |
| a pooled DB engine whose creator reads creds live | mutate the live cred object in place |
| a pool that captured creds at build | reconnect / dispose + rebuild |

Keeping this out of the package means the package stays tiny and every service stages its own
depth (e.g. cert seamless + providers re-init now, DB/redis reconnect later).

## Operational notes

- **inotify across Docker volumes works.** A common worry is that a cross-container write to a
  shared volume won't reach another container's inotify watch. In practice it does — watchfiles
  in one container sees the agent's rename in another. If a particular filesystem/driver
  doesn't deliver events, pass `force_polling=True` (and optionally `poll_delay_ms`) to
  `watch()`, or set `WATCHFILES_FORCE_POLLING=true`. Either way the periodic resync bounds
  the damage of a lost event to `resync_interval`.
- **The agent must be able to write the shared volume.** If the vault image entrypoint drops to
  a non-root user it can't write a root-owned volume; run it as root / override the entrypoint,
  or pre-create the dir with the right ownership.
- **Startup gate.** A TLS server loads its cert at boot, so the app must wait until the sidecar
  has rendered the leaf before binding.
- **Hold the watch task reference.** `asyncio.ensure_future(rotator.watch())` returns a Task; a
  bare, unreferenced task can be garbage-collected mid-run. Store it (a local in a frame that
  lives for the server's lifetime is enough).

## Testing

`pytest` (32 tests): secrets watcher fires on change (sync + async callbacks); the target
predicate ignores siblings/tempfiles deterministically; `CertRotator` reloads on change; a
half-written PEM is swallowed; the adapters call `settings.reload()` + re-resolve and grab
`config.ssl`; and — the headline — a **real socketpair TLS handshake** proves the served leaf
serial swaps (`1001 → 2002`) after `reload()`. `tests/test_resync.py` covers issue #6 with an
`awatch` stand-in that never reports events (deterministic arming-gap and dropped-event
cases), plus real-watchfiles polling runs — including a same-second rewrite the poller
genuinely misses, recovered by the resync.
