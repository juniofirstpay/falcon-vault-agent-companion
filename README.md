# vault-agent-companion

App-side companion for the **Vault Agent sidecar**. The sidecar (a separate container)
authenticates to Vault via AppRole and renders, to a shared volume:

- a **secrets file** (e.g. `/shared/vault-secrets.yaml`) the app merges into its config, and
- a rotating **mTLS leaf** `cert+key` PEM (e.g. `/shared/certs/<svc>-leaf.pem`).

This package watches those files and **hot-reloads them in-process — no restart**:

- secrets change → invoke a reload callback (you decide what to re-resolve),
- leaf rotation → `SSLContext.load_cert_chain()` on the live server/client context.

It does **not** talk to Vault — that's the sidecar's job. The language-agnostic standard is
the sidecar's **rendered-file contract**; this package is the Python-side convenience.
Detailed design + operational notes are in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Install

```bash
pip install vault-agent-companion            # core only (watchfiles)
pip install "vault-agent-companion[dynaconf,uvicorn]"   # + adapters
```

## API

### `core.secrets` — watch a rendered secrets file

```python
from vault_agent_companion import secrets

secrets.spawn("/shared/vault-secrets.yaml", on_change)   # background task
# or: await secrets.watch(path, on_change)               # run inline
```
`on_change` may be sync or async. It watches the file's **parent directory** so the Vault
Agent's atomic temp-file-then-rename is caught (watching the file inode would leave you on a
stale, unlinked inode). Only changes to the target path fire the callback.

### `core.tls` — hot-reload rotating certs

```python
from vault_agent_companion import CertRotator

rotator = (
    CertRotator()
    .register(server_ssl_ctx, "/shared/certs/auth-leaf.pem")   # inbound (uvicorn)
    .register(client_ssl_ctx, "/shared/certs/auth-leaf.pem")   # outbound east-west
)
await rotator.watch()
```
`register(ctx, cert_path[, key_path])` — `key_path` defaults to `cert_path` (the sidecar
renders cert+key into **one** PEM; `load_cert_chain` reads the key from it). On change it
calls `ctx.load_cert_chain(...)`, which swaps the cert for **new** handshakes; in-flight
connections and the trust root are untouched. A half-written file is logged and skipped,
never raised.

Events can be missed (a render before the watch arms, a dropped inotify event), so `watch()`
also **resyncs**: once armed, and then every `resync_interval` seconds, it reloads any cert
whose content (sha256) differs from what it last loaded. `Watcher.watch()` does the same for
its handlers, against the content at `on()` time — so register a cert loaded **before**
`on()` with `sync_on_arm=True`, which fires its handlers once the watch is armed:

```python
watcher = Watcher("/shared")
watcher.on("/shared/vault-secrets.yaml", on_secrets_change)
watcher.on("/shared/certs/auth-leaf.pem", rotator.reload, sync_on_arm=True)
watcher.spawn(on_error=report)
```

```python
await rotator.watch(
    resync_interval=300,   # seconds; None = only the post-arm sync
    force_polling=None,    # True for volumes that don't deliver events (None = env var)
    poll_delay_ms=300,
)
rotator.resync()           # also callable directly, e.g. from a health check
```

### Adapters

```python
from vault_agent_companion.adapters.dynaconf import make_reload
from vault_agent_companion.adapters.uvicorn import attach

# secrets: file change -> settings.reload() + your re-resolve hook
on_change = make_reload(settings, re_resolve=rebuild_pools_and_providers)
secrets.spawn("/shared/vault-secrets.yaml", on_change)

# certs: grab uvicorn's live SSLContext and register it
attach(rotator, server, "/shared/certs/auth-leaf.pem")   # forces config.load(), takes config.ssl
```

## Reload depth is the app's concern

The core only **fires your callback** — it has no opinion about whether you reconnect a DB
pool, re-init providers, or just `settings.reload()`. That keeps the package tiny and lets
each service stage its reload depth. See `docs/ARCHITECTURE.md` §"Reload depth".

## Dev

```bash
pipenv install --dev
pipenv run pytest        # 35 tests incl. a real socketpair handshake proving cert swap
```

## Design notes (short)

- **Standalone, not part of `falcon-svcplane`** — this is a config/rotation concern, not
  authz/mTLS termination; bundling would drag `dynaconf`/`watchfiles` into the authz library
  and wouldn't cover outbound client contexts.
- **Agnostic core + adapters** — `core` depends only on `watchfiles`; `dynaconf`/`uvicorn`
  are pulled by their adapters.
- **Single-file cert** — pair with a sidecar template that renders cert+key from **one**
  `pki/issue` call, so `cert_path == key_path` and they always match.
