#!/usr/bin/env python3
"""Production process entrypoint (Phase 5, docs/decisiones.md D-077
follow-up).

THE ONE place in this backend allowed to read os.environ - see backend/
billing.py's and backend/db.py's own "explicit config, never
environment" docstrings, which both already describe exactly this file
as the future caller that reads os.environ ONCE and passes values in
explicitly. Every other module still takes its configuration as
constructor arguments, completely unchanged by this file's existence.

TWO ROLES, ONE FILE, NEVER COMBINED - dispatched by the required ROLE
environment variable:
  * ROLE=web    runs the HTTP server (backend/http_app.py). Handles
    untrusted public traffic. Never touches Docker.
  * ROLE=worker runs the job-queue worker/reaper loop (backend/
    worker_supervisor.py) plus its own egress allowlist proxy (backend/
    egress_proxy.py, started in a background thread of this same
    process - the worker supervisor is the one component that creates
    the Docker network job containers join and knows the allowlist they
    need, so bundling the proxy here is the fewest moving parts, not a
    layering violation). Needs Docker access (spawns one isolated
    container per job) and never accepts a public HTTP connection at all.
Splitting these is a deliberate SECURITY boundary, not an accident of
convenience: a process handling untrusted HTTP input should never also
hold the capability to launch Docker containers - see backend/
worker_supervisor.py's own module docstring for why that capability is
treated as sensitive everywhere else in this codebase. Run as many
ROLE=worker processes as needed for throughput; ROLE=web is what a load
balancer points at.

FAILS FAST: every mandatory config value for the selected role is
validated BEFORE anything starts serving or claiming jobs - a missing
DATABASE_URL, STRIPE_SECRET_KEY, S3_BUCKET, etc. raises ConfigError
immediately from main(), never a lazy per-request failure deep inside a
handler and never a silent SQLite/local-storage fallback (see backend/
db.py's connect_postgres(), which already refuses to silently degrade -
this module trusts that and never second-guesses it with a fallback of
its own).

MIGRATIONS ARE NOT RUN HERE, deliberately: applying backend/migrations/
*.sql is kept a separate, explicit, ONE-TIME-per-deploy operational step
(backend/migrate.py, already the tool backend/verify_postgres.sh uses),
run once before any ROLE=web/ROLE=worker process starts. Auto-running
migrations from every process on every start would race unsafely across
multiple concurrently-starting replicas (two processes both seeing an
unapplied version and both trying to CREATE TABLE/ADD COLUMN it at once -
a real, not hypothetical, failure mode for a forward-only, no-checksum
runner like backend/migrate.py, which this phase was not asked to make
concurrency-safe). A process that starts against a schema still missing
a migration fails loudly on the first query that needs it - the correct,
visible failure, never a silent partial-schema run.

EMAIL DELIVERY IS A KNOWN, EXPLICIT GAP, not an oversight: backend/
email_sender.py ships exactly one implementation, LoggingEmailSender,
whose own docstring says "Never use in production." This file wires it
anyway (there is nothing else to wire - see that module's docstring on
why a real provider was deliberately never added without being asked for
explicitly) and is honest about it in run_web()'s own comment; every
other piece of the ROLE=web process (auth rate-limiting, session
issuance, entitlement gating, CSRF/host-header safety) works correctly
regardless - only actual magic-link email delivery is a stand-in.

Standard library only at this file's own top level, plus whichever of
psycopg/stripe/boto3 the selected role's config actually constructs
(backend/db.py, backend/billing.py, backend/object_storage.py already
import each lazily/optionally and raise a clear error if missing -
never silently skipped).
"""
from __future__ import annotations

import os
import sys
import threading
from typing import Any, Callable, Dict

import backend.billing as billing_module
import backend.db as db
import backend.egress_proxy as egress_proxy
import backend.email_sender as email_sender_module
import backend.http_app as http_app
import backend.object_storage as object_storage
import backend.worker_supervisor as worker_supervisor


class ConfigError(Exception):
    """Raised only for missing/malformed required configuration - see
    module docstring on failing fast. Never raised once the selected
    role has actually started serving/claiming jobs."""


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise ConfigError("required environment variable %s is not set" % name)
    return value


def _bool_env(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _int_env(name: str, default: int) -> int:
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        raise ConfigError("environment variable %s must be an integer, got %r" % (name, value))


def _connect_fn(database_url: str) -> Callable[[], Any]:
    # A fresh connection per unit of work, never one shared across
    # threads/requests - matches backend/http_app.py's own module
    # docstring on why (a real PostgreSQL connection pool would sit
    # behind this exact same zero-argument callable later, so nothing
    # here changes shape when that swap happens).
    return lambda: db.connect_postgres(database_url)


def _load_web_config() -> Dict[str, Any]:
    """Validates every required/optional variable ROLE=web needs and
    returns them as plain values - no client/socket is constructed here.
    Deliberately separate from run_web() so EVERY variable is checked
    before ANY construction begins (including one, S3Storage, that needs
    a package - boto3 - not every environment has installed): a
    misconfiguration discovered only after another dependency was already
    half-constructed would both fail less clearly and, for the worker
    role's proxy socket, leak a resource on the failure path - see
    _load_worker_config()'s own docstring for that concrete case."""
    host_allowlist = [h.strip() for h in _require_env("HOST_ALLOWLIST").split(",") if h.strip()]
    if not host_allowlist:
        raise ConfigError("HOST_ALLOWLIST must contain at least one hostname")
    return {
        "database_url": _require_env("DATABASE_URL"),
        "host_allowlist": host_allowlist,
        "secure_cookies": _bool_env("SECURE_COOKIES", True),
        "host": os.environ.get("HTTP_HOST", "0.0.0.0"),
        "port": _int_env("HTTP_PORT", 8080),
        "s3_bucket": _require_env("S3_BUCKET"),
        "s3_region": _require_env("S3_REGION"),
        "stripe_secret_key": _require_env("STRIPE_SECRET_KEY"),
        "stripe_webhook_secret": _require_env("STRIPE_WEBHOOK_SECRET"),
        "stripe_price_allowlist": {
            "quick": _require_env("STRIPE_PRICE_QUICK"),
            "standard": _require_env("STRIPE_PRICE_STANDARD"),
            "pro": _require_env("STRIPE_PRICE_PRO"),
        },
    }


def _load_worker_config() -> Dict[str, Any]:
    """Same validate-everything-first discipline as _load_web_config()
    above, for ROLE=worker. Concretely: without this separation,
    run_worker() would bind the egress proxy's real listening socket
    BEFORE checking EGRESS_PROXY_HOST/LLM_API_KEY - so a missing one of
    those would fail after a socket was already opened, which the
    original version of this function then had to remember to close on
    every failure path. Validating first means the failure path never
    has anything to clean up."""
    return {
        "database_url": _require_env("DATABASE_URL"),
        "s3_bucket": _require_env("S3_BUCKET"),
        "s3_region": _require_env("S3_REGION"),
        "worker_id": os.environ.get("WORKER_ID") or "worker-%d" % os.getpid(),
        "docker_image": _require_env("WORKER_DOCKER_IMAGE"),
        "network_name": _require_env("WORKER_NETWORK_NAME"),
        # No safe default is ever guessed for EGRESS_PROXY_HOST - see
        # run_worker()'s own comment on why (Docker network topology is
        # deployment-specific).
        "proxy_host": _require_env("EGRESS_PROXY_HOST"),
        "proxy_bind_port": _int_env("EGRESS_PROXY_PORT", 0),
        "llm_allowlist_host": os.environ.get("LLM_API_ALLOWLIST_HOST", "api.anthropic.com"),
        "llm_allowlist_port": _int_env("LLM_API_ALLOWLIST_PORT", 443),
        "llm_api_key": _require_env("LLM_API_KEY"),
        "llm_model": _require_env("LLM_MODEL"),
    }


def _build_storage(bucket: str, region: str) -> object_storage.ObjectStorage:
    # S3Storage only - LocalFilesystemStorage is dev/test-only (see its
    # own docstring), never wired from this production entrypoint.
    return object_storage.S3Storage(
        bucket=bucket,
        region=region,
        access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
        secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY"),
    )


def _build_billing(secret_key: str, webhook_secret: str, price_allowlist: Dict[str, str]) -> billing_module.StripeBilling:
    return billing_module.StripeBilling(secret_key=secret_key, webhook_secret=webhook_secret, price_allowlist=price_allowlist)


def run_web() -> None:
    cfg = _load_web_config()
    storage = _build_storage(cfg["s3_bucket"], cfg["s3_region"])
    billing = _build_billing(cfg["stripe_secret_key"], cfg["stripe_webhook_secret"], cfg["stripe_price_allowlist"])
    # See module docstring on email delivery - this is the only
    # implementation that exists anywhere in this codebase today.
    sender = email_sender_module.LoggingEmailSender()

    httpd = http_app.run_server(
        connect_fn=_connect_fn(cfg["database_url"]),
        email_sender=sender,
        host_allowlist=cfg["host_allowlist"],
        host=cfg["host"],
        port=cfg["port"],
        secure_cookies=cfg["secure_cookies"],
        billing=billing,
        storage=storage,
    )
    sys.stderr.write("backend web process listening on %s:%d (secure_cookies=%s)\n" % (cfg["host"], cfg["port"], cfg["secure_cookies"]))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


def run_worker() -> None:
    cfg = _load_worker_config()
    storage = _build_storage(cfg["s3_bucket"], cfg["s3_region"])

    proxy = egress_proxy.run_egress_proxy(
        {(cfg["llm_allowlist_host"], cfg["llm_allowlist_port"])}, host="0.0.0.0", port=cfg["proxy_bind_port"]
    )
    actual_proxy_port = proxy.server_address[1]
    proxy_thread = threading.Thread(target=proxy.serve_forever, daemon=True)
    proxy_thread.start()
    sys.stderr.write(
        "egress proxy listening on 0.0.0.0:%d, allowing only %s:%d\n"
        % (actual_proxy_port, cfg["llm_allowlist_host"], cfg["llm_allowlist_port"])
    )

    # EGRESS_PROXY_HOST (cfg["proxy_host"]) is the address a job CONTAINER
    # dials to reach the proxy above over the Docker network it joins -
    # NOT necessarily "0.0.0.0" (what this process itself bound above) -
    # see _load_worker_config()'s own comment.
    config = worker_supervisor.WorkerConfig(
        docker_image=cfg["docker_image"],
        network_name=cfg["network_name"],
        proxy_host=cfg["proxy_host"],
        proxy_port=actual_proxy_port,
        llm_api_key=cfg["llm_api_key"],
        llm_model=cfg["llm_model"],
    )
    sys.stderr.write("backend worker process %r starting (image=%s)\n" % (cfg["worker_id"], config.docker_image))
    try:
        worker_supervisor.run_worker_supervisor_loop(
            connect_fn=_connect_fn(cfg["database_url"]),
            worker_id=cfg["worker_id"],
            config=config,
            storage=storage,
        )
    except KeyboardInterrupt:
        pass
    finally:
        proxy.shutdown()
        proxy.server_close()


_ROLES: Dict[str, Callable[[], None]] = {"web": run_web, "worker": run_worker}

# Every construction-time misconfiguration a role's own _build_*() helpers
# can raise, from each dependency's own established "explicit config,
# never environment, never a silent fallback" exception type - never a
# bare `except Exception`, which would also swallow a genuine bug (same
# narrow-exception discipline this codebase applies at every other public
# boundary - see website/server.py's own comment on this). A truly
# unexpected exception still propagates as a raw traceback - the
# process refusing to start loudly is itself a correct "fails fast", even
# unformatted.
_STARTUP_FAILURE_TYPES = (
    ConfigError,
    db.DBAdapterError,
    billing_module.BillingError,
    object_storage.ObjectStorageError,
    worker_supervisor.WorkerSupervisorError,
)


def main() -> int:
    role = os.environ.get("ROLE")
    if role not in _ROLES:
        sys.stderr.write("ConfigError: ROLE must be one of %r (got %r)\n" % (sorted(_ROLES), role))
        return 1
    try:
        _ROLES[role]()
    except _STARTUP_FAILURE_TYPES as exc:
        sys.stderr.write("%s: %s\n" % (type(exc).__name__, exc))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
