# Deployment (Phase 6C, docs/decisiones.md D-084)

The smallest deployment shape this codebase's own architecture already
requires - not locked to any cloud vendor (every piece here is a plain
Docker container, a plain Postgres DSN, or a plain S3-compatible
endpoint; see `docs/production-config.md` for the exact variables). This
file documents what to run and how the pieces fit together; it invents no
provider, price, or domain.

## Components

| Component | What it is | Container? |
|---|---|---|
| `ROLE=web` | Public HTTP server (`backend/http_app.py`). Handles untrusted traffic. Never touches Docker. | Yes - `backend/docker/Dockerfile.web` + `backend/docker/docker-compose.yml` (Phase 6C, built and smoke-tested against a real disposable Postgres while building this phase). |
| `ROLE=worker` (the SUPERVISOR) | Job-queue worker/reaper loop (`backend/worker_supervisor.py`) plus its own egress allowlist proxy. Needs local Docker access to spawn one container per job. | **Not containerized in this repo** - see "Why the worker supervisor is not itself a container" below. Runs as a plain host process (systemd unit example below) on a Docker-capable VPS. |
| The per-job analysis container | What the supervisor spawns, ONE PER JOB, fully isolated (`--read-only` rootfs, no host mounts, no Docker socket, egress-proxy-only network). | Yes - `backend/docker/Dockerfile.worker` (already existed, Phase 4) - built once, spawned repeatedly by the supervisor, never run standalone/long-lived. |

### Why the worker supervisor is not itself a container

Containerizing `ROLE=worker` would need either (a) mounting the host's
`/var/run/docker.sock` into that container ("Docker-outside-of-Docker"),
which hands the container the same host-level Docker control the rest of
this codebase's isolation model treats as sensitive (see
`backend/worker_supervisor.py`'s own docstring), adding a real privilege-
escalation surface for no operational benefit at this scale, or (b) full
Docker-in-Docker, which is meaningfully more complex to run correctly and
is not something the current code or tests exercise. Running it as a
plain process on the same Docker-capable VPS the web container's host
already is (or a second, worker-only VPS) is simpler, matches "prefer
simple/low-operational-overhead", and is exactly what this repo's own
Docker-based tests already assume ("Docker is installed/reachable" -
`tests/test_backend_worker_supervisor.py`'s own module docstring).

## Persistent external services (never containerized by this manifest)

- **PostgreSQL** - any server reachable via `DATABASE_URL`; a managed
  service (RDS, Cloud SQL, Neon, ...) or a self-hosted server. Apply
  `backend/migrations/*.sql` via `backend.migrate.apply_pending_migrations()`
  as a separate, explicit, one-time-per-deploy step BEFORE starting either
  role - see `backend/main.py`'s own module docstring on why this is
  deliberately never automatic.
- **S3-compatible object storage** - any endpoint `boto3` can reach via
  `S3_BUCKET`/`S3_REGION` (+ optional explicit `AWS_ACCESS_KEY_ID`/
  `AWS_SECRET_ACCESS_KEY`, or an IAM role/default credential chain).

## Web container

```bash
docker compose -f backend/docker/docker-compose.yml --env-file .env up -d --build
```

`backend/docker/docker-compose.yml` declares every required variable with
`${VAR:?message}` - `docker compose config` fails immediately, naming
every missing variable, if any required one is absent (verified while
building this phase). `restart: unless-stopped` + `stop_grace_period: 40s`
(comfortably above the default `SHUTDOWN_GRACE_SECONDS=30`) so Docker's
own SIGKILL never arrives before `backend/main.py`'s own graceful-shutdown
window (Phase 6A, `_serve_until_shutdown()`) finishes on its own. The
image's own `HEALTHCHECK` (`backend/docker/Dockerfile.web`) polls
`GET /health` - point a load balancer's own health check at the same
route (or `GET /ready` for a stronger "is this instance actually usable"
signal - see that route's own docstring on the difference).

## Worker supervisor (systemd example - adapt init system as needed)

```ini
# /etc/systemd/system/vericexa-worker.service
[Unit]
Description=Vericexa job-queue worker supervisor
After=docker.service network-online.target
Requires=docker.service

[Service]
Type=simple
EnvironmentFile=/etc/vericexa/worker.env   # DATABASE_URL, S3_*, LLM_*, WORKER_*, EGRESS_PROXY_*, etc. - see docs/production-config.md. Never committed to this repo.
Environment=ROLE=worker
WorkingDirectory=/opt/vericexa
ExecStart=/usr/bin/python3 -m backend.main
Restart=on-failure
RestartSec=5
# Comfortably above SHUTDOWN_GRACE_SECONDS-equivalent worker behavior:
# run_worker_supervisor_loop() stops claiming NEW jobs on shutdown_event
# but never aborts an already-claimed job - give it real headroom rather
# than an invented tight number (Phase 6A, backend/main.py's own docstring).
TimeoutStopSec=120
KillSignal=SIGTERM

[Install]
WantedBy=multi-user.target
```

`docker build -f backend/docker/Dockerfile.worker -t <WORKER_DOCKER_IMAGE
value> .` must be run once (and after every code change to the analyzer
or `backend/worker_entrypoint.py`) on the SAME host before this service
starts - `WORKER_DOCKER_IMAGE` must name that exact tag.

## Internal worker network

Already built (Phase 4), not new this phase: `WORKER_NETWORK_NAME` is a
dedicated, non-default Docker network the supervisor creates and every
per-job container joins; `EGRESS_PROXY_HOST`/`EGRESS_PROXY_PORT` is the
one address a job container is allowed to reach on that network, forwarding
only to the LLM provider allowlist (`LLM_API_ALLOWLIST_HOST`/`_PORT`) - see
`backend/worker_supervisor.py`/`backend/egress_proxy.py`'s own docstrings.
Nothing in this phase changes that model.

## Health/readiness

- `GET /health` (web) - liveness only, always 200, touches nothing.
- `GET /ready` (web) - real dependency check (database `SELECT 1`,
  storage/billing configured), 503 if not all usable.
- Worker supervisor has no HTTP endpoint of its own; systemd's own
  process-liveness (`Restart=on-failure`) plus the existing lease/reaper
  recovery (a dead worker's claimed jobs are reclaimed automatically,
  already built) is the equivalent signal - adding an HTTP health port to
  a process that "never accepts a public HTTP connection at all" (see
  `backend/main.py`'s own docstring) was deliberately not done here.

## Backups

See `backend/backup_postgres.py` (Phase 6C) - not installed/scheduled by
this repo (per the task's own scope: "provide a scheduler example, do NOT
install it"). Cron example:

```cron
# /etc/cron.d/vericexa-backup - adapt path/venv as needed. Runs daily at
# 03:00 UTC; DATABASE_URL comes from the environment (never hardcoded
# here). No retention frequency is invented - --retention-days is
# deliberately omitted below; add it only once Diego confirms a real
# policy (see docs/production-config.md's own RETENTION_DAYS section for
# the same "never invent a retention period" rule applied to report/
# contract content).
0 3 * * * vericexa DATABASE_URL=... /usr/bin/python3 -m backend.backup_postgres --output-dir /var/backups/vericexa >> /var/log/vericexa-backup.log 2>&1
```

A systemd timer is an equally valid alternative to cron; neither is
installed by this repo.
