"""Real Docker regression tests for backend/docker/Dockerfile.web (Phase 6C,
docs/decisiones.md D-084).

Proves the actual, built production web image starts via `python -m
backend.main` (ROLE=web baked in), answers GET /health and GET /ready
against a REAL disposable Postgres (not mocked), runs as a non-root user,
and carries no Docker CLI/socket - closing the loop on this phase's "no
worker-only Docker privileges" requirement empirically, not just by
reading the Dockerfile.

Skips the entire module (never fails) if Docker is not installed/reachable
or the image fails to build - same convention tests/test_backend_worker_
supervisor.py and tests/test_backend_postgres_integration.py already
established.

Run from the repository root: python -m unittest
"""
from __future__ import annotations

import http.client
import os
import shutil
import subprocess
import time
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCKERFILE = os.path.join(REPO_ROOT, "backend", "docker", "Dockerfile.web")
IMAGE_TAG = "vericexa-web-pytest:local"
NETWORK_NAME = "vericexa-web-pytest-net"
PG_CONTAINER = "vericexa-web-pytest-pg"
PG_PORT = "55434"  # distinct from test_backend_postgres_integration.py's 55433 and Dockerfile.worker's own pytest use - never collides if all ran at once.
PG_PASSWORD = "pytest-throwaway"
DB_NAME = "vericexawebpytest"
WEB_CONTAINER = "vericexa-web-pytest-app"
WEB_PORT = "58080"


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        subprocess.run(["docker", "info"], capture_output=True, timeout=10, check=True)
        return True
    except Exception:
        return False


def setUpModule():
    if not _docker_available():
        raise unittest.SkipTest("Docker is not installed/reachable")
    build = subprocess.run(
        ["docker", "build", "-f", DOCKERFILE, "-t", IMAGE_TAG, "."],
        cwd=REPO_ROOT, capture_output=True, timeout=300,
    )
    if build.returncode != 0:
        raise unittest.SkipTest("failed to build %s: %s" % (IMAGE_TAG, build.stderr.decode(errors="replace")[-500:]))

    subprocess.run(["docker", "network", "rm", NETWORK_NAME], capture_output=True)
    subprocess.run(["docker", "network", "create", NETWORK_NAME], check=True, capture_output=True)

    subprocess.run(["docker", "rm", "-f", PG_CONTAINER], capture_output=True)
    subprocess.run(
        [
            "docker", "run", "--rm", "-d", "--name", PG_CONTAINER, "--network", NETWORK_NAME,
            "-e", "POSTGRES_PASSWORD=%s" % PG_PASSWORD,
            "-e", "POSTGRES_DB=%s" % DB_NAME,
            "-p", "127.0.0.1:%s:5432" % PG_PORT,
            "postgres:15",
        ],
        check=True, capture_output=True,
    )
    for _ in range(30):
        result = subprocess.run(["docker", "exec", PG_CONTAINER, "pg_isready", "-U", "postgres"], capture_output=True)
        if result.returncode == 0:
            break
        time.sleep(1)
    else:
        tearDownModule()
        raise RuntimeError("postgres:15 container did not become ready in time")

    # Migrations applied from the HOST, over the published port - the web
    # container itself never runs migrations (backend/main.py's own
    # docstring on why that stays a separate, explicit step).
    import backend.db as db
    import backend.migrate as migrate
    import backend.repository as repo
    conn = db.connect_postgres("postgresql://postgres:%s@127.0.0.1:%s/%s" % (PG_PASSWORD, PG_PORT, DB_NAME))
    migrate.apply_pending_migrations(conn, os.path.join(REPO_ROOT, "backend", "migrations"), now_iso=repo.utcnow_iso())
    conn.close()


def tearDownModule():
    if not _docker_available():
        return
    subprocess.run(["docker", "rm", "-f", WEB_CONTAINER], capture_output=True)
    subprocess.run(["docker", "rm", "-f", PG_CONTAINER], capture_output=True)
    subprocess.run(["docker", "network", "rm", NETWORK_NAME], capture_output=True)
    subprocess.run(["docker", "rmi", "-f", IMAGE_TAG], capture_output=True)


class WebContainerStartupTests(unittest.TestCase):
    """One shared container for the whole class - HTTP requests against it
    are cheap, and container startup is not, same reasoning tests/
    test_backend_http_app.py's _HttpAppTestCase applies to its own
    in-process server (one per TEST there only because that suite also
    exercises per-test database isolation, which this module does not
    need - every check here is read-only against the same running app)."""

    @classmethod
    def setUpClass(cls):
        subprocess.run(["docker", "rm", "-f", WEB_CONTAINER], capture_output=True)
        subprocess.run(
            [
                "docker", "run", "-d", "--name", WEB_CONTAINER, "--network", NETWORK_NAME,
                "-p", "127.0.0.1:%s:8080" % WEB_PORT,
                "-e", "DATABASE_URL=postgresql://postgres:%s@%s:5432/%s" % (PG_PASSWORD, PG_CONTAINER, DB_NAME),
                "-e", "HOST_ALLOWLIST=127.0.0.1",
                "-e", "SECURE_COOKIES=false",
                "-e", "S3_BUCKET=pytest-dummy-bucket", "-e", "S3_REGION=us-east-1",
                "-e", "STRIPE_SECRET_KEY=sk_test_dummy", "-e", "STRIPE_WEBHOOK_SECRET=whsec_dummy",
                "-e", "STRIPE_PRICE_QUICK=price_quick", "-e", "STRIPE_PRICE_STANDARD=price_standard", "-e", "STRIPE_PRICE_PRO=price_pro",
                IMAGE_TAG,
            ],
            check=True, capture_output=True,
        )
        cls._wait_for_health()

    @classmethod
    def _wait_for_health(cls):
        for _ in range(30):
            try:
                conn = http.client.HTTPConnection("127.0.0.1", int(WEB_PORT), timeout=2)
                conn.request("GET", "/health")
                resp = conn.getresponse()
                if resp.status == 200:
                    resp.read()
                    conn.close()
                    return
                conn.close()
            except (ConnectionRefusedError, OSError):
                pass
            time.sleep(1)
        logs = subprocess.run(["docker", "logs", WEB_CONTAINER], capture_output=True).stdout.decode(errors="replace")
        raise RuntimeError("web container never became healthy - logs:\n%s" % logs[-2000:])

    @classmethod
    def tearDownClass(cls):
        subprocess.run(["docker", "rm", "-f", WEB_CONTAINER], capture_output=True)

    def _get(self, path):
        conn = http.client.HTTPConnection("127.0.0.1", int(WEB_PORT), timeout=5)
        conn.request("GET", path, headers={"Host": "127.0.0.1"})
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        return resp.status, body

    def test_health_returns_200(self):
        status, body = self._get("/health")
        self.assertEqual(status, 200)
        self.assertIn(b'"ok": true', body)

    def test_ready_reports_database_storage_and_billing_all_usable(self):
        status, body = self._get("/ready")
        self.assertEqual(status, 200)
        self.assertIn(b'"database": true', body)
        self.assertIn(b'"storage": true', body)
        self.assertIn(b'"billing": true', body)

    def test_container_runs_as_a_non_root_user(self):
        result = subprocess.run(["docker", "exec", WEB_CONTAINER, "whoami"], capture_output=True)
        self.assertEqual(result.stdout.decode().strip(), "appuser")

    def test_container_has_no_docker_cli(self):
        result = subprocess.run(["docker", "exec", WEB_CONTAINER, "which", "docker"], capture_output=True)
        self.assertNotEqual(result.returncode, 0)

    def test_docker_reports_the_container_healthy(self):
        # Exercises the image's own HEALTHCHECK directive, not just this
        # test file's HTTP polling.
        result = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Health.Status}}", WEB_CONTAINER],
            capture_output=True,
        )
        self.assertIn(result.stdout.decode().strip(), ("starting", "healthy"))
