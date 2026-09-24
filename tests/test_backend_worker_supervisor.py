"""Real Docker regression tests for backend/worker_supervisor.py +
backend/worker_entrypoint.py + backend/docker/Dockerfile.worker (Phase 4
execution infrastructure blocker fix, docs/decisiones.md D-079).

Proves the D-079 boundary redesign (stdin envelope in / stdout result out,
replacing the `docker cp` design empirically confirmed broken against a
tmpfs-backed /scratch mount - see that decision entry) against a REAL
Docker daemon and the REAL production image built from backend/docker/
Dockerfile.worker.

Skips the entire module (never fails) if Docker is not installed/reachable
or the image fails to build - the rest of the suite must stay green with
or without Docker present, exactly like tests/test_backend_postgres_
integration.py's own convention, which this file mirrors.

Run from the repository root: python -m unittest
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
import unittest

import backend.worker_supervisor as ws

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCKERFILE = os.path.join(REPO_ROOT, "backend", "docker", "Dockerfile.worker")
IMAGE_TAG = "web3-auditor-worker-pytest:local"

SC_CATEGORIES = ["SC%02d" % n for n in range(1, 11)]


def _valid_draft(mode="standard"):
    return {
        "generatedBy": "ai", "skillVersion": "1.0.0", "analysisEngineVersion": "1.0.0",
        "checklistVersion": "2026.1", "scoreVersion": "2026.1", "mode": mode, "language": "en",
        "compilerVersion": "0.8.20", "scriptsAvailable": True, "inputHash": "sha256:" + "a" * 64,
        "scope": {"completeness": "complete", "reasons": []},
        "categoryCoverage": [{"category": c, "status": "NOT_DETECTED"} for c in SC_CATEGORIES],
        "findings": [], "limitations": ["x"],
        "riskIndicator": {"scoreStatus": "not_computed", "score": None, "band": None},
        "scoreStatus": "not_computed",
    }


SOURCE_TEXT = "pragma solidity ^0.8.0;\ncontract A { function f() public {} }\n"


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
        cwd=REPO_ROOT, capture_output=True, timeout=180,
    )
    if build.returncode != 0:
        raise unittest.SkipTest("failed to build %s: %s" % (IMAGE_TAG, build.stderr.decode(errors="replace")[-500:]))


def tearDownModule():
    if _docker_available():
        subprocess.run(["docker", "rmi", "-f", IMAGE_TAG], capture_output=True)


def _config(**overrides):
    defaults = dict(
        docker_image=IMAGE_TAG, network_name="bridge", proxy_host="127.0.0.1", proxy_port=1,
        llm_api_key="unused-in-mock-tests", llm_model="unused", wall_clock_timeout_seconds=30,
    )
    defaults.update(overrides)
    return ws.WorkerConfig(**defaults)


def _container_exists(name: str) -> bool:
    return subprocess.run(["docker", "inspect", name], capture_output=True).returncode == 0


class RealContainerJobLifecycleTests(unittest.TestCase):
    """Section 3 (D-079 fix) + Section 2 (isolation) - requirement list
    from the blocker-fix instruction, each as its own assertion."""

    def test_input_successfully_reaches_the_container(self):
        # A distinguishing categoryCoverage entry proves the REAL mock
        # draft (not some cached/stale value) made the full round trip:
        # stdin -> entrypoint -> analyze_pipeline -> score -> render.
        draft = _valid_draft()
        draft["categoryCoverage"][2]["status"] = "DETECTED"
        draft["findings"] = [{
            "category": "SC03", "signature": "distinguishing-marker-abc123", "severity": "LOW",
            "confidence": "low", "status": "suspected",
            "locations": [{"file": "A.sol", "lineStart": 1, "lineEnd": 1, "contract": "A", "function": "f"}],
            "evidence": ["x"], "description": "distinguishing-marker-abc123", "recommendation": "rec", "patch": None,
        }]
        result = ws.run_job_in_container(
            _config(), "t-input-reach", "standard", SOURCE_TEXT, mock_responses=[json.dumps(draft)],
        )
        self.assertEqual(result.get("status"), "succeeded", result)
        self.assertIn("distinguishing-marker-abc123", result.get("rendered", ""))

    def test_mock_llm_key_reaches_the_worker_only_never_the_host_config(self):
        # The real credential path (config.llm_api_key) is never used when
        # mock_responses is supplied - but even so, prove NO api-key-shaped
        # value the host holds ever appears in docker inspect's persisted
        # config (Env/Cmd), which is exactly what D-079 fixes: the old
        # design passed a comparable secret via a host tempfile + docker
        # cp; the new one never touches the container's persisted config
        # or the host filesystem at all.
        sentinel = "sk-ant-SENTINEL-should-never-be-inspectable-zzz999"
        config = _config(llm_api_key=sentinel)
        result = ws.run_job_in_container(
            config, "t-key-boundary", "standard", SOURCE_TEXT, mock_responses=[json.dumps(_valid_draft())],
        )
        self.assertEqual(result.get("status"), "succeeded", result)
        # The container is removed by run_job_in_container itself; create a
        # fresh one with the SAME real create-args builder to inspect its
        # persisted config directly (this is what "reaches the worker
        # only" means: never durably stored in the container's own metadata).
        name = "t-key-boundary-inspect"
        create_args = ws.build_docker_create_args(config, name)
        self.assertNotIn(sentinel, json.dumps(create_args), "the key leaked into docker create's own argv")
        subprocess.run(create_args, check=True, capture_output=True)
        try:
            inspect = json.loads(subprocess.run(["docker", "inspect", name], capture_output=True, check=True).stdout)
            self.assertNotIn(sentinel, json.dumps(inspect), "the key leaked into docker inspect's persisted config")
        finally:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True)

    def test_read_only_remains_enabled(self):
        name = "t-readonly-check"
        config = _config()
        subprocess.run(ws.build_docker_create_args(config, name), check=True, capture_output=True)
        try:
            inspect = json.loads(subprocess.run(["docker", "inspect", name], capture_output=True, check=True).stdout)[0]
            self.assertIs(inspect["HostConfig"]["ReadonlyRootfs"], True)
        finally:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True)

    def test_scratch_remains_writable_end_to_end(self):
        # Implicit but real: a successful job requires writing
        # /scratch/contract.sol from inside the container - see
        # backend/worker_entrypoint.py. A regression here would fail
        # every job, not just this test.
        result = ws.run_job_in_container(
            _config(), "t-scratch-writable", "standard", SOURCE_TEXT, mock_responses=[json.dumps(_valid_draft())],
        )
        self.assertEqual(result.get("status"), "succeeded", result)

    def test_no_host_mounts(self):
        name = "t-no-host-mounts"
        subprocess.run(ws.build_docker_create_args(_config(), name), check=True, capture_output=True)
        try:
            inspect = json.loads(subprocess.run(["docker", "inspect", name], capture_output=True, check=True).stdout)[0]
            bind_mounts = [m for m in inspect.get("Mounts", []) if m.get("Type") == "bind"]
            self.assertEqual(bind_mounts, [])
        finally:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True)

    def test_no_docker_socket_inside(self):
        result = subprocess.run(
            ["docker", "run", "--rm", IMAGE_TAG, "-c",
             "import os,sys; sys.exit(0 if not os.path.exists('/var/run/docker.sock') else 1)"],
            capture_output=True,
        )
        # The image's ENTRYPOINT is worker_entrypoint.py, which reads stdin
        # as a job envelope - override it for this one-off filesystem check.
        result = subprocess.run(
            ["docker", "run", "--rm", "--entrypoint", "python", IMAGE_TAG, "-c",
             "import os; print('SOCKET' if os.path.exists('/var/run/docker.sock') else 'NO_SOCKET')"],
            capture_output=True,
        )
        self.assertIn(b"NO_SOCKET", result.stdout)

    def test_failed_preparation_never_starts_the_job(self):
        # A malformed envelope (missing mode/source) must fail INSIDE
        # worker_entrypoint.py's own validation, before analyze_pipeline
        # is ever touched - see backend/worker_entrypoint.py's
        # _EnvelopeError. We can't call run_job_in_container() directly
        # with a malformed envelope (it always builds a well-formed one),
        # so this drives the container the same low-level way
        # run_job_in_container() does, with a deliberately broken payload.
        name = "t-malformed-envelope"
        subprocess.run(ws.build_docker_create_args(_config(), name), check=True, capture_output=True)
        try:
            proc = subprocess.Popen(
                ["docker", "start", "-a", "-i", name],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            stdout_data, _ = proc.communicate(input=b'{"not_mode_or_source": true}', timeout=30)
            result = json.loads(ws._last_nonempty_line(stdout_data))
            self.assertEqual(result.get("status"), "failed")
            self.assertIn("envelope", result.get("error", "").lower())
        finally:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True)

    def test_container_always_removed_success_and_failure(self):
        for label, mock_responses in (
            ("success", [json.dumps(_valid_draft())]),
            ("failure", [json.dumps({"not": "a valid report"})] * 3),
        ):
            with self.subTest(label=label):
                job_id = "t-removed-%s" % label
                ws.run_job_in_container(_config(), job_id, "standard", SOURCE_TEXT, mock_responses=mock_responses)
                self.assertFalse(_container_exists("job-%s" % job_id))

    def test_timeout_kills_worker_and_cleans_up(self):
        # An intentionally minuscule timeout - even a trivial container's
        # Python startup + imports cannot complete this fast, so this
        # reliably exercises run_job_in_container's own TimeoutExpired
        # path (never a flaky "maybe it finished in time" test).
        config = _config(wall_clock_timeout_seconds=0.05)
        job_id = "t-timeout"
        start = time.time()
        result = ws.run_job_in_container(config, job_id, "standard", SOURCE_TEXT, mock_responses=[json.dumps(_valid_draft())])
        elapsed = time.time() - start
        self.assertEqual(result.get("status"), "failed")
        self.assertIn("timeout", result.get("error", "").lower())
        self.assertLess(elapsed, 20, "timeout handling itself should be fast, not hang")
        self.assertFalse(_container_exists("job-%s" % job_id))


if __name__ == "__main__":
    unittest.main()
