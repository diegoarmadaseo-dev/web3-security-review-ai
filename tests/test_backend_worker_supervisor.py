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
import re
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


# Runs INSIDE the worker image, under the exact production isolation flags
# (build_docker_create_args with only the entrypoint swapped): the trickle
# server of tests/test_backend_provider_call_deadline.py on the container's
# loopback, and both real SDK providers built as the worker builds them
# under a Step 6 deadline (sdk_max_retries 0 + provider_for_step6()).
_HARD_DEADLINE_PROBE = r'''
import json, os, select, subprocess, sys, time
from unittest import mock
sys.path.insert(0, "/app")
import backend.llm_client as lc
SERVER = %r
os.environ["NO_PROXY"] = "127.0.0.1,localhost"
server = subprocess.Popen([sys.executable, "-c", SERVER, "8", "0.5"], stdout=subprocess.PIPE)
fd = server.stdout.fileno(); pending = [b""]
def event(timeout):
    end = time.monotonic() + timeout
    while b"\n" not in pending[0]:
        ready, _, _ = select.select([fd], [], [], max(0.0, end - time.monotonic()))
        if not ready:
            return None
        pending[0] += os.read(fd, 65536)
    line, pending[0] = pending[0].split(b"\n", 1)
    return json.loads(line)
base = "http://127.0.0.1:%%d" %% event(10)["port"]
def conns():
    out = {}
    while True:
        e = event(1.0)
        if e is None:
            return [out[k] for k in sorted(out)]
        if e["event"] == "open":
            out[e["id"]] = {"open": e["t"]}
        elif e["event"] == "close":
            out[e["id"]].update(close=e["t"], reason=e["reason"])
report = {}
with mock.patch.object(lc, "_DEEPSEEK_BASE_URL", base):
    deepseek = lc.DeepSeekLLMProvider(api_key="fake-not-a-key", model="m", sdk_max_retries=lc.sdk_max_retries_for(285))
os.environ["ANTHROPIC_BASE_URL"] = base
anthropic_p = lc.AnthropicLLMProvider(api_key="fake-not-a-key", model="m", sdk_max_retries=lc.sdk_max_retries_for(285))
for name, inner in (("deepseek", deepseek), ("anthropic", anthropic_p)):
    wrapped = lc.provider_for_step6(inner, 285)
    start = time.monotonic()
    try:
        wrapped.complete("p", 1, 3); outcome = "returned"
    except lc.ProviderError as exc:
        outcome = str(exc)
    elapsed = time.monotonic() - start
    pid = wrapped.last_child_pid
    try:
        os.waitpid(pid, os.WNOHANG); reaped = False
    except ChildProcessError:
        reaped = True
    c = conns()
    report[name] = {"sdk_max_retries": inner._client.max_retries, "elapsed": round(elapsed, 2), "outcome": outcome,
                    "reaped": reaped and not os.path.exists("/proc/%%d" %% pid), "connections": len(c),
                    "reasons": [x.get("reason") for x in c], "closed_after": [round(x["close"] - start, 2) for x in c if "close" in x]}
start = time.monotonic()
try:
    deepseek.complete("p", 1, 3); outcome = "returned"
except lc.ProviderError as exc:
    outcome = str(exc)
report["deepseek_without_isolation"] = {"elapsed": round(time.monotonic() - start, 2), "outcome": outcome, "reasons": [x.get("reason") for x in conns()]}
server.kill(); server.wait()
print(json.dumps(report))
'''


class WorkerImageHardCallDeadlineTests(unittest.TestCase):
    def test_hard_total_call_deadline_inside_the_isolated_worker_container(self):
        from tests.test_backend_provider_call_deadline import TRICKLE_SERVER
        name = "worker-hard-deadline-%d" % os.getpid()
        args = ws.build_docker_create_args(_config(wall_clock_timeout_seconds=120, max_passes=6), name)
        for flag in ("--read-only", "--cap-drop", "no-new-privileges", "--memory", "--cpus", "--pids-limit", "--tmpfs"):
            self.assertIn(flag, args)
        self.assertFalse(any(a in ("-v", "--volume", "--mount", "--privileged") for a in args))
        self.assertNotIn("docker.sock", " ".join(args))
        self.assertIn("HTTPS_PROXY=http://127.0.0.1:1", args)
        image = args.index(IMAGE_TAG)
        args = args[:image] + ["--entrypoint", "python"] + args[image:] + ["-c", _HARD_DEADLINE_PROBE % TRICKLE_SERVER]
        self.assertEqual(subprocess.run(args, capture_output=True, timeout=30).returncode, 0)
        try:
            run = subprocess.run(["docker", "start", "-a", name], capture_output=True, timeout=120)
        finally:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        self.assertEqual(run.returncode, 0, run.stderr.decode(errors="replace")[-2000:])
        report = json.loads(run.stdout.decode().strip().splitlines()[-1])
        for provider in ("deepseek", "anthropic"):
            with self.subTest(provider=provider):
                r = report[provider]
                self.assertEqual(r["sdk_max_retries"], 0)
                self.assertIn("exceeded its total time limit of 3 s", r["outcome"])
                self.assertGreaterEqual(r["elapsed"], 3.0)
                self.assertLess(r["elapsed"], 3.5)
                self.assertTrue(r["reaped"])
                self.assertEqual(r["connections"], 1)  # no SDK retry
                self.assertEqual(r["reasons"], ["peer_closed"])  # the request was aborted
                self.assertLess(r["closed_after"][0], 3.6)
        # The bug itself, same container: without isolation a 3 s SDK timeout lasts the whole 8 s trickle.
        self.assertGreaterEqual(report["deepseek_without_isolation"]["elapsed"], 7.5)
        self.assertEqual(report["deepseek_without_isolation"]["reasons"], ["finished"])


class WorkerImageRuntimeDependencyTests(unittest.TestCase):
    """The worker image COPYs individual backend/ files (minimal image), so
    a new local import of backend/llm_client.py that is not also COPYed in
    Dockerfile.worker only fails inside the real container, at import time,
    before worker_entrypoint.main() can report anything ("worker entrypoint
    crashed before producing a result"). This imports the worker's runtime
    modules inside the image built from the current repository."""

    def test_image_imports_worker_runtime_modules(self):
        probe = (
            "import backend.context_selection as cs, backend.llm_client as lc; "
            "assert lc.context_selection is cs; "
            "print(cs.APPLICATION_CONTEXT_BUDGET_BYTES)"
        )
        run = subprocess.run(
            ["docker", "run", "--rm", "--network", "none", "--entrypoint", "python", IMAGE_TAG, "-c", probe],
            capture_output=True, timeout=60,
        )
        self.assertEqual(run.returncode, 0, run.stderr.decode(errors="replace"))
        self.assertEqual(run.stdout.decode().strip(), "1572864")

    def test_every_local_backend_import_of_llm_client_is_in_the_image(self):
        # Every backend.* module llm_client.py imports must exist in the image,
        # not just the one known today.
        with open(os.path.join(REPO_ROOT, "backend", "llm_client.py"), encoding="utf-8") as handle:
            source = handle.read()
        local = sorted(set(re.findall(r"^\s*(?:import|from)\s+backend\.(\w+)", source, re.M)))
        self.assertIn("context_selection", local)
        probe = "import importlib; [importlib.import_module('backend.' + m) for m in %r]" % (local,)
        run = subprocess.run(
            ["docker", "run", "--rm", "--network", "none", "--entrypoint", "python", IMAGE_TAG, "-c", probe],
            capture_output=True, timeout=60,
        )
        self.assertEqual(run.returncode, 0, run.stderr.decode(errors="replace"))

    def test_image_round_trips_the_compact_v2_context_encoding(self):
        # Phase 15K-A (D-096): backend/context_encoding.py is a new local
        # import of llm_client.py - it must be in the image and behave the
        # same there (lossless round trip of the opt-in compact-v2 format).
        probe = (
            "import json, backend.context_encoding as ce, backend.llm_client as lc; "
            "assert lc.context_encoding is ce; "
            "a = {'signals': [{'file': 'A.sol', 'line': 1}, {'file': 'A.sol', 'line': 2}], 'x': [None, False, '']}; "
            "t = ce.encode_context_artifact(a, ce.CONTEXT_FORMAT_V2); "
            "assert ce.decode_context_artifact(t, ce.CONTEXT_FORMAT_V2) == a; "
            "assert ce.encode_context_artifact(a) == json.dumps(a, ensure_ascii=False); "
            "print(json.loads(t)['contextArtifactFormat'])"
        )
        run = subprocess.run(
            ["docker", "run", "--rm", "--network", "none", "--entrypoint", "python", IMAGE_TAG, "-c", probe],
            capture_output=True, timeout=60,
        )
        self.assertEqual(run.returncode, 0, run.stderr.decode(errors="replace"))
        self.assertEqual(run.stdout.decode().strip(), "compact-v2")


def _large_bundle_source(target_bytes):
    """A multi-file pro bundle just under target_bytes of UTF-8 (the HTTP
    raw-source limit, D-096), in preprocess.py's === FILE === format."""
    parts, size, index = [], 0, 0
    while True:
        lines = ["pragma solidity ^0.8.20;", "/// @notice Vault %d - dep\u00f3sito" % index, "contract Vault%d {" % index, "    mapping(address => uint256) public balances;"]
        for fn in range(10):
            lines += ["    function move%d(address to, uint256 amount) external {" % fn, "        balances[msg.sender] -= amount;", "        balances[to] += amount;", "    }"]
        part = "=== FILE: src/Vault%d.sol ===\n%s\n}\n=== END FILE ===\n" % (index, "\n".join(lines))
        if size + len(part.encode("utf-8")) > target_bytes:
            return "".join(parts)
        parts.append(part)
        size += len(part.encode("utf-8"))
        index += 1


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

    def test_source_near_the_raw_source_limit_reaches_the_worker_over_stdin(self):
        # Phase 15K-A (D-096): a submission just under the new 2 MiB HTTP
        # raw-source limit travels host -> stdin envelope -> container ->
        # /scratch (tmpfs) -> preprocess -> context selection -> Step 6 prompt
        # (default canonical format) and back. It is a pro job over the mode's
        # LOC limit, so selection runs and the report must be scoped partial.
        source = _large_bundle_source(2 * 1024 * 1024 - 1024)
        self.assertGreater(len(source.encode("utf-8")), 512 * 1024)
        draft = _valid_draft("pro")
        draft["scope"] = {"completeness": "partial", "reasons": [{"code": "LOC_LIMIT_EXCEEDED", "detail": "scoped"}]}
        draft["categoryCoverage"][0]["status"] = "NOT_ASSESSED"
        result = ws.run_job_in_container(
            _config(wall_clock_timeout_seconds=240), "t-large-source", "pro", source, mock_responses=[json.dumps(draft)],
        )
        self.assertEqual(result.get("status"), "succeeded", result)
        self.assertIn("CONTEXT_SELECTION_APPLIED", result.get("rendered", ""))

    def test_multi_pass_job_runs_end_to_end_in_the_container(self):
        # Phase 15K-B (D-097): with max_passes > 1 the same ~2 MiB pro
        # submission is partitioned into several passes inside the real
        # container (every pass answered by the same valid partial draft,
        # which has no finding and so fits any pass's scope), merged, and
        # scored/validated/rendered once. LLM_MAX_PASSES and the Step 6
        # deadline reach the container through its curated env.
        source = _large_bundle_source(2 * 1024 * 1024 - 1024)
        draft = _valid_draft("pro")
        draft["scope"] = {"completeness": "partial", "reasons": [{"code": "LOC_LIMIT_EXCEEDED", "detail": "scoped"}]}
        draft["categoryCoverage"][0]["status"] = "NOT_ASSESSED"
        result = ws.run_job_in_container(
            _config(wall_clock_timeout_seconds=240, max_passes=8), "t-multi-pass", "pro", source,
            mock_responses=[json.dumps(draft)] * 24,
        )
        self.assertEqual(result.get("status"), "succeeded", result)
        self.assertIn("MULTI_PASS_ANALYSIS", result.get("rendered", ""))
        self.assertNotIn("CONTEXT_SELECTION_APPLIED", result.get("rendered", ""))

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
