#!/usr/bin/env python3
"""Host-side worker supervisor (Phase 4 execution infrastructure,
docs/decisiones.md D-077/D-079 follow-up). Trusted process: claims jobs from
the Phase-1 queue, launches ONE ephemeral Docker container per job,
never itself touches submitted source or the LLM credential beyond
handing the credential to that one container.

ISOLATION, exactly as the Phase 4 audit specified:
  * one container per job, destroyed in a finally block regardless of
    success/timeout/crash - see run_job_in_container();
  * --read-only root filesystem + one dedicated, size-bounded tmpfs
    scratch mount (/scratch) - the only writable path in the container;
  * CPU/RAM/PID-count/wall-clock/output-size limits, all enforced by
    Docker or this module, never trusted to the container's own
    cooperation;
  * NEVER mounts the Docker socket and NEVER bind-mounts any host
    directory into the container;
  * network: the container is attached ONLY to a dedicated, non-default
    Docker network with no route to the public internet, and reaches
    the configured LLM API (if at all) only through backend/
    egress_proxy.py's CONNECT-only allowlist proxy - see that module's
    own docstring for why a hostname-only check INSIDE the container
    would not be a real boundary.

BOUNDARY REDESIGN (D-079, blocker fix - replaces the pre-D-079 `docker cp`
design): empirically confirmed against a real Docker daemon that `docker
cp` cannot read or write ANY path backed by a tmpfs mount, in either
direction, independent of --read-only (copy-IN into a --read-only
container fails outright; copy-OUT fails for BOTH --read-only and non
---read-only containers, running or exited - docker cp operates on the
container's storage-driver layer, which a kernel tmpfs mount is never
part of). The original design would have failed to deliver a job's input
or LLM key into the container for every single job.

FIX: `docker create -i` (open stdin) + `docker start -a -i` (attached,
interactive), driven via subprocess.Popen(stdin=PIPE, stdout=PIPE,
stderr=PIPE).communicate(input=..., timeout=...) - the ENTIRE job
envelope (job_id, mode, source, and the LLM key OR test-only
mock_responses) is written to the container process's stdin and the
Popen call closes it (EOF) automatically; the container's own
worker_entrypoint.py reads that envelope, does its work using /scratch
exactly as before (only INTERNAL to the container - never crossed via
docker cp), and prints its ONE JSON result line to stdout, which this
module reads back via the same communicate() call. Neither direction
touches the container's filesystem from the HOST side at all - a pipe is
not part of the container's read-only rootfs or its tmpfs mount, so this
crosses the boundary without weakening --read-only, without a host bind
mount, and without the Docker socket. This is also a STRICTLY STRONGER
credential property than the pre-D-079 design: the LLM key is now never
written to a host-side temp file at all (the old design wrote it to one
before `docker cp`-ing it in) - it exists only in this process's own
memory and the pipe buffer until the container consumes it.

_copy_into_container()/_copy_out_of_container() (pre-D-079) are REMOVED,
not merely fixed: given the boundary now crosses via stdin/stdout,
neither has any remaining call site, and this module's own established
discipline (elsewhere in this codebase) is to delete code with no call
site rather than leave it as an unused, misleading relic. "docker cp
failures must propagate" (the specific bug this redesign fixes) is now
satisfied structurally instead: subprocess.Popen.communicate() either
returns real data or raises (TimeoutExpired, OSError), there is no
separate fire-and-forget subprocess call whose exit code could be
silently discarded anymore.

CREDENTIAL HANDLING: the LLM API key is held only in this supervisor
process's own memory (WorkerConfig.llm_api_key) until it is written
directly into the envelope piped to ONE container's stdin - never a
`docker create -e KEY=value` argument (which would appear in this host's
own process listing), never a host-side file, never logged.

Standard library only (subprocess + backend.repository/object_storage/
llm_client). No LLM calls happen in THIS process - only inside the
container this module launches.
"""
from __future__ import annotations

import json
import subprocess
import threading
import time
from typing import Any, Dict, List, Optional

import backend.alerting as alerting
import backend.object_storage as object_storage
import backend.repository as repo
import backend.retention as retention

DEFAULT_DOCKER_BINARY = "docker"
DEFAULT_MEMORY_LIMIT = "512m"
DEFAULT_CPU_LIMIT = "1"
DEFAULT_PIDS_LIMIT = "128"
DEFAULT_TMPFS_SIZE = "64m"
DEFAULT_WALL_CLOCK_TIMEOUT_SECONDS = 300
DEFAULT_OUTPUT_SIZE_LIMIT_BYTES = 2 * 1024 * 1024  # 2 MiB - a rendered report is text, never expected to approach this.
# Phase 15K-B (docs/decisiones.md D-097): the container's Step 6 gets the
# wall clock minus this reserve as its own deadline (STEP6_DEADLINE_SECONDS),
# so its attempts, passes and final pipeline always end before this
# supervisor kills the container. Covers everything outside Step 6:
# container start (measured 0.3-0.6 s), the stdin envelope, interpreter and
# SDK imports, and writing the result line.
WORKER_STEP6_STARTUP_RESERVE_SECONDS = 15
DEFAULT_MAX_PASSES = 1  # multi-pass is opt-in (LLM_MAX_PASSES)

_SCRATCH_DIR = "/scratch"
_SOURCE_PATH = _SCRATCH_DIR + "/contract.sol"


class WorkerSupervisorError(Exception):
    """Raised for supervisor-level misconfiguration (bad limits, docker
    binary missing) - never for a single job's own failure, which is
    always reported as that job's terminal status instead (see
    claim_and_run_one_job() - a job failing must never crash the
    supervisor loop itself)."""


class WorkerConfig:
    """Explicit config, constructed once by whatever process starts the
    supervisor (mirrors backend/billing.StripeBilling's own explicit-
    config discipline) - this module never reads os.environ itself."""

    def __init__(
        self,
        docker_image: str,
        network_name: str,
        proxy_host: str,
        proxy_port: int,
        llm_api_key: str,
        llm_model: str,
        llm_provider: str = "anthropic",
        docker_binary: str = DEFAULT_DOCKER_BINARY,
        memory_limit: str = DEFAULT_MEMORY_LIMIT,
        cpu_limit: str = DEFAULT_CPU_LIMIT,
        pids_limit: str = DEFAULT_PIDS_LIMIT,
        tmpfs_size: str = DEFAULT_TMPFS_SIZE,
        wall_clock_timeout_seconds: int = DEFAULT_WALL_CLOCK_TIMEOUT_SECONDS,
        output_size_limit_bytes: int = DEFAULT_OUTPUT_SIZE_LIMIT_BYTES,
        max_output_tokens: int = 8000,
        per_attempt_timeout_seconds: int = 120,
        max_passes: int = DEFAULT_MAX_PASSES,
        targeted_review_enabled: bool = False,
    ) -> None:
        if not docker_image:
            raise WorkerSupervisorError("docker_image is required")
        self.docker_image = docker_image
        self.network_name = network_name
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.llm_api_key = llm_api_key
        self.llm_model = llm_model
        self.llm_provider = llm_provider
        self.docker_binary = docker_binary
        self.memory_limit = memory_limit
        self.cpu_limit = cpu_limit
        self.pids_limit = pids_limit
        self.tmpfs_size = tmpfs_size
        self.wall_clock_timeout_seconds = wall_clock_timeout_seconds
        self.output_size_limit_bytes = output_size_limit_bytes
        self.max_output_tokens = max_output_tokens
        self.per_attempt_timeout_seconds = per_attempt_timeout_seconds
        self.max_passes = max_passes
        # Layer 2 targeted code review (docs/decisiones.md D-105): opt-in, off by default.
        self.targeted_review_enabled = bool(targeted_review_enabled)

    @property
    def step6_deadline_seconds(self) -> int:
        """The container's own Step 6 deadline - see
        WORKER_STEP6_STARTUP_RESERVE_SECONDS."""
        return max(1, self.wall_clock_timeout_seconds - WORKER_STEP6_STARTUP_RESERVE_SECONDS)


def build_docker_create_args(config: WorkerConfig, container_name: str) -> List[str]:
    """Pure - builds the argv for `docker create`, no subprocess call.
    Deliberately a separate, easily unit-tested function (see tests/
    test_backend_worker_supervisor.py) so every isolation flag can be
    asserted on directly, without needing a real Docker daemon for that
    assertion. No `-v`/`--mount` anywhere (no host filesystem mount, no
    Docker socket) - job data crosses the boundary via stdin/stdout only
    (see module docstring's boundary redesign, D-079). `-i` keeps stdin
    open so a later `docker start -a -i` can pipe the job envelope in;
    this is the ONLY change to the isolation flags themselves - every
    flag already audited (--read-only, --cap-drop ALL, --security-opt
    no-new-privileges, --memory/--cpus/--pids-limit, the bounded --tmpfs)
    is unchanged."""
    return [
        config.docker_binary, "create", "-i",
        "--name", container_name,
        "--read-only",
        "--network", config.network_name,
        "--memory", config.memory_limit,
        "--cpus", config.cpu_limit,
        "--pids-limit", config.pids_limit,
        "--tmpfs", "%s:rw,size=%s" % (_SCRATCH_DIR, config.tmpfs_size),
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "-e", "HTTPS_PROXY=http://%s:%d" % (config.proxy_host, config.proxy_port),
        "-e", "SOURCE_PATH=%s" % _SOURCE_PATH,
        "-e", "LLM_MODEL=%s" % config.llm_model,
        "-e", "LLM_PROVIDER=%s" % config.llm_provider,
        "-e", "LLM_MAX_OUTPUT_TOKENS=%d" % config.max_output_tokens,
        "-e", "LLM_PER_ATTEMPT_TIMEOUT_SECONDS=%d" % config.per_attempt_timeout_seconds,
        "-e", "LLM_MAX_PASSES=%d" % config.max_passes,
        "-e", "STEP6_DEADLINE_SECONDS=%d" % config.step6_deadline_seconds,
    ] + (["-e", "TARGETED_REVIEW_ENABLED=1"] if config.targeted_review_enabled else []) + [
        config.docker_image,
    ]


def _run(args: List[str], timeout_seconds: Optional[float] = None) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, timeout=timeout_seconds, check=False)


def _last_nonempty_line(data: bytes) -> Optional[str]:
    for line in reversed(data.decode("utf-8", "replace").splitlines()):
        if line.strip():
            return line
    return None


def run_job_in_container(
    config: WorkerConfig, job_id: str, mode: str, source: str, mock_responses: Optional[List[Any]] = None,
) -> Dict[str, Any]:
    """The full per-job container lifecycle: create -> start attached with
    the job envelope piped to stdin -> read the one JSON result line back
    from stdout (bounded by wall_clock_timeout_seconds) -> ALWAYS remove
    the container, even on a failed create, a malformed envelope, a
    timeout, or an unexpected exception (see the finally block) - "destroy
    container in finally" and "cleanup even after timeout/crash" from the
    Phase 4 audit, applied literally, now via subprocess.Popen instead of
    a separate docker cp/start/wait sequence (see module docstring,
    D-079). "Never start a partially prepared job": the envelope is built
    and fully JSON-serialized BEFORE `docker create` even runs, so a
    malformed config here (see WorkerConfig's own validation) is caught
    before any container exists at all; a malformed envelope on the
    CONTAINER side is worker_entrypoint.py's own concern (it validates
    before touching /scratch or the LLM provider - see that module's own
    docstring) and comes back as an ordinary status="failed" result here,
    same as any other job-level failure.

    mock_responses is test-only (see backend/llm_client.MockLLMProvider) -
    production callers (claim_and_run_one_job) never pass it, so the
    envelope always carries the real llm_api_key instead.

    Always returns a dict with a "status" key ("succeeded" or "failed")
    - never raises for a job-level failure (timeout, crash, oversized
    output, malformed result); those are exactly as expected an outcome
    here as a clean success, and the caller (claim_and_run_one_job)
    treats them uniformly. Only WorkerSupervisorError-worthy
    misconfiguration would raise, and none of this function's own logic
    does."""
    container_name = "job-%s" % job_id
    envelope: Dict[str, Any] = {"job_id": job_id, "mode": mode, "source": source}
    if mock_responses is not None:
        envelope["mock_responses"] = mock_responses
    else:
        envelope["llm_api_key"] = config.llm_api_key
    envelope_bytes = json.dumps(envelope, ensure_ascii=False).encode("utf-8")

    create_result = _run(build_docker_create_args(config, container_name), timeout_seconds=30)
    if create_result.returncode != 0:
        return {"status": "failed", "error": "container create failed"}

    try:
        try:
            proc = subprocess.Popen(
                [config.docker_binary, "start", "-a", "-i", container_name],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        except OSError as exc:
            return {"status": "failed", "error": "failed to launch docker start: %s" % type(exc).__name__}

        try:
            stdout_data, _stderr_data = proc.communicate(input=envelope_bytes, timeout=config.wall_clock_timeout_seconds)
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.communicate(timeout=15)  # reap the killed local process, avoid a zombie.
            except Exception:
                pass
            # proc.kill() only kills OUR local `docker start -a` client
            # process, which does not by itself stop the container (an
            # attached client detaching never implies a stop, exactly
            # like `docker attach` + Ctrl-P Ctrl-Q) - the container
            # itself must be killed explicitly.
            _run([config.docker_binary, "kill", container_name], timeout_seconds=15)
            return {"status": "failed", "error": "worker exceeded the wall-clock timeout"}

        if len(stdout_data) > config.output_size_limit_bytes:
            return {"status": "failed", "error": "worker output exceeded the size limit"}

        last_line = _last_nonempty_line(stdout_data)
        if last_line is None:
            return {"status": "failed", "error": "container produced no result (crashed before writing output)"}
        try:
            result = json.loads(last_line)
        except json.JSONDecodeError:
            return {"status": "failed", "error": "worker output was not valid JSON"}
        if not isinstance(result, dict) or "status" not in result:
            return {"status": "failed", "error": "worker output was not a valid result object"}

        if proc.returncode != 0 and result.get("status") == "succeeded":
            # Belt-and-suspenders: a non-zero exit with a claimed success is
            # a contradiction this supervisor never trusts at face value.
            return {"status": "failed", "error": "worker exited non-zero despite reporting success"}
        return result
    finally:
        _run([config.docker_binary, "rm", "-f", container_name], timeout_seconds=30)


def claim_and_run_one_job(
    conn: Any,
    worker_id: str,
    config: WorkerConfig,
    storage: object_storage.ObjectStorage,
    alert_sender: Optional[alerting.AlertSender] = None,
) -> Optional[str]:
    """Claims at most one job and runs it to a terminal state. Returns
    the claimed job's id, or None if the queue was empty. Budget is
    reserved BEFORE the container ever starts (so a workspace at its
    ceiling never pays for compute it can't afford) and released on any
    failure path, consumed only on a real success - see repository.py's
    reserve_workspace_budget()/consume_reserved_workspace_budget()/
    release_workspace_budget().

    Phase 6A hardening: object-storage calls (fetching the source,
    storing the report) are now explicitly caught - previously, either
    one raising (a transient S3/network failure, not hypothetical)
    propagated uncaught all the way out of run_worker_supervisor_loop()
    and killed the entire worker process instead of just failing this
    one job. Both paths now release the reserved budget, transition the
    job to a clean 'failed' terminal state, and emit a
    alerting.EVENT_STORAGE_FAILURE alert (alert_sender is optional and
    never required - see backend/alerting.py's own module docstring).

    FENCING (concurrency audit, post-reap-atomicity-fix): every write
    this function makes to the job/report/budget AFTER the claim below
    now goes through repo.finalize_job_attempt() instead of calling
    transition_job_status()/record_report()/consume_reserved_workspace_
    budget()/release_workspace_budget() directly - a confirmed gap let a
    worker whose lease had already expired (container still legitimately
    running past LEASE_DURATION_SECONDS, e.g. under a misconfigured
    WORKER_WALL_CLOCK_TIMEOUT_SECONDS - see _load_worker_config()'s own
    validation) finish AFTER reap_expired_jobs() had already reclaimed
    (and possibly re-run) the same job: a plain job_id+status='running'
    check is not enough fencing, because a reaped-and-re-claimed job is
    'running' again too, just for a different attempt - see
    finalize_job_attempt()'s own docstring for the full reasoning and why
    (attempt_count, claimed_by), captured once right below immediately
    after claim_next_job() returns, is what actually distinguishes them.
    Every finalize_job_attempt() call below threads that SAME pair
    through unchanged - never re-read from the job row later, which
    could already reflect a newer attempt."""
    job = repo.claim_next_job(conn, worker_id)
    if job is None:
        return None
    job_id = job["id"]
    workspace_id = job["workspace_id"]
    mode = job["mode"]
    units = repo.JOB_MODE_BUDGET_COST.get(mode, 1)
    attempt_count = job["attempt_count"]
    claimed_by = job["claimed_by"]

    if not repo.reserve_workspace_budget(conn, workspace_id, units):
        repo.finalize_job_attempt(
            conn, job_id, workspace_id, attempt_count, claimed_by,
            from_status="claimed", to_status="failed", error="workspace budget exhausted",
        )
        return job_id

    if not repo.finalize_job_attempt(
        conn, job_id, workspace_id, attempt_count, claimed_by,
        from_status="claimed", to_status="running",
    )["applied"]:
        # Lost fencing before the container ever started - a concurrent
        # reap already reclaimed this job while it was still 'claimed'.
        # reap_expired_jobs() deliberately never releases budget for a
        # job it finds 'claimed' (the reservation there is ambiguous from
        # its side - see that function's own docstring), so the units
        # reserved just above are this worker's own, unambiguously, and
        # ONLY this worker will ever release them - a plain call here
        # (not fenced - nothing else could legitimately touch this exact
        # reservation) is correct regardless of ordering against whatever
        # the job's NEXT attempt goes on to reserve for itself.
        repo.release_workspace_budget(conn, workspace_id, units)
        return job_id

    contract = repo.get_contract(conn, job["contract_id"])
    try:
        source = storage.get_object(contract["storage_ref"]).decode("utf-8", "replace")
    except Exception as exc:
        alerting.emit_safe(alert_sender, alerting.EVENT_STORAGE_FAILURE, "error", {"job_id": job_id, "phase": "fetch_source", "error_type": type(exc).__name__})
        repo.finalize_job_attempt(
            conn, job_id, workspace_id, attempt_count, claimed_by,
            from_status="running", to_status="failed",
            error="object storage error fetching source: %s" % type(exc).__name__,
            budget_units=units, budget_action="release",
        )
        return job_id

    try:
        result = run_job_in_container(config, job_id, mode, source)
    except Exception as exc:  # never let a single job's unexpected failure kill the supervisor loop.
        result = {"status": "failed", "error": "supervisor error: %s" % type(exc).__name__}

    if result.get("status") == "succeeded":
        report_key = object_storage.workspace_key(workspace_id, "reports", job_id)
        try:
            storage.put_object(report_key, result.get("rendered", "").encode("utf-8"), content_type="text/markdown")
        except Exception as exc:
            alerting.emit_safe(alert_sender, alerting.EVENT_STORAGE_FAILURE, "error", {"job_id": job_id, "phase": "store_report", "error_type": type(exc).__name__})
            repo.finalize_job_attempt(
                conn, job_id, workspace_id, attempt_count, claimed_by,
                from_status="running", to_status="failed",
                error="object storage error storing report: %s" % type(exc).__name__,
                budget_units=units, budget_action="release",
            )
            return job_id
        risk_indicator = result.get("risk_indicator") or {}
        finalized = repo.finalize_job_attempt(
            conn, job_id, workspace_id, attempt_count, claimed_by,
            from_status="running", to_status="succeeded",
            budget_units=units, budget_action="consume",
            report_storage_ref=report_key,
            report_score_status="computed" if risk_indicator.get("score") is not None else "not_computed",
            report_score=risk_indicator.get("score"), report_risk_band=risk_indicator.get("band"),
        )
        if isinstance(result.get("targeted_review"), dict) and isinstance(finalized, dict) and finalized.get("applied"):
            _persist_targeted_review(conn, storage, workspace_id, job_id, result["targeted_review"], alert_sender)
    else:
        alerting.emit_safe(alert_sender, alerting.EVENT_WORKER_JOB_FAILED, "warning", {"job_id": job_id, "workspace_id": workspace_id, "error": str(result.get("error", ""))[:200]})
        repo.finalize_job_attempt(
            conn, job_id, workspace_id, attempt_count, claimed_by,
            from_status="running", to_status="failed",
            error=str(result.get("error", "unknown worker failure"))[:500],
            budget_units=units, budget_action="release",
        )
    return job_id


def _persist_targeted_review(
    conn: Any,
    storage: object_storage.ObjectStorage,
    workspace_id: str,
    job_id: str,
    payload: Dict[str, Any],
    alert_sender: Optional[alerting.AlertSender],
) -> None:
    """Layer 2 (docs/decisiones.md D-105), best effort and only after the job
    is already 'succeeded': the advisory section and the raw provider text as
    two objects next to the report (ids derived from it, so report retention
    deletes them too - see targeted_review.companion_keys()), plus one
    summary audit event (no source, no quotes, no raw text). Any failure only
    alerts; the job's terminal state never changes."""
    import backend.targeted_review as targeted_review  # stdlib-only module

    section = payload.get("section")
    raw = payload.get("raw")
    if not isinstance(section, dict):
        return
    try:
        section_id, raw_id = targeted_review.object_ids(job_id)
        storage.put_object(object_storage.workspace_key(workspace_id, "reports", section_id),
                           json.dumps(section, ensure_ascii=False, sort_keys=True).encode("utf-8"), content_type="application/json")
        if isinstance(raw, str):
            storage.put_object(object_storage.workspace_key(workspace_id, "reports", raw_id), raw.encode("utf-8"), content_type="text/plain")
        repo.append_audit_event(conn, workspace_id, None, targeted_review.AUDIT_EVENT_TYPE,
                                json.dumps(dict(targeted_review.audit_metadata(section), jobId=job_id), sort_keys=True))
    except Exception as exc:
        alerting.emit_safe(alert_sender, alerting.EVENT_STORAGE_FAILURE, "warning",
                           {"job_id": job_id, "phase": "store_targeted_review", "error_type": type(exc).__name__})


def run_worker_supervisor_loop(
    connect_fn: Any,
    worker_id: str,
    config: WorkerConfig,
    storage: object_storage.ObjectStorage,
    poll_interval_seconds: float = 2.0,
    max_iterations: Optional[int] = None,
    alert_sender: Optional[alerting.AlertSender] = None,
    shutdown_event: Optional[threading.Event] = None,
    retention_days: Optional[int] = None,
    retention_check_interval_seconds: float = 3600.0,
    retention_dry_run: bool = False,
) -> None:
    """Thin polling wrapper - reaps expired leases, then claims/runs at
    most one job, repeating forever (max_iterations=None) or a bounded
    number of times (tests only - see tests/test_backend_worker_
    supervisor.py). A fresh connection per iteration, matching this
    codebase's own connection-per-unit-of-work discipline.

    GRACEFUL SHUTDOWN (Phase 6A): shutdown_event, if given, is checked
    ONLY at the top of each iteration, BEFORE reaping or claiming a new
    job - so once set, this loop stops claiming new work but never
    aborts a job it has already claimed and started; that job runs to
    its own natural terminal state exactly as if no shutdown were in
    progress (claim_and_run_one_job's own per-job wall-clock timeout is
    what already bounds how long that can take - see backend/
    worker_supervisor.py's module docstring - no separate shutdown-
    specific job timeout is added here). If the process is killed before
    that job finishes despite this, its lease eventually expires and
    repo.reap_expired_jobs() (called by whichever worker starts next)
    requeues or fails it exactly as it already does for any other
    process death - lease/reaper semantics remain the ONE recovery
    mechanism for a job in flight when its worker disappears, unchanged
    by this shutdown path.

    RETENTION SCHEDULER (Phase 6B, docs/decisiones.md D-077 follow-up):
    retention_days is None by default - retention stays completely
    disabled (never runs, never even queries) unless a caller (backend/
    main.py, from the explicit RETENTION_DAYS environment variable)
    supplies a real value. This is deliberate: this codebase never
    invents a legal retention period on its own (see backend/
    retention.py's own module docstring) - "unset" must fail/disable
    safely, never fall back to some guessed number of days. When set,
    this loop calls backend.retention.purge_expired_contracts()/
    purge_expired_reports() at most once every
    retention_check_interval_seconds (a real Postgres table scan on
    every 2-second poll iteration would be wasteful) - checked via a
    plain monotonic deadline local to this loop, reset after each run
    regardless of whether it found anything to purge. retention_dry_run
    (also from an explicit environment variable, never invented) lets an
    operator prove the mechanism runs without deleting anything even
    once RETENTION_DAYS is set - see backend/retention.py's own purge
    functions for what dry_run actually does. Uses the SAME per-
    iteration connection reap/claim already use, never a second one."""
    iterations = 0
    next_retention_check = 0.0  # 0.0 - due immediately on the very first iteration this process ever runs, if retention_days is configured at all.
    while max_iterations is None or iterations < max_iterations:
        if shutdown_event is not None and shutdown_event.is_set():
            break
        conn = connect_fn()
        try:
            if retention_days is not None and time.monotonic() >= next_retention_check:
                contracts_result = retention.purge_expired_contracts(conn, storage, retention_days, dry_run=retention_dry_run)
                reports_result = retention.purge_expired_reports(conn, storage, retention_days, dry_run=retention_dry_run)
                next_retention_check = time.monotonic() + retention_check_interval_seconds
                purged_total = contracts_result.get("purged", 0) + reports_result.get("purged", 0)
                if purged_total:
                    alerting.emit_safe(alert_sender, alerting.EVENT_RETENTION_PURGE, "info", {"purged_contracts": contracts_result.get("purged", 0), "purged_reports": reports_result.get("purged", 0)})
            reap_result = repo.reap_expired_jobs(conn)
            if reap_result.get("requeued"):
                alerting.emit_safe(alert_sender, alerting.EVENT_WORKER_REPEATED_RETRY, "warning", {"requeued": reap_result["requeued"]})
            if reap_result.get("failed"):
                alerting.emit_safe(alert_sender, alerting.EVENT_WORKER_JOB_FAILED, "error", {"permanently_failed_by_reaper": reap_result["failed"]})
            claimed = claim_and_run_one_job(conn, worker_id, config, storage, alert_sender=alert_sender)
        finally:
            conn.close()
        iterations += 1
        if claimed is None:
            time.sleep(poll_interval_seconds)
