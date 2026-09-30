#!/usr/bin/env python3
"""Runs ONLY inside the isolated per-job worker container (Phase 4
execution infrastructure, docs/decisiones.md D-077/D-079 follow-up) - never
imported or run by the host-side supervisor process, which never sees
the LLM credential this script reads (see module docstring on the LLM
boundary).

BOUNDARY REDESIGN (D-079, blocker fix): the original design crossed the
host<->container boundary via `docker cp` into/out of this container's
`/scratch` tmpfs mount. Empirically confirmed broken on a real Docker
daemon: `docker cp` cannot read or write a tmpfs-backed path at all -
copy-IN into a `--read-only` container fails ("container rootfs is marked
read-only"), and copy-OUT fails independently of `--read-only` too ("Could
not find the file") in every combination tested (running/exited,
read-only/not) - `docker cp`'s implementation operates on the container's
storage-driver layer, which a kernel tmpfs mount is never part of. Every
job would have failed in production.

FIX: the entire job envelope (job_id, mode, source, and EITHER llm_api_key
OR mock_responses) now arrives as ONE JSON object read from STDIN (see
_read_stdin_envelope() below), and the final result is the ONE thing this
script ever writes to STDOUT (see _write_result() below) - a single JSON
line, nothing else. Neither a pipe's read nor write end is affected by
--read-only at all (pipes are not part of the container's filesystem), so
this crosses the exact same isolation boundary (one process, one
container, `--read-only` + tmpfs `/scratch` completely unchanged) without
weakening it. backend/worker_supervisor.py's own docstring covers the
host-side half of this contract (`docker create -i` + `docker start -a -i`
via subprocess.Popen(stdin=PIPE, stdout=PIPE)).

`/scratch` itself is UNCHANGED as this script's own internal working
directory (submitted source is still written to SOURCE_PATH before being
handed to preprocess.run()/analyze_pipeline.run_analyze_pipeline() as DATA
only - this script never compiles or executes it, see backend/
llm_client.py's own docstring on the same boundary) - only the CROSSING of
the host<->container boundary changed, never this script's own use of its
one writable mount.

Exit codes: 0 on a rendered report, 1 on any failure (exactly one result
line is still printed either way, with "status": "failed" and a short,
non-traceback error message). Never prints source, the API key, or a raw
traceback anywhere - only the one structured result line on stdout, and
short diagnostic lines (never secrets/source) on stderr.

Environment variables this script itself reads (nowhere else in this
codebase reads them - see backend/llm_client.py's own docstring on why
business logic never reads os.environ directly). Note LLM_API_KEY,
LLM_API_KEY_FILE, JOB_INPUT_PATH, JOB_OUTPUT_PATH and
LLM_MOCK_RESPONSES_PATH from the pre-D-079 design are GONE - that data now
arrives via the stdin envelope instead, never an env var or a file path:
  SOURCE_PATH, SKILL_SCRIPTS_DIR, REPO_ROOT,
  LLM_MODEL, LLM_PROVIDER, LLM_MAX_OUTPUT_TOKENS, LLM_PER_ATTEMPT_TIMEOUT_SECONDS.

PROVIDER SELECTION (docs/decisiones.md, the phase that wired the already-
validated DeepSeekLLMProvider into this real worker path): LLM_PROVIDER
selects which concrete backend.llm_client provider class this script
constructs - "anthropic" (the default, byte-identical to every prior
deployment that never set this variable) or "deepseek". Any other value
fails closed with a clear configuration error before any real work
begins, same "never start a partially prepared job" discipline as
_read_stdin_envelope()'s own errors - never silently falls back to a
default a deployer did not ask for. reasoning_effort is NOT a variable
here: DeepSeekLLMProvider's own constructor default ("low", the value a
real empirical benchmark validated - see backend/llm_client.py's own
docstring) is used as-is, since nothing in this codebase yet needs it to
vary per-deployment.
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, Mapping, Optional, Tuple

SOURCE_PATH = os.environ.get("SOURCE_PATH", "/scratch/contract.sol")
SKILL_SCRIPTS_DIR = os.environ.get("SKILL_SCRIPTS_DIR", "/app/.claude/skills/web3-auditor/scripts")
REPO_ROOT = os.environ.get("REPO_ROOT", "/app")


def _write_result(status: str, **fields: Any) -> None:
    """The ONE and ONLY stdout write this script ever makes - a single
    JSON line, always. See module docstring's boundary redesign: the host
    reads this via subprocess.Popen(stdout=PIPE).communicate(), parsing
    the last non-empty line (robust against any accidental stray output
    elsewhere, even though inspection confirms nothing else in this call
    chain ever writes to stdout)."""
    payload: Dict[str, Any] = {"status": status}
    payload.update(fields)
    sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def _select_provider(llm_client_module: Any, provider_name: str, api_key: str, model: str, sdk_max_retries: Optional[int] = None) -> Any:
    """Constructs the real LLMProvider named by provider_name - see module
    docstring's PROVIDER SELECTION section. A separate, directly-testable
    function (see tests/test_backend_worker_entrypoint.py) rather than
    inline in main(), so provider selection can be asserted on in
    isolation without needing to drive main()'s own stdin/stdout/sys.path
    setup. llm_client_module is passed in explicitly (never a module-level
    import here) because main() itself only imports backend.llm_client
    after inserting REPO_ROOT onto sys.path - see main()'s own comment.
    Raises llm_client_module.LLMError for an unrecognized name (fail
    closed, never a silent default) or whichever of that error the
    underlying provider's own constructor raises (missing package,
    missing credential).

    sdk_max_retries (see _step6_run_config()) is forwarded only when set,
    so a single-pass run constructs its provider exactly as before."""
    kwargs: Dict[str, Any] = {"api_key": api_key, "model": model}
    if sdk_max_retries is not None:
        kwargs["sdk_max_retries"] = sdk_max_retries
    if provider_name == "anthropic":
        return llm_client_module.AnthropicLLMProvider(**kwargs)
    if provider_name == "deepseek":
        return llm_client_module.DeepSeekLLMProvider(**kwargs)
    raise llm_client_module.LLMError(
        "unknown LLM_PROVIDER %r - must be 'anthropic' or 'deepseek'" % provider_name
    )


def _step6_run_config(environ: Mapping[str, str], llm_client_module: Any) -> Tuple[int, Optional[int], Optional[int]]:
    """(max_passes, deadline_seconds, sdk_max_retries) for this job - the
    one place the worker decides them (phase 15K-B, docs/decisiones.md
    D-097). Multi-pass is opt-in (LLM_MAX_PASSES, default 1 = the
    single-pass path, unchanged). With multi-pass, the Step 6 deadline
    from the supervisor (STEP6_DEADLINE_SECONDS: its wall clock minus its
    startup reserve) bounds every attempt, pass and the final pipeline;
    retrying is then the application's job alone (MAX_STEP6_ATTEMPTS per
    pass, each attempt sized by the deadline), so the provider's SDK must
    not retry internally - an SDK retry would run past the timeout the
    deadline granted - and sdk_max_retries is 0. Disabling SDK retries is
    not enough on its own: the SDK timeout applies to each network read,
    not to the whole call, so main() also wraps the real provider with
    llm_client.provider_for_step6() (a hard total deadline per call, in an
    isolated child process). The single-pass path gets no deadline,
    sdk_max_retries None and no wrapper: its historical per-attempt
    timeouts and the SDK's own default retries, all unchanged."""
    max_passes = int(environ.get("LLM_MAX_PASSES", "1"))
    deadline_env = environ.get("STEP6_DEADLINE_SECONDS")
    deadline_seconds = int(deadline_env) if (deadline_env and max_passes > 1) else None
    return max_passes, deadline_seconds, llm_client_module.sdk_max_retries_for(deadline_seconds)


class _EnvelopeError(Exception):
    """Malformed/incomplete stdin envelope - always a clean 'failed'
    result, never a traceback. Raised and caught entirely within main()
    before any real analysis work begins - see module docstring's "never
    start a partially prepared job" property."""


def _read_stdin_envelope() -> Dict[str, Any]:
    """Reads and validates the ONE JSON object the host writes to this
    process's stdin then closes (EOF) - see backend/worker_supervisor.py.
    Raises _EnvelopeError for anything malformed; never partially acts on
    an envelope it hasn't fully validated first."""
    raw = sys.stdin.buffer.read()
    try:
        envelope = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _EnvelopeError("stdin envelope is not valid UTF-8 JSON: %s" % type(exc).__name__) from exc
    if not isinstance(envelope, dict):
        raise _EnvelopeError("stdin envelope must be a JSON object")
    mode = envelope.get("mode")
    source = envelope.get("source")
    if not isinstance(mode, str) or not isinstance(source, str):
        raise _EnvelopeError("stdin envelope missing mode/source")
    mock_responses = envelope.get("mock_responses")
    llm_api_key = envelope.get("llm_api_key")
    if mock_responses is None and not llm_api_key:
        raise _EnvelopeError("stdin envelope must supply either llm_api_key or mock_responses")
    if mock_responses is not None and not isinstance(mock_responses, list):
        raise _EnvelopeError("mock_responses must be an array")
    return envelope


def main() -> int:
    if REPO_ROOT not in sys.path:
        sys.path.insert(0, REPO_ROOT)
    if SKILL_SCRIPTS_DIR not in sys.path:
        sys.path.insert(0, SKILL_SCRIPTS_DIR)

    import backend.llm_client as llm_client
    from analyze_pipeline import run_analyze_pipeline
    from preprocess import run as preprocess_run
    from score import score_report
    from validate_report import validate_report

    try:
        envelope = _read_stdin_envelope()
    except _EnvelopeError as exc:
        # Never started the job: no source written, no provider
        # constructed, no pipeline call made - see module docstring.
        _write_result("failed", error=str(exc))
        return 1

    mode = envelope["mode"]
    source = envelope["source"]
    mock_responses = envelope.get("mock_responses")
    max_passes, deadline_seconds, sdk_max_retries = _step6_run_config(os.environ, llm_client)

    if mock_responses is not None:
        # Test-only path - see backend/llm_client.MockLLMProvider's own
        # docstring. Lets a real Docker integration test exercise this
        # ENTIRE container lifecycle (create/start-attached/stdin-in/
        # stdout-out/rm, isolation flags, network) without any real LLM
        # credentials.
        provider = llm_client.MockLLMProvider([json.dumps(item) if isinstance(item, dict) else item for item in mock_responses])
    else:
        api_key = envelope.get("llm_api_key")
        model = os.environ.get("LLM_MODEL", "")
        provider_name = os.environ.get("LLM_PROVIDER", "anthropic")
        try:
            provider = _select_provider(llm_client, provider_name, api_key, model, sdk_max_retries=sdk_max_retries)
            # Under the Step 6 deadline every real call gets a hard total
            # deadline (see _step6_run_config()); single-pass: unchanged.
            provider = llm_client.provider_for_step6(provider, deadline_seconds)
        except llm_client.LLMError as exc:
            _write_result("failed", error=str(exc))
            return 1

    # Only now, with a fully validated envelope and a constructed
    # provider, does this script touch its own writable scratch mount or
    # begin real work - see module docstring.
    with open(SOURCE_PATH, "w", encoding="utf-8") as handle:
        handle.write(source)

    max_output_tokens = int(os.environ.get("LLM_MAX_OUTPUT_TOKENS", str(llm_client.DEFAULT_MAX_OUTPUT_TOKENS)))
    per_attempt_timeout = int(os.environ.get("LLM_PER_ATTEMPT_TIMEOUT_SECONDS", str(llm_client.DEFAULT_PER_ATTEMPT_TIMEOUT_SECONDS)))
    # max_passes/deadline_seconds come from _step6_run_config() above (the
    # provider was built with the matching sdk_max_retries). A pass draft
    # is validated with the same score + validate the pipeline applies;
    # that score is discarded - the report is scored once, on the merged
    # draft.

    def validate_pass_draft(draft):
        return validate_report(score_report(draft))

    try:
        result = llm_client.run_step6_with_retries(
            [SOURCE_PATH], mode, provider, run_analyze_pipeline,
            max_output_tokens=max_output_tokens, per_attempt_timeout_seconds=per_attempt_timeout,
            preprocess_run=preprocess_run, max_passes=max_passes, validate_pass_draft=validate_pass_draft,
            deadline_seconds=deadline_seconds,
        )
    except llm_client.Step6Failed as exc:
        _write_result("failed", error=str(exc))
        return 1
    except Exception as exc:  # never a raw traceback on stdout - see module docstring.
        _write_result("failed", error="unexpected worker error: %s" % type(exc).__name__)
        sys.stderr.write("worker_entrypoint: unexpected error: %s\n" % type(exc).__name__)
        return 1

    _write_result(
        "succeeded",
        rendered=result["rendered"],
        render_format=result["renderFormat"],
        risk_indicator=(result.get("scoredReport") or {}).get("riskIndicator"),
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        # Absolute last resort: still never leak a traceback, and still
        # print SOME result line so the supervisor's read never itself
        # fails with an empty-stdout error.
        try:
            _write_result("failed", error="worker entrypoint crashed before producing a result")
        except Exception:
            pass
        sys.stderr.write("worker_entrypoint: crashed\n")
        sys.exit(1)
