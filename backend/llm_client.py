#!/usr/bin/env python3
"""LLM provider abstraction and Step-6 orchestration (Phase 4 execution
infrastructure, docs/decisiones.md D-077 follow-up).

WHY THIS MODULE EXISTS: .claude/skills/web3-auditor/scripts/
analyze_pipeline.py explicitly, deliberately never performs Step 6 (the
AI's own analysis/judgment) - it takes an ALREADY-authored draft_report
as input and only mechanizes the deterministic steps around it (preprocess/
score/validate/render), matching SKILL.md's own step numbering. Today
Step 6 is performed by a human-directed interactive Claude Code session.
An unattended worker (Phase 4) has no human in the loop, so something has
to call an LLM provider programmatically and hand analyze_pipeline.py a
draft_report - this module is that something, and nothing else in this
codebase does it (confirmed by a repo-wide search for any existing
Anthropic/LLM client code before writing this - there was none).

PROVIDER ABSTRACTION: LLMProvider is a plain Protocol (one method,
complete()) so the worker never depends on a specific SDK. Two
implementations:
  * MockLLMProvider - deterministic, test-only, returns a caller-supplied
    canned response (or raises a caller-supplied error) - the ONLY
    provider this phase's tests ever use (see module docstring's "Do NOT
    invent a production provider if none is configured").
  * AnthropicLLMProvider - real, lazy-imports the `anthropic` package
    (same optional-dependency pattern as backend/db.py's psycopg and
    backend/billing.py's stripe) and is never constructed by anything in
    this codebase unless a caller explicitly supplies real credentials -
    there is no default/fallback path that silently uses it.

CREDENTIAL BOUNDARY: the API key is a constructor argument only (same
explicit-config discipline as billing.StripeBilling) - this module never
reads os.environ itself, and the key is held only in this worker
PROCESS's memory: it never becomes a queue column, a DB column, or a log
line (see backend/worker_entrypoint.py, which is the only thing that
constructs a real provider, and only inside the isolated container - the
host-side supervisor never sees the key).

PROMPT CONTRACT - HONEST DISCLOSURE: _build_step6_prompt() below is a
first-cut, generic prompt asking for a JSON report; it is NOT a fully
schema-validated, prompt-engineered mapping against report-schema.json's
complete field set (that would be its own substantial, iterative task
against real model outputs, out of this phase's scope). What IS load-
bearing and fully tested here is the STRUCTURE around it - the retry-on-
validation-error loop, the 3-attempt cap matching analyze_pipeline.py's
own SKILL.md-documented limit, timeout/output-size bounds, and the
failure/budget behavior - never the prompt's own wording.

Standard library only for the orchestration logic. No network access
except through whichever LLMProvider is injected.
"""
from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional, Protocol

try:
    import anthropic
except ImportError:  # optional - see module docstring.
    anthropic = None


class LLMError(Exception):
    """Raised for provider misuse (bad config, missing SDK) - never for
    a normal provider failure/timeout, which LLMProvider.complete()
    implementations raise as ProviderError instead (see below)."""


class ProviderError(Exception):
    """A real, expected-to-happen provider failure (timeout, rate limit,
    API error, malformed response) - the caller (run_step6_with_retries)
    treats this as a job failure after retries are exhausted, never
    retries silently forever."""


class LLMProvider(Protocol):
    def complete(self, prompt: str, max_output_tokens: int, timeout_seconds: int) -> str: ...


class MockLLMProvider:
    """Deterministic, test-only - see module docstring. responses is a
    list consumed in order (one per call, across retries too) so a test
    can script "first attempt returns an invalid report, second attempt
    returns a valid one" precisely. A ProviderError instance in the list
    is raised instead of returned, for testing provider-failure paths."""

    def __init__(self, responses: List[Any]):
        self._responses = list(responses)
        self.calls: List[Dict[str, Any]] = []

    def complete(self, prompt: str, max_output_tokens: int, timeout_seconds: int) -> str:
        self.calls.append({"prompt": prompt, "max_output_tokens": max_output_tokens, "timeout_seconds": timeout_seconds})
        if not self._responses:
            raise ProviderError("MockLLMProvider has no more scripted responses")
        next_response = self._responses.pop(0)
        if isinstance(next_response, Exception):
            raise next_response
        return next_response


class AnthropicLLMProvider:
    """Real provider. Never constructed unless a caller has an actual
    API key - see module docstring on credential boundary."""

    def __init__(self, api_key: str, model: str):
        if anthropic is None:
            raise LLMError('the "anthropic" package is not installed - only needed for a real, live provider; tests use MockLLMProvider.')
        if not api_key:
            raise LLMError("api_key is required")
        if not model:
            raise LLMError("model is required")
        self._client = anthropic.Anthropic(api_key=api_key)
        self._model = model

    def complete(self, prompt: str, max_output_tokens: int, timeout_seconds: int) -> str:
        try:
            response = self._client.messages.create(
                model=self._model,
                max_tokens=max_output_tokens,
                timeout=timeout_seconds,
                messages=[{"role": "user", "content": prompt}],
            )
        except Exception as exc:  # the real SDK's own exception hierarchy - never inspected for message content that could echo the prompt/key.
            raise ProviderError("provider call failed: %s" % type(exc).__name__) from exc
        text_blocks = [block.text for block in response.content if getattr(block, "type", None) == "text"]
        return "".join(text_blocks)


MAX_STEP6_ATTEMPTS = 3  # matches analyze_pipeline.py's own SKILL.md-documented "3 attempts total" cap - never independently configurable, so the two can never drift apart.
DEFAULT_MAX_OUTPUT_TOKENS = 8000
DEFAULT_PER_ATTEMPT_TIMEOUT_SECONDS = 120


class Step6Failed(Exception):
    """Raised when every attempt is exhausted (provider failures and/or
    validation failures, in any combination) without producing a
    rendered report - the worker entrypoint catches this and marks the
    job failed with this exception's own message as last_error, never a
    raw traceback."""


def _build_step6_prompt(preprocess_artifact: Dict[str, Any], previous_errors: Optional[List[str]]) -> str:
    """First-cut prompt - see module docstring's honest disclosure on
    why this is not a fully schema-validated prompt-engineering pass."""
    base = (
        "You are performing a smart contract security analysis (SKILL.md Step 6). "
        "Given the preprocessed artifact below (already secret-redacted, deterministic "
        "structural signals only), produce a JSON object matching this Skill's report "
        "schema: an object with at least riskIndicator (score 0-100, band one of "
        "LOW/MODERATE/HIGH/CRITICAL) and a findings array. Respond with ONLY the JSON "
        "object, no surrounding prose.\n\nPreprocessed artifact:\n%s"
        % json.dumps(preprocess_artifact, ensure_ascii=False)
    )
    if previous_errors:
        base += (
            "\n\nYour previous draft was INVALID for these reasons - fix them and "
            "return a corrected JSON object, still ONLY the JSON:\n%s" % json.dumps(previous_errors, ensure_ascii=False)
        )
    return base


def _parse_draft_report(raw_text: str) -> Dict[str, Any]:
    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise ProviderError("provider response was not valid JSON: %s" % exc) from exc
    if not isinstance(parsed, dict):
        raise ProviderError("provider response was valid JSON but not a JSON object")
    return parsed


def run_step6_with_retries(
    source_paths: List[str],
    mode: str,
    provider: LLMProvider,
    run_analyze_pipeline: Callable[..., Dict[str, Any]],
    max_output_tokens: int = DEFAULT_MAX_OUTPUT_TOKENS,
    per_attempt_timeout_seconds: int = DEFAULT_PER_ATTEMPT_TIMEOUT_SECONDS,
    modes_config: Optional[Dict[str, Any]] = None,
    render_format: str = "markdown",
    preprocess_run: Optional[Callable[..., Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Orchestrates Step 6 (this module) around the existing mechanized
    Steps 3/7/8/9 (analyze_pipeline.run_analyze_pipeline, injected by the
    caller so this module never hard-imports a path into the Skill's own
    scripts/ directory - see backend/worker_entrypoint.py, which does
    that path setup once and passes the function in).

    Up to MAX_STEP6_ATTEMPTS total: each attempt asks the provider for a
    draft_report (the first attempt's prompt has no prior errors; a
    retry's prompt includes the previous attempt's validation errors, so
    the model has a real chance of fixing them - never a blind repeat),
    then calls run_analyze_pipeline(). A "rendered" result returns
    immediately. A "needs_revision" result becomes the next attempt's
    error context. Any ProviderError (timeout, malformed JSON, rate
    limit) is treated as an ATTEMPT-CONSUMED failure, same as an invalid
    report - a flaky provider is not exempt from the same total-attempts
    cap a stubborn validation error is. Raises Step6Failed if every
    attempt is exhausted."""
    preprocess_run = preprocess_run or (lambda **kwargs: None)
    preprocess_artifact = preprocess_run(source_paths, mode=mode, max_loc=None, use_stdin=False, include_timestamp=False, modes_config=modes_config)

    previous_errors: Optional[List[str]] = None
    last_failure = "unknown failure"
    for attempt in range(1, MAX_STEP6_ATTEMPTS + 1):
        prompt = _build_step6_prompt(preprocess_artifact, previous_errors)
        try:
            raw_text = provider.complete(prompt, max_output_tokens=max_output_tokens, timeout_seconds=per_attempt_timeout_seconds)
            draft_report = _parse_draft_report(raw_text)
        except ProviderError as exc:
            last_failure = str(exc)
            previous_errors = [last_failure]
            continue
        try:
            result = run_analyze_pipeline(
                source_paths, mode=mode, draft_report=draft_report, attempt=attempt,
                use_stdin=False, render_format=render_format, modes_config=modes_config,
            )
        except Exception as exc:
            # Covers analyze_pipeline.AnalyzePipelineError's own raise
            # when its cap is reached on the last attempt (this module
            # never hard-imports that class - see run_analyze_pipeline's
            # own docstring - so a broad catch is the only option here),
            # and any other unexpected pipeline failure. Never crashes
            # the worker; always counted as this attempt's outcome, same
            # as a ProviderError.
            last_failure = str(exc)
            previous_errors = [last_failure]
            continue
        if result["status"] == "rendered":
            return result
        # status == "needs_revision" - give the next attempt the real errors to fix.
        previous_errors = result.get("errors") or ["report failed validation"]
        last_failure = "report invalid after attempt %d: %s" % (attempt, previous_errors)

    raise Step6Failed("Step 6 failed after %d attempt(s): %s" % (MAX_STEP6_ATTEMPTS, last_failure))
