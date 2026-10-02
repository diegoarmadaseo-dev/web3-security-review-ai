#!/usr/bin/env python3
"""Mechanized deterministic pipeline: SKILL.md Steps 3 (preprocess) -> 7
(score) -> 8 (validate, retry cap enforced) -> 9 (render) (V2.11, docs/
decisiones.md D-066, capability A-03).

THIS MODULE NEVER PERFORMS STEP 6 (Analysis - the only step with judgment).
It takes an ALREADY AI-authored draft_report (produced by whoever is calling
this, using the Step 3 preprocess artifact as data, exactly as SKILL.md Step
6 already requires) and mechanizes only the deterministic steps around it:
scoring, validating, enforcing SKILL.md's own "at most 2 retry attempts in
total" cap, and rendering once the report is valid. Deciding WHAT belongs in
draft_report, and HOW to fix a field SKILL.md Step 8 flags as invalid between
retries, remains entirely the caller's (AI's) job - this module has no code
path that inspects a finding's substance or edits draft_report's content.

Reuses preprocess.run() / score.score_report() / validate_report.
validate_report() / render_report.render_markdown()/render_html() UNCHANGED
- this module contains no new preprocessing, scoring, validation, or
rendering logic, only the sequencing and retry-cap bookkeeping SKILL.md
Step 8 already specifies in prose.

attempt is a caller-declared, never-inferred integer (same convention as
monitor_diff.py's snapshotTimestamp and pr_gate.py's refLabel): this module
holds no state and does not count attempts itself across calls.

Standard library only. No network access, no LLM calls. Python 3.8+.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from preprocess import run as preprocess_run, PreprocessError, ModesConfigError, load_modes_config  # noqa: E402
from score import score_report, ScoreError  # noqa: E402
from validate_report import validate_report, ReportValidationError  # noqa: E402
from render_report import render_markdown, render_html, ReportRenderError  # noqa: E402

PIPELINE_VERSION = "2026.1"

EXIT_OK = 0
EXIT_FAILED = 1

_MAX_ATTEMPTS = 3  # SKILL.md Step 8: "at most 2 retry attempts in total" => 3 attempts total.

PIPELINE_NEVER_STEP6_NOTE = (
    "This pipeline mechanizes SKILL.md Steps 3 (preprocess), 7 (score), 8 "
    "(validate, retry cap enforced) and 9 (render) ONLY - it NEVER performs "
    "Step 6 (Analysis). draft_report must already be the AI-authored draft "
    "for the SAME source this call preprocesses; deciding which findings "
    "belong in that draft, and how to fix a field flagged as invalid "
    "between retries, remains entirely the caller's (AI's) job."
)


class AnalyzePipelineError(Exception):
    """Raised for a malformed call (bad attempt count, bad render_format) or
    when SKILL.md's own retry cap (at most 2 retries, 3 attempts total) is
    reached while the report is still invalid - "never present an
    unvalidated report as if it were normal." A per-attempt validation
    failure BEFORE the cap is never raised here - it comes back as a
    status="needs_revision" result instead, since the caller may still
    retry with a fixed draft."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AnalyzePipelineError(message)


def run_analyze_pipeline(
    paths: List[str],
    *,
    mode: str,
    draft_report: Dict[str, Any],
    attempt: int = 1,
    max_loc: Optional[int] = None,
    use_stdin: bool = False,
    render_format: str = "markdown",
    modes_config: Optional[Dict[str, Any]] = None,
    allow_forced_detected_partial: bool = False,
) -> Dict[str, Any]:
    """Runs Step 3 (preprocess) once, then Step 7 (score) + Step 8
    (validate) on draft_report; if valid, runs Step 9 (render) and returns a
    status="rendered" result. If invalid and attempt < 3, returns a
    status="needs_revision" result carrying validate_report()'s own error
    list (no render). If invalid and attempt == 3 (the last allowed
    attempt), raises AnalyzePipelineError - matching SKILL.md's "say so
    plainly... never present an unvalidated report as if it were normal."

    attempt must be 1, 2, or 3; any other value raises immediately, before
    Step 3 even runs - SKILL.md's cap is never silently exceeded.

    allow_forced_detected_partial (default False) is internal and only
    forwarded to validate_report(); only the merged multi-pass report sets
    it (docs/decisiones.md D-101). The CLI never exposes it."""
    _require(isinstance(attempt, int) and not isinstance(attempt, bool), "attempt must be an integer, not %r" % (attempt,))
    _require(1 <= attempt <= _MAX_ATTEMPTS, "attempt must be between 1 and %d (SKILL.md Step 8: at most 2 retries) - got %r" % (_MAX_ATTEMPTS, attempt))
    _require(render_format in ("markdown", "html"), "render_format must be 'markdown' or 'html', not %r" % (render_format,))

    preprocess_artifact = preprocess_run(
        paths,
        mode=mode,
        max_loc=max_loc,
        use_stdin=use_stdin,
        include_timestamp=False,
        modes_config=modes_config,
    )

    scored = score_report(draft_report)
    errors = validate_report(scored, allow_forced_detected_partial=allow_forced_detected_partial)

    if errors:
        if attempt >= _MAX_ATTEMPTS:
            raise AnalyzePipelineError(
                "report still invalid after %d attempt(s) (SKILL.md Step 8 cap reached): %s" % (attempt, errors)
            )
        return {
            "pipelineVersion": PIPELINE_VERSION,
            "status": "needs_revision",
            "attempt": attempt,
            "attemptsRemaining": _MAX_ATTEMPTS - attempt,
            "errors": errors,
            "preprocessArtifact": preprocess_artifact,
            "note": PIPELINE_NEVER_STEP6_NOTE,
        }

    rendered = render_html(scored) if render_format == "html" else render_markdown(scored)
    return {
        "pipelineVersion": PIPELINE_VERSION,
        "status": "rendered",
        "attempt": attempt,
        "scoredReport": scored,
        "preprocessArtifact": preprocess_artifact,
        "renderFormat": render_format,
        "rendered": rendered,
        "note": PIPELINE_NEVER_STEP6_NOTE,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _force_utf8_stdio() -> None:
    for stream_name in ("stdin", "stdout"):
        stream = getattr(sys, stream_name, None)
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8")
            except (ValueError, OSError):
                pass


def _read_json_file(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as handle:
        raw = handle.read()
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AnalyzePipelineError("%s is not valid JSON: %s" % (path, exc)) from exc


def build_arg_parser(modes_config: Dict[str, Any]) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="analyze_pipeline.py",
        description=(
            "Mechanizes SKILL.md Steps 3->7->8(retry<=2)->9 around an already "
            "AI-authored draft report. NEVER performs Step 6 (Analysis)."
        ),
    )
    parser.add_argument("paths", nargs="*", help="Source files or directories to preprocess (Step 3). Reads a bundle from stdin if omitted.")
    parser.add_argument("--draft-report", required=True, help="Path to the AI-authored draft report JSON (Step 6 output, produced OUTSIDE this pipeline).")
    parser.add_argument(
        "--mode",
        choices=sorted(modes_config["modes"].keys()),
        default=modes_config["defaultMode"],
        help="Review mode; limits and feature-gating come from config/modes.json.",
    )
    parser.add_argument("--attempt", type=int, default=1, help="Caller-declared attempt number for this draft (1-3; SKILL.md: at most 2 retries).")
    parser.add_argument("--max-loc", type=int, default=None, help="Override the mode's maxEffectiveLoc limit.")
    parser.add_argument("--format", choices=["markdown", "html"], default="markdown", help="Render format for a valid report (Step 9).")
    parser.add_argument("--out", default=None, help="Write the JSON result to this file instead of stdout.")
    parser.add_argument("--indent", type=int, default=2, help="JSON indentation (0 for compact output).")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    _force_utf8_stdio()
    try:
        modes_config = load_modes_config()
    except ModesConfigError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stdout)
        return EXIT_FAILED
    parser = build_arg_parser(modes_config)
    args = parser.parse_args(argv)
    use_stdin = not args.paths and not sys.stdin.isatty()
    try:
        draft_report = _read_json_file(args.draft_report)
        result = run_analyze_pipeline(
            args.paths,
            mode=args.mode,
            draft_report=draft_report,
            attempt=args.attempt,
            max_loc=args.max_loc,
            use_stdin=use_stdin,
            render_format=args.format,
            modes_config=modes_config,
        )
    except (AnalyzePipelineError, PreprocessError, ScoreError, ReportValidationError, ReportRenderError, ModesConfigError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stdout)
        return EXIT_FAILED
    indent = args.indent if args.indent > 0 else None
    text = json.dumps(result, ensure_ascii=False, indent=indent, sort_keys=True)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")
    else:
        print(text)
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
