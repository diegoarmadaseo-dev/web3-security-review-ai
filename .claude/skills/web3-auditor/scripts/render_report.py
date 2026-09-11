#!/usr/bin/env python3
"""Deterministic Markdown/HTML rendering for a validated security review report.

Renders whatever is already in the report JSON - it never authors prose and
never calls a model. The mandatory disclaimer, the pre-fixed risk-indicator
sentences and every structural label are fixed English constants (see
docs/decisiones.md and the original brief, sections 6.2 and 14): only the
AI-authored narrative fields (finding descriptions, recommendations) carry
the user's language, because the analysis step already wrote them that way.

HTML output is self-contained (inline CSS only, no external requests) and
only available for modes where config/modes.json sets allowHtmlReport: true
(currently "pro"; rule R-06). Every value that originates from
analyzed, potentially adversarial source code (evidence, diffs, file paths,
descriptions) is HTML-escaped before being written out, so the report itself
never becomes an injection vector when opened in a browser.

Standard library only. No network access, no LLM calls. Python 3.8+.
"""
from __future__ import annotations

import argparse
import html
import os
import json
import sys
from typing import Any, Dict, List, Optional

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from preprocess import CATEGORIES, ModesConfigError, load_modes_config  # noqa: E402

EXIT_OK = 0
EXIT_FAILED = 1

RECOMMENDED_HTML_FILENAME = "security-review-report.html"

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]

MANDATORY_NOTICE_TITLE = "IMPORTANT SECURITY REVIEW NOTICE"
MANDATORY_NOTICE_LINES = [
    "This report is an automated, AI-assisted security review of the source code provided for analysis.",
    "",
    "It is NOT:",
    "",
    "* a formal security audit;",
    "* a certification;",
    "* a guarantee that the code is secure or free from vulnerabilities;",
    "* a guarantee that deployment is safe;",
    "* a penetration test;",
    "* a complete assessment of the protocol, infrastructure, deployed addresses, off-chain systems, economic model, governance, operational security, or third-party dependencies;",
    "* legal, financial, investment, or other professional advice.",
    "",
    "The analysis may produce false positives, false negatives, incomplete findings, incorrect recommendations, or miss vulnerabilities that are not observable from the supplied material.",
    "",
    "Security findings and risk indicators apply ONLY to the material and scope available during this review.",
    "",
    "The absence of a reported finding does NOT mean that no vulnerability exists.",
    "",
    "Any recommendation, patch, remediation suggestion, risk indicator, or risk band must be independently reviewed and validated before being relied upon for deployment, upgrades, migrations, custody, financial activity, or other security-critical decisions.",
    "",
    "The user remains responsible for validating the reviewed code, testing all changes, determining whether and when to deploy, and assessing the consequences of any action taken based on this report.",
    "",
    "No statement in this report creates a warranty, certification, guarantee, or professional audit engagement.",
    "",
    "Where applicable, rights or liabilities that cannot lawfully be excluded or limited remain unaffected.",
]

PATCH_DISCLAIMER = "Suggested remediation only. Review, compile, test and validate independently before use."
RISK_HEADING = "Automated Risk Indicator"
SCORE_UNAVAILABLE_FALLBACK = "Automated deterministic scoring was unavailable in this runtime."
NOT_DETECTED_NOTE = "No findings matching the configured detection criteria were identified within the analyzed scope."

COVERAGE_STATUS_LABEL = {
    "DETECTED": "Detected",
    "NOT_DETECTED": "Not detected",
    "NOT_ASSESSED": "Not assessed",
}


class ReportRenderError(Exception):
    """Raised for a usage-level problem: bad input, or html for a non-'pro' report."""


def _category_label(category: str) -> str:
    name = CATEGORIES.get(category)
    return "%s (%s)" % (category, name) if name else category


def _location_text(loc: Dict[str, Any]) -> str:
    parts = [str(loc.get("file", ""))]
    if loc.get("contract"):
        parts.append(str(loc["contract"]))
    if loc.get("function"):
        parts.append(str(loc["function"]))
    text = "#".join(parts)
    if loc.get("lineStart"):
        line_text = "line %s" % loc["lineStart"]
        if loc.get("lineEnd") and loc["lineEnd"] != loc["lineStart"]:
            line_text = "lines %s-%s" % (loc["lineStart"], loc["lineEnd"])
        text = "%s (%s)" % (text, line_text)
    return text


def _sorted_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    def key(finding: Dict[str, Any]):
        severity_index = SEVERITY_ORDER.index(finding.get("severity", "INFORMATIONAL"))
        return (severity_index, str(finding.get("category", "")), str(finding.get("id", "")))
    return sorted(findings, key=key)


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------

def _md_finding(finding: Dict[str, Any]) -> List[str]:
    lines: List[str] = []
    lines.append("### [%s] %s — %s" % (finding.get("severity"), _category_label(finding.get("category", "")), finding.get("id")))
    lines.append("")
    lines.append("- **Confidence:** %s" % finding.get("confidence"))
    lines.append("- **Status:** %s" % finding.get("status"))
    locations = finding.get("locations") or []
    if locations:
        lines.append("- **Location(s):** " + "; ".join(_location_text(loc) for loc in locations))
    lines.append("")
    lines.append(finding.get("description") or "")
    evidence = finding.get("evidence") or []
    if evidence:
        lines.append("")
        lines.append("**Evidence**")
        lines.append("")
        lines.append("```")
        lines.extend(evidence)
        lines.append("```")
    recommendation = finding.get("recommendation")
    if recommendation:
        lines.append("")
        lines.append("**Recommendation**")
        lines.append("")
        lines.append(recommendation)
    patch = finding.get("patch")
    if patch:
        lines.append("")
        lines.append("**Suggested patch**")
        lines.append("")
        lines.append("_%s_" % PATCH_DISCLAIMER)
        lines.append("")
        lines.append("```diff")
        lines.append(patch.get("diff", ""))
        lines.append("```")
    lines.append("")
    return lines


def render_markdown(report: Dict[str, Any]) -> str:
    lines: List[str] = []
    lines.append("# Automated AI-Assisted Smart Contract Security Review")
    lines.append("")
    lines.append("Mode: `%s` | Compiler: `%s` | Language of this report's prose: `%s`" % (
        report.get("mode"), report.get("compilerVersion"), report.get("language") or "en",
    ))
    lines.append("")
    lines.append("## %s" % MANDATORY_NOTICE_TITLE)
    lines.append("")
    lines.extend(MANDATORY_NOTICE_LINES)
    lines.append("")

    executive_summary = report.get("executiveSummary")
    if executive_summary:
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(executive_summary)
        lines.append("")

    scope = report.get("scope") or {}
    lines.append("## Scope")
    lines.append("")
    lines.append("- **Completeness:** `%s`" % scope.get("completeness"))
    for reason in scope.get("reasons") or []:
        lines.append("  - `%s`: %s" % (reason.get("code"), reason.get("detail")))
    lines.append("")

    lines.append("## %s" % RISK_HEADING)
    lines.append("")
    indicator = report.get("riskIndicator") or {}
    if indicator.get("scoreStatus") == "computed":
        lines.append("**Score: %s/100 — Band: %s** (%s)" % (indicator.get("score"), indicator.get("band"), indicator.get("scopeNote", "according to the analyzed scope")))
        lines.append("")
        lines.append(indicator.get("explanation", ""))
        if indicator.get("band") == "LOW" and indicator.get("lowBandNote"):
            lines.append("")
            lines.append(indicator["lowBandNote"])
    else:
        lines.append(indicator.get("message") or SCORE_UNAVAILABLE_FALLBACK)
    lines.append("")

    lines.append("## Category Coverage")
    lines.append("")
    lines.append("| Category | Status | Note |")
    lines.append("|---|---|---|")
    for entry in report.get("categoryCoverage") or []:
        status = entry.get("status")
        note = entry.get("note") or (NOT_DETECTED_NOTE if status == "NOT_DETECTED" else "")
        lines.append("| %s | %s | %s |" % (_category_label(entry.get("category", "")), COVERAGE_STATUS_LABEL.get(status, status), note))
    lines.append("")

    architecture_notes = report.get("architectureNotes") or []
    if architecture_notes:
        lines.append("## Architecture Notes")
        lines.append("")
        for note in architecture_notes:
            lines.append("### %s" % note.get("title", ""))
            lines.append("")
            lines.append(note.get("description", ""))
            lines.append("")

    findings = _sorted_findings(report.get("findings") or [])
    real_findings = [f for f in findings if f.get("status") != "informational"]
    info_findings = [f for f in findings if f.get("status") == "informational"]

    lines.append("## Findings")
    lines.append("")
    if not real_findings:
        lines.append(NOT_DETECTED_NOTE)
        lines.append("")
    for finding in real_findings:
        lines.extend(_md_finding(finding))

    gas_suggestions = report.get("gasSuggestions") or []
    if gas_suggestions:
        lines.append("## Gas Optimization Notes")
        lines.append("")
        for item in gas_suggestions:
            lines.append("- **%s** (%s impact) — %s — %s" % (
                item.get("technique"), item.get("impact"), _location_text(item.get("location", {})), item.get("explanation"),
            ))
        lines.append("")

    if info_findings:
        lines.append("## Informational Notices")
        lines.append("")
        for finding in info_findings:
            lines.extend(_md_finding(finding))

    lines.append("## Limitations")
    lines.append("")
    for item in report.get("limitations") or []:
        lines.append("- %s" % item)
    lines.append("")

    lines.append("## Report Metadata")
    lines.append("")
    for key in ("skillVersion", "analysisEngineVersion", "checklistVersion", "scoreVersion", "inputHash"):
        lines.append("- `%s`: `%s`" % (key, report.get(key)))
    lines.append("")

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# HTML rendering (self-contained, mode 'pro' only)
# ---------------------------------------------------------------------------

_HTML_STYLE = """
body { font-family: -apple-system, Segoe UI, Arial, sans-serif; line-height: 1.5; margin: 2rem auto; max-width: 860px; color: #1a1a1a; }
h1, h2, h3 { color: #111; }
.notice { border: 2px solid #b45309; background: #fffbeb; padding: 1rem 1.25rem; border-radius: 6px; }
.notice h2 { margin-top: 0; color: #92400e; }
table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
th, td { border: 1px solid #ccc; padding: 0.4rem 0.6rem; text-align: left; font-size: 0.95rem; }
th { background: #f3f4f6; }
pre { background: #f6f8fa; padding: 0.75rem; border-radius: 6px; overflow-x: auto; white-space: pre-wrap; word-break: break-word; }
.finding { border-left: 4px solid #9ca3af; padding-left: 1rem; margin: 1.5rem 0; }
.finding.CRITICAL { border-color: #b91c1c; }
.finding.HIGH { border-color: #c2410c; }
.finding.MEDIUM { border-color: #a16207; }
.finding.LOW { border-color: #4d7c0f; }
.finding.INFORMATIONAL { border-color: #6b7280; }
.patch-disclaimer { font-style: italic; color: #555; }
@media print { body { max-width: 100%; } }
""".strip()


def _esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def _html_finding(finding: Dict[str, Any]) -> str:
    parts: List[str] = []
    severity = _esc(finding.get("severity"))
    parts.append('<div class="finding %s">' % severity)
    parts.append("<h3>[%s] %s — %s</h3>" % (severity, _esc(_category_label(finding.get("category", ""))), _esc(finding.get("id"))))
    parts.append("<p><strong>Confidence:</strong> %s &nbsp; <strong>Status:</strong> %s</p>" % (_esc(finding.get("confidence")), _esc(finding.get("status"))))
    locations = finding.get("locations") or []
    if locations:
        parts.append("<p><strong>Location(s):</strong> %s</p>" % _esc("; ".join(_location_text(loc) for loc in locations)))
    parts.append("<p>%s</p>" % _esc(finding.get("description")))
    evidence = finding.get("evidence") or []
    if evidence:
        parts.append("<p><strong>Evidence</strong></p>")
        parts.append("<pre>%s</pre>" % _esc("\n".join(evidence)))
    recommendation = finding.get("recommendation")
    if recommendation:
        parts.append("<p><strong>Recommendation</strong></p><p>%s</p>" % _esc(recommendation))
    patch = finding.get("patch")
    if patch:
        parts.append("<p><strong>Suggested patch</strong></p>")
        parts.append('<p class="patch-disclaimer">%s</p>' % _esc(PATCH_DISCLAIMER))
        parts.append("<pre>%s</pre>" % _esc(patch.get("diff", "")))
    parts.append("</div>")
    return "\n".join(parts)


def render_html(report: Dict[str, Any]) -> str:
    # No silent fallback: a missing or malformed config/modes.json must stop
    # rendering rather than guess whether this mode may produce HTML.
    modes_config = load_modes_config()
    mode = report.get("mode")
    mode_rules = modes_config["modes"].get(mode)
    if mode_rules is None or not mode_rules["allowHtmlReport"]:
        raise ReportRenderError("HTML rendering is not enabled for mode %r (rule R-06; see config/modes.json)" % mode)

    parts: List[str] = []
    lang = _esc(report.get("language") or "en")
    parts.append("<!doctype html>")
    parts.append('<html lang="%s">' % lang)
    parts.append("<head>")
    parts.append('<meta charset="utf-8">')
    parts.append("<title>Automated AI-Assisted Smart Contract Security Review</title>")
    parts.append("<style>%s</style>" % _HTML_STYLE)
    parts.append("</head>")
    parts.append("<body>")
    parts.append("<h1>Automated AI-Assisted Smart Contract Security Review</h1>")
    parts.append("<p>Mode: <code>%s</code> | Compiler: <code>%s</code></p>" % (_esc(report.get("mode")), _esc(report.get("compilerVersion"))))

    parts.append('<div class="notice">')
    parts.append("<h2>%s</h2>" % _esc(MANDATORY_NOTICE_TITLE))
    for line in MANDATORY_NOTICE_LINES:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("* "):
            parts.append("<p>&bull; %s</p>" % _esc(stripped[2:]))
        else:
            parts.append("<p>%s</p>" % _esc(stripped))
    parts.append("</div>")

    executive_summary = report.get("executiveSummary")
    if executive_summary:
        parts.append("<h2>Executive Summary</h2>")
        parts.append("<p>%s</p>" % _esc(executive_summary))

    scope = report.get("scope") or {}
    parts.append("<h2>Scope</h2>")
    parts.append("<p><strong>Completeness:</strong> <code>%s</code></p>" % _esc(scope.get("completeness")))
    reasons = scope.get("reasons") or []
    if reasons:
        parts.append("<ul>")
        for reason in reasons:
            parts.append("<li><code>%s</code>: %s</li>" % (_esc(reason.get("code")), _esc(reason.get("detail"))))
        parts.append("</ul>")

    parts.append("<h2>%s</h2>" % _esc(RISK_HEADING))
    indicator = report.get("riskIndicator") or {}
    if indicator.get("scoreStatus") == "computed":
        parts.append("<p><strong>Score: %s/100 — Band: %s</strong> (%s)</p>" % (
            _esc(indicator.get("score")), _esc(indicator.get("band")), _esc(indicator.get("scopeNote", "according to the analyzed scope")),
        ))
        parts.append("<p>%s</p>" % _esc(indicator.get("explanation", "")))
        if indicator.get("band") == "LOW" and indicator.get("lowBandNote"):
            parts.append("<p>%s</p>" % _esc(indicator["lowBandNote"]))
    else:
        parts.append("<p>%s</p>" % _esc(indicator.get("message") or SCORE_UNAVAILABLE_FALLBACK))

    parts.append("<h2>Category Coverage</h2>")
    parts.append("<table><tr><th>Category</th><th>Status</th><th>Note</th></tr>")
    for entry in report.get("categoryCoverage") or []:
        status = entry.get("status")
        note = entry.get("note") or (NOT_DETECTED_NOTE if status == "NOT_DETECTED" else "")
        parts.append("<tr><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            _esc(_category_label(entry.get("category", ""))), _esc(COVERAGE_STATUS_LABEL.get(status, status)), _esc(note),
        ))
    parts.append("</table>")

    architecture_notes = report.get("architectureNotes") or []
    if architecture_notes:
        parts.append("<h2>Architecture Notes</h2>")
        for note in architecture_notes:
            parts.append("<h3>%s</h3>" % _esc(note.get("title", "")))
            parts.append("<p>%s</p>" % _esc(note.get("description", "")))

    findings = _sorted_findings(report.get("findings") or [])
    real_findings = [f for f in findings if f.get("status") != "informational"]
    info_findings = [f for f in findings if f.get("status") == "informational"]

    parts.append("<h2>Findings</h2>")
    if not real_findings:
        parts.append("<p>%s</p>" % _esc(NOT_DETECTED_NOTE))
    for finding in real_findings:
        parts.append(_html_finding(finding))

    gas_suggestions = report.get("gasSuggestions") or []
    if gas_suggestions:
        parts.append("<h2>Gas Optimization Notes</h2><ul>")
        for item in gas_suggestions:
            parts.append("<li><strong>%s</strong> (%s impact) — %s — %s</li>" % (
                _esc(item.get("technique")), _esc(item.get("impact")), _esc(_location_text(item.get("location", {}))), _esc(item.get("explanation")),
            ))
        parts.append("</ul>")

    if info_findings:
        parts.append("<h2>Informational Notices</h2>")
        for finding in info_findings:
            parts.append(_html_finding(finding))

    parts.append("<h2>Limitations</h2><ul>")
    for item in report.get("limitations") or []:
        parts.append("<li>%s</li>" % _esc(item))
    parts.append("</ul>")

    parts.append("<h2>Report Metadata</h2><ul>")
    for key in ("skillVersion", "analysisEngineVersion", "checklistVersion", "scoreVersion", "inputHash"):
        parts.append("<li><code>%s</code>: <code>%s</code></li>" % (_esc(key), _esc(report.get(key))))
    parts.append("</ul>")

    parts.append("</body></html>")
    return "\n".join(parts) + "\n"


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


def _read_input(path: Optional[str]) -> Dict[str, Any]:
    if path:
        with open(path, "r", encoding="utf-8") as handle:
            raw = handle.read()
    else:
        raw = sys.stdin.read()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ReportRenderError("input is not valid JSON: %s" % exc) from exc
    if not isinstance(data, dict):
        raise ReportRenderError("report must be a JSON object")
    return data


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="render_report.py",
        description="Render a validated security review report as Markdown or (mode 'pro' only) self-contained HTML.",
    )
    parser.add_argument("path", nargs="?", default=None, help="Validated report JSON file. Reads stdin if omitted.")
    parser.add_argument("--format", choices=["markdown", "html"], default="markdown")
    parser.add_argument("--out", default=None, help="Write rendered output to this file instead of stdout.")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    _force_utf8_stdio()
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        report = _read_input(args.path)
        rendered = render_html(report) if args.format == "html" else render_markdown(report)
    except (ReportRenderError, ModesConfigError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stdout)
        return EXIT_FAILED
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(rendered)
    else:
        sys.stdout.write(rendered)
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
