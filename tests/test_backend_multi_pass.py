"""Tests for phase 15K-B deterministic multi-pass Step 6 (docs/decisiones.md
D-097): backend/multi_pass.py (plan, per-pass artifact/note/scope, merge,
global scope) and its execution in backend/llm_client.py
(run_step6_with_retries(max_passes=...), per-pass attempts, time budget),
plus the worker/supervisor/main plumbing.

Synthetic artifacts (tests/test_backend_context_selection._artifact) with a
patched application budget give exact, reproducible pass counts; the real
score_report / validate_report / render_markdown judge every draft.

Run: python -m unittest tests.test_backend_multi_pass
"""
from __future__ import annotations

import copy
import json
import re
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
SKILL_SCRIPTS_DIR = REPO_ROOT / ".claude" / "skills" / "web3-auditor" / "scripts"
for p in (str(REPO_ROOT), str(SKILL_SCRIPTS_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

import backend.context_encoding as ce  # noqa: E402
import backend.context_selection as cs  # noqa: E402
import backend.llm_client as llm_client  # noqa: E402
import backend.multi_pass as mp  # noqa: E402
from render_report import render_markdown  # noqa: E402
from score import compute_id, compute_stable_key, score_report  # noqa: E402
from validate_report import validate_report  # noqa: E402
from tests.test_backend_context_selection import _artifact  # noqa: E402
from tests.test_backend_llm_client import FAKE_ARTIFACT, _extract_example  # noqa: E402

V1 = ce.CONTEXT_FORMAT_V1
V2 = ce.CONTEXT_FORMAT_V2
RESERVE = llm_client.STEP6_PROMPT_RESERVE_BYTES
FILES = ["src/F%02d.sol" % i for i in range(9)]


def _art(n_files=6, pad=3000, imports=None, extra_reasons=()):
    art = _artifact([(FILES[i], 9 - i, pad) for i in range(n_files)], imports=imports)
    art["completeness"]["reasons"] = art["completeness"]["reasons"] + [dict(r) for r in extra_reasons]
    return art


def _plan(art, fmt, prompt_budget, max_passes=8):
    return mp.plan_passes(art, fmt, max_passes, prompt_budget - RESERVE, prompt_budget)


def _budget_for(art, fmt, passes):
    """Smallest prompt budget whose plan has exactly `passes` passes and
    assigns every file (plans need fewer passes as the budget grows)."""
    lo, hi = RESERVE + 1000, RESERVE + 2_000_000
    while lo < hi:
        mid = (lo + hi) // 2
        plan = _plan(art, fmt, mid)
        if plan.pass_count and plan.pass_count <= passes and not plan.unassigned:
            hi = mid
        else:
            lo = mid + 1
    assert _plan(art, fmt, lo).pass_count == passes, "no budget gives exactly %d passes" % passes
    return lo


def _imports(pairs):
    return [{"file": a, "line": 1, "shape": "relative", "path": "./x.sol", "resolved": True, "resolvedTo": b, "symbols": [], "alias": None} for a, b in pairs]


def _primary_files(prompt):
    match = re.search(r'"primaryFiles": ?(\[[^\]]*\])', prompt)
    return json.loads(match.group(1)) if match else []


def _pass_index(prompt):
    match = re.search(r"this prompt is pass (\d+) of (\d+)", prompt)
    return int(match.group(1)) if match else 0


class ScriptedProvider:
    """Answers per pass (read from the prompt's own pass note) from a script
    {pass_index: [response, ...]}; a response is a draft dict, a raw string
    or a ProviderError to raise. Unscripted passes get a valid draft with
    one finding in the pass's first primary file."""

    def __init__(self, script=None, finding=True):
        self.script = {k: list(v) for k, v in (script or {}).items()}
        self.finding = finding
        self.calls = []

    def complete(self, prompt, max_output_tokens, timeout_seconds):
        index = _pass_index(prompt)
        self.calls.append({"pass": index, "prompt": prompt, "timeout_seconds": timeout_seconds})
        queue = self.script.get(index)
        response = queue.pop(0) if queue else _valid_draft(_primary_files(prompt)[:1] if self.finding else [])
        if isinstance(response, Exception):
            raise response
        return response if isinstance(response, str) else json.dumps(response)


def _valid_draft(finding_files=(), mode="pro"):
    example = _extract_example(llm_client._build_step6_prompt(FAKE_ARTIFACT, None, mode))
    example["mode"] = mode
    example["scope"] = {"completeness": "partial", "reasons": [{"code": "LOC_LIMIT_EXCEEDED", "detail": "carried over"}]}
    example["categoryCoverage"][0]["status"] = "NOT_ASSESSED"
    example["findings"] = [_finding(f) for f in finding_files]
    if example["findings"]:
        example["categoryCoverage"][7]["status"] = "DETECTED"
    return example


def _finding(path, category="SC08", severity="LOW", function="f"):
    return {"category": category, "severity": severity, "confidence": "low", "status": "suspected",
            "locations": [{"file": path, "contract": "C", "function": function}], "evidence": ["e"],
            "description": "d", "recommendation": "r", "patch": None}


class _Counters:
    def __init__(self):
        self.pipeline = 0
        self.render = 0
        self.validate_pass = 0
        self.pipeline_drafts = []
        self.pipeline_forced_flags = []

    def validator(self, draft):
        self.validate_pass += 1
        return validate_report(score_report(draft))

    def pipeline_fn(self, paths, *, mode, draft_report, attempt, use_stdin, render_format, modes_config, allow_forced_detected_partial=False):
        self.pipeline += 1
        self.pipeline_drafts.append(copy.deepcopy(draft_report))
        self.pipeline_forced_flags.append(allow_forced_detected_partial)
        scored = score_report(draft_report)
        errors = validate_report(scored, allow_forced_detected_partial=allow_forced_detected_partial)
        if errors:
            return {"status": "needs_revision", "errors": errors}
        self.render += 1
        return {"status": "rendered", "scoredReport": scored, "renderFormat": render_format, "rendered": render_markdown(scored)}


def _run(art, prompt_budget, provider, counters=None, fmt=V1, max_passes=8, **kwargs):
    counters = counters or _Counters()
    extra = {} if fmt == V1 else {"context_format": fmt}
    with mock.patch.object(cs, "APPLICATION_CONTEXT_BUDGET_BYTES", prompt_budget):
        result = llm_client.run_step6_with_retries(
            ["/x.sol"], "pro", provider, counters.pipeline_fn, preprocess_run=lambda paths, **kw: art,
            max_passes=max_passes, validate_pass_draft=counters.validator, **extra, **kwargs,
        )
    return result, counters


class PlanTests(unittest.TestCase):
    def test_exactly_two_and_three_passes(self):  # 1, 2
        art = _art()
        for fmt in (V1, V2):
            for passes in (2, 3):
                plan = _plan(art, fmt, _budget_for(art, fmt, passes))
                self.assertEqual(plan.pass_count, passes, fmt)
                self.assertEqual(plan.unassigned, [])

    def test_same_input_same_partition(self):  # 3
        art = _art(imports=_imports([(FILES[0], FILES[5]), (FILES[3], FILES[1])]))
        for fmt in (V1, V2):
            budget = _budget_for(art, fmt, 3)
            first = _plan(art, fmt, budget)
            again = _plan(copy.deepcopy(art), fmt, budget)
            self.assertEqual(first.passes, again.passes)
            self.assertEqual(mp.plan_summary(first), mp.plan_summary(again))

    def test_every_file_primary_exactly_once_full_coverage(self):  # 6
        art = _art(9)
        plan = _plan(art, V1, _budget_for(art, V1, 3))
        primaries = [f for p in plan.passes for f in p["primaryFiles"]]
        self.assertEqual(sorted(primaries), sorted(FILES[:9]))
        self.assertEqual(len(primaries), len(set(primaries)))
        for p in plan.passes:
            self.assertEqual(p["primaryFiles"], sorted(p["primaryFiles"]))
            self.assertFalse(set(p["primaryFiles"]) & set(p["contextFiles"]))

    def test_shared_dependency_is_primary_once_and_context_elsewhere(self):  # 4, 5
        # F00 and F01 (highest priority) both import F05; three files per pass.
        art = _art(imports=_imports([(FILES[0], FILES[5]), (FILES[1], FILES[5]), (FILES[2], FILES[5])]))
        plan = _plan(art, V1, _budget_for(art, V1, 3))
        owners = [p["passIndex"] for p in plan.passes if FILES[5] in p["primaryFiles"]]
        self.assertEqual(len(owners), 1)
        context_in = [p["passIndex"] for p in plan.passes if FILES[5] in p["contextFiles"]]
        self.assertTrue(context_in, "the shared dependency must be repeated as context")
        for p in plan.passes:
            for importer in (FILES[0], FILES[1], FILES[2]):
                if importer in p["primaryFiles"]:
                    self.assertIn(FILES[5], p["primaryFiles"] + p["contextFiles"])  # closure always present

    def test_file_too_large_for_any_pass_is_unassigned_with_reason(self):  # 7
        art = _art()
        budget = _budget_for(art, V1, 2)
        art["comments"][1]["text"] = "x" * (budget * 2)
        plan = _plan(art, V1, budget)
        self.assertEqual(plan.unassigned, [{"file": FILES[1], "reason": "file_exceeds_budget_alone"}])
        self.assertNotIn(FILES[1], [f for p in plan.passes for f in p["primaryFiles"] + p["contextFiles"]])

    def test_max_passes_leaves_the_rest_unassigned(self):  # 8
        art = _art()
        plan = _plan(art, V1, _budget_for(art, V1, 3), max_passes=2)
        self.assertEqual(plan.pass_count, 2)
        self.assertEqual(len(plan.unassigned), 2)
        self.assertTrue(all(u["reason"] == mp.UNASSIGNED_MAX_PASSES for u in plan.unassigned))


class PassArtifactTests(unittest.TestCase):
    def test_pass_artifact_metadata_is_exact_and_deterministic(self):  # 22, 25
        art = _art()
        for fmt in (V1, V2):
            plan = _plan(art, fmt, _budget_for(art, fmt, 3))
            for entry in plan.passes:
                built = mp.build_pass_artifact(art, plan, entry)
                meta = built[mp.PASS_FIELD]
                self.assertEqual(meta["estimatedContextBytes"], ce.context_artifact_bytes(built, fmt))
                self.assertLessEqual(meta["estimatedContextBytes"], plan.artifact_budget)
                self.assertEqual(meta["excludedFiles"], sorted(set(FILES[:6]) - set(entry["primaryFiles"]) - set(entry["contextFiles"])))
                self.assertEqual(ce.encode_context_artifact(built, fmt), ce.encode_context_artifact(mp.build_pass_artifact(art, plan, entry), fmt))
                self.assertEqual(built["secrets"], art["secrets"])  # never filtered
                self.assertNotIn("contextSelection", built)

    def test_pass_note_is_fixed_size_and_absent_elsewhere(self):
        art = _art()
        plan = _plan(art, V1, _budget_for(art, V1, 3))
        built = mp.build_pass_artifact(art, plan, plan.passes[0])
        self.assertIn("this prompt is pass 1 of 3", llm_client._build_step6_prompt(built, None, "pro"))
        self.assertEqual(mp.pass_prompt_note(FAKE_ARTIFACT), "")
        self.assertNotIn("Multi-pass analysis", llm_client._build_step6_prompt(FAKE_ARTIFACT, None, "pro"))


class PassPromptRulesTests(unittest.TestCase):
    """The pass note states the pass's location and category-coverage rules,
    and a pass prompt no longer carries the single-pass rule "partial needs a
    NOT_ASSESSED category" (R-05 applies to the merged report only,
    docs/decisiones.md D-098). Single-pass prompts are unchanged."""

    OLD_RULE = 'If scope.completeness is "partial" or "failed", categoryCoverage MUST include at least one entry with status "NOT_ASSESSED"'

    def setUp(self):
        art = _art()
        plan = _plan(art, V1, _budget_for(art, V1, 3))
        self.pass_artifact = mp.build_pass_artifact(art, plan, plan.passes[1])
        self.note = mp.pass_prompt_note(self.pass_artifact)

    def test_note_states_the_locations_anchor_rule(self):  # A
        self.assertIn("locations[0] is the identity and ownership anchor of the finding and MUST be a file listed in contextPass.primaryFiles", self.note)
        self.assertIn("a context-only file must NEVER be used as locations[0]", self.note)
        self.assertIn("keep the finding anchored to the primary file", self.note)
        # Same rule pass_scope_errors() enforces for every other location.
        self.assertIn("Every other location (locations[1..n]) and every gas suggestion location must also be a file listed in contextPass.primaryFiles", self.note)
        self.assertIn("never a context-only, excluded or unknown file", self.note)

    def test_note_defines_pass_category_coverage(self):  # B
        self.assertIn("DETECTED is REQUIRED for any category that has at least one non-informational finding in this pass", self.note)
        self.assertIn("NOT_ASSESSED means the category could not be properly evaluated within this pass's primary files", self.note)
        self.assertIn("does NOT by itself require any category to be NOT_ASSESSED", self.note)

    def test_pass_prompt_drops_the_old_partial_rule(self):  # C
        for fmt in (V1, V2):
            with self.subTest(fmt=fmt):
                prompt = llm_client._build_step6_prompt(self.pass_artifact, ["previous error"], "pro", **({} if fmt == V1 else {"context_format": fmt}))
                self.assertNotIn(self.OLD_RULE, prompt)
                self.assertIn(self.note, prompt)

    def test_single_pass_prompts_keep_the_rule_and_get_no_pass_rules(self):  # D
        from tests.test_backend_context_selection import _artifact
        selected = dict(_artifact([("src/A.sol", 5, 100)]), contextSelection={"status": "applied", "selectedFiles": [], "excludedFiles": []})
        for artifact in (FAKE_ARTIFACT, selected):
            for mode in ("quick", "standard", "pro"):
                with self.subTest(mode=mode, selection="contextSelection" in artifact):
                    prompt = llm_client._build_step6_prompt(artifact, None, mode)
                    self.assertIn(llm_client._PARTIAL_COVERAGE_RULE, prompt)
                    self.assertNotIn("Multi-pass analysis", prompt)
                    self.assertNotIn("identity and ownership anchor", prompt)
                    self.assertNotIn("Category coverage in this pass", prompt)

    def test_pass_prompt_overhead_stays_within_the_reserve(self):
        worst = llm_client._build_step6_prompt(self.pass_artifact, ["x" * 40000], "pro", context_format=V2)
        artifact_bytes = len(ce.encode_context_artifact(self.pass_artifact, V2).encode("utf-8"))
        self.assertLessEqual(len(worst.encode("utf-8")) - artifact_bytes, RESERVE)


class PassFinalFormatCheckTests(unittest.TestCase):
    """docs/decisiones.md D-103 (H-5, measure C): every pass prompt ends with
    a short format-only reminder, after the artifact, the pass note and any
    retry note. Single-pass prompts are byte-identical; nothing else moves."""

    CHECK = mp._PASS_FINAL_FORMAT_CHECK

    def setUp(self):
        self.art = _art()
        self.budget = _budget_for(self.art, V1, 3)
        self.plan = _plan(self.art, V1, self.budget)
        self.pass_artifact = mp.build_pass_artifact(self.art, self.plan, self.plan.passes[1])

    def test_check_is_short_and_format_only(self):
        self.assertTrue(self.CHECK.startswith("\n\nFINAL FORMAT CHECK: "))
        self.assertLess(len(self.CHECK.encode("utf-8")), 200)
        for phrase in ("ONLY one valid JSON object", "no markdown code fences", "no prose before or after it", "Do not omit any required field"):
            self.assertIn(phrase, self.CHECK)

    def test_a_every_pass_prompt_ends_with_the_check(self):  # A
        for fmt in (V1, V2):
            for mode in ("quick", "standard", "pro"):
                with self.subTest(fmt=fmt, mode=mode):
                    prompt = llm_client._build_step6_prompt(self.pass_artifact, None, mode, context_format=fmt)
                    self.assertTrue(prompt.endswith(self.CHECK))
                    self.assertEqual(prompt.count("FINAL FORMAT CHECK"), 1)

    def test_b_check_comes_after_the_artifact_and_the_pass_note(self):  # B
        for fmt in (V1, V2):
            with self.subTest(fmt=fmt):
                prompt = llm_client._build_step6_prompt(self.pass_artifact, None, "pro", context_format=fmt)
                encoded = ce.encode_context_artifact(self.pass_artifact, fmt)
                check_at = prompt.rindex(self.CHECK)
                self.assertLess(prompt.index(encoded) + len(encoded), check_at)
                self.assertLess(prompt.index(mp.pass_prompt_note(self.pass_artifact)), check_at)

    def test_c_single_pass_prompts_are_byte_identical(self):  # C
        selected = dict(_artifact([("src/A.sol", 5, 100)]), contextSelection={"status": "applied", "selectedFiles": [], "excludedFiles": []})
        self.assertEqual(mp.pass_final_format_check(FAKE_ARTIFACT), "")
        self.assertEqual(mp.pass_final_format_check(selected), "")
        for artifact in (FAKE_ARTIFACT, selected):
            for fmt in (V1, V2):
                for previous in (None, ["previous error"]):
                    with self.subTest(selection="contextSelection" in artifact, fmt=fmt, retry=bool(previous)):
                        prompt = llm_client._build_step6_prompt(artifact, previous, "pro", context_format=fmt)
                        with mock.patch.object(mp, "_PASS_FINAL_FORMAT_CHECK", "SHOULD NEVER APPEAR"):
                            self.assertEqual(llm_client._build_step6_prompt(artifact, previous, "pro", context_format=fmt), prompt)
                        self.assertNotIn("FINAL FORMAT CHECK", prompt)

    def test_d_every_pass_prompt_and_worst_retry_stay_within_budget(self):  # D
        for entry in self.plan.passes:
            pass_artifact = mp.build_pass_artifact(self.art, self.plan, entry)
            for fmt in (V1, V2):
                with self.subTest(pass_index=entry["passIndex"], fmt=fmt):
                    worst = llm_client._build_step6_prompt(pass_artifact, ["x" * 40000], "pro", context_format=fmt)
                    artifact_bytes = len(ce.encode_context_artifact(pass_artifact, fmt).encode("utf-8"))
                    self.assertLessEqual(len(worst.encode("utf-8")) - artifact_bytes, RESERVE)  # check included in the reserve
                    self.assertTrue(worst.endswith(self.CHECK))

    def test_e_same_pass_same_prompt(self):  # E
        again = mp.build_pass_artifact(self.art, self.plan, self.plan.passes[1])
        for previous in (None, ["e"]):
            self.assertEqual(llm_client._build_step6_prompt(self.pass_artifact, previous, "pro"),
                             llm_client._build_step6_prompt(again, previous, "pro"))

    def test_f_retry_note_is_kept_and_the_check_stays_last(self):  # F
        prompt = llm_client._build_step6_prompt(self.pass_artifact, ["findings[0] missing required field 'status'"], "pro")
        retry_at = prompt.index("Your previous draft was INVALID")
        self.assertIn("findings[0] missing required field 'status'", prompt[retry_at:])
        self.assertLess(retry_at, prompt.rindex(self.CHECK))
        self.assertTrue(prompt.endswith(self.CHECK))

    def test_g_run_outcome_is_unchanged_except_prompt_bytes(self):  # G
        def run():
            provider = ScriptedProvider({2: ["not json", llm_client.ProviderError("provider call failed: Timeout")]})
            result, counters = _run(self.art, self.budget, provider)
            return result, provider
        with mock.patch.object(mp, "_PASS_FINAL_FORMAT_CHECK", ""):
            before, before_provider = run()
        after, after_provider = run()
        extra = len(self.CHECK.encode("utf-8"))
        strip = lambda passes: [{k: v for k, v in p.items() if k != "promptBytes"} for p in passes]
        self.assertEqual(strip(after["multiPass"]["passes"]), strip(before["multiPass"]["passes"]))  # files, attempts, statuses
        self.assertEqual([p["promptBytes"] - q["promptBytes"] for p, q in zip(after["multiPass"]["passes"], before["multiPass"]["passes"])], [extra] * 3)
        self.assertEqual(after["scoredReport"]["categoryCoverage"], before["scoredReport"]["categoryCoverage"])
        self.assertEqual(after["scoredReport"]["findings"], before["scoredReport"]["findings"])
        self.assertEqual(after["scoredReport"]["scope"], before["scoredReport"]["scope"])
        self.assertEqual([(c["pass"], c["timeout_seconds"]) for c in after_provider.calls], [(c["pass"], c["timeout_seconds"]) for c in before_provider.calls])
        self.assertTrue(all(c["prompt"].endswith(self.CHECK) for c in after_provider.calls))


class PassScopeTests(unittest.TestCase):
    ENTRY = {"passIndex": 2, "passCount": 3, "primaryFiles": ["src/A.sol"], "contextFiles": ["src/B.sol"]}

    def test_primary_allowed_context_excluded_and_unknown_rejected(self):  # 5, 12, 16
        ok = _valid_draft(["src/A.sol", "./src/A.sol"])
        self.assertEqual(mp.pass_scope_errors(ok, self.ENTRY), [])
        for path in ("src/B.sol", "src/C.sol", "invented.sol"):
            with self.subTest(path=path):
                errors = mp.pass_scope_errors(_valid_draft([path]), self.ENTRY)
                self.assertEqual(len(errors), 1)
        gas = _valid_draft()
        gas["gasSuggestions"] = [{"technique": "t", "location": {"file": "src/B.sol"}, "explanation": "e", "impact": "low"}]
        self.assertEqual(len(mp.pass_scope_errors(gas, self.ENTRY)), 1)

    def test_complete_scope_rejected_for_a_pass(self):
        draft = _valid_draft()
        draft["scope"] = {"completeness": "complete"}
        self.assertEqual(len(mp.pass_scope_errors(draft, self.ENTRY)), 1)


class MultiPassRunTests(unittest.TestCase):
    def setUp(self):
        self.art = _art()
        self.budget = _budget_for(self.art, V1, 3)

    def test_all_passes_succeed_complete_scope_single_score_and_render(self):  # 1, 6, 18, 19, 20, 21
        provider = ScriptedProvider()
        result, counters = _run(self.art, self.budget, provider)
        self.assertEqual(result["status"], "rendered")
        self.assertEqual([c["pass"] for c in provider.calls], [1, 2, 3])
        self.assertEqual(counters.pipeline, 1)
        self.assertEqual(counters.render, 1)
        self.assertEqual(counters.validate_pass, 3)
        merged_draft = counters.pipeline_drafts[0]
        for field in ("riskIndicator", "scoreStatus", "scoreVersion"):
            self.assertNotIn(field, merged_draft)  # the report is scored only by the one final pipeline run
        self.assertTrue(all("id" not in f and "stableKey" not in f for f in merged_draft["findings"]))
        scope = result["scoredReport"]["scope"]
        self.assertEqual(scope["completeness"], "complete")
        self.assertIn(mp.MULTI_PASS_REASON_CODE, [r["code"] for r in scope["reasons"]])
        self.assertIn(mp.MULTI_PASS_LIMITATION, result["scoredReport"]["limitations"])
        self.assertEqual(len(result["scoredReport"]["findings"]), 3)
        self.assertEqual(result["multiPass"]["passCount"], 3)
        self.assertTrue(all(p["status"] == mp.PASS_SUCCESS for p in result["multiPass"]["passes"]))

    def test_findings_only_from_primary_files_with_stable_keys(self):  # 15, 16
        provider = ScriptedProvider()
        result, _ = _run(self.art, self.budget, provider)
        plan = _plan(self.art, V1, self.budget)
        owner = plan.primary_owner()
        for finding in result["scoredReport"]["findings"]:
            self.assertIn(finding["locations"][0]["file"], owner)
            self.assertEqual(finding["stableKey"], compute_stable_key(finding))
            self.assertEqual(finding["id"], compute_id(finding["stableKey"]))

    def test_same_input_same_report(self):  # 3, 25
        first, _ = _run(self.art, self.budget, ScriptedProvider())
        second, _ = _run(copy.deepcopy(self.art), self.budget, ScriptedProvider())
        self.assertEqual(first["rendered"], second["rendered"])
        self.assertEqual(json.dumps(first["scoredReport"], sort_keys=True), json.dumps(second["scoredReport"], sort_keys=True))
        self.assertEqual(first["multiPass"], second["multiPass"])

    def test_provider_error_fails_that_pass_only(self):  # 9, 11, 17
        err = llm_client.ProviderError("provider call failed: Timeout")
        provider = ScriptedProvider({2: [err, err, err]})
        result, _ = _run(self.art, self.budget, provider)
        passes = result["multiPass"]["passes"]
        self.assertEqual([p["status"] for p in passes], [mp.PASS_SUCCESS, mp.PASS_FAILED, mp.PASS_SUCCESS])
        self.assertEqual(passes[1]["providerOutcome"], "error")
        self.assertEqual(passes[1]["attempts"], 3)
        scope = result["scoredReport"]["scope"]
        self.assertEqual(scope["completeness"], "partial")
        failed = [r for r in scope["reasons"] if r["code"] == mp.FAILED_PASSES_REASON_CODE]
        plan = _plan(self.art, V1, self.budget)
        for path in plan.passes[1]["primaryFiles"]:
            self.assertIn(path, failed[0]["detail"])
        coverage = {c["category"]: c["status"] for c in result["scoredReport"]["categoryCoverage"]}
        self.assertNotIn("NOT_DETECTED", coverage.values())  # nothing claimed about files never analyzed

    def test_invalid_json_after_retries_fails_the_pass(self):  # 10
        provider = ScriptedProvider({1: ["not json", "{", "[]"]})
        result, _ = _run(self.art, self.budget, provider)
        first = result["multiPass"]["passes"][0]
        self.assertEqual((first["status"], first["validationOutcome"], first["attempts"]), (mp.PASS_FAILED, "invalid_json", 3))

    def test_invalid_json_then_valid_recovers_with_its_own_errors(self):  # 10, 24
        provider = ScriptedProvider({2: ["not json"]})
        result, _ = _run(self.art, self.budget, provider)
        self.assertEqual(result["scoredReport"]["scope"]["completeness"], "complete")
        second_pass = [c for c in provider.calls if c["pass"] == 2]
        self.assertEqual(len(second_pass), 2)
        self.assertIn("previous draft was INVALID", second_pass[1]["prompt"])
        third_pass = [c for c in provider.calls if c["pass"] == 3]
        self.assertNotIn("previous draft was INVALID", third_pass[0]["prompt"])  # errors never cross passes

    def test_out_of_scope_location_is_discarded_not_retried(self):  # 12 (D-100: finding-level discard)
        plan = _plan(self.art, V1, self.budget)
        foreign = plan.passes[2]["primaryFiles"][0]  # primary in pass 3, so never valid in pass 1
        provider = ScriptedProvider({1: [_valid_draft([foreign])] * 3})
        result, _ = _run(self.art, self.budget, provider)
        first = result["multiPass"]["passes"][0]
        self.assertEqual((first["status"], first["attempts"], first["discardedFindings"]), (mp.PASS_SUCCESS, 1, 1))
        self.assertEqual(len([c for c in provider.calls if c["pass"] == 1]), 1)  # a discard alone never consumes an attempt
        report_files = [f["locations"][0]["file"] for f in result["scoredReport"]["findings"]]
        self.assertFalse(set(report_files) & set(plan.passes[0]["primaryFiles"]))  # pass 1's only finding was discarded
        self.assertEqual(report_files.count(foreign), 1)  # only pass 3's own (primary) finding on that file

    def test_complete_scope_is_still_retried(self):
        complete = _valid_draft()
        complete["scope"] = {"completeness": "complete", "reasons": []}
        provider = ScriptedProvider({1: [complete]})
        result, _ = _run(self.art, self.budget, provider)
        first = result["multiPass"]["passes"][0]
        self.assertEqual((first["status"], first["attempts"]), (mp.PASS_SUCCESS, 2))
        self.assertIn("must not be 'complete'", [c for c in provider.calls if c["pass"] == 1][1]["prompt"])

    def test_all_passes_failing_fails_closed(self):
        err = llm_client.ProviderError("down")
        provider = ScriptedProvider({i: [err] * 3 for i in (1, 2, 3)})
        with self.assertRaises(llm_client.Step6Failed) as ctx:
            _run(self.art, self.budget, provider)
        self.assertIn("all 3 pass(es) failed", str(ctx.exception))

    def test_unassigned_and_max_passes_give_partial_scope(self):  # 7, 8, 17
        result, _ = _run(self.art, self.budget, ScriptedProvider(), max_passes=2)
        scope = result["scoredReport"]["scope"]
        self.assertEqual(scope["completeness"], "partial")
        self.assertIn(mp.UNASSIGNED_REASON_CODE, [r["code"] for r in scope["reasons"]])

    def test_non_size_completeness_reason_keeps_scope_partial(self):  # 18
        art = _art(extra_reasons=[{"code": "MISSING_IMPORT", "detail": "x"}])
        result, _ = _run(art, _budget_for(art, V1, 3), ScriptedProvider())
        self.assertEqual(result["scoredReport"]["scope"]["completeness"], "partial")

    def test_every_pass_prompt_within_the_hard_gate(self):  # 23
        provider = ScriptedProvider({1: ["x"], 2: [llm_client.ProviderError("e")]})
        _run(self.art, self.budget, provider)
        self.assertTrue(all(len(c["prompt"].encode("utf-8")) <= self.budget for c in provider.calls))

    def test_hard_gate_blocks_an_oversized_pass_prompt_without_provider_call(self):  # 23
        provider = ScriptedProvider()
        real = mp.pass_prompt_note
        with mock.patch.object(mp, "pass_prompt_note", lambda artifact: real(artifact) + ("y" * self.budget if _index_of(artifact) == 2 else "")):
            with self.assertRaises(llm_client.Step6Failed) as ctx:
                _run(self.art, self.budget, provider)
        self.assertIn("pass 2/3", str(ctx.exception))
        self.assertEqual([c["pass"] for c in provider.calls], [1])

    def test_previous_errors_are_bounded_per_pass(self):  # 24
        huge = llm_client.ProviderError("z" * (5 * llm_client.STEP6_PREVIOUS_ERRORS_MAX_BYTES))
        provider = ScriptedProvider({1: [huge]})
        _run(self.art, self.budget, provider)
        retry = [c for c in provider.calls if c["pass"] == 1][1]["prompt"]
        self.assertIn("bytes omitted", retry)
        self.assertLessEqual(len(retry.encode("utf-8")), self.budget)

    def test_duplicate_findings_in_a_pass_are_merged_by_score(self):  # 13
        plan = _plan(self.art, V1, self.budget)
        path = plan.passes[0]["primaryFiles"][0]
        provider = ScriptedProvider({1: [_valid_draft([path, path])]})
        result, _ = _run(self.art, self.budget, provider)
        merged = [f for f in result["scoredReport"]["findings"] if f["locations"][0]["file"] == path]
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["mergedCount"], 2)

    def test_v2_multi_pass_sends_compact_v2_pass_artifacts(self):  # 22
        budget = _budget_for(self.art, V2, 3)
        provider = ScriptedProvider()
        result, _ = _run(self.art, budget, provider, fmt=V2)
        self.assertEqual(result["scoredReport"]["scope"]["completeness"], "complete")
        plan = _plan(self.art, V2, budget)
        for call, entry in zip(provider.calls, plan.passes):
            self.assertIn(ce.prompt_legend(V2), call["prompt"])
            embedded = call["prompt"].split("Preprocessed artifact:\n", 1)[1].split("\n\nMulti-pass analysis:", 1)[0]
            decoded = ce.decode_context_artifact(embedded, V2)
            self.assertEqual(decoded[mp.PASS_FIELD]["primaryFiles"], entry["primaryFiles"])
            self.assertEqual(decoded[mp.PASS_FIELD]["estimatedContextBytes"], len(embedded.encode("utf-8")))

    def test_deadline_skips_a_pass_without_calling_the_provider(self):  # 9
        clock = _FakeClock()
        # Pass 1's call overruns its share and uses up the provider window
        # (250 s - 20 s final-pipeline reserve): passes 2 and 3 are never started.
        provider = _AdvancingProvider(clock, seconds_per_call=240)
        result, _ = _run(self.art, self.budget, provider, deadline_seconds=250, clock=clock)
        passes = result["multiPass"]["passes"]
        self.assertEqual(passes[0]["status"], mp.PASS_SUCCESS)
        self.assertEqual([p["status"] for p in passes[1:]], [mp.PASS_FAILED, mp.PASS_FAILED])
        self.assertTrue(all("time budget exhausted" in p["failureReason"] for p in passes[1:]))
        self.assertEqual(len(provider.calls), 1)
        self.assertEqual(result["scoredReport"]["scope"]["completeness"], "partial")


def _index_of(artifact):
    meta = artifact.get(mp.PASS_FIELD) if isinstance(artifact, dict) else None
    return meta.get("passIndex") if isinstance(meta, dict) else None


class _FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class _AdvancingProvider(ScriptedProvider):
    def __init__(self, clock, seconds_per_call):
        super().__init__()
        self.clock = clock
        self.seconds = seconds_per_call

    def complete(self, prompt, max_output_tokens, timeout_seconds):
        self.clock.now += self.seconds
        return super().complete(prompt, max_output_tokens, timeout_seconds)


class MergeTests(unittest.TestCase):
    def _plan_and_outcomes(self, drafts):
        art = _art()
        plan = _plan(art, V1, _budget_for(art, V1, 3))
        outcomes = []
        for entry, draft in zip(plan.passes, drafts):
            outcomes.append({"passIndex": entry["passIndex"], "passCount": entry["passCount"], "primaryFiles": entry["primaryFiles"],
                             "contextFiles": entry["contextFiles"], "status": mp.PASS_SUCCESS if draft else mp.PASS_FAILED,
                             "failureReason": None if draft else "x", "draft": draft})
        return art, plan, outcomes

    def test_cross_pass_duplicate_prefers_the_primary_pass_regardless_of_input_order(self):  # 14
        art = _art()
        plan = _plan(art, V1, _budget_for(art, V1, 3))
        owned_by_2 = plan.passes[1]["primaryFiles"][0]
        from_primary = _finding(owned_by_2, severity="LOW")
        from_other = _finding(owned_by_2, severity="HIGH")
        from_other["description"] = "from pass 1"
        drafts = [_valid_draft(), _valid_draft(), _valid_draft()]
        drafts[0]["findings"] = [from_other]
        drafts[1]["findings"] = [from_primary]
        _, _, outcomes = self._plan_and_outcomes(drafts)
        merged, provenance = mp.merge_pass_drafts(art, plan, outcomes, "pro")
        self.assertEqual(provenance[0][0], 2)  # the primary pass's finding comes first
        scored = score_report(merged)
        self.assertEqual(len(scored["findings"]), 1)
        self.assertEqual(scored["findings"][0]["description"], "d")  # group primary = primary pass
        self.assertEqual(scored["findings"][0]["severity"], "HIGH")  # score.py's own merge rule
        shuffled, _ = mp.merge_pass_drafts(art, plan, list(reversed(outcomes)), "pro")
        self.assertEqual(merged, shuffled)
        self.assertEqual(len(mp.merged_location_errors(provenance, merged, plan, outcomes)), 1)  # pass 1's copy is out of its scope

    def test_merge_and_scope_do_not_depend_on_outcome_order(self):  # 25
        drafts = [_valid_draft(), None, None]
        art, plan, outcomes = self._plan_and_outcomes(drafts)
        forward, _ = mp.merge_pass_drafts(art, plan, outcomes, "pro")
        backward, _ = mp.merge_pass_drafts(art, plan, list(reversed(outcomes)), "pro")
        self.assertEqual(json.dumps(forward, sort_keys=True), json.dumps(backward, sort_keys=True))
        self.assertEqual(forward["scope"]["completeness"], "partial")

    def test_coverage_merge_is_conservative(self):
        drafts = [_valid_draft(), _valid_draft(), _valid_draft()]
        drafts[1]["categoryCoverage"][2]["status"] = "DETECTED"
        drafts[1]["findings"] = [_finding("src/X.sol", category="SC03")]  # real non-informational backing (D-102)
        art, plan, outcomes = self._plan_and_outcomes(drafts)
        merged, _ = mp.merge_pass_drafts(art, plan, outcomes, "pro")
        coverage = {c["category"]: c["status"] for c in merged["categoryCoverage"]}
        self.assertEqual(coverage["SC03"], "DETECTED")
        self.assertEqual(coverage["SC01"], "NOT_ASSESSED")  # some pass did not assess it
        self.assertEqual(coverage["SC02"], "NOT_DETECTED")
        drafts[1]["findings"] = []  # the same DETECTED without backing never survives the merge
        art, plan, outcomes = self._plan_and_outcomes(drafts)
        merged, _ = mp.merge_pass_drafts(art, plan, outcomes, "pro")
        self.assertEqual({c["category"]: c["status"] for c in merged["categoryCoverage"]}["SC03"], "NOT_ASSESSED")

    def test_notes_suggestions_and_limitations_deduplicated_in_pass_order(self):
        drafts = [_valid_draft(), _valid_draft(), _valid_draft()]
        for d in drafts:
            d["limitations"] = ["same", "only %d" % id(d)]
            d["architectureNotes"] = [{"title": "t", "description": "same"}]
        art, plan, outcomes = self._plan_and_outcomes(drafts)
        merged, _ = mp.merge_pass_drafts(art, plan, outcomes, "pro")
        self.assertEqual(merged["limitations"][0], "same")
        self.assertEqual(merged["limitations"].count("same"), 1)
        self.assertEqual(merged["architectureNotes"], [{"title": "t", "description": "same"}])


class SinglePassCompatibilityTests(unittest.TestCase):  # 26
    def test_default_max_passes_is_the_unchanged_single_pass_path(self):
        provider_default = llm_client.MockLLMProvider([json.dumps(_extract_example(llm_client._build_step6_prompt(FAKE_ARTIFACT, None, "quick")))])
        counters = _Counters()
        llm_client.run_step6_with_retries(["/x.sol"], "quick", provider_default, counters.pipeline_fn, preprocess_run=lambda paths, **kw: FAKE_ARTIFACT)
        self.assertEqual(provider_default.calls[0]["prompt"], llm_client._build_step6_prompt(FAKE_ARTIFACT, None, "quick"))
        self.assertEqual(provider_default.calls[0]["timeout_seconds"], llm_client.DEFAULT_PER_ATTEMPT_TIMEOUT_SECONDS)

    def test_artifact_that_fits_one_prompt_stays_single_pass_with_multi_pass_enabled(self):
        art = _art()
        provider = ScriptedProvider()
        big_budget = cs.APPLICATION_CONTEXT_BUDGET_BYTES
        result, counters = _run(art, big_budget, provider)
        self.assertEqual(len(provider.calls), 1)
        self.assertNotIn("Multi-pass analysis", provider.calls[0]["prompt"])
        self.assertIn("Context selection:", provider.calls[0]["prompt"])  # the existing 10K path (LOC_LIMIT_EXCEEDED)
        self.assertNotIn("multiPass", result)
        self.assertEqual(counters.validate_pass, 0)

    def test_parameter_validation(self):
        with self.assertRaises(ValueError):
            llm_client.run_step6_with_retries(["/x"], "quick", None, None, max_passes=0)
        with self.assertRaises(ValueError):
            llm_client.run_step6_with_retries(["/x"], "quick", None, None, max_passes=llm_client.MAX_STEP6_PASSES + 1)
        with self.assertRaises(ValueError):
            llm_client.run_step6_with_retries(["/x"], "quick", None, None, max_passes=2)  # no validate_pass_draft


class DeadlineTests(unittest.TestCase):
    def test_attempt_timeouts_respect_reserve_minimum_and_pass_share(self):
        clock = _FakeClock()
        deadline = llm_client._Step6Deadline(300, clock)
        self.assertEqual(deadline.attempt_timeout(120), 120)
        clock.now += 300 - llm_client.STEP6_FINAL_PIPELINE_RESERVE_SECONDS - 50
        self.assertEqual(deadline.attempt_timeout(120), 50)
        clock.now += 50 - llm_client.STEP6_MIN_ATTEMPT_SECONDS + 1
        self.assertIsNone(deadline.attempt_timeout(120))
        fresh = llm_client._Step6Deadline(200, _FakeClock())
        end = fresh.pass_end(4)
        self.assertEqual(fresh.attempt_timeout(120, end), int((200 - llm_client.STEP6_FINAL_PIPELINE_RESERVE_SECONDS) / 4))

    def test_single_pass_with_deadline_stops_instead_of_outliving_the_container(self):
        clock = _FakeClock()
        example = json.dumps(_extract_example(llm_client._build_step6_prompt(FAKE_ARTIFACT, None, "quick")))
        provider = _AdvancingProvider(clock, 230)  # attempt 1 leaves 10 s (< STEP6_MIN_ATTEMPT_SECONDS) before the reserve
        provider.script = {0: ["not json", example]}
        with self.assertRaises(llm_client.Step6Failed) as ctx:
            llm_client.run_step6_with_retries(["/x.sol"], "quick", provider, _Counters().pipeline_fn, preprocess_run=lambda paths, **kw: FAKE_ARTIFACT, deadline_seconds=260, clock=clock)
        self.assertIn("time budget", str(ctx.exception))
        self.assertEqual(len(provider.calls), 1)


def _draft_without_not_assessed(finding_files=()):
    """A valid partial pass draft whose categories were all assessed within
    its primary files (DETECTED / NOT_DETECTED only, no NOT_ASSESSED)."""
    draft = _valid_draft(finding_files)
    draft["categoryCoverage"][0]["status"] = "NOT_DETECTED"
    assert "NOT_ASSESSED" not in [c["status"] for c in draft["categoryCoverage"]]
    return draft


class _AllAssessedProvider(ScriptedProvider):
    def complete(self, prompt, max_output_tokens, timeout_seconds):
        index = _pass_index(prompt)
        self.calls.append({"pass": index, "prompt": prompt, "timeout_seconds": timeout_seconds})
        queue = self.script.get(index)
        response = queue.pop(0) if queue else _draft_without_not_assessed(_primary_files(prompt)[:1])
        if isinstance(response, Exception):
            raise response
        return json.dumps(response)


class _WorkerCounters(_Counters):
    """The worker's per-pass validator (backend/worker_entrypoint.py):
    score + validate without rule R-05 (docs/decisiones.md D-098)."""

    def validator(self, draft):
        self.validate_pass += 1
        return validate_report(score_report(draft), enforce_partial_coverage_rule=False)


class R05GlobalOnlyTests(unittest.TestCase):
    """R-05 applies to the merged report the pipeline validates and renders,
    not to each intermediate pass draft (docs/decisiones.md D-098)."""

    def setUp(self):
        self.art = _art()
        self.budget = _budget_for(self.art, V1, 3)

    def test_passes_without_not_assessed_succeed_and_a_complete_report_keeps_not_detected(self):
        result, counters = _run(self.art, self.budget, _AllAssessedProvider(), counters=_WorkerCounters())
        self.assertEqual([p["status"] for p in result["multiPass"]["passes"]], [mp.PASS_SUCCESS] * 3)
        self.assertEqual((counters.pipeline, counters.render), (1, 1))
        report = result["scoredReport"]
        self.assertEqual(report["scope"]["completeness"], "complete")
        statuses = {c["category"]: c["status"] for c in report["categoryCoverage"]}
        self.assertNotIn("NOT_ASSESSED", statuses.values())  # every pass assessed every category
        self.assertEqual(statuses["SC01"], "NOT_DETECTED")

    def test_global_partial_report_still_satisfies_r05(self):
        err = llm_client.ProviderError("provider call failed: Timeout")
        result, counters = _run(self.art, self.budget, _AllAssessedProvider({2: [err, err, err]}), counters=_WorkerCounters())
        report = result["scoredReport"]
        self.assertEqual(report["scope"]["completeness"], "partial")
        self.assertIn("NOT_ASSESSED", [c["status"] for c in report["categoryCoverage"]])
        self.assertEqual(validate_report(report), [])  # R-05 enforced on the rendered report, and satisfied
        self.assertEqual(counters.render, 1)

    def test_with_r05_on_each_pass_the_same_drafts_fail(self):
        # The previous per-pass behaviour, kept by validate_report's default.
        with self.assertRaises(llm_client.Step6Failed) as ctx:
            _run(self.art, self.budget, _AllAssessedProvider(), counters=_Counters())
        self.assertIn("R-05", str(ctx.exception))


class _SplitCategoriesProvider(ScriptedProvider):
    """Pass i answers with one non-informational finding per category in
    categories[i] (all in its first primary file), those categories
    DETECTED and the rest NOT_DETECTED - no NOT_ASSESSED; passes listed in
    `failing` raise a provider error on every attempt."""

    def __init__(self, categories, failing=()):
        super().__init__()
        self.categories = categories
        self.failing = set(failing)

    def complete(self, prompt, max_output_tokens, timeout_seconds):
        index = _pass_index(prompt)
        self.calls.append({"pass": index, "prompt": prompt, "timeout_seconds": timeout_seconds})
        if index in self.failing:
            raise llm_client.ProviderError("provider call failed: Timeout")
        cats = self.categories.get(index, [])
        primary = _primary_files(prompt)[0]
        draft = _valid_draft()
        draft["findings"] = [_finding(primary, category=c, function="f_%s" % c.lower()) for c in cats]
        for entry in draft["categoryCoverage"]:
            entry["status"] = "DETECTED" if entry["category"] in cats else "NOT_DETECTED"
        return json.dumps(draft)


class ForcedDetectedPartialGlobalTests(unittest.TestCase):
    """docs/decisiones.md D-101 - the real 20K run's H-1: a failed pass makes
    the merged report "partial", the other passes' findings cover all ten
    categories, so R-04 forbids every NOT_ASSESSED that R-05 asked for. The
    merged report must render, still "partial", nothing converted or lost."""

    SPLIT = {1: ["SC01", "SC02", "SC03", "SC04", "SC05"], 3: ["SC06", "SC07", "SC08", "SC09", "SC10"]}

    def setUp(self):
        self.art = _art()
        self.budget = _budget_for(self.art, V1, 3)

    def test_failed_pass_with_all_categories_detected_renders_as_partial(self):
        result, counters = _run(self.art, self.budget, _SplitCategoriesProvider(self.SPLIT, failing=[2]), counters=_WorkerCounters())
        self.assertEqual([p["status"] for p in result["multiPass"]["passes"]], [mp.PASS_SUCCESS, mp.PASS_FAILED, mp.PASS_SUCCESS])
        self.assertEqual((counters.pipeline, counters.render), (1, 1))
        self.assertEqual(counters.pipeline_forced_flags, [True])  # only the merged report's validation sets it
        report = result["scoredReport"]
        self.assertEqual(report["scope"]["completeness"], "partial")
        codes = [r["code"] for r in report["scope"]["reasons"]]
        self.assertIn(mp.FAILED_PASSES_REASON_CODE, codes)
        self.assertIn(mp.MULTI_PASS_LIMITATION, report["limitations"])
        self.assertEqual([c["status"] for c in report["categoryCoverage"]], ["DETECTED"] * 10)  # nothing converted
        self.assertNotIn("NOT_ASSESSED", [c["status"] for c in report["categoryCoverage"]])     # nothing fabricated
        self.assertEqual(sorted(f["category"] for f in report["findings"]), sorted(c for cats in self.SPLIT.values() for c in cats))  # nothing lost
        self.assertEqual(validate_report(report, allow_forced_detected_partial=True), [])
        self.assertTrue(any("R-05" in e for e in validate_report(report)))  # the default (single-pass, CLI) still rejects it
        self.assertIn("partial", result["rendered"])
        self.assertIn(mp.FAILED_PASSES_REASON_CODE, result["rendered"])

    def test_same_run_without_the_exception_fails_closed_on_r05(self):
        # The pre-D-101 global validation: a pipeline that ignores the flag.
        class _NoExceptionCounters(_WorkerCounters):
            def pipeline_fn(self, paths, *, allow_forced_detected_partial=False, **kwargs):
                return super().pipeline_fn(paths, allow_forced_detected_partial=False, **kwargs)
        with self.assertRaises(llm_client.Step6Failed) as ctx:
            _run(self.art, self.budget, _SplitCategoriesProvider(self.SPLIT, failing=[2]), counters=_NoExceptionCounters())
        self.assertIn("R-05", str(ctx.exception))

    def test_a_category_left_undetected_still_becomes_not_assessed(self):
        split = {1: ["SC01", "SC02", "SC03", "SC04"], 3: ["SC06", "SC07", "SC08", "SC09", "SC10"]}  # SC05 never detected
        result, counters = _run(self.art, self.budget, _SplitCategoriesProvider(split, failing=[2]), counters=_WorkerCounters())
        report = result["scoredReport"]
        self.assertEqual(report["scope"]["completeness"], "partial")
        statuses = {c["category"]: c["status"] for c in report["categoryCoverage"]}
        self.assertEqual(statuses["SC05"], "NOT_ASSESSED")
        self.assertEqual([s for s in statuses.values() if s != "DETECTED"], ["NOT_ASSESSED"])
        self.assertEqual(validate_report(report), [])  # satisfies the unchanged default R-05 as before

    def test_complete_run_with_all_categories_detected_is_unchanged(self):
        result, _ = _run(self.art, self.budget, _SplitCategoriesProvider(self.SPLIT), counters=_WorkerCounters())
        report = result["scoredReport"]
        self.assertEqual(report["scope"]["completeness"], "complete")
        self.assertEqual([c["status"] for c in report["categoryCoverage"]], ["DETECTED"] * 10)
        self.assertEqual(validate_report(report), [])


def _informational(path, category):
    finding = _finding(path, category=category, severity="INFORMATIONAL", function="info_%s" % category.lower())
    finding["status"] = "informational"
    return finding


class DetectedRequiresEvidenceTests(unittest.TestCase):
    """docs/decisiones.md D-102 - the second real 20K run's H-4: a pass's
    DETECTED survives the merge only when a merged non-informational finding
    backs it; otherwise it becomes NOT_ASSESSED (never NOT_DETECTED).
    Through the real run: pass validation, discard, merge, one pipeline."""

    def setUp(self):
        self.art = _art()
        self.budget = _budget_for(self.art, V1, 3)
        self.own = [p["primaryFiles"] for p in _plan(self.art, V1, self.budget).passes]

    def _draft(self, findings, detected=()):
        draft = _valid_draft()
        draft["findings"] = findings
        for entry in draft["categoryCoverage"]:
            entry["status"] = "DETECTED" if entry["category"] in detected else "NOT_DETECTED"
        return draft

    def _run(self, drafts):
        result, counters = _run(self.art, self.budget, ScriptedProvider({i + 1: [d] for i, d in enumerate(drafts)}), counters=_WorkerCounters())
        self.assertEqual([p["status"] for p in result["multiPass"]["passes"]], [mp.PASS_SUCCESS] * 3)
        return result, result["scoredReport"], {c["category"]: c["status"] for c in result["scoredReport"]["categoryCoverage"]}

    def test_a_detected_without_any_finding_becomes_not_assessed(self):  # A
        result, report, coverage = self._run([
            self._draft([], detected=["SC06"]),                                    # pass 1: DETECTED, no SC06 finding
            self._draft([_finding(self.own[1][0], category="SC08")], ["SC08"]),
            self._draft([_finding(self.own[2][0], category="SC05")], ["SC05"]),
        ])
        self.assertEqual(report["scope"]["completeness"], "complete")
        self.assertEqual(coverage["SC06"], "NOT_ASSESSED")                          # never NOT_DETECTED
        self.assertEqual((coverage["SC08"], coverage["SC05"]), ("DETECTED", "DETECTED"))
        self.assertEqual({k for k, v in coverage.items() if v == "NOT_DETECTED"}, set(mp._SC_CATEGORIES) - {"SC05", "SC06", "SC08"})
        self.assertEqual(sorted(f["category"] for f in report["findings"]), ["SC05", "SC08"])  # nothing lost or invented
        self.assertEqual(validate_report(report), [])

    def test_b_and_g_informational_only_category_becomes_not_assessed(self):  # B, G (the SC09 case)
        result, report, coverage = self._run([
            self._draft([_informational(self.own[0][0], "SC09"), _finding(self.own[0][0], category="SC01")], ["SC09", "SC01"]),
            self._draft([_finding(self.own[1][0], category="SC08")], ["SC08"]),
            self._draft([], []),
        ])
        self.assertEqual(coverage["SC09"], "NOT_ASSESSED")
        self.assertEqual((coverage["SC01"], coverage["SC08"]), ("DETECTED", "DETECTED"))
        self.assertIn(("SC09", "informational"), [(f["category"], f["status"]) for f in report["findings"]])  # the informational finding stays
        self.assertEqual(len(report["findings"]), 3)
        self.assertEqual(validate_report(report), [])

    def test_c_detected_backed_by_another_pass_finding_stays_detected(self):  # C
        result, report, coverage = self._run([
            self._draft([], detected=["SC06"]),                                    # no evidence in this pass
            self._draft([_finding(self.own[1][0], category="SC06")], ["SC06"]),    # real evidence in another pass
            self._draft([], []),
        ])
        self.assertEqual(coverage["SC06"], "DETECTED")
        self.assertEqual([f["category"] for f in report["findings"]], ["SC06"])
        self.assertEqual(validate_report(report), [])

    def test_d_discarded_evidence_never_backs_detected(self):  # D (the real SC06 case)
        out_of_scope = _finding(self.own[1][0], category="SC06", function="g")     # pass 1 locates it in pass 2's file
        result, report, coverage = self._run([
            self._draft([out_of_scope], detected=["SC06"]),                         # all its SC06 evidence is discarded
            self._draft([], detected=["SC06"]),                                     # another pass: DETECTED, no evidence
            self._draft([_finding(self.own[2][0], category="SC08")], ["SC08"]),
        ])
        passes = result["multiPass"]["passes"]
        self.assertEqual((passes[0]["discardedFindings"], passes[0]["coverageAdjusted"]), (1, ["SC06"]))
        self.assertEqual(report["scope"]["completeness"], "partial")                # any discard forbids "complete" (D-100)
        self.assertEqual(coverage["SC06"], "NOT_ASSESSED")
        self.assertNotIn("SC06", [f["category"] for f in report["findings"]])
        self.assertEqual(validate_report(report), [])

    def test_e_h1_forced_case_still_renders_with_ten_backed_detected(self):  # E (D-101 unchanged)
        result, counters = _run(self.art, self.budget, _SplitCategoriesProvider(ForcedDetectedPartialGlobalTests.SPLIT, failing=[2]), counters=_WorkerCounters())
        report = result["scoredReport"]
        self.assertEqual(report["scope"]["completeness"], "partial")
        self.assertEqual([c["status"] for c in report["categoryCoverage"]], ["DETECTED"] * 10)  # no artificial NOT_ASSESSED
        self.assertEqual(len(report["findings"]), 10)
        self.assertEqual(counters.render, 1)
        self.assertEqual(validate_report(report, allow_forced_detected_partial=True), [])
        self.assertTrue(any("R-05" in e for e in validate_report(report)))  # default R-05 unchanged


class DiscardOutOfScopeTests(unittest.TestCase):
    """The pure filter of finding-level discard (docs/decisiones.md D-100)."""

    ENTRY = {"passIndex": 1, "passCount": 2, "primaryFiles": ["src/A.sol"], "contextFiles": ["src/B.sol"]}
    KNOWN = ["src/A.sol", "src/B.sol", "src/C.sol"]

    def _draft(self, findings=(), gas=None, detected=()):
        draft = _valid_draft()
        draft["findings"] = [copy.deepcopy(f) for f in findings]
        for entry in draft["categoryCoverage"]:
            entry["status"] = "DETECTED" if entry["category"] in detected else ("NOT_ASSESSED" if entry["category"] == "SC01" else "NOT_DETECTED")
        if gas is not None:
            draft["gasSuggestions"] = gas
        return draft

    def _filter(self, draft):
        return mp.discard_out_of_scope(draft, self.ENTRY, self.KNOWN)

    def test_one_valid_one_invalid(self):  # A
        valid, invalid = _finding("src/A.sol"), _finding("src/B.sol", function="g")
        draft = self._draft([valid, invalid], detected=["SC08"])
        filtered, record = self._filter(draft)
        self.assertEqual(filtered["findings"], [valid])  # kept exactly as given
        self.assertEqual(record["discardedFindings"], 1)
        [d] = record["discards"]
        self.assertEqual((d["kind"], d["index"], d["category"], d["severity"], d["status"], d["reason"]),
                         ("finding", 1, "SC08", "LOW", "suspected", mp.DISCARD_REASON))
        self.assertEqual(d["invalidLocations"], [{"index": 0, "file": "src/B.sol", "fileKind": "context"}])
        self.assertEqual(filtered["categoryCoverage"][7]["status"], "DETECTED")  # still supported by the kept SC08 finding

    def test_all_invalid(self):  # B
        draft = self._draft([_finding("src/B.sol"), _finding("src/C.sol"), _finding("lib/X.sol")], detected=["SC08"])
        filtered, record = self._filter(draft)
        self.assertEqual(filtered["findings"], [])
        self.assertEqual([d["invalidLocations"][0]["fileKind"] for d in record["discards"]], ["context", "excluded", "unknown"])
        self.assertEqual(validate_report(score_report(filtered), enforce_partial_coverage_rule=False), [])

    def test_invalid_anchor_discards_whole_finding(self):  # C
        finding = _finding("src/B.sol")
        finding["locations"].append({"file": "src/A.sol"})
        filtered, record = self._filter(self._draft([finding], detected=["SC08"]))
        self.assertEqual(filtered["findings"], [])
        self.assertEqual(record["discards"][0]["invalidLocations"], [{"index": 0, "file": "src/B.sol", "fileKind": "context"}])

    def test_invalid_secondary_discards_whole_finding(self):  # D
        finding = _finding("src/A.sol")
        finding["locations"].append({"file": "src/B.sol"})
        filtered, record = self._filter(self._draft([finding], detected=["SC08"]))
        self.assertEqual(filtered["findings"], [])  # never kept with only its secondary removed
        self.assertEqual(record["discards"][0]["invalidLocations"], [{"index": 1, "file": "src/B.sol", "fileKind": "context"}])

    def test_invalid_gas_location_discards_only_that_suggestion(self):  # E
        ok = {"title": "t", "description": "d", "location": {"file": "src/A.sol"}}
        bad = {"title": "t2", "description": "d2", "location": {"file": "src/C.sol"}}
        filtered, record = self._filter(self._draft([_finding("src/A.sol")], gas=[ok, bad], detected=["SC08"]))
        self.assertEqual(filtered["gasSuggestions"], [ok])
        self.assertEqual(len(filtered["findings"]), 1)
        self.assertEqual(record["discards"], [{"kind": "gas", "index": 1, "location": "src/C.sol", "fileKind": "excluded", "reason": mp.DISCARD_REASON}])
        self.assertEqual((record["discardedFindings"], record["discardedGasSuggestions"]), (0, 1))

    def test_detected_without_a_kept_finding_becomes_not_assessed(self):  # F
        filtered, record = self._filter(self._draft([_finding("src/B.sol", category="SC03")], detected=["SC03"]))
        coverage = {c["category"]: c["status"] for c in filtered["categoryCoverage"]}
        self.assertEqual(coverage["SC03"], "NOT_ASSESSED")
        self.assertEqual(record["coverageAdjusted"], ["SC03"])

    def test_detected_kept_when_another_finding_supports_it(self):  # G
        filtered, record = self._filter(self._draft([_finding("src/B.sol", category="SC03"), _finding("src/A.sol", category="SC03", function="g")], detected=["SC03"]))
        self.assertEqual({c["category"]: c["status"] for c in filtered["categoryCoverage"]}["SC03"], "DETECTED")
        self.assertEqual(record["coverageAdjusted"], [])

    def test_unaffected_categories_and_informational_discards_keep_their_status(self):
        info = _finding("src/B.sol", category="SC05", severity="INFORMATIONAL")
        info["status"] = "informational"
        draft = self._draft([info], detected=["SC05"])
        filtered, record = self._filter(draft)
        self.assertEqual(filtered["categoryCoverage"], draft["categoryCoverage"])
        self.assertEqual(record["coverageAdjusted"], [])

    def test_pure_and_deterministic(self):  # M
        draft = self._draft([_finding("src/A.sol"), _finding("src/B.sol")], gas=[{"title": "t", "description": "d", "location": {"file": "src/C.sol"}}], detected=["SC08"])
        before = copy.deepcopy(draft)
        first = self._filter(draft)
        self.assertEqual(draft, before)  # never mutates its input
        self.assertEqual(first, self._filter(draft))

    def test_no_invalid_location_changes_nothing(self):  # N
        draft = self._draft([_finding("src/A.sol")], gas=[{"title": "t", "description": "d", "location": {"file": "src/A.sol"}}], detected=["SC08"])
        filtered, record = self._filter(draft)
        self.assertEqual(filtered, draft)
        self.assertEqual(record, {"discards": [], "discardedFindings": 0, "discardedGasSuggestions": 0, "coverageAdjusted": []})
        self.assertEqual(mp.pass_location_errors(filtered, self.ENTRY), [])

    def test_scope_rules_are_split(self):
        draft = self._draft([_finding("src/B.sol")])
        draft["scope"] = {"completeness": "complete", "reasons": []}
        self.assertEqual(len(mp.pass_completeness_errors(draft, self.ENTRY)), 1)
        self.assertEqual(len(mp.pass_location_errors(draft, self.ENTRY)), 1)
        self.assertEqual(mp.pass_scope_errors(draft, self.ENTRY), mp.pass_completeness_errors(draft, self.ENTRY) + mp.pass_location_errors(draft, self.ENTRY))
        partial = self._draft([_finding("src/A.sol")])
        self.assertEqual(mp.pass_completeness_errors(partial, self.ENTRY), [])  # "partial" is never an error by itself


class FindingLevelDiscardRunTests(unittest.TestCase):
    """Finding-level discard through the real run: pass validation, merge,
    global scope, one scoring/validation/render (docs/decisiones.md D-100)."""

    def setUp(self):
        self.art = _art()
        self.budget = _budget_for(self.art, V1, 3)
        self.plan = _plan(self.art, V1, self.budget)
        self.own = [p["primaryFiles"] for p in self.plan.passes]

    def _run(self, script):
        return _run(self.art, self.budget, ScriptedProvider(script), counters=_WorkerCounters())

    def _draft(self, findings, detected=("SC08",)):
        draft = _valid_draft()
        draft["findings"] = findings
        for entry in draft["categoryCoverage"]:
            if entry["category"] != "SC01":
                entry["status"] = "DETECTED" if entry["category"] in detected else "NOT_DETECTED"
        return draft

    def test_valid_kept_invalid_discarded_pass_succeeds_and_report_says_so(self):  # A, J, L
        bad = _finding(self.own[2][0], function="g")
        bad["description"] = "DISCARD-ME-UNIQUE"
        result, counters = self._run({1: [self._draft([_finding(self.own[0][0]), bad])]})
        first = result["multiPass"]["passes"][0]
        self.assertEqual((first["status"], first["attempts"], first["discardedFindings"]), (mp.PASS_SUCCESS, 1, 1))
        self.assertEqual(first["discards"][0]["invalidLocations"][0]["fileKind"], "excluded")
        scope = result["scoredReport"]["scope"]
        self.assertEqual(scope["completeness"], "partial")  # every pass succeeded, but a discard forbids "complete"
        [reason] = [r for r in scope["reasons"] if r["code"] == mp.DISCARDED_REASON_CODE]
        self.assertIn("1 finding(s) and 0 gas suggestion(s) discarded", reason["detail"])
        self.assertIn("pass 1 of 3: SC08/LOW at %s" % self.own[2][0], reason["detail"])
        self.assertIn(mp.MULTI_PASS_DISCARD_LIMITATION, result["scoredReport"]["limitations"])
        rendered = result["rendered"]
        self.assertIn(mp.DISCARDED_REASON_CODE, rendered)
        self.assertIn(mp.MULTI_PASS_DISCARD_LIMITATION, rendered)
        self.assertNotIn("DISCARD-ME-UNIQUE", rendered)  # never rendered as a finding
        self.assertEqual((counters.pipeline, counters.render), (1, 1))

    def test_all_findings_discarded_pass_still_succeeds(self):  # B
        result, _ = self._run({1: [self._draft([_finding(self.own[1][0]), _finding(self.own[2][0])])]})
        first = result["multiPass"]["passes"][0]
        self.assertEqual((first["status"], first["discardedFindings"]), (mp.PASS_SUCCESS, 2))
        self.assertEqual(result["scoredReport"]["scope"]["completeness"], "partial")
        self.assertFalse(any(f["locations"][0]["file"] in self.own[0] for f in result["scoredReport"]["findings"]))

    def test_discarded_duplicate_never_reaches_merge(self):  # H
        target = self.own[1][0]
        intruder = _finding(target, severity="CRITICAL")
        intruder["description"] = "from pass 1"
        result, _ = self._run({1: [self._draft([intruder])], 2: [self._draft([_finding(target)])]})
        on_target = [f for f in result["scoredReport"]["findings"] if f["locations"][0]["file"] == target]
        self.assertEqual(len(on_target), 1)
        self.assertEqual((on_target[0]["severity"], on_target[0]["description"], on_target[0]["mergedCount"]), ("LOW", "d", 1))
        self.assertEqual(on_target[0]["stableKey"], compute_stable_key(_finding(target)))

    def test_owner_pass_failed_no_discarded_finding_appears(self):  # I
        err = llm_client.ProviderError("down")
        result, _ = self._run({1: [self._draft([_finding(self.own[1][0], severity="HIGH")])], 2: [err, err, err]})
        passes = result["multiPass"]["passes"]
        self.assertEqual((passes[0]["status"], passes[1]["status"]), (mp.PASS_SUCCESS, mp.PASS_FAILED))
        self.assertFalse(any(f["locations"][0]["file"] in self.own[1] for f in result["scoredReport"]["findings"]))
        codes = [r["code"] for r in result["scoredReport"]["scope"]["reasons"]]
        self.assertIn(mp.FAILED_PASSES_REASON_CODE, codes)
        self.assertIn(mp.DISCARDED_REASON_CODE, codes)

    def test_dropped_category_is_not_falsely_detected_globally(self):  # K
        sc03 = _finding(self.own[1][0], category="SC03")
        result, _ = self._run({1: [self._draft([sc03], detected=("SC03",))]})
        report = result["scoredReport"]
        coverage = {c["category"]: c["status"] for c in report["categoryCoverage"]}
        self.assertNotIn("SC03", [f["category"] for f in report["findings"]])
        self.assertNotEqual(coverage["SC03"], "DETECTED")
        self.assertEqual(validate_report(report), [])  # global R-04 / R-05 hold
        self.assertEqual(result["multiPass"]["passes"][0]["coverageAdjusted"], ["SC03"])

    def test_same_input_same_discard_record(self):  # M
        script = {1: [self._draft([_finding(self.own[0][0]), _finding(self.own[2][0], function="g")])]}
        first, _ = self._run(copy.deepcopy(script))
        second, _ = self._run(copy.deepcopy(script))
        self.assertEqual(first["multiPass"], second["multiPass"])
        self.assertEqual(first["rendered"], second["rendered"])

    def test_no_discard_run_is_unchanged(self):  # N
        result, _ = self._run({})
        self.assertEqual(result["scoredReport"]["scope"]["completeness"], "complete")
        self.assertNotIn(mp.MULTI_PASS_DISCARD_LIMITATION, result["scoredReport"]["limitations"])
        self.assertNotIn(mp.DISCARDED_REASON_CODE, [r["code"] for r in result["scoredReport"]["scope"]["reasons"]])
        self.assertTrue(all(p["discardedFindings"] == 0 and p["discards"] == [] for p in result["multiPass"]["passes"]))

    def test_global_scope_forbids_complete_with_any_discard(self):  # J
        outcomes = [{"passIndex": p["passIndex"], "passCount": p["passCount"], "primaryFiles": p["primaryFiles"], "status": mp.PASS_SUCCESS,
                     "discardedFindings": 0, "discardedGasSuggestions": 0, "discards": []} for p in self.plan.passes]
        self.assertEqual(mp.global_scope(self.art, self.plan, outcomes)["completeness"], "complete")
        outcomes[1].update(discardedGasSuggestions=1, discards=[{"kind": "gas", "index": 0, "location": "x.sol", "fileKind": "unknown", "reason": mp.DISCARD_REASON}])
        scope = mp.global_scope(self.art, self.plan, outcomes)
        self.assertEqual(scope["completeness"], "partial")
        self.assertIn("0 finding(s) and 1 gas suggestion(s) discarded", [r for r in scope["reasons"] if r["code"] == mp.DISCARDED_REASON_CODE][0]["detail"])


class _FakeSdkTimeout(Exception):
    pass


class _FakeSdk:
    """Stands in for both the anthropic and the openai module with their
    real retry semantics (audit finding F1): a client built without
    max_retries retries a failed request DEFAULT_MAX_RETRIES more times
    internally, as both real SDKs do. responder(prompt, timeout) returns
    the text of one HTTP attempt or raises _FakeSdkTimeout after advancing
    the fake clock; every HTTP attempt is recorded."""

    DEFAULT_MAX_RETRIES = 2

    def __init__(self, responder):
        self.responder = responder
        self.client_kwargs = []
        self.http_attempts = []

    def _create(self, max_retries, call):
        prompt = call["messages"][0]["content"]
        for _ in range(max_retries + 1):
            self.http_attempts.append(call["timeout"])
            try:
                return self.responder(prompt, call["timeout"])
            except _FakeSdkTimeout:
                continue
        raise _FakeSdkTimeout()

    def Anthropic(self, **kwargs):
        self.client_kwargs.append(kwargs)
        retries = kwargs.get("max_retries", self.DEFAULT_MAX_RETRIES)

        def create(**call):
            text = self._create(retries, call)
            return SimpleNamespace(content=[SimpleNamespace(type="text", text=text)])
        return SimpleNamespace(messages=SimpleNamespace(create=create))

    def OpenAI(self, **kwargs):
        self.client_kwargs.append(kwargs)
        retries = kwargs.get("max_retries", self.DEFAULT_MAX_RETRIES)

        def create(**call):
            text = self._create(retries, call)
            choice = SimpleNamespace(finish_reason="stop", message=SimpleNamespace(content=text))
            return SimpleNamespace(choices=[choice], usage=None)
        return SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))


def _real_provider(kind, sdk, **kwargs):
    """A real AnthropicLLMProvider / DeepSeekLLMProvider on top of _FakeSdk."""
    if kind == "anthropic":
        with mock.patch.object(llm_client, "anthropic", sdk):
            return llm_client.AnthropicLLMProvider(api_key="fake-key", model="m", **kwargs)
    with mock.patch.object(llm_client, "openai", sdk):
        return llm_client.DeepSeekLLMProvider(api_key="fake-key", model="m", **kwargs)


class _AppCalls:
    """Counts the application-level provider.complete() calls (each one is
    one of run_step6_with_retries' own attempts) and their timeouts."""

    def __init__(self, provider):
        self.provider = provider
        self.timeouts = []

    def complete(self, prompt, max_output_tokens, timeout_seconds):
        self.timeouts.append(timeout_seconds)
        return self.provider.complete(prompt, max_output_tokens, timeout_seconds)


class SdkRetryPolicyTests(unittest.TestCase):
    """Audit finding F1: under a Step 6 deadline (multi-pass) the provider's
    SDK must not retry internally - retries are the application's own
    (MAX_STEP6_ATTEMPTS per pass, each sized by the deadline). Single-pass
    keeps the SDK's historical default retries."""

    DEADLINE = 250  # provider window: 250 - 20 s final-pipeline reserve = 230 s
    WINDOW = DEADLINE - llm_client.STEP6_FINAL_PIPELINE_RESERVE_SECONDS

    def setUp(self):
        self.art = _art()
        self.budget = _budget_for(self.art, V1, 2)

    def _timing_out_sdk(self, clock):
        def responder(prompt, timeout):
            clock.now += timeout
            raise _FakeSdkTimeout()
        return _FakeSdk(responder)

    def _run_all_timeouts(self, kind, sdk_max_retries):
        clock = _FakeClock()
        sdk = self._timing_out_sdk(clock)
        app = _AppCalls(_real_provider(kind, sdk, **({} if sdk_max_retries is None else {"sdk_max_retries": sdk_max_retries})))
        start = clock.now
        with self.assertRaises(llm_client.Step6Failed):
            _run(self.art, self.budget, app, deadline_seconds=self.DEADLINE, clock=clock)
        return sdk, app, clock.now - start

    def test_decision_point_maps_deadline_to_zero_and_single_pass_to_sdk_default(self):  # 1, 2, 3
        self.assertEqual(llm_client.MULTI_PASS_SDK_MAX_RETRIES, 0)
        self.assertEqual(llm_client.sdk_max_retries_for(self.DEADLINE), 0)
        self.assertEqual(llm_client.sdk_max_retries_for(0), 0)
        self.assertIsNone(llm_client.sdk_max_retries_for(None))

    def test_anthropic_multi_pass_client_gets_max_retries_zero(self):  # 1
        sdk = _FakeSdk(lambda prompt, timeout: "{}")
        provider = _real_provider("anthropic", sdk, sdk_max_retries=llm_client.sdk_max_retries_for(self.DEADLINE))
        self.assertEqual(sdk.client_kwargs, [{"api_key": "fake-key", "max_retries": 0}])
        self.assertEqual(provider.sdk_max_retries, 0)

    def test_deepseek_multi_pass_client_gets_max_retries_zero(self):  # 2
        sdk = _FakeSdk(lambda prompt, timeout: "{}")
        provider = _real_provider("deepseek", sdk, sdk_max_retries=llm_client.sdk_max_retries_for(self.DEADLINE))
        self.assertEqual(sdk.client_kwargs, [{"api_key": "fake-key", "base_url": "https://api.deepseek.com", "max_retries": 0}])
        self.assertEqual(provider.sdk_max_retries, 0)

    def test_single_pass_clients_are_built_exactly_as_before(self):  # 3
        for kind, expected in (("anthropic", {"api_key": "fake-key"}),
                               ("deepseek", {"api_key": "fake-key", "base_url": "https://api.deepseek.com"})):
            for kwargs in ({}, {"sdk_max_retries": llm_client.sdk_max_retries_for(None)}):
                with self.subTest(kind=kind, kwargs=kwargs):
                    sdk = _FakeSdk(lambda prompt, timeout: "{}")
                    provider = _real_provider(kind, sdk, **kwargs)
                    self.assertEqual(sdk.client_kwargs, [expected])  # no max_retries: the SDK's own default, unchanged
                    self.assertIsNone(provider.sdk_max_retries)

    def test_invalid_sdk_max_retries_is_refused(self):
        for kind in ("anthropic", "deepseek"):
            for bad in (-1, True, 1.5, "0"):
                with self.subTest(kind=kind, bad=bad):
                    with self.assertRaises(llm_client.LLMError):
                        _real_provider(kind, _FakeSdk(lambda prompt, timeout: "{}"), sdk_max_retries=bad)

    def test_timing_out_provider_makes_no_hidden_sdk_retries_in_multi_pass(self):  # 4
        for kind in ("anthropic", "deepseek"):
            with self.subTest(kind=kind):
                sdk, app, _ = self._run_all_timeouts(kind, llm_client.sdk_max_retries_for(self.DEADLINE))
                self.assertTrue(app.timeouts)
                self.assertEqual(sdk.http_attempts, app.timeouts)  # one HTTP attempt per application attempt

    def test_deadline_is_respected_with_sdk_retries_disabled(self):  # 5
        for kind in ("anthropic", "deepseek"):
            with self.subTest(kind=kind):
                _, app, elapsed = self._run_all_timeouts(kind, llm_client.sdk_max_retries_for(self.DEADLINE))
                self.assertLessEqual(elapsed, self.WINDOW)
                self.assertLessEqual(sum(app.timeouts), self.WINDOW)

    def test_sdk_default_retries_would_overrun_the_deadline(self):  # F1 reproduced: why the decision point exists
        for kind in ("anthropic", "deepseek"):
            with self.subTest(kind=kind):
                sdk, app, elapsed = self._run_all_timeouts(kind, None)
                self.assertEqual(len(sdk.http_attempts), (_FakeSdk.DEFAULT_MAX_RETRIES + 1) * len(app.timeouts))
                self.assertGreater(elapsed, self.WINDOW)

    def test_application_retries_still_work_with_sdk_retries_disabled(self):  # 6
        for kind in ("anthropic", "deepseek"):
            with self.subTest(kind=kind):
                clock = _FakeClock()
                failures = {2: 1}  # pass 2's first HTTP attempt times out, its application retry succeeds

                def responder(prompt, timeout):
                    index = _pass_index(prompt)
                    if failures.get(index):
                        failures[index] -= 1
                        clock.now += timeout
                        raise _FakeSdkTimeout()
                    clock.now += 10
                    return json.dumps(_valid_draft(_primary_files(prompt)[:1]))

                sdk = _FakeSdk(responder)
                app = _AppCalls(_real_provider(kind, sdk, sdk_max_retries=llm_client.sdk_max_retries_for(600)))
                result, _ = _run(self.art, self.budget, app, deadline_seconds=600, clock=clock)
                self.assertEqual(result["status"], "rendered")
                passes = result["multiPass"]["passes"]
                self.assertEqual([p["status"] for p in passes], [mp.PASS_SUCCESS, mp.PASS_SUCCESS])
                self.assertEqual([p["attempts"] for p in passes], [1, 2])
                self.assertEqual(len(sdk.http_attempts), 3)
                self.assertEqual(sdk.http_attempts, app.timeouts)
                self.assertEqual(result["scoredReport"]["scope"]["completeness"], "complete")

    def test_application_attempt_cap_per_pass_is_unchanged(self):  # 6
        clock = _FakeClock()

        def responder(prompt, timeout):
            clock.now += 1
            return "not json"
        sdk = _FakeSdk(responder)
        app = _AppCalls(_real_provider("deepseek", sdk, sdk_max_retries=0))
        with self.assertRaises(llm_client.Step6Failed):
            _run(self.art, self.budget, app, deadline_seconds=600, clock=clock)
        self.assertEqual(len(app.timeouts), 2 * llm_client.MAX_STEP6_ATTEMPTS)
        self.assertEqual(len(sdk.http_attempts), 2 * llm_client.MAX_STEP6_ATTEMPTS)


class WorkerPlumbingTests(unittest.TestCase):
    def test_supervisor_passes_max_passes_and_a_deadline_inside_the_wall_clock(self):
        import backend.worker_supervisor as ws
        config = ws.WorkerConfig(docker_image="i", network_name="n", proxy_host="h", proxy_port=1, llm_api_key="k", llm_model="m",
                                 wall_clock_timeout_seconds=600, max_passes=4)
        args = ws.build_docker_create_args(config, "c")
        self.assertIn("LLM_MAX_PASSES=4", args)
        self.assertIn("STEP6_DEADLINE_SECONDS=%d" % (600 - ws.WORKER_STEP6_STARTUP_RESERVE_SECONDS), args)
        self.assertIn("LLM_MAX_PASSES=1", ws.build_docker_create_args(ws.WorkerConfig(docker_image="i", network_name="n", proxy_host="h", proxy_port=1, llm_api_key="k", llm_model="m"), "c"))

    def test_main_refuses_an_incoherent_time_budget(self):
        import backend.main as main
        main._validate_step6_time_budget(300, 1)
        main._validate_step6_time_budget(30, 1)  # single-pass: no deadline, historical behavior
        main._validate_step6_time_budget(300, llm_client.MAX_STEP6_PASSES)
        with self.assertRaises(main.ConfigError):
            main._validate_step6_time_budget(300, llm_client.MAX_STEP6_PASSES + 1)
        with self.assertRaises(main.ConfigError):
            main._validate_step6_time_budget(60, 4)


if __name__ == "__main__":
    unittest.main()
