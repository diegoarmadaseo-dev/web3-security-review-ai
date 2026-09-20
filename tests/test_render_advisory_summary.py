"""Tests for scripts/render_advisory_summary.py (V3 Block 6, E3,
docs/decisiones.md D-074): Markdown rendering of already-computed advisory
outputs. Formatting only.

Run from the repository root: python -m unittest
"""
from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / ".claude" / "skills" / "web3-auditor" / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import render_advisory_summary as ras  # noqa: E402


class RenderMarkdownTests(unittest.TestCase):
    def test_positive_known_section_renders_its_title_and_fields(self):
        bundle = {"storageLayout": {"status": "unchanged", "contractsCompared": ["A"]}}
        text = ras.render_markdown(bundle)
        self.assertIn("## Storage Layout (B1)", text)
        self.assertIn("**status:** unchanged", text)
        self.assertIn("A", text)

    def test_positive_empty_bundle_yields_explicit_no_data_line(self):
        text = ras.render_markdown({})
        self.assertIn("No advisory tool outputs were provided", text)

    def test_negative_absent_tool_is_not_rendered_as_a_placeholder(self):
        text = ras.render_markdown({"storageLayout": {"status": "unchanged"}})
        self.assertNotIn("Cross-Contract Privilege Paths", text)

    def test_adversarial_unknown_key_is_rendered_generically_not_dropped(self):
        text = ras.render_markdown({"someFutureTool": {"status": "computed"}})
        self.assertIn("## someFutureTool", text)
        self.assertIn("**status:** computed", text)

    def test_adversarial_3000_depth_unknown_section_raises_clean_error_never_recursion_error(self):
        nested: dict = {}
        cursor = nested
        for _ in range(3000):
            cursor["x"] = {}
            cursor = cursor["x"]
        cursor["leaf"] = "bottom"
        with self.assertRaises(ras.RenderAdvisorySummaryError):
            ras.render_markdown({"someFutureTool": nested})

    def test_adversarial_newline_heading_control_char_key_never_injects_a_real_heading(self):
        adversarial_key = "evil\n## Fake Injected Heading\n\x00\x1b[31m"
        text = ras.render_markdown({adversarial_key: {"status": "x"}})
        self.assertNotIn("\x00", text)
        self.assertNotIn("\x1b", text)
        heading_lines = [line for line in text.split("\n") if line.startswith("##")]
        # Exactly the one legitimate heading this call produces - the
        # adversarial content must never become an INDEPENDENT heading line
        # (a substring match alone is not the right check: the content is
        # still visible, flattened as inert text inside that one heading).
        self.assertEqual(len(heading_lines), 1)
        self.assertIn("status", text)  # the legitimate data is still present, never dropped.

    def test_ordinary_unknown_key_still_renders_after_the_fix(self):
        text = ras.render_markdown({"anotherNewTool": {"status": "ok", "count": 3}})
        self.assertIn("## anotherNewTool", text)
        self.assertIn("**status:** ok", text)
        self.assertIn("**count:** 3", text)

    def test_adversarial_c1_control_characters_are_stripped(self):
        # \x80 (first C1 code point), \x85 (NEL), \x9b (CSI - the 8-bit
        # equivalent of ESC[, the exact class of escape a C0-only filter
        # would still let through), \x9f (last C1 code point).
        for cp, label in [(0x80, "C1-first"), (0x85, "NEL"), (0x9b, "CSI"), (0x9f, "C1-last")]:
            with self.subTest(label=label):
                char = chr(cp)
                bundle = {"someTool": {"field%s" % label: "a%sb" % char}}
                text = ras.render_markdown(bundle)
                self.assertNotIn(char, text)

    def test_adversarial_c1_key_never_injects_a_real_heading_no_data_loss(self):
        adversarial_key = "evil\x9b[31m\x85tail"
        text = ras.render_markdown({adversarial_key: {"status": "ok"}})
        self.assertNotIn("\x9b", text)
        self.assertNotIn("\x85", text)
        heading_lines = [line for line in text.split("\n") if line.startswith("##")]
        self.assertEqual(len(heading_lines), 1)  # no independent injected heading.
        self.assertIn("evil", text)  # the legitimate (sanitized) key text is preserved, never dropped.
        self.assertIn("tail", text)
        self.assertIn("**status:** ok", text)  # the legitimate data is preserved, never dropped.

    def test_normal_printable_unicode_is_never_touched(self):
        bundle = {"someTool": {"note": "café ñ 日本語 emoji\U0001F600 NBSP\xa0end"}}
        text = ras.render_markdown(bundle)
        self.assertIn("café ñ 日本語 emoji\U0001F600 NBSP\xa0end", text)

    def test_adversarial_malformed_section_value_reported_never_crashes(self):
        text = ras.render_markdown({"storageLayout": "not-an-object"})
        self.assertIn("malformed entry", text)

    def test_adversarial_deeply_nested_list_never_crashes(self):
        bundle = {"privilegePath": {"paths": [{"hops": [{"from": "A", "to": "B"}]}]}}
        text = ras.render_markdown(bundle)
        self.assertIn("A", text)
        self.assertIn("B", text)

    def test_large_list_is_capped_with_a_remainder_note(self):
        bundle = {"upgradeGap": {"contractsFlagged": ["c%d" % i for i in range(30)]}}
        text = ras.render_markdown(bundle)
        self.assertIn("more)", text)

    def test_never_computes_or_selects_which_fields_matter(self):
        # Every top-level key of the section must appear somewhere in the
        # output - a curating/selective renderer would drop some.
        section = {"a": 1, "b": 2, "c": 3}
        text = ras.render_markdown({"bytecodeSize": section})
        for key in section:
            self.assertIn("**%s:**" % key, text)

    def test_malformed_bundle_not_a_dict_raises(self):
        with self.assertRaises(ras.RenderAdvisorySummaryError):
            ras.render_markdown("not-a-dict")

    def test_never_mutates_bundle(self):
        bundle = {"storageLayout": {"status": "unchanged"}}
        before = json.loads(json.dumps(bundle))
        ras.render_markdown(bundle)
        self.assertEqual(bundle, before)


class CliTests(unittest.TestCase):
    def _run_cli(self, argv):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = ras.main(argv)
        return exit_code, stdout.getvalue()

    def test_cli_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "input.json"
            p.write_text(json.dumps({"storageLayout": {"status": "unchanged"}}), encoding="utf-8")
            exit_code, out = self._run_cli([str(p)])
        self.assertEqual(exit_code, ras.EXIT_OK)
        self.assertIn("# Advisory Checks Summary", out)

    def test_cli_reads_from_stdin_when_input_omitted(self):
        old_stdin = sys.stdin
        sys.stdin = io.StringIO(json.dumps({}))
        try:
            exit_code, out = self._run_cli([])
        finally:
            sys.stdin = old_stdin
        self.assertEqual(exit_code, ras.EXIT_OK)
        self.assertIn("No advisory tool outputs", out)

    def test_cli_malformed_json_yields_clean_error_envelope(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.json"
            bad.write_text("not json", encoding="utf-8")
            exit_code, out = self._run_cli([str(bad)])
        self.assertEqual(exit_code, ras.EXIT_FAILED)
        self.assertFalse(json.loads(out)["ok"])


class CliWiredThroughUnifiedDispatcherTests(unittest.TestCase):
    def test_render_advisory_summary_is_registered_in_cli_commands(self):
        import cli
        self.assertEqual(cli.COMMANDS["render-advisory-summary"], "render_advisory_summary")


if __name__ == "__main__":
    unittest.main()
