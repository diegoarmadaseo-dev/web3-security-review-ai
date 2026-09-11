"""Tests for config/modes.json and scripts/preprocess.py's loader for it
(Subfase 2.2 - Modes).

config/modes.json is the single source of truth for review-mode limits and
feature-gating; scripts/preprocess.py, scripts/validate_report.py and
scripts/render_report.py all read it through preprocess.load_modes_config().
These tests cover the loader's own validation (so a broken config fails
loudly instead of silently) and the real repository file.

Run from the repository root: python -m unittest
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SKILL_DIR = REPO_ROOT / ".claude" / "skills" / "web3-auditor"
SCRIPTS_DIR = SKILL_DIR / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import preprocess  # noqa: E402

REAL_CONFIG_PATH = str(SKILL_DIR / "config" / "modes.json")

VALID_MODE_ENTRY = {
    "maxEffectiveLoc": 1500,
    "maxSourceFiles": 5,
    "allowPatch": True,
    "allowGasSuggestions": True,
    "allowHtmlReport": False,
    "allowArchitectureChecks": False,
    "allowExecutiveSummary": False,
}


def _write_config(tmp_dir: str, data) -> str:
    path = os.path.join(tmp_dir, "modes.json")
    with open(path, "w", encoding="utf-8") as handle:
        if isinstance(data, str):
            handle.write(data)
        else:
            json.dump(data, handle)
    return path


class RealConfigTests(unittest.TestCase):
    """The actual config/modes.json shipped with the Skill must itself load cleanly."""

    def test_real_config_loads_without_error(self):
        config = preprocess.load_modes_config(REAL_CONFIG_PATH)
        self.assertEqual(set(config["modes"].keys()), {"quick", "standard", "pro"})

    def test_real_config_default_mode_is_standard(self):
        config = preprocess.load_modes_config(REAL_CONFIG_PATH)
        self.assertEqual(config["defaultMode"], "standard")

    def test_quick_forbids_every_extra_feature(self):
        config = preprocess.load_modes_config(REAL_CONFIG_PATH)
        quick = config["modes"]["quick"]
        for key in ("allowPatch", "allowGasSuggestions", "allowHtmlReport", "allowArchitectureChecks", "allowExecutiveSummary"):
            self.assertFalse(quick[key], "quick.%s should be false" % key)

    def test_only_pro_allows_html_architecture_and_executive_summary(self):
        config = preprocess.load_modes_config(REAL_CONFIG_PATH)
        for mode_name in ("quick", "standard"):
            mode = config["modes"][mode_name]
            self.assertFalse(mode["allowHtmlReport"], "%s.allowHtmlReport should be false" % mode_name)
            self.assertFalse(mode["allowArchitectureChecks"], "%s.allowArchitectureChecks should be false" % mode_name)
            self.assertFalse(mode["allowExecutiveSummary"], "%s.allowExecutiveSummary should be false" % mode_name)
        pro = config["modes"]["pro"]
        self.assertTrue(pro["allowHtmlReport"])
        self.assertTrue(pro["allowArchitectureChecks"])
        self.assertTrue(pro["allowExecutiveSummary"])

    def test_standard_and_pro_allow_patch_and_gas(self):
        config = preprocess.load_modes_config(REAL_CONFIG_PATH)
        for mode_name in ("standard", "pro"):
            mode = config["modes"][mode_name]
            self.assertTrue(mode["allowPatch"], "%s.allowPatch should be true" % mode_name)
            self.assertTrue(mode["allowGasSuggestions"], "%s.allowGasSuggestions should be true" % mode_name)

    def test_max_source_files_differs_between_standard_and_pro(self):
        # Subfase 2.2, first requirement: standard and pro must not share the same
        # (previously both-unlimited) file-count limit.
        config = preprocess.load_modes_config(REAL_CONFIG_PATH)
        standard_limit = config["modes"]["standard"]["maxSourceFiles"]
        pro_limit = config["modes"]["pro"]["maxSourceFiles"]
        self.assertNotEqual(standard_limit, pro_limit)
        self.assertIsNotNone(standard_limit)
        self.assertIsNone(pro_limit)

    def test_quick_is_the_most_restrictive_file_limit(self):
        config = preprocess.load_modes_config(REAL_CONFIG_PATH)
        self.assertEqual(config["modes"]["quick"]["maxSourceFiles"], 1)


class LoaderFailsLoudlyTests(unittest.TestCase):
    """No silent defaults: a missing or malformed config must raise, never fall back."""

    def test_missing_file_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(preprocess.ModesConfigError):
                preprocess.load_modes_config(os.path.join(tmp, "does-not-exist.json"))

    def test_invalid_json_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_config(tmp, "{not valid json")
            with self.assertRaises(preprocess.ModesConfigError):
                preprocess.load_modes_config(path)

    def test_non_object_root_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_config(tmp, [1, 2, 3])
            with self.assertRaises(preprocess.ModesConfigError):
                preprocess.load_modes_config(path)

    def test_empty_modes_object_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_config(tmp, {"defaultMode": "standard", "modes": {}})
            with self.assertRaises(preprocess.ModesConfigError):
                preprocess.load_modes_config(path)

    def test_mode_missing_a_required_key_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            broken = dict(VALID_MODE_ENTRY)
            del broken["allowPatch"]
            path = _write_config(tmp, {"defaultMode": "standard", "modes": {"standard": broken}})
            with self.assertRaises(preprocess.ModesConfigError):
                preprocess.load_modes_config(path)

    def test_wrong_type_for_limit_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            broken = dict(VALID_MODE_ENTRY)
            broken["maxEffectiveLoc"] = "1500"  # string, not int/null
            path = _write_config(tmp, {"defaultMode": "standard", "modes": {"standard": broken}})
            with self.assertRaises(preprocess.ModesConfigError):
                preprocess.load_modes_config(path)

    def test_bool_for_limit_raises(self):
        # bool is an int subclass in Python; must be rejected explicitly.
        with tempfile.TemporaryDirectory() as tmp:
            broken = dict(VALID_MODE_ENTRY)
            broken["maxSourceFiles"] = True
            path = _write_config(tmp, {"defaultMode": "standard", "modes": {"standard": broken}})
            with self.assertRaises(preprocess.ModesConfigError):
                preprocess.load_modes_config(path)

    def test_wrong_type_for_feature_flag_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            broken = dict(VALID_MODE_ENTRY)
            broken["allowHtmlReport"] = "yes"
            path = _write_config(tmp, {"defaultMode": "standard", "modes": {"standard": broken}})
            with self.assertRaises(preprocess.ModesConfigError):
                preprocess.load_modes_config(path)

    def test_default_mode_missing_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_config(tmp, {"modes": {"standard": VALID_MODE_ENTRY}})
            with self.assertRaises(preprocess.ModesConfigError):
                preprocess.load_modes_config(path)

    def test_default_mode_not_in_modes_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_config(tmp, {"defaultMode": "ultra", "modes": {"standard": VALID_MODE_ENTRY}})
            with self.assertRaises(preprocess.ModesConfigError):
                preprocess.load_modes_config(path)

    def test_valid_minimal_config_loads(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_config(tmp, {"defaultMode": "standard", "modes": {"standard": VALID_MODE_ENTRY}})
            config = preprocess.load_modes_config(path)
            self.assertEqual(config["defaultMode"], "standard")


class ResolveLimitsTests(unittest.TestCase):
    def test_resolve_limits_uses_injected_config_without_touching_disk(self):
        custom = {"defaultMode": "standard", "modes": {"standard": VALID_MODE_ENTRY}}
        limits = preprocess.resolve_limits("standard", None, modes_config=custom)
        self.assertEqual(limits["maxEffectiveLoc"], 1500)
        self.assertEqual(limits["maxSourceFiles"], 5)

    def test_resolve_limits_rejects_a_mode_absent_from_the_config(self):
        custom = {"defaultMode": "standard", "modes": {"standard": VALID_MODE_ENTRY}}
        with self.assertRaises(preprocess.ModesConfigError):
            preprocess.resolve_limits("pro", None, modes_config=custom)

    def test_resolve_limits_max_loc_override_still_applies(self):
        custom = {"defaultMode": "standard", "modes": {"standard": VALID_MODE_ENTRY}}
        limits = preprocess.resolve_limits("standard", 42, modes_config=custom)
        self.assertEqual(limits["maxEffectiveLoc"], 42)


class PreprocessCLIFailsLoudlyTests(unittest.TestCase):
    """main() must not run at all against a broken config - not even to reach argparse."""

    def test_main_reports_broken_config_as_a_clean_error_envelope(self):
        import contextlib
        import io as _io

        original = preprocess.MODES_CONFIG_PATH
        with tempfile.TemporaryDirectory() as tmp:
            preprocess.MODES_CONFIG_PATH = os.path.join(tmp, "missing.json")
            buf = _io.StringIO()
            try:
                with contextlib.redirect_stdout(buf):
                    exit_code = preprocess.main([])
            finally:
                preprocess.MODES_CONFIG_PATH = original
        self.assertEqual(exit_code, preprocess.EXIT_FAILED)
        payload = json.loads(buf.getvalue())
        self.assertFalse(payload["ok"])


if __name__ == "__main__":
    unittest.main()
