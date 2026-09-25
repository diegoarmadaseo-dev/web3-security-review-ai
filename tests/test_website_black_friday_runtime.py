"""Tests for the RUNTIME (client-side) Black Friday presentation script
website/build_site.py emits (D-087, docs/decisiones.md - fixes the
build-time staleness bug D-086 left: a static site built before
2026-11-23 would never show the campaign without a rebuild exactly at
the boundary).

Two layers, matching "distinguish build-time structural validation from
runtime campaign visibility" (the task's own framing):
  * BoundaryValuesEmbeddedInBuildTests (pure Python) - the REAL rendered
    page embeds the exact same UTC boundary strings content.py defines,
    never a second hand-typed copy that could drift.
  * BlackFridayBoundaryJsTests - the actual isBlackFridayActive() JS
    source website/build_site.py ships (BLACK_FRIDAY_BOUNDARY_CHECK_JS)
    is executed FOR REAL via Node.js (no browser, no DOM needed for this
    pure function) with deterministic INJECTED now/start/end values -
    never the machine's real clock. Skips cleanly (never fails) if
    Node.js is not installed, same convention tests/test_backend_worker_
    supervisor.py's own _docker_available() already established for an
    optional external tool.

The DOM-manipulation glue in render_black_friday_script() (querySelectorAll
+ .hidden - standard, minimal browser API surface) is not re-executed
here without a real browser/DOM (no jsdom or other npm package is added
- see module docstring on why); it is covered by direct code reading and
by BlackFridayWebsiteTests' structural assertions in test_website_build.py
that every data-bf-* element exists with the right default state.

Run from the repository root: python -m unittest
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
WEBSITE_DIR = REPO_ROOT / "website"
SCRIPTS_DIR = REPO_ROOT / ".claude" / "skills" / "web3-auditor" / "scripts"
for p in (str(WEBSITE_DIR), str(SCRIPTS_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

import build_site as bs  # noqa: E402
import content  # noqa: E402

TEST_BASE_URL = "https://example-vericexa.invalid"


def _node_available() -> bool:
    if shutil.which("node") is None:
        return False
    try:
        subprocess.run(["node", "--version"], capture_output=True, timeout=10, check=True)
        return True
    except Exception:
        return False


class BoundaryValuesEmbeddedInBuildTests(unittest.TestCase):
    """Pure Python, no Node needed - proves the REAL rendered page embeds
    content.py's own boundary strings, exactly, never a drifted copy."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        written = bs.build_site(self._tmp.name, base_url=TEST_BASE_URL)
        self.pricing_html = Path(written["pricing.html"]).read_text(encoding="utf-8")

    def test_script_tag_is_present_on_the_pricing_page(self):
        self.assertIn("<script>", self.pricing_html)
        self.assertIn("isBlackFridayActive", self.pricing_html)

    def test_embedded_start_and_end_match_content_py_exactly(self):
        self.assertIn(json.dumps(content.BLACK_FRIDAY_START_UTC), self.pricing_html)
        self.assertIn(json.dumps(content.BLACK_FRIDAY_END_UTC), self.pricing_html)

    def test_boundary_strings_are_utc_z_suffixed_never_ambiguous_local_time(self):
        self.assertTrue(content.BLACK_FRIDAY_START_UTC.endswith("Z"))
        self.assertTrue(content.BLACK_FRIDAY_END_UTC.endswith("Z"))

    def test_confirmed_d086_campaign_dates_are_exact(self):
        self.assertEqual(content.BLACK_FRIDAY_START_UTC, "2026-11-23T00:00:00Z")
        self.assertEqual(content.BLACK_FRIDAY_END_UTC, "2026-11-30T23:59:59Z")

    def test_script_never_contains_a_customer_facing_promo_code(self):
        # No code string, no "enter code", no coupon/promotion literal of
        # any kind - the script only ever toggles `hidden`.
        lowered = self.pricing_html.lower()
        for forbidden in ("promo code", "coupon code", "enter code", "promotion_code", "voucher"):
            with self.subTest(term=forbidden):
                self.assertNotIn(forbidden, lowered)

    def test_script_contains_no_discount_or_stripe_price_logic(self):
        script_block = re.search(r"<script>(.*?)</script>", self.pricing_html, re.S).group(1)
        for forbidden in ("stripe", "price_", "discount", "checkout"):
            with self.subTest(term=forbidden):
                self.assertNotIn(forbidden, script_block.lower())


@unittest.skipUnless(_node_available(), "Node.js is not installed/reachable - see module docstring")
class BlackFridayBoundaryJsTests(unittest.TestCase):
    """The EXACT shipped isBlackFridayActive() source, executed via Node
    with injected (never real) timestamps - see module docstring."""

    @classmethod
    def setUpClass(cls):
        # Computed independently via Python's own datetime - never
        # hand-typed as a literal ms number that could silently drift
        # from content.py's own ISO strings.
        cls.START_MS = int(datetime(2026, 11, 23, 0, 0, 0, tzinfo=timezone.utc).timestamp() * 1000)
        cls.END_MS = int(datetime(2026, 11, 30, 23, 59, 59, tzinfo=timezone.utc).timestamp() * 1000)

    def _is_active(self, now_ms: int, tz: str = "UTC") -> bool:
        script = "%s\nprocess.stdout.write(String(isBlackFridayActive(%d, %d, %d)));" % (
            bs.BLACK_FRIDAY_BOUNDARY_CHECK_JS, now_ms, self.START_MS, self.END_MS,
        )
        env = dict(os.environ)
        env["TZ"] = tz
        result = subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=10, env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip() == "true"

    def test_before_campaign_is_inactive(self):
        self.assertFalse(self._is_active(self.START_MS - 1))

    def test_exactly_at_start_is_active(self):
        self.assertTrue(self._is_active(self.START_MS))

    def test_inside_campaign_is_active(self):
        midpoint = (self.START_MS + self.END_MS) // 2
        self.assertTrue(self._is_active(midpoint))

    def test_exactly_at_end_is_active(self):
        self.assertTrue(self._is_active(self.END_MS))

    def test_immediately_after_end_is_inactive(self):
        self.assertFalse(self._is_active(self.END_MS + 1))

    def test_far_before_and_far_after_are_inactive(self):
        self.assertFalse(self._is_active(self.START_MS - 1000 * 60 * 60 * 24 * 365))
        self.assertFalse(self._is_active(self.END_MS + 1000 * 60 * 60 * 24 * 365))

    def test_result_is_identical_regardless_of_the_runtimes_own_local_timezone(self):
        # nowMs/Date.parse("...Z") are both epoch-ms (inherently UTC) -
        # the local TZ the JS engine itself runs under must never change
        # the verdict for the SAME instant.
        midpoint = (self.START_MS + self.END_MS) // 2
        for tz in ("UTC", "America/Los_Angeles", "Asia/Tokyo", "Pacific/Kiritimati"):
            with self.subTest(tz=tz):
                self.assertTrue(self._is_active(midpoint, tz=tz))
        for tz in ("UTC", "America/Los_Angeles", "Asia/Tokyo", "Pacific/Kiritimati"):
            with self.subTest(tz=tz, when="before"):
                self.assertFalse(self._is_active(self.START_MS - 1, tz=tz))

    def test_date_parse_of_the_real_embedded_strings_matches_the_independently_computed_ms(self):
        # Ties this test class's own START_MS/END_MS (computed via Python's
        # datetime, independently of the JS side) back to what Date.parse()
        # actually does with content.py's real strings - proves the two
        # languages agree on what these ISO strings mean, not just that
        # the JS function is internally consistent with itself.
        script = (
            'process.stdout.write(String(Date.parse(%s)) + "," + String(Date.parse(%s)));'
            % (json.dumps(content.BLACK_FRIDAY_START_UTC), json.dumps(content.BLACK_FRIDAY_END_UTC))
        )
        result = subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=10)
        js_start, js_end = result.stdout.strip().split(",")
        self.assertEqual(int(js_start), self.START_MS)
        self.assertEqual(int(js_end), self.END_MS)
