"""Tests for backend/black_friday.py (Phase 7, docs/decisiones.md D-086).
Pure function, no I/O - see that module's own docstring on why plan is
not a parameter (all three plans are equally eligible) and why "first-
time customer" is not re-implemented here (delegated to Stripe's own
PromotionCode.restrictions.first_time_transaction).

Run from the repository root: python -m unittest
"""
from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

import backend.black_friday as black_friday

PROMO_ID = "promo_bf_test"


class ResolvePromotionCodeTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 11, 25, 12, 0, 0, tzinfo=timezone.utc)
        self.start = datetime(2026, 11, 23, 0, 0, 0, tzinfo=timezone.utc)
        self.end = datetime(2026, 11, 30, 23, 59, 59, tzinfo=timezone.utc)

    def test_annual_inside_window_enabled_returns_the_promotion_code(self):
        result = black_friday.resolve_promotion_code("annual", self.now, True, self.start, self.end, PROMO_ID)
        self.assertEqual(result, PROMO_ID)

    def test_monthly_inside_window_returns_none(self):
        result = black_friday.resolve_promotion_code("monthly", self.now, True, self.start, self.end, PROMO_ID)
        self.assertIsNone(result)

    def test_disabled_returns_none_even_annual_inside_window(self):
        result = black_friday.resolve_promotion_code("annual", self.now, False, self.start, self.end, PROMO_ID)
        self.assertIsNone(result)

    def test_before_window_returns_none(self):
        result = black_friday.resolve_promotion_code("annual", self.start - timedelta(seconds=1), True, self.start, self.end, PROMO_ID)
        self.assertIsNone(result)

    def test_after_window_returns_none(self):
        result = black_friday.resolve_promotion_code("annual", self.end + timedelta(seconds=1), True, self.start, self.end, PROMO_ID)
        self.assertIsNone(result)

    def test_exact_window_boundaries_are_inclusive(self):
        self.assertEqual(black_friday.resolve_promotion_code("annual", self.start, True, self.start, self.end, PROMO_ID), PROMO_ID)
        self.assertEqual(black_friday.resolve_promotion_code("annual", self.end, True, self.start, self.end, PROMO_ID), PROMO_ID)

    def test_missing_promotion_code_id_returns_none_even_if_otherwise_eligible(self):
        result = black_friday.resolve_promotion_code("annual", self.now, True, self.start, self.end, None)
        self.assertIsNone(result)

    def test_missing_start_or_end_returns_none_fails_closed(self):
        self.assertIsNone(black_friday.resolve_promotion_code("annual", self.now, True, None, self.end, PROMO_ID))
        self.assertIsNone(black_friday.resolve_promotion_code("annual", self.now, True, self.start, None, PROMO_ID))

    def test_unrecognized_interval_returns_none(self):
        result = black_friday.resolve_promotion_code("weekly", self.now, True, self.start, self.end, PROMO_ID)
        self.assertIsNone(result)
