"""Tests for the D-115 Stripe Sandbox E2E harness (tests/stripe_sandbox_e2e.py)
itself, run entirely in --simulate mode (tests/stripe_simulator.py): no
network, no real Stripe, no secrets. Proves the harness passes on a correct
backend, prints every stage, refuses unsafe configuration (live key, missing
Price IDs, env file inside the repository) without printing any secret, and
fails with a precise diagnosis (wrong price amount, unpaid / expired
Checkout, missing events) - including the WAITING -> --resume path.

Run from the repository root: python -m unittest tests.test_stripe_sandbox_e2e
"""
from __future__ import annotations

import contextlib
import io
import os
import shutil
import tempfile
import unittest

import backend.plans as plans
import tests.stripe_sandbox_e2e as e2e
from tests.stripe_simulator import StripeSimulator

STAGES = ("Configuración", "Price ID verificado", "Servidor local arrancado", "Checkout creado", "Payment confirmado", "Webhook recibido",
          "Webhook verificado", "Entitlement actualizado", "Quota actualizado", "Consumo verificado", "Idempotencia verificada",
          "Firma inválida rechazada", "E2E PASS")
SENTINEL_SECRET = "whsec_SENTINEL_never_printed_0123456789"
SENTINEL_KEY = "sk_test_SENTINEL_never_printed_9876543210"


def _run(argv, env=None):
    lines = []
    stderr = io.StringIO()
    with contextlib.redirect_stderr(stderr):
        code = e2e.main(list(argv) + ["--poll", "0.01", "--event-timeout", "2"], env=env or {}, out=lines.append)
    return code, "\n".join(lines)


class HarnessSimulatedRunTests(unittest.TestCase):
    def test_quick_and_a_subscription_pass_with_every_stage_in_order(self):
        for plan in ("quick", "pro-annual"):
            with self.subTest(plan=plan):
                code, output = _run(["--plan", plan, "--simulate"])
                self.assertEqual(code, e2e.EXIT_PASS, output)
                positions = [output.find(stage) for stage in STAGES]
                self.assertNotIn(-1, positions, output)
                self.assertEqual(positions, sorted(positions), output)
                self.assertEqual("Cancelación verificada" in output, plan != "quick")

    def test_all_five_price_modes_pass_in_shuffled_event_order(self):
        code, output = _run(["--plan", "all", "--simulate", "--shuffle"])
        self.assertEqual(code, e2e.EXIT_PASS, output)
        for name in e2e.PLAN_CHOICES:
            self.assertIn("-- %s" % name, output)
        self.assertEqual(output.count("Checkout creado"), 5)

    def test_secrets_are_never_printed(self):
        code, output = _run(["--plan", "quick", "--simulate"], env={"STRIPE_SECRET_KEY": SENTINEL_KEY, "STRIPE_WEBHOOK_SECRET": SENTINEL_SECRET})
        self.assertEqual(code, e2e.EXIT_PASS, output)
        self.assertNotIn("SENTINEL", output)
        self.assertIn("clave Stripe: PRESENTE (sk_test", output)
        self.assertIn("webhook secret: STRIPE_WEBHOOK_SECRET", output)


class HarnessConfigurationTests(unittest.TestCase):
    def _env(self, **overrides):
        env = {"STRIPE_SECRET_KEY": SENTINEL_KEY}
        env.update({name: e2e.DOCUMENTED_SANDBOX_PRICE_IDS[key] for key, name in plans.PRICE_ENV_VARS.items()})
        env.update(overrides)
        return {k: v for k, v in env.items() if v is not None}

    def test_live_or_non_secret_keys_are_blocked_without_echoing_them(self):
        for key in ("sk_live_SENTINEL_live_key_value", "rk_live_SENTINEL_live_key_value", "pk_test_SENTINEL_publishable"):
            code, output = _run(["--check-config"], env=self._env(STRIPE_SECRET_KEY=key))
            self.assertEqual(code, e2e.EXIT_BLOCKED, output)
            self.assertIn("E2E BLOCKED en 'Configuración'", output)
            self.assertNotIn("SENTINEL", output)

    def test_missing_or_malformed_values_are_each_named(self):
        code, output = _run(["--check-config"], env=self._env(STRIPE_PRICE_PRO_ANNUAL=None, STRIPE_PRICE_QUICK_ONETIME="prod_not_a_price",
                                                              STRIPE_WEBHOOK_SECRET="not_whsec"))
        self.assertEqual(code, e2e.EXIT_BLOCKED)
        for fragment in ("STRIPE_PRICE_PRO_ANNUAL: AUSENTE", "STRIPE_PRICE_QUICK_ONETIME: no tiene forma price_", "STRIPE_WEBHOOK_SECRET: presente pero"):
            self.assertIn(fragment, output)
        code, output = _run(["--check-config"], env=self._env(STRIPE_PRICE_PRO_ANNUAL=e2e.DOCUMENTED_SANDBOX_PRICE_IDS["vericexa_pro_monthly"]))
        self.assertEqual(code, e2e.EXIT_BLOCKED)
        self.assertIn("more than one price mode", output)

    def test_env_file_must_live_outside_the_repository(self):
        inside = os.path.join(e2e.REPO_ROOT, "tests", "stripe_sandbox_e2e.py")
        code, output = _run(["--check-config", "--env-file", inside])
        self.assertEqual((code, "OUTSIDE the repository" in output), (e2e.EXIT_BLOCKED, True))
        tmp = tempfile.mkdtemp(prefix="e2e-envfile-")
        self.addCleanup(shutil.rmtree, tmp, True)
        path = os.path.join(tmp, "stripe-sandbox.env")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("# comment\nexport STRIPE_SECRET_KEY='sk_live_SENTINEL_from_file'\nOTHER=ignored\n")
        code, output = _run(["--check-config", "--simulate", "--env-file", path])
        self.assertEqual(code, e2e.EXIT_BLOCKED, output)                  # the file's (live) key overrides, and is refused
        self.assertIn("clave LIVE", output)
        self.assertNotIn("SENTINEL", output)
        self.assertEqual(e2e.load_env_file(path), {"STRIPE_SECRET_KEY": "sk_live_SENTINEL_from_file"})

    def test_check_config_verifies_the_prices_in_stripe(self):
        code, output = _run(["--check-config", "--simulate"])
        self.assertEqual(code, e2e.EXIT_PASS, output)
        self.assertEqual(output.count("Price ID verificado en Stripe"), 5)
        self.assertIn("CONFIG OK", output)

    def test_a_price_that_differs_from_the_catalog_fails_with_the_reason(self):
        prices = dict(e2e.DOCUMENTED_SANDBOX_PRICE_IDS)
        sim = StripeSimulator(prices)
        sim.prices_store[prices["vericexa_pro_annual"]]["unit_amount"] = 100
        sim.prices_store[prices["vericexa_quick_onetime"]]["active"] = False
        sim.prices_store[prices["vericexa_standard_monthly"]]["livemode"] = True
        del sim.prices_store[prices["vericexa_standard_annual"]]
        with self.assertRaises(e2e.HarnessFailure) as ctx:
            e2e.verify_prices(sim, prices)
        for fragment in ("vericexa_pro_annual: importe 100 usd, el catálogo", "vericexa_quick_onetime: la Price está archivada",
                         "vericexa_standard_monthly: la Price no es de Sandbox", "vericexa_standard_annual (price_1UMFvU1jc8PYYLrPg7Kia6bO): InvalidRequestError"):
            self.assertIn(fragment, ctx.exception.diagnosis)


class HarnessDiagnosisTests(unittest.TestCase):
    def setUp(self):
        self.state_dir = tempfile.mkdtemp(prefix="e2e-diag-")
        self.addCleanup(shutil.rmtree, self.state_dir, True)
        self.lines = []
        cfg = e2e.check_config({}, simulate=True)
        self.harness = e2e.Harness(cfg, True, self.lines.append, self.state_dir, timeout=0.2, event_timeout=0.2, poll_seconds=0.01,
                                   shuffle=False, keep_subscription=False)
        self.stderr = contextlib.redirect_stderr(io.StringIO())
        self.stderr.__enter__()
        self.harness.start_server()
        self.addCleanup(self.stderr.__exit__, None, None, None)
        self.addCleanup(self.harness.stop_server)

    def test_an_unpaid_checkout_waits_then_resumes_to_pass(self):
        state = self.harness.create_checkout("standard", "annual")
        self.harness.simulate = False                                     # behave like real mode: nobody pays
        with self.assertRaises(e2e.HarnessFailure) as ctx:
            self.harness.wait_for_payment(state)
        self.assertEqual(ctx.exception.code, e2e.EXIT_WAITING)
        self.assertIn("--resume %s" % self.state_dir, ctx.exception.diagnosis)
        self.assertTrue(any("ACCIÓN HUMANA" in line for line in self.lines))
        self.assertTrue(any(state["checkout_url"] in line for line in self.lines))
        self.harness.client.pay_checkout(state["session_id"])            # the human pays later...
        self.harness.run_plan("standard", "annual", resume=state)        # ...and the run resumes from the saved state
        self.assertTrue(any("Cancelación verificada" in line for line in self.lines))

    def test_an_expired_checkout_fails_precisely(self):
        state = self.harness.create_checkout("quick", "one_time")
        self.harness.client.checkout.sessions.expire(state["session_id"])
        self.harness.simulate = False
        with self.assertRaises(e2e.HarnessFailure) as ctx:
            self.harness.wait_for_payment(state)
        self.assertEqual((ctx.exception.stage, ctx.exception.code), ("Payment confirmado", e2e.EXIT_FAIL))
        self.assertIn("expiró", ctx.exception.diagnosis)

    def test_missing_stripe_events_are_named(self):
        state = self.harness.create_checkout("pro", "monthly")
        state = self.harness.wait_for_payment(state)
        self.harness.client.emitted[:] = [e for e in self.harness.client.emitted if e["type"] != "invoice.paid"]
        with self.assertRaises(e2e.HarnessFailure) as ctx:
            self.harness.fetch_events(state, ["checkout.session.completed", "customer.subscription.created", "invoice.paid"])
        self.assertEqual(ctx.exception.stage, "Webhook recibido")
        self.assertIn("no generó invoice.paid", ctx.exception.diagnosis)

    def test_a_backend_rejection_fails_the_run_with_its_outcome(self):
        state = self.harness.create_checkout("quick", "one_time")
        self.harness.client.checkout.sessions.line_items.store[state["session_id"]] = [("price_wrong", 1)]
        state = self.harness.wait_for_payment(state)
        with self.assertRaises(e2e.HarnessFailure) as ctx:
            self.harness.relay(self.harness.fetch_events(state, ["checkout.session.completed"]))
        self.assertEqual(ctx.exception.stage, "Webhook verificado")
        self.assertIn("rejected:line_items_mismatch", ctx.exception.diagnosis)


if __name__ == "__main__":
    unittest.main()
