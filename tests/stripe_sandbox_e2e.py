#!/usr/bin/env python3
"""D-115 Stripe Sandbox E2E harness (docs/stripe-billing.md, "E2E Sandbox").

Runs the REAL billing path end to end against Stripe's Sandbox (test mode):

  configuration check -> the 5 Price IDs verified in Stripe -> local web
  server (temporary SQLite + local storage, started by this process) ->
  POST /billing/checkout -> the customer pays on Stripe's hosted Checkout
  (the ONE human step) -> Stripe's events for that checkout are read from
  the Stripe API and relayed, signed, to the local /billing/webhook ->
  entitlement + quota checked -> a scan consumes the purchase -> replays
  are no-ops, a forged signature is refused -> (subscriptions) the test
  subscription is canceled and the cancellation verified -> E2E PASS.

No Stripe CLI, no tunnel, no external terminal state: Stripe's events are
fetched over the authenticated API (so they are authentic) and signed with
the webhook secret the local server was started with, which exercises the
server's real signature verification. What this does NOT cover is Stripe
delivering to a registered public endpoint - that is a deployment check
(docs/stripe-billing.md, "Staging").

Secrets: read from the environment or from --env-file (a KEY=VALUE file
OUTSIDE the repository - refused inside it); never printed, never logged,
never written anywhere. Only "test"/Sandbox keys are accepted.

  python -m tests.stripe_sandbox_e2e --check-config [--env-file PATH]
  python -m tests.stripe_sandbox_e2e --plan quick [--env-file PATH]
  python -m tests.stripe_sandbox_e2e --plan all --simulate      # no Stripe, no secrets, no human

Exit codes: 0 E2E PASS, 1 E2E FAIL, 2 BLOCKED (configuration), 3 WAITING
(the Checkout was not paid in time - rerun with the printed --resume).
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import random
import secrets
import shutil
import sys
import tempfile
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import backend.auth as auth  # noqa: E402
import backend.billing as billing  # noqa: E402
import backend.http_app as http_app  # noqa: E402
import backend.object_storage as object_storage  # noqa: E402
import backend.plans as plans  # noqa: E402
import backend.repository as repo  # noqa: E402

EXIT_PASS, EXIT_FAIL, EXIT_BLOCKED, EXIT_WAITING = 0, 1, 2, 3
PLAN_CHOICES = {
    "quick": ("quick", "one_time"),
    "standard-monthly": ("standard", "monthly"),
    "standard-annual": ("standard", "annual"),
    "pro-monthly": ("pro", "monthly"),
    "pro-annual": ("pro", "annual"),
}
# Public identifiers (docs/staging-config.md, D-107) - used by --simulate
# when the environment has none.
DOCUMENTED_SANDBOX_PRICE_IDS = {
    "vericexa_quick_onetime": "price_1UMFnY1jc8PYYLrPXxSbSEUF",
    "vericexa_standard_monthly": "price_1UMFvU1jc8PYYLrPsrZuTqJl",
    "vericexa_standard_annual": "price_1UMFvU1jc8PYYLrPg7Kia6bO",
    "vericexa_pro_monthly": "price_1UMFwj1jc8PYYLrP2rA1xonm",
    "vericexa_pro_annual": "price_1UMFy51jc8PYYLrPLyQHT8Fh",
}
HOST = "127.0.0.1"
TEST_CARD = "4242 4242 4242 4242"


class HarnessFailure(Exception):
    def __init__(self, stage: str, diagnosis: str, code: int = EXIT_FAIL) -> None:
        super().__init__(diagnosis)
        self.stage, self.diagnosis, self.code = stage, diagnosis, code


# ---------------------------------------------------------------------------
# Configuration (never prints a secret value)
# ---------------------------------------------------------------------------

def load_env_file(path: str) -> Dict[str, str]:
    """STRIPE_* KEY=VALUE pairs from a file outside the repository."""
    real = os.path.realpath(path)
    if os.path.commonpath([real, os.path.realpath(REPO_ROOT)]) == os.path.realpath(REPO_ROOT):
        raise HarnessFailure("Configuración", "--env-file must be OUTSIDE the repository (a secrets file inside it could be committed)", EXIT_BLOCKED)
    try:
        with open(real, "r", encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    except OSError:
        raise HarnessFailure("Configuración", "--env-file cannot be read", EXIT_BLOCKED)
    values: Dict[str, str] = {}
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key.startswith("export "):
            key = key[len("export "):].strip()
        if key.startswith("STRIPE_"):
            values[key] = value.strip().strip('"').strip("'")
    return values


def check_config(env: Dict[str, str], simulate: bool) -> Dict[str, Any]:
    """The harness configuration, validated. Raises HarnessFailure (BLOCKED)
    naming every problem; reports presence only, never values."""
    problems: List[str] = []
    key = env.get("STRIPE_SECRET_KEY", "")
    if simulate and not key:
        key = "sk_test_simulated"
    mode = billing.key_mode(key)
    if not key:
        problems.append("STRIPE_SECRET_KEY: AUSENTE")
    elif mode == billing.MODE_LIVE:
        problems.append("STRIPE_SECRET_KEY: es una clave LIVE - este harness solo acepta Sandbox (sk_test_/rk_test_)")
    elif mode != billing.MODE_TEST:
        problems.append("STRIPE_SECRET_KEY: no es una clave secreta/restringida de Stripe (sk_test_/rk_test_)")
    secret = env.get("STRIPE_WEBHOOK_SECRET", "")
    if secret and not billing.is_valid_webhook_secret(secret):
        problems.append("STRIPE_WEBHOOK_SECRET: presente pero no tiene forma whsec_...")
    prices: Dict[str, str] = {}
    for price_key, env_name in plans.PRICE_ENV_VARS.items():
        value = env.get(env_name, "").strip() or (DOCUMENTED_SANDBOX_PRICE_IDS[price_key] if simulate else "")
        if not value:
            problems.append("%s: AUSENTE" % env_name)
        elif not billing.is_valid_price_id(value):
            problems.append("%s: no tiene forma price_..." % env_name)
        prices[price_key] = value
    if not problems:
        try:
            billing.validate_price_allowlist(prices)
        except billing.BillingError as exc:
            problems.append(str(exc))
    if problems:
        raise HarnessFailure("Configuración", "; ".join(problems), EXIT_BLOCKED)
    return {"secret_key": key, "key_class": key[:7], "webhook_secret": secret or "whsec_" + secrets.token_hex(24),
            "webhook_secret_source": "STRIPE_WEBHOOK_SECRET" if secret else "efímero (generado por el harness)", "prices": prices}


def verify_prices(client: Any, prices: Dict[str, str]) -> List[str]:
    """Each Price exists in the key's Stripe account, is a Sandbox object,
    active, of the right type/interval, and matches the catalog amount
    (backend/plans.py) - a mismatch is a FAIL, never "fixed" here."""
    lines, problems = [], []
    for price_key, price_id in prices.items():
        mode = plans.PRICE_MODES[price_key]
        try:
            price = client.prices.retrieve(price_id)
        except Exception as exc:   # stripe.InvalidRequestError "No such price" = other account / mode
            problems.append("%s (%s): %s - ¿la clave pertenece a otra cuenta Sandbox?" % (price_key, price_id, type(exc).__name__))
            continue
        expected_interval = None if mode["interval"] == plans.INTERVAL_ONE_TIME else ("month" if mode["interval"] == plans.INTERVAL_MONTHLY else "year")
        actual_interval = ((price.get("recurring") or {}).get("interval")) if price.get("recurring") else None
        if price.get("livemode") is not False:
            problems.append("%s: la Price no es de Sandbox" % price_key)
        if price.get("active") is not True:
            problems.append("%s: la Price está archivada (active=false)" % price_key)
        if actual_interval != expected_interval or (price.get("type") == "one_time") != (expected_interval is None):
            problems.append("%s: tipo/intervalo %s/%s, el catálogo espera %s" % (price_key, price.get("type"), actual_interval, expected_interval or "one_time"))
        if price.get("unit_amount") != mode["amount_cents"] or price.get("currency") != mode["currency"]:
            problems.append("%s: importe %s %s, el catálogo (backend/plans.py) espera %s %s" % (
                price_key, price.get("unit_amount"), price.get("currency"), mode["amount_cents"], mode["currency"]))
        lines.append("%s = %s (%s %s, %s)" % (price_key, price_id, price.get("unit_amount"), price.get("currency"), expected_interval or "one_time"))
    if problems:
        raise HarnessFailure("Price IDs", "; ".join(problems))
    return lines


# ---------------------------------------------------------------------------
# The run
# ---------------------------------------------------------------------------

class _StderrCapture(io.TextIOBase):
    """Keeps the server's own log lines (access log, structured webhook
    lines - neither ever contains a secret) out of the harness output, but
    available for the failure diagnosis."""

    def __init__(self) -> None:
        self.lines: List[str] = []
        self._lock = threading.Lock()

    def write(self, text: str) -> int:
        with self._lock:
            self.lines.extend(line for line in text.splitlines() if line.strip())
        return len(text)

    def webhook_lines(self, last: int = 20) -> List[str]:
        return [line for line in self.lines if '"stripe_webhook"' in line][-last:]


class Harness:
    def __init__(self, cfg: Dict[str, Any], simulate: bool, out: Callable[[str], None], state_dir: str, timeout: float,
                 event_timeout: float, poll_seconds: float, shuffle: bool, keep_subscription: bool) -> None:
        self.cfg, self.simulate, self.out = cfg, simulate, out
        self.state_dir, self.timeout, self.event_timeout, self.poll = state_dir, timeout, event_timeout, poll_seconds
        self.shuffle, self.keep_subscription = shuffle, keep_subscription
        self.billing = billing.StripeBilling(cfg["secret_key"], cfg["webhook_secret"], dict(cfg["prices"]), mode=billing.MODE_TEST)
        if simulate:
            from tests.stripe_simulator import StripeSimulator
            self.billing._client = StripeSimulator(dict(cfg["prices"]), start=int(time.time()))
        self.client = self.billing._client
        self.db_path = os.path.join(state_dir, "e2e.sqlite3")
        self.httpd = None
        self.relayed: List[Dict[str, Any]] = []

    def step(self, label: str, detail: str = "") -> None:
        self.out("  [OK] %s%s" % (label, (" - " + detail) if detail else ""))

    # -- server ---------------------------------------------------------------

    def start_server(self) -> None:
        if not os.path.exists(self.db_path):
            conn = repo.connect(self.db_path)
            repo.init_schema(conn)
            conn.close()
        storage = object_storage.LocalFilesystemStorage(os.path.join(self.state_dir, "storage"), sign_secret=secrets.token_hex(16))

        class _NoEmail:
            def send(self, *args: Any) -> None:
                return None

        self.httpd = http_app.run_server(connect_fn=lambda: repo.connect(self.db_path), email_sender=_NoEmail(), host_allowlist=[HOST], host=HOST,
                                         port=0, secure_cookies=False, billing=self.billing, storage=storage)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base = "%s:%d" % (HOST, self.httpd.server_address[1])

    def stop_server(self) -> None:
        if self.httpd is not None:
            self.httpd.shutdown()
            self.httpd.server_close()

    def request(self, method: str, path: str, body: bytes = b"", headers: Optional[Dict[str, str]] = None) -> Tuple[int, Dict[str, Any]]:
        import http.client
        conn = http.client.HTTPConnection(self.base, timeout=30)
        hdrs = {"Host": self.base, "Content-Length": str(len(body)), "Content-Type": "application/json"}
        hdrs.update(headers or {})
        try:
            conn.request(method, path, body=body, headers=hdrs)
            resp = conn.getresponse()
            raw = resp.read()
        finally:
            conn.close()
        try:
            return resp.status, json.loads(raw.decode("utf-8") or "{}")
        except ValueError:
            return resp.status, {"raw": raw[:200].decode("utf-8", "replace")}

    def session_cookie(self, user_id: str) -> str:
        conn = repo.connect(self.db_path)
        try:
            session = auth.create_session(conn, user_id)
            conn.commit()
        finally:
            conn.close()
        return "%s=%s" % (http_app.SESSION_COOKIE_NAME, session["session_token"])

    def db_read(self, fn: Callable[[Any], Any]) -> Any:
        conn = repo.connect(self.db_path)
        try:
            return fn(conn)
        finally:
            conn.close()

    # -- stages ---------------------------------------------------------------

    def create_checkout(self, plan: str, interval: str) -> Dict[str, Any]:
        conn = repo.connect(self.db_path)
        try:
            user_id = repo.create_user(conn, "e2e-%s@example.invalid" % secrets.token_hex(6))
            workspace_id = repo.create_workspace(conn, "Stripe Sandbox E2E (%s %s)" % (plan, interval), user_id)
        finally:
            conn.close()
        state = {"plan": plan, "interval": interval, "user_id": user_id, "workspace_id": workspace_id, "started": int(time.time()) - 5}
        status, body = self.request("POST", "/billing/checkout", json.dumps({"workspace_id": workspace_id, "plan": plan, "interval": interval}).encode(),
                                    {"Cookie": self.session_cookie(user_id), "Origin": "http://" + self.base})
        if status != 200 or not body.get("checkout_url"):
            raise HarnessFailure("Checkout creado", "POST /billing/checkout -> HTTP %s %s" % (status, body.get("error")))
        row = self.db_read(lambda c: repo.list_pending_checkout_sessions(c, workspace_id))
        if len(row) != 1:
            raise HarnessFailure("Checkout creado", "no hay exactamente una sesión abierta en billing_checkout_sessions")
        state.update({"session_id": row[0]["id"], "checkout_url": body["checkout_url"]})
        self.save_state(state)
        self.step("Checkout creado", "%s %s, sesión %s, Price %s" % (plan, interval, state["session_id"], row[0]["price_id"]))
        return state

    def save_state(self, state: Dict[str, Any]) -> None:
        with open(os.path.join(self.state_dir, "state.json"), "w", encoding="utf-8") as handle:
            json.dump(state, handle)

    def wait_for_payment(self, state: Dict[str, Any]) -> Dict[str, Any]:
        session_id = state["session_id"]
        if self.simulate:
            self.client.pay_checkout(session_id)
        else:
            self.out("")
            self.out("  >>> ACCIÓN HUMANA: abre esta URL de Stripe Checkout (Sandbox) y paga con la tarjeta de prueba %s," % TEST_CARD)
            self.out("      cualquier fecha futura, cualquier CVC y cualquier email:")
            self.out("      %s" % state["checkout_url"])
            self.out("      (esperando hasta %d s; Ctrl+C para salir y reanudar luego con --resume)" % self.timeout)
            self.out("")
        deadline = time.monotonic() + self.timeout
        while True:
            session = self.client.checkout.sessions.retrieve(session_id)
            if session.get("status") == "complete" and session.get("payment_status") in ("paid", "no_payment_required"):
                break
            if session.get("status") == "expired":
                raise HarnessFailure("Payment confirmado", "la sesión de Checkout expiró sin pago (Stripe status=expired) - crea otra con --plan")
            if time.monotonic() >= deadline:
                raise HarnessFailure("Payment confirmado", "la sesión sigue sin pagar (status=%s, payment_status=%s). Continúa con: "
                                     "python -m tests.stripe_sandbox_e2e --resume %s" % (session.get("status"), session.get("payment_status"), self.state_dir),
                                     EXIT_WAITING)
            time.sleep(self.poll)
        state["subscription_id"] = billing._object_id(session.get("subscription"))
        self.save_state(state)
        self.step("Payment confirmado", "Stripe: status=complete, payment_status=%s%s" % (
            session.get("payment_status"), (", suscripción %s" % state["subscription_id"]) if state["subscription_id"] else ""))
        return state

    def _related(self, event: Dict[str, Any], state: Dict[str, Any]) -> bool:
        obj = ((event.get("data") or {}).get("object")) or {}
        ids = {state["session_id"], state.get("subscription_id")} - {None}
        return bool(ids & {obj.get("id"), billing._object_id(obj.get("subscription")), billing.invoice_subscription_id(obj)})

    def fetch_events(self, state: Dict[str, Any], required: List[str]) -> List[Dict[str, Any]]:
        deadline = time.monotonic() + self.event_timeout
        while True:
            listing = self.client.events.list({"created": {"gte": state["started"]}, "limit": 100})
            events = [e for e in reversed(list(listing.get("data") or [])) if self._related(e, state) and e.get("id") not in {r["id"] for r in self.relayed}]
            missing = [t for t in required if t not in {e.get("type") for e in events}]
            if not missing:
                return events
            if time.monotonic() >= deadline:
                raise HarnessFailure("Webhook recibido", "en %d s Stripe no generó %s para esta sesión (recibidos: %s)" % (
                    self.event_timeout, ", ".join(missing), ", ".join(sorted({e.get("type") for e in events})) or "ninguno"))
            time.sleep(self.poll)

    def relay(self, events: List[Dict[str, Any]], expect_outcome_prefix: str = "applied:") -> None:
        if self.shuffle:
            random.shuffle(events)
        for event in events:
            body = json.dumps(event, default=str).encode("utf-8")
            status, data = self.request("POST", "/billing/webhook", body, {"Stripe-Signature": self.sign(body)})
            self.step("Webhook recibido", "%s %s -> HTTP %d" % (event.get("type"), event.get("id"), status))
            if status != 200:
                raise HarnessFailure("Webhook verificado", "%s respondió HTTP %d (%s)" % (event.get("type"), status, data.get("error")))
            outcome = "ignored:duplicate" if data.get("duplicate") else str(data.get("outcome"))
            if outcome.startswith("rejected:"):
                raise HarnessFailure("Webhook verificado", "%s fue rechazado por el backend: %s" % (event.get("type"), outcome))
            self.step("Webhook verificado", "firma y modo Sandbox válidos, resultado %s" % outcome)
            self.relayed.append(event)

    def sign(self, body: bytes) -> str:
        from tests.stripe_simulator import sign_payload
        return sign_payload(body, self.cfg["webhook_secret"])

    def check_entitlement(self, state: Dict[str, Any], expected_status: str = "active") -> Dict[str, Any]:
        ent = self.db_read(lambda c: repo.get_entitlement_by_workspace(c, state["workspace_id"]))
        expected = (state["plan"], expected_status, None if state["plan"] == plans.PLAN_QUICK else state["interval"])
        actual = (ent or {}).get("plan"), (ent or {}).get("status"), (ent or {}).get("billing_interval")
        if actual != expected:
            raise HarnessFailure("Entitlement actualizado", "esperado plan/status/intervalo %s, obtenido %s" % (expected, actual))
        if state.get("subscription_id") and ent.get("stripe_subscription_id") != state["subscription_id"]:
            raise HarnessFailure("Entitlement actualizado", "la suscripción guardada no es la de este checkout")
        self.step("Entitlement actualizado", "plan=%s status=%s intervalo=%s" % actual)
        return ent

    def check_quota_and_consume(self, state: Dict[str, Any]) -> None:
        ws, plan = state["workspace_id"], state["plan"]
        usage = self.db_read(lambda c: repo.usage_summary(c, ws, repo.get_entitlement_by_workspace(c, ws)))
        spec = plans.PLANS[plan]
        if plan == plans.PLAN_QUICK:
            if usage.get("scans_available") != 1:
                raise HarnessFailure("Quota actualizado", "Quick debe dejar exactamente 1 escaneo disponible, hay %s" % usage.get("scans_available"))
            self.step("Quota actualizado", "1 escaneo Quick disponible (máx. %d LOC)" % spec["max_loc_per_scan"])
        else:
            if (usage.get("loc_limit"), usage.get("loc_used")) != (spec["monthly_loc_quota"], 0):
                raise HarnessFailure("Quota actualizado", "cuota %s/%s, esperado 0/%s" % (usage.get("loc_used"), usage.get("loc_limit"), spec["monthly_loc_quota"]))
            self.step("Quota actualizado", "mes de servicio %s -> %s, %d LOC/mes, %d LOC por escaneo" % (
                usage["period_start"][:10], usage["period_end"][:10], spec["monthly_loc_quota"], spec["max_loc_per_scan"]))
        source = "pragma solidity ^0.8.20;\ncontract E2E {\n    uint256 public v;\n}\n"
        status, body = self.request("POST", "/workspaces/%s/jobs" % ws, json.dumps({"mode": "quick", "source": source}).encode(),
                                    {"Cookie": self.session_cookie(state["user_id"]), "Origin": "http://" + self.base})
        if status != 200:
            raise HarnessFailure("Consumo", "el envío de un escaneo respondió HTTP %d (%s)" % (status, body.get("error")))
        usage = self.db_read(lambda c: repo.usage_summary(c, ws, repo.get_entitlement_by_workspace(c, ws)))
        if plan == plans.PLAN_QUICK and (usage.get("scans_available"), usage.get("scans_reserved")) != (0, 1):
            raise HarnessFailure("Consumo", "el escaneo no reservó el crédito Quick")
        if plan != plans.PLAN_QUICK and not usage.get("loc_used"):
            raise HarnessFailure("Consumo", "el escaneo no reservó cuota del mes")
        self.step("Consumo verificado", "un escaneo encolado (job %s) reservó %s" % (body.get("job_id"), "el crédito Quick" if plan == plans.PLAN_QUICK else "%d LOC" % usage["loc_used"]))

    def check_idempotency_and_forgery(self, state: Dict[str, Any]) -> None:
        before = self.db_read(lambda c: (repo.get_entitlement_by_workspace(c, state["workspace_id"]),
                                         c.execute("SELECT COUNT(*) FROM scan_credits WHERE workspace_id = ?", (state["workspace_id"],)).fetchone()[0]))
        for event in list(self.relayed):
            body = json.dumps(event, default=str).encode("utf-8")
            status, data = self.request("POST", "/billing/webhook", body, {"Stripe-Signature": self.sign(body)})
            if status != 200 or not data.get("duplicate"):
                raise HarnessFailure("Idempotencia", "el reenvío de %s no se trató como duplicado (HTTP %d)" % (event.get("id"), status))
        after = self.db_read(lambda c: (repo.get_entitlement_by_workspace(c, state["workspace_id"]),
                                        c.execute("SELECT COUNT(*) FROM scan_credits WHERE workspace_id = ?", (state["workspace_id"],)).fetchone()[0]))
        if before != after:
            raise HarnessFailure("Idempotencia", "un reenvío cambió el estado")
        self.step("Idempotencia verificada", "%d reenvíos = duplicados, estado sin cambios" % len(self.relayed))
        body = json.dumps(self.relayed[0], default=str).encode("utf-8")
        status, _ = self.request("POST", "/billing/webhook", body, {"Stripe-Signature": "t=%d,v1=%s" % (int(time.time()), "0" * 64)})
        if status != 400:
            raise HarnessFailure("Firma", "una firma falsa no fue rechazada (HTTP %d)" % status)
        self.step("Firma inválida rechazada", "HTTP 400")

    def cancel_subscription(self, state: Dict[str, Any]) -> None:
        self.client.subscriptions.cancel(state["subscription_id"])
        self.relay(self.fetch_events(state, ["customer.subscription.deleted"]))
        self.check_entitlement(state, expected_status="canceled")
        self.step("Cancelación verificada", "suscripción de prueba cancelada en Stripe y reflejada (status=canceled)")

    def run_plan(self, plan: str, interval: str, resume: Optional[Dict[str, Any]] = None) -> None:
        self.relayed = []
        state = resume or self.create_checkout(plan, interval)
        state = self.wait_for_payment(state)
        required = ["checkout.session.completed"] + ([] if plan == plans.PLAN_QUICK else ["customer.subscription.created", "invoice.paid"])
        self.relay(self.fetch_events(state, required))
        self.check_entitlement(state)
        self.check_quota_and_consume(state)
        self.check_idempotency_and_forgery(state)
        if plan != plans.PLAN_QUICK and not self.keep_subscription:
            self.cancel_subscription(state)


def main(argv: Optional[List[str]] = None, env: Optional[Dict[str, str]] = None, out: Callable[[str], None] = print) -> int:
    parser = argparse.ArgumentParser(description="D-115 Stripe Sandbox E2E harness (docs/stripe-billing.md)")
    parser.add_argument("--plan", choices=sorted(PLAN_CHOICES) + ["all"], help="what to buy (all = the 5 price modes, one after another)")
    parser.add_argument("--check-config", action="store_true", help="only validate configuration and the Price IDs in Stripe")
    parser.add_argument("--simulate", action="store_true", help="use the in-repo Stripe simulator: no network, no secrets, no human step")
    parser.add_argument("--env-file", help="KEY=VALUE file with the STRIPE_* variables, OUTSIDE the repository")
    parser.add_argument("--resume", metavar="STATE_DIR", help="continue a run whose Checkout was not paid in time")
    parser.add_argument("--state-dir", help="where the temporary database and state live (default: a new temp dir)")
    parser.add_argument("--timeout", type=float, default=900, help="seconds to wait for the human payment (default 900)")
    parser.add_argument("--event-timeout", type=float, default=120, help="seconds to wait for Stripe's events (default 120)")
    parser.add_argument("--poll", type=float, default=3, help="polling interval in seconds (default 3)")
    parser.add_argument("--shuffle", action="store_true", help="relay each batch of events in random order (order independence)")
    parser.add_argument("--keep-subscription", action="store_true", help="do not cancel the test subscription at the end")
    args = parser.parse_args(argv)
    if not (args.plan or args.check_config or args.resume):
        parser.error("one of --plan, --check-config or --resume is required")

    out("Vericexa - Stripe Sandbox E2E (D-115)%s" % (" [SIMULADO: sin Stripe real]" if args.simulate else ""))
    capture = _StderrCapture()
    harness: Optional[Harness] = None
    stage = "Configuración"
    try:
        values = dict(os.environ if env is None else env)
        if args.env_file:
            values.update(load_env_file(args.env_file))
        cfg = check_config(values, args.simulate)
        out("  [OK] Configuración - clave Stripe: PRESENTE (%s, Sandbox); webhook secret: %s; Price IDs: 5/5 PRESENTES" % (
            cfg["key_class"], cfg["webhook_secret_source"]))
        resume_state = None
        if args.resume:
            with open(os.path.join(args.resume, "state.json"), "r", encoding="utf-8") as handle:
                resume_state = json.load(handle)
            state_dir = args.resume
        else:
            state_dir = args.state_dir or tempfile.mkdtemp(prefix="vericexa-stripe-e2e-")
            os.makedirs(state_dir, exist_ok=True)
        harness = Harness(cfg, args.simulate, out, state_dir, args.timeout, args.event_timeout, args.poll, args.shuffle, args.keep_subscription)
        stage = "Price IDs"
        for line in verify_prices(harness.client, cfg["prices"]):
            out("  [OK] Price ID verificado en Stripe - %s" % line)
        if args.check_config:
            out("CONFIG OK")
            return EXIT_PASS
        stage = "Servidor"
        with contextlib.redirect_stderr(capture):
            harness.start_server()
            out("  [OK] Servidor local arrancado - http://%s (SQLite temporal en %s)" % (harness.base, state_dir))
            if resume_state:
                out("  -- reanudando %s %s (sesión %s)" % (resume_state["plan"], resume_state["interval"], resume_state["session_id"]))
                harness.run_plan(resume_state["plan"], resume_state["interval"], resume_state)
            else:
                for name in (sorted(PLAN_CHOICES, key=list(PLAN_CHOICES).index) if args.plan == "all" else [args.plan]):
                    out("  -- %s" % name)
                    harness.run_plan(*PLAN_CHOICES[name])
        out("E2E PASS")
        if not args.state_dir and not args.resume:
            shutil.rmtree(state_dir, ignore_errors=True)
        return EXIT_PASS
    except HarnessFailure as failure:
        label = {EXIT_BLOCKED: "E2E BLOCKED", EXIT_WAITING: "E2E WAITING"}.get(failure.code, "E2E FAIL")
        out("%s en '%s': %s" % (label, failure.stage, failure.diagnosis))
        for line in capture.webhook_lines():
            out("  log del servidor: %s" % line)
        return failure.code
    except KeyboardInterrupt:
        out("E2E WAITING: interrumpido. Continúa con: python -m tests.stripe_sandbox_e2e --resume %s" % (harness.state_dir if harness else "<state-dir>"))
        return EXIT_WAITING
    except Exception as exc:   # an unexpected error: type only (a message could quote a request)
        out("E2E FAIL en '%s': error inesperado %s" % (stage, type(exc).__name__))
        for line in capture.webhook_lines():
            out("  log del servidor: %s" % line)
        return EXIT_FAIL
    finally:
        if harness is not None:
            with contextlib.redirect_stderr(capture):
                harness.stop_server()


if __name__ == "__main__":
    if not sys.stdout.isatty() and hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")   # piped output (CI, IDE panes): UTF-8, never a crash
    sys.exit(main())
