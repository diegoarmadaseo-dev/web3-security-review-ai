#!/usr/bin/env python3
"""Stripe SANDBOX end-to-end smoke harness (docs/stripe-sandbox-e2e.md, D-115).

Not a unit test (no `test_` prefix: `python -m unittest` never runs it). It
starts the REAL web app (backend/http_app.py) on 127.0.0.1 with SQLite,
local object storage, the REAL backend.billing.StripeBilling talking to
Stripe SANDBOX, and a stand-in worker that completes queued scans with a
fixed scored report (the analysis engine is not part of this smoke). Stripe
events reach it through `stripe listen --forward-to`.

Required environment (nothing is read from files, nothing is printed):
  STRIPE_SECRET_KEY        a Sandbox/test key: sk_test_... or rk_test_...
                           (a live key is refused before anything starts)
  STRIPE_WEBHOOK_SECRET    the whsec_... printed by `stripe listen --print-secret`
  STRIPE_PRICE_QUICK_ONETIME, STRIPE_PRICE_STANDARD_MONTHLY,
  STRIPE_PRICE_STANDARD_ANNUAL, STRIPE_PRICE_PRO_MONTHLY,
  STRIPE_PRICE_PRO_ANNUAL  the Sandbox Price IDs of docs/staging-config.md
Optional: SMOKE_PORT (default 8790), SMOKE_DIR (default: a temp directory).

It prints one sign-in link per test workspace (smoke owners, local only) and
then a status line whenever a workspace's entitlement or usage changes.
Stop with Ctrl+C.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
for path in (str(REPO_ROOT), str(REPO_ROOT / ".claude" / "skills" / "web3-auditor" / "scripts")):
    if path not in sys.path:
        sys.path.insert(0, path)

import backend.auth as auth  # noqa: E402
import backend.billing as billing  # noqa: E402
import backend.http_app as http_app  # noqa: E402
import backend.object_storage as object_storage  # noqa: E402
import backend.repository as repo  # noqa: E402

PRICE_ENV = {
    "vericexa_quick_onetime": "STRIPE_PRICE_QUICK_ONETIME",
    "vericexa_standard_monthly": "STRIPE_PRICE_STANDARD_MONTHLY",
    "vericexa_standard_annual": "STRIPE_PRICE_STANDARD_ANNUAL",
    "vericexa_pro_monthly": "STRIPE_PRICE_PRO_MONTHLY",
    "vericexa_pro_annual": "STRIPE_PRICE_PRO_ANNUAL",
}
REPORT = {"findings": [{"id": "F-smoke", "severity": "LOW", "category": "SC05", "confidence": "high", "status": "confirmed"}],
          "riskIndicator": {"band": "LOW", "score": 92, "scoreStatus": "computed"}, "scoreStatus": "computed"}


class _LogSender:
    def __init__(self):
        self.links = []

    def send(self, to_email, subject, body):
        self.links.append(body)


def _config() -> dict:
    key = os.environ.get("STRIPE_SECRET_KEY", "")
    if not key.startswith(("sk_test_", "rk_test_")):
        sys.exit("STRIPE_SECRET_KEY must be a Sandbox/test key (sk_test_... or rk_test_...). Live keys are refused.")
    secret = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
    if not secret.startswith("whsec_"):
        sys.exit("STRIPE_WEBHOOK_SECRET must be the whsec_... printed by `stripe listen --print-secret`.")
    prices = {}
    for mode, name in PRICE_ENV.items():
        if not os.environ.get(name, "").startswith("price_"):
            sys.exit("%s is required (the Sandbox Price ID from docs/staging-config.md)." % name)
        prices[mode] = os.environ[name]
    return {"key": key, "secret": secret, "prices": prices}


def _worker(db_path: str, storage: object_storage.ObjectStorage, stop: threading.Event) -> None:
    conn = repo.connect(db_path)
    while not stop.is_set():
        job = repo.claim_next_job(conn, "smoke-worker")
        if job is None:
            stop.wait(2)
            continue
        repo.finalize_job_attempt(conn, job["id"], job["workspace_id"], job["attempt_count"], "smoke-worker", "claimed", "running")
        key = object_storage.workspace_key(job["workspace_id"], "reports", job["id"])
        storage.put_object(key, b"# Automated security review (smoke)\n", content_type="text/markdown")
        storage.put_object(object_storage.report_json_key(key), json.dumps(REPORT).encode(), content_type="application/json")
        repo.finalize_job_attempt(conn, job["id"], job["workspace_id"], job["attempt_count"], "smoke-worker", "running", "succeeded",
                                  report_storage_ref=key, report_score_status="computed", report_score=92, report_risk_band="LOW")
        print("[smoke] scan %s completed (stand-in worker)" % job["id"], flush=True)


def _watch(db_path: str, workspaces: dict, stop: threading.Event) -> None:
    last = {}
    while not stop.is_set():
        conn = repo.connect(db_path)
        try:
            for label, ws in workspaces.items():
                ent = repo.get_entitlement_by_workspace(conn, ws)
                usage = repo.usage_summary(conn, ws, ent) if ent else None
                state = None if ent is None else (ent["plan"], ent["status"], ent["billing_interval"], ent["stripe_subscription_id"], ent["current_period_start"],
                                                  usage.get("scans_available") if usage else None, usage.get("loc_used") if usage else None)
                if state != last.get(label):
                    last[label] = state
                    print("[smoke] %-10s entitlement=%s" % (label, state), flush=True)
        finally:
            conn.close()
        stop.wait(2)


def main() -> int:
    cfg = _config()
    port = int(os.environ.get("SMOKE_PORT", "8790"))
    work = os.environ.get("SMOKE_DIR") or tempfile.mkdtemp(prefix="vericexa-stripe-smoke-")
    db_path = os.path.join(work, "smoke.sqlite3")
    conn = repo.connect(db_path)
    repo.init_schema(conn)
    storage = object_storage.LocalFilesystemStorage(os.path.join(work, "objects"), sign_secret="smoke-only")
    stripe_billing = billing.StripeBilling(cfg["key"], cfg["secret"], cfg["prices"])
    sender = _LogSender()
    workspaces = {}
    for label in ("quick", "standard-m", "standard-a", "pro-m", "pro-a"):
        email = "%s.owner@smoke.test" % label
        user = repo.create_user(conn, email)
        workspaces[label] = repo.create_workspace(conn, "Smoke %s" % label, user)
    conn.commit()
    httpd = http_app.run_server(connect_fn=lambda: repo.connect(db_path), email_sender=sender, host_allowlist=["127.0.0.1", "localhost"],
                                host="127.0.0.1", port=port, secure_cookies=False, billing=stripe_billing, storage=storage)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    print("[smoke] Vericexa listening on http://127.0.0.1:%d (data in %s)" % (port, work), flush=True)
    print("[smoke] webhook endpoint: http://127.0.0.1:%d/billing/webhook" % port, flush=True)
    for label, ws in workspaces.items():
        token = auth.request_magic_link(conn, "%s.owner@smoke.test" % label, "127.0.0.1")
        print("[smoke] sign in as %-10s http://127.0.0.1:%d/auth/verify?token=%s  (workspace %s)" % (label, port, token, ws), flush=True)
    conn.close()
    stop = threading.Event()
    threading.Thread(target=_worker, args=(db_path, storage, stop), daemon=True).start()
    threading.Thread(target=_watch, args=(db_path, workspaces, stop), daemon=True).start()
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        stop.set()
        httpd.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
