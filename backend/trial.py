#!/usr/bin/env python3
"""Free Trial eligibility and grant (docs/decisiones.md D-112).

ONE TRIAL PER NORMALIZED EMAIL, FOR EVER: the record is trial_grants, keyed
by backend/email_policy.normalize_email() (= auth.normalize_email(): trim +
lower-case) and independent of the users row, so deleting an account and
signing up again with the same address never yields a second Trial. The
primary key also makes two simultaneous grants for one email impossible.

WHEN: never at sign-up itself. Sign-up only sends a verification link
(a single-use, 15-minute magic-link token, stored as a hash - backend/
auth.py); the Trial is granted when that link is verified (or later, from
the app, by a signed-in member whose email is verified). Each grant checks,
in the backend: verified email, not a disposable domain, never granted
before.

WHAT: repository.grant_trial() creates a "Trial workspace" with an active
'trial' entitlement (backend/plans.py TRIAL: one scan of <= 500 effective
LOC, one project, Layer 1 only, report viewable for 7 days, no downloads,
no Layer 2, no Private GitHub). No Stripe object of any kind is created.

Refusals carry stable codes and plain sentences that never describe the
anti-abuse mechanism in detail.

Standard library only.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import backend.auth as auth
import backend.email_policy as email_policy
import backend.plans as plans
import backend.repository as repo

STATE_AVAILABLE = "available"                    # may be activated now
STATE_ACTIVE = "active"                          # granted, scan not used yet (or running)
STATE_USED = "used"                              # this email already had its Trial
STATE_NOT_ELIGIBLE = "not_eligible"              # address not accepted for the Trial
STATE_VERIFICATION_REQUIRED = "verification_required"

NOT_ELIGIBLE_DETAIL = "This email address is not eligible for the free Trial. Please use a personal or work email address."


class TrialError(Exception):
    def __init__(self, code: str, detail: str, http_status: int) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail
        self.http_status = http_status


def history_cutoff(now: Optional[datetime] = None) -> str:
    """Trial scans created before this instant are outside the Trial's
    history window."""
    return ((now or datetime.now(timezone.utc)) - timedelta(days=int(plans.TRIAL["history_days"]))).isoformat()


def _normalized(user: Dict[str, Any]) -> str:
    return email_policy.normalize_email(user["email"])


def status_for_user(conn: Any, user: Dict[str, Any], policy: email_policy.DisposableDomainPolicy) -> Dict[str, Any]:
    """What the app shows about the Trial for this signed-in user."""
    email = _normalized(user)
    verified = bool(user.get("email_verified_at"))
    out: Dict[str, Any] = {"email_verified": verified, "workspace_id": None, "max_loc_per_scan": plans.TRIAL["max_loc_per_scan"],
                           "scans_per_email": plans.TRIAL["scans_per_email"], "max_projects": plans.TRIAL["max_projects"],
                           "history_days": plans.TRIAL["history_days"], "scans_remaining": 0}
    grant = repo.get_trial_grant(conn, email)
    if grant is not None:
        member = any(w["id"] == grant["workspace_id"] for w in repo.list_workspaces_by_user(conn, user["id"]))
        entitlement = repo.get_entitlement_by_workspace(conn, grant["workspace_id"]) if member else None
        live_trial = entitlement is not None and entitlement["plan"] == plans.PLAN_TRIAL and entitlement["status"] == "active"
        out["workspace_id"] = grant["workspace_id"] if member else None
        if live_trial and grant["status"] in ("available", "reserved"):
            out.update({"state": STATE_ACTIVE, "scans_remaining": 1 if grant["status"] == "available" else 0, "scan_status": grant["status"]})
        else:
            out["state"] = STATE_USED
        return out
    if policy.is_disposable(email):
        out["state"] = STATE_NOT_ELIGIBLE
    elif not verified:
        out["state"] = STATE_VERIFICATION_REQUIRED
    else:
        out.update({"state": STATE_AVAILABLE, "scans_remaining": 1})
    return out


def grant_for_user(conn: Any, user: Dict[str, Any], policy: email_policy.DisposableDomainPolicy) -> str:
    """Grants the Trial to a signed-in user; returns the Trial workspace id.
    Raises TrialError (email_not_verified 403, trial_not_eligible 403,
    trial_already_used 409)."""
    try:
        email = _normalized(user)
    except auth.AuthError:
        raise TrialError("trial_not_eligible", NOT_ELIGIBLE_DETAIL, 403)
    if not user.get("email_verified_at"):
        raise TrialError("email_not_verified", "Verify your email address to start the free Trial.", 403)
    if policy.is_disposable(email):
        raise TrialError("trial_not_eligible", NOT_ELIGIBLE_DETAIL, 403)
    if repo.get_trial_grant(conn, email) is not None:
        raise TrialError("trial_already_used", "This email address has already used its free Trial. Choose Quick, Standard or Pro to keep scanning.", 409)
    try:
        return repo.grant_trial(conn, email, user["id"])
    except repo.TrialAlreadyGrantedError:
        raise TrialError("trial_already_used", "This email address has already used its free Trial. Choose Quick, Standard or Pro to keep scanning.", 409)
