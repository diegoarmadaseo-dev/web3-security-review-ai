-- Free Trial + sign-up (docs/decisiones.md D-112). Mirrored in
-- backend/schema_sqlite.sql. No existing row changes meaning; the paid
-- plans' values are untouched.
--
-- 1. entitlements.plan and job_usage.plan accept 'trial' (a free, non-Stripe
--    entitlement - backend/plans.py TRIAL), and job_usage gains the 'trial'
--    usage model: a Trial scan reserves the email's single Trial (no credit,
--    no service month), released if the scan fails, consumed if it succeeds.
--
-- 2. auth_tokens.purpose - 'login' (every existing row and every ordinary
--    sign-in link) or 'signup' (a link sent by POST /auth/signup): verifying
--    a sign-up link is what grants the Trial. The token itself is unchanged
--    (hash only, single use, 15-minute expiry).
--
-- 3. trial_grants - THE record that an email received its Trial, keyed by
--    the NORMALIZED email (PRIMARY KEY = at most one Trial per email, ever,
--    also under concurrency). It has no foreign key to users on purpose: it
--    must outlive the account, so deleting and re-creating an account with
--    the same email never yields a second Trial. status follows the single
--    scan: available -> reserved (job queued) -> consumed (job succeeded),
--    or back to available if that job failed.

ALTER TABLE entitlements DROP CONSTRAINT entitlements_plan_check;
ALTER TABLE entitlements ADD CONSTRAINT entitlements_plan_check CHECK (plan IN ('trial', 'quick', 'standard', 'pro'));

ALTER TABLE job_usage DROP CONSTRAINT job_usage_plan_check;
ALTER TABLE job_usage ADD CONSTRAINT job_usage_plan_check CHECK (plan IN ('trial', 'quick', 'standard', 'pro'));
ALTER TABLE job_usage DROP CONSTRAINT job_usage_usage_model_check;
ALTER TABLE job_usage ADD CONSTRAINT job_usage_usage_model_check CHECK (usage_model IN ('scan_credit', 'service_month', 'trial'));
ALTER TABLE job_usage DROP CONSTRAINT job_usage_model_fields;
ALTER TABLE job_usage ADD CONSTRAINT job_usage_model_fields CHECK (
    (usage_model = 'scan_credit' AND credit_id IS NOT NULL AND period_start IS NULL)
    OR (usage_model = 'service_month' AND period_start IS NOT NULL AND credit_id IS NULL)
    OR (usage_model = 'trial' AND period_start IS NULL AND credit_id IS NULL)
);

ALTER TABLE auth_tokens ADD COLUMN purpose TEXT NOT NULL DEFAULT 'login' CHECK (purpose IN ('login', 'signup'));

CREATE TABLE trial_grants (
    normalized_email  TEXT PRIMARY KEY CHECK (normalized_email = lower(normalized_email) AND normalized_email = btrim(normalized_email)),
    user_id           UUID,
    workspace_id      UUID NOT NULL REFERENCES workspaces(id),
    status            TEXT NOT NULL CHECK (status IN ('available', 'reserved', 'consumed')),
    job_id            UUID,
    granted_at        TIMESTAMPTZ NOT NULL,
    reserved_at       TIMESTAMPTZ,
    consumed_at       TIMESTAMPTZ,
    updated_at        TIMESTAMPTZ NOT NULL,
    CONSTRAINT trial_grants_job_matches_status CHECK ((status = 'available') = (job_id IS NULL))
);
CREATE UNIQUE INDEX uq_trial_grants_workspace ON trial_grants(workspace_id);
