-- Launch commercial catalog and usage accounting (docs/decisiones.md D-107).
-- Purely additive: one nullable column and three new tables; no data
-- migration, trivial rollback. Mirrored in backend/schema_sqlite.sql.
--
-- 1. entitlements.current_period_start - start of the subscription's
--    current Stripe period (copied from the subscription item, like
--    current_period_end). Anchor for Standard/Pro SERVICE MONTHS
--    (backend/plans.py service_month()): an annual subscription keeps the
--    same period start for 12 months and is metered month by month from
--    it. Nullable: rows created before this column fall back to their own
--    created_at as the anchor (repository.usage_period_for_entitlement()).
--
-- 2. scan_credits - one row per PAID Quick checkout (id = the Stripe
--    Checkout Session id, so a redelivered webhook can never grant twice).
--    available -> reserved (a submitted job holds it) -> consumed (that job
--    succeeded); a failed/canceled job gives it back (reserved ->
--    available). job_id is UNIQUE: one credit per job, one job per credit.
--
-- 3. usage_periods - per workspace and SERVICE MONTH, the effective LOC
--    reserved by pending jobs and consumed by succeeded ones. The allowance
--    check is a conditional UPDATE (reserved + consumed + new <= limit) on
--    this row, so two concurrent submissions can never both pass the last
--    few LOC. limit_loc records the plan allowance last applied; no CHECK
--    ties it to reserved/consumed, because a downgrade may legitimately
--    leave consumed above the new, lower allowance (further scans are then
--    refused, history is never rewritten).
--
-- 4. job_usage - the per-job ledger row (job_id PRIMARY KEY = idempotency:
--    a job can hold at most one reservation and settle it at most once,
--    reserved -> consumed | released, each a conditional UPDATE).

ALTER TABLE entitlements ADD COLUMN current_period_start TIMESTAMPTZ;

CREATE TABLE scan_credits (
    id           TEXT PRIMARY KEY,
    workspace_id UUID NOT NULL REFERENCES workspaces(id),
    status       TEXT NOT NULL CHECK (status IN ('available', 'reserved', 'consumed')),
    job_id       UUID UNIQUE REFERENCES analysis_jobs(id),
    granted_at   TIMESTAMPTZ NOT NULL,
    updated_at   TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_scan_credits_workspace_status ON scan_credits(workspace_id, status, granted_at);

CREATE TABLE usage_periods (
    workspace_id  UUID NOT NULL REFERENCES workspaces(id),
    period_start  TIMESTAMPTZ NOT NULL,
    period_end    TIMESTAMPTZ NOT NULL,
    limit_loc     INTEGER NOT NULL,
    reserved_loc  INTEGER NOT NULL DEFAULT 0,
    consumed_loc  INTEGER NOT NULL DEFAULT 0,
    updated_at    TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (workspace_id, period_start),
    CONSTRAINT usage_periods_non_negative CHECK (reserved_loc >= 0 AND consumed_loc >= 0 AND limit_loc >= 0),
    CONSTRAINT usage_periods_end_after_start CHECK (period_end > period_start)
);

CREATE TABLE job_usage (
    job_id         UUID PRIMARY KEY REFERENCES analysis_jobs(id),
    workspace_id   UUID NOT NULL REFERENCES workspaces(id),
    plan           TEXT NOT NULL CHECK (plan IN ('quick', 'standard', 'pro')),
    usage_model    TEXT NOT NULL CHECK (usage_model IN ('scan_credit', 'service_month')),
    effective_loc  INTEGER NOT NULL CHECK (effective_loc >= 0),
    period_start   TIMESTAMPTZ,
    credit_id      TEXT REFERENCES scan_credits(id),
    status         TEXT NOT NULL CHECK (status IN ('reserved', 'consumed', 'released')),
    created_at     TIMESTAMPTZ NOT NULL,
    updated_at     TIMESTAMPTZ NOT NULL,
    CONSTRAINT job_usage_model_fields CHECK (
        (usage_model = 'scan_credit' AND credit_id IS NOT NULL AND period_start IS NULL)
        OR (usage_model = 'service_month' AND period_start IS NOT NULL AND credit_id IS NULL)
    )
);
CREATE INDEX idx_job_usage_workspace ON job_usage(workspace_id, status);
