-- Commercial Foundation guards (docs/decisiones.md D-108). Purely
-- additive: two columns with defaults and two new tables; no data
-- migration, trivial rollback. Mirrored in backend/schema_sqlite.sql.
--
-- 1. analysis_jobs.priority - 1 for a job submitted under a plan whose
--    catalog queue_priority is "priority" (Pro), 0 otherwise. Set once at
--    admission (repository.enqueue_job_with_usage()) and only read by
--    claim_next_job()'s ordering: a priority job's workspace competes as if
--    it had been served QUEUE_PRIORITY_BONUS_SECONDS earlier - preference,
--    never exclusivity, so Standard/Quick work can never starve.
--
-- 2. job_usage.tech_units - the technical (runaway-cost) budget units this
--    job reserved at admission, 0 when it reserved none (Quick, or a row
--    written before this migration). Settled with the job's usage row.
--
-- 3. technical_budget_periods - per workspace and SERVICE MONTH (the same
--    period key as usage_periods), the technical safety guard for
--    Standard/Pro. NOT a commercial allowance: its ceiling is a technical
--    heuristic (monthly LOC quota / 20 x the plan's most expensive mode
--    cost: Standard 2,000, Pro 12,000 units) chosen so a workspace using its
--    plan normally reaches its LOC allowance first
--    (repository.technical_budget_limit_units()). A unit is a relative
--    per-job compute weight, never a LOC equivalent. It resets with the
--    service month because each month is its own row. No CHECK ties
--    reserved/consumed to limit_units: a plan downgrade may lower the
--    ceiling below what was already used (further scans are refused,
--    history is never rewritten).
--
-- 4. submit_attempts - one row per scan-submission request from an
--    identified member inside the rate-limit window (POST
--    /workspaces/<id>/jobs), whatever its later outcome (402/413, duplicate
--    idempotency_key...), pruned on every attempt by the same user, counted
--    under a per-user lock. Only a request refused by the rate limit itself
--    records nothing, so it never extends the caller's own wait.

ALTER TABLE analysis_jobs ADD COLUMN priority SMALLINT NOT NULL DEFAULT 0 CHECK (priority IN (0, 1));

ALTER TABLE job_usage ADD COLUMN tech_units INTEGER NOT NULL DEFAULT 0 CHECK (tech_units >= 0);

CREATE TABLE technical_budget_periods (
    workspace_id    UUID NOT NULL REFERENCES workspaces(id),
    period_start    TIMESTAMPTZ NOT NULL,
    period_end      TIMESTAMPTZ NOT NULL,
    limit_units     INTEGER NOT NULL,
    reserved_units  INTEGER NOT NULL DEFAULT 0,
    consumed_units  INTEGER NOT NULL DEFAULT 0,
    updated_at      TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (workspace_id, period_start),
    CONSTRAINT technical_budget_periods_non_negative CHECK (reserved_units >= 0 AND consumed_units >= 0 AND limit_units >= 0),
    CONSTRAINT technical_budget_periods_end_after_start CHECK (period_end > period_start)
);

CREATE TABLE submit_attempts (
    id            UUID PRIMARY KEY,
    user_id       UUID NOT NULL REFERENCES users(id),
    workspace_id  UUID NOT NULL REFERENCES workspaces(id),
    created_at    TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_submit_attempts_user_created ON submit_attempts(user_id, created_at);
