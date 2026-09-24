-- Phase 4 execution infrastructure (docs/decisiones.md D-077 follow-up).
-- Two additions, both required for a worker that can actually run
-- unattended in production rather than only ever being claimed once:
--
-- 1. analysis_jobs.lease_expires_at - a claimed/running job with no
--    heartbeat past this timestamp is presumed to belong to a crashed
--    or hung worker. Nullable: only ever set while a job is actually
--    claimed (repository.claim_next_job()), cleared on every terminal
--    or requeue transition - a NULL lease on a queued job is the normal,
--    expected state, never a bug.
--
-- 2. workspace_budgets - the smallest transactional spend-control
--    primitive: one row per workspace, reserved_units/consumed_units
--    tracked separately so a job's estimated cost can be reserved
--    BEFORE the LLM call (preventing concurrent jobs from racing past
--    the ceiling) and only converted to consumed_units once the call
--    actually happens, with reserved_units given back on failure/
--    cancellation. This is a UNITS ledger, not money - Stripe/billing
--    is unrelated and untouched (Phase 3). The CHECK constraints are a
--    second, DB-enforced line of defense behind the application's own
--    atomic conditional-UPDATE reservation logic (backend/repository.py
--    reserve_workspace_budget()) - the same defense-in-depth this
--    schema already applies elsewhere (e.g. reports_score_and_band_match_status).

ALTER TABLE analysis_jobs ADD COLUMN lease_expires_at TIMESTAMPTZ;

CREATE TABLE workspace_budgets (
    workspace_id     UUID PRIMARY KEY REFERENCES workspaces(id),
    period_start     TIMESTAMPTZ NOT NULL,
    limit_units      INTEGER NOT NULL,
    reserved_units   INTEGER NOT NULL DEFAULT 0,
    consumed_units   INTEGER NOT NULL DEFAULT 0,
    updated_at       TIMESTAMPTZ NOT NULL,
    CONSTRAINT workspace_budgets_non_negative CHECK (reserved_units >= 0 AND consumed_units >= 0 AND limit_units >= 0),
    CONSTRAINT workspace_budgets_within_limit CHECK (reserved_units + consumed_units <= limit_units)
);
