-- Admission control / queue fairness (docs/decisiones.md D-077 follow-up,
-- post reap-atomicity-fix and worker-fencing hardening). Confirmed by a
-- dedicated read-only audit: claim_next_job() selects globally by
-- created_at with no per-workspace partition - a workspace with many
-- queued jobs can occupy every idle worker while a different workspace's
-- job waits, and reap_expired_jobs()'s requeue never touched created_at,
-- so a repeatedly-expiring job kept its original (favorable) position
-- ahead of genuinely newer jobs from other workspaces.
--
-- Two additions, both purely additive (nullable column / new table, no
-- data migration, trivial rollback):
--
-- 1. analysis_jobs.next_eligible_at - a retry-backoff ELIGIBILITY GATE,
--    never a ranking key. NULL for every freshly-enqueued job (identical
--    behavior to today). Only reap_expired_jobs()'s own requeue branch
--    ever sets it (see that function's own docstring for the backoff
--    formula) - the existing job-status UPDATE there gains this ONE
--    extra column, inside the SAME single-commit transaction that
--    already atomically pairs it with the budget release; no new query,
--    no new commit boundary. created_at remains untouched and remains
--    the sole FIFO/audit ordering key among ELIGIBLE candidates.
--
-- 2. workspace_queue_state - one row per workspace, the persisted
--    fairness cursor claim_next_job() orders candidates by
--    (last_claimed_at, this row's own created_at, job created_at, job
--    id) - see claim_next_job()'s own docstring for the full ordering
--    and the locking discipline (FOR UPDATE OF ... SKIP LOCKED) that
--    makes concurrent multi-worker claims respect it correctly. Created
--    lazily inside enqueue_job()'s OWN transaction (never on first
--    claim, unlike workspace_budgets) - a job must never reach 'queued'
--    without its workspace's row already existing, or the claim query's
--    JOIN would silently exclude that workspace from ever being
--    selected. Deliberately carries NO budget/plan/priority/weight
--    column - fairness ordering here is fully independent of
--    workspace_budgets and of any commercial concept; see the read-only
--    design audit for why weighting is explicitly out of scope for now.

ALTER TABLE analysis_jobs ADD COLUMN next_eligible_at TIMESTAMPTZ;

DROP INDEX idx_analysis_jobs_claim_queue;
CREATE INDEX idx_analysis_jobs_claim_queue ON analysis_jobs(status, next_eligible_at, created_at);

CREATE TABLE workspace_queue_state (
    workspace_id     UUID PRIMARY KEY REFERENCES workspaces(id),
    created_at       TIMESTAMPTZ NOT NULL,
    last_claimed_at  TIMESTAMPTZ
);
