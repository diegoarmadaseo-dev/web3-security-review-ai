-- SQLite TEST MIRROR of backend/migrations/0001_initial_schema.sql - NOT a
-- second source of truth. This file exists only because this environment
-- has no PostgreSQL server or driver (psycopg2/psycopg/sqlalchemy) available
-- and this project's own long-standing discipline is standard-library-only
-- code with no new third-party dependency added without it being asked for
-- explicitly. sqlite3 is stdlib and genuinely enforces FOREIGN KEY/UNIQUE/
-- CHECK constraints, which makes it an honest (if not byte-identical) way
-- to test this schema's LOGICAL constraints and the job state machine.
--
-- Known, deliberate differences from the Postgres migration (never silently
-- papered over):
--   * UUID -> TEXT. The application layer (backend/repository.py) always
--     generates the UUID itself in Python (uuid.uuid4()) and supplies it
--     explicitly on every insert, for BOTH backends - so this difference
--     never leaks into repository.py's own logic, only into the DDL.
--   * TIMESTAMPTZ -> TEXT (ISO-8601 UTC, e.g. "2026-09-20T20:30:00+00:00").
--     repository.py always supplies timestamps explicitly (datetime.now
--     (timezone.utc).isoformat()) rather than relying on either engine's
--     own now()/CURRENT_TIMESTAMP, so behavior is identical either way.
--   * JSONB -> TEXT (JSON-encoded). No native JSON type in SQLite.
--   * gen_random_uuid()/now() defaults are dropped - the application always
--     supplies these values explicitly (see above), so no default is needed.
--   * FOREIGN KEY enforcement is OFF by default per SQLite connection and
--     MUST be turned on with "PRAGMA foreign_keys = ON" - backend/
--     repository.py's connect() helper does this on every connection it
--     opens; a test bypassing that helper would silently test nothing.
--   * There is no equivalent to "FOR UPDATE SKIP LOCKED" in SQLite - the
--     claim-race test in tests/test_backend_job_queue.py verifies the
--     narrower, portable property (a conditional UPDATE ... WHERE status=
--     'queued' only ever succeeds for exactly one claimant), not the
--     Postgres-specific row-locking mechanism itself.

CREATE TABLE schema_migrations (
    version     TEXT PRIMARY KEY,
    applied_at  TEXT NOT NULL
);

CREATE TABLE users (
    id                  TEXT PRIMARY KEY,
    email               TEXT NOT NULL UNIQUE,
    email_verified_at   TEXT,
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    deleted_at          TEXT,
    CHECK (email = lower(email))
);

CREATE TABLE workspaces (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    owner_user_id   TEXT NOT NULL REFERENCES users(id),
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    deleted_at      TEXT
);
CREATE INDEX idx_workspaces_owner ON workspaces(owner_user_id);

CREATE TABLE workspace_members (
    workspace_id    TEXT NOT NULL REFERENCES workspaces(id),
    user_id         TEXT NOT NULL REFERENCES users(id),
    role            TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    created_at      TEXT NOT NULL,
    PRIMARY KEY (workspace_id, user_id)
);
CREATE INDEX idx_workspace_members_user ON workspace_members(user_id);

CREATE TABLE sessions (
    id              TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL REFERENCES users(id),
    token_hash      TEXT NOT NULL UNIQUE,
    created_at      TEXT NOT NULL,
    expires_at      TEXT NOT NULL,
    revoked_at      TEXT,
    last_seen_at    TEXT,
    CHECK (expires_at > created_at)
);
CREATE INDEX idx_sessions_user ON sessions(user_id);

CREATE TABLE entitlements (
    id                          TEXT PRIMARY KEY,
    workspace_id                TEXT NOT NULL UNIQUE REFERENCES workspaces(id),
    plan                        TEXT NOT NULL CHECK (plan IN ('quick', 'standard', 'pro')),
    -- Phase 3 (backend/migrations/0003_entitlement_status_expand.sql's
    -- mirror): the full set of real Stripe Subscription statuses.
    status                      TEXT NOT NULL CHECK (status IN ('active', 'trialing', 'past_due', 'canceled', 'incomplete', 'incomplete_expired', 'unpaid')),
    stripe_customer_id          TEXT,
    stripe_subscription_id      TEXT UNIQUE,
    current_period_end          TEXT,
    -- Phase 3 (backend/migrations/0004_entitlement_event_provenance.sql's
    -- mirror): ordering baseline against stale/out-of-order webhooks.
    stripe_event_created_at     TEXT,
    -- Phase 7 (backend/migrations/0007_billing_interval.sql's mirror):
    -- 'monthly'/'annual', nullable - see that migration's own comment.
    billing_interval            TEXT CHECK (billing_interval IN ('monthly', 'annual')),
    -- D-107 (backend/migrations/0009_commercial_usage.sql's mirror): anchor
    -- for Standard/Pro service months; nullable (falls back to created_at).
    current_period_start        TEXT,
    created_at                  TEXT NOT NULL,
    updated_at                  TEXT NOT NULL
);

CREATE TABLE projects (
    id              TEXT PRIMARY KEY,
    workspace_id    TEXT NOT NULL REFERENCES workspaces(id),
    name            TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    deleted_at      TEXT
);
CREATE INDEX idx_projects_workspace ON projects(workspace_id);
CREATE UNIQUE INDEX uq_projects_workspace_name_live ON projects(workspace_id, name) WHERE deleted_at IS NULL;

CREATE TABLE contracts (
    id              TEXT PRIMARY KEY,
    workspace_id    TEXT NOT NULL REFERENCES workspaces(id),
    project_id      TEXT REFERENCES projects(id),
    name            TEXT NOT NULL,
    storage_ref     TEXT NOT NULL,
    content_hash    TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    deleted_at      TEXT
);
CREATE INDEX idx_contracts_workspace ON contracts(workspace_id);
CREATE INDEX idx_contracts_project ON contracts(project_id);

CREATE TABLE analysis_jobs (
    id                      TEXT PRIMARY KEY,
    workspace_id            TEXT NOT NULL REFERENCES workspaces(id),
    contract_id             TEXT NOT NULL REFERENCES contracts(id),
    requested_by_user_id    TEXT NOT NULL REFERENCES users(id),
    mode                    TEXT NOT NULL CHECK (mode IN ('quick', 'standard', 'pro')),
    status                  TEXT NOT NULL DEFAULT 'queued'
                                CHECK (status IN ('queued', 'claimed', 'running', 'succeeded', 'failed', 'canceled')),
    claimed_by              TEXT,
    claimed_at              TEXT,
    started_at              TEXT,
    completed_at            TEXT,
    attempt_count           INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    last_error              TEXT,
    idempotency_key         TEXT UNIQUE,
    created_at              TEXT NOT NULL,
    -- Phase 4 (backend/migrations/0005_job_queue_hardening.sql's mirror).
    lease_expires_at        TEXT,
    -- Admission control / queue fairness (backend/migrations/0008_queue_fairness.sql's
    -- mirror): NULL for every freshly-enqueued job (immediately eligible,
    -- no behavior change). Only reap_expired_jobs()'s own requeue branch
    -- ever sets it, as a retry-backoff gate - see that function's own
    -- docstring. Purely a WHERE-clause eligibility filter, never an
    -- ORDER BY key - created_at remains the sole FIFO/audit timestamp.
    next_eligible_at        TEXT,
    -- D-108 (backend/migrations/0010_commercial_guards.sql's mirror): 1 for
    -- a job admitted under a priority plan (Pro), read only by
    -- claim_next_job()'s ordering.
    priority                INTEGER NOT NULL DEFAULT 0 CHECK (priority IN (0, 1))
);
CREATE INDEX idx_analysis_jobs_workspace ON analysis_jobs(workspace_id);
CREATE INDEX idx_analysis_jobs_claim_queue ON analysis_jobs(status, next_eligible_at, created_at);

CREATE TABLE reports (
    id              TEXT PRIMARY KEY,
    job_id          TEXT NOT NULL UNIQUE REFERENCES analysis_jobs(id),
    workspace_id    TEXT NOT NULL REFERENCES workspaces(id),
    storage_ref     TEXT NOT NULL,
    score_status    TEXT NOT NULL CHECK (score_status IN ('computed', 'not_computed')),
    score           INTEGER CHECK (score IS NULL OR (score BETWEEN 0 AND 100)),
    risk_band       TEXT CHECK (risk_band IS NULL OR risk_band IN ('LOW', 'MODERATE', 'HIGH', 'CRITICAL')),
    created_at      TEXT NOT NULL,
    -- Phase 6A (backend/migrations/0006_retention_purge.sql's mirror).
    purged_at       TEXT,
    -- Mirrors report-schema.json's R-08 exactly (see the same constraint,
    -- named, in the Postgres migration - docs/decisiones.md D-077
    -- follow-up): 'computed' REQUIRES score AND risk_band non-null,
    -- 'not_computed' requires both null.
    CHECK (
        (score_status = 'computed' AND score IS NOT NULL AND risk_band IS NOT NULL)
        OR (score_status = 'not_computed' AND score IS NULL AND risk_band IS NULL)
    )
);
CREATE INDEX idx_reports_workspace ON reports(workspace_id);

CREATE TABLE audit_events (
    id                  TEXT PRIMARY KEY,
    workspace_id        TEXT REFERENCES workspaces(id),
    actor_user_id       TEXT REFERENCES users(id),
    event_type          TEXT NOT NULL,
    metadata            TEXT NOT NULL DEFAULT '{}',
    created_at          TEXT NOT NULL
);
CREATE INDEX idx_audit_events_workspace ON audit_events(workspace_id);
CREATE INDEX idx_audit_events_actor ON audit_events(actor_user_id);

CREATE TABLE webhook_events (
    id                  TEXT PRIMARY KEY,
    event_type          TEXT NOT NULL,
    received_at         TEXT NOT NULL,
    processed_at        TEXT,
    processing_error    TEXT
);

-- Phase 2 (backend/migrations/0002_auth_tokens.sql's mirror - see that
-- file's docstring for why this is separate from `sessions`, and for
-- requested_ip's rate-limit-only purpose).
CREATE TABLE auth_tokens (
    id              TEXT PRIMARY KEY,
    email           TEXT NOT NULL,
    token_hash      TEXT NOT NULL UNIQUE,
    requested_ip    TEXT,
    created_at      TEXT NOT NULL,
    expires_at      TEXT NOT NULL,
    consumed_at     TEXT,
    CHECK (expires_at > created_at),
    CHECK (email = lower(email))
);
CREATE INDEX idx_auth_tokens_email_created ON auth_tokens(email, created_at);
CREATE INDEX idx_auth_tokens_ip_created ON auth_tokens(requested_ip, created_at);

-- Phase 4 (backend/migrations/0005_job_queue_hardening.sql's mirror).
CREATE TABLE workspace_budgets (
    workspace_id     TEXT PRIMARY KEY REFERENCES workspaces(id),
    period_start     TEXT NOT NULL,
    limit_units      INTEGER NOT NULL,
    reserved_units   INTEGER NOT NULL DEFAULT 0,
    consumed_units   INTEGER NOT NULL DEFAULT 0,
    updated_at       TEXT NOT NULL,
    CHECK (reserved_units >= 0 AND consumed_units >= 0 AND limit_units >= 0),
    CHECK (reserved_units + consumed_units <= limit_units)
);

-- Admission control / queue fairness (backend/migrations/0008_queue_fairness.sql's
-- mirror). One row per workspace, created lazily inside enqueue_job()'s OWN
-- transaction (never on first claim, unlike workspace_budgets above) -
-- a job must never become 'queued' without its workspace already having
-- this row, or claim_next_job()'s own INNER JOIN would silently exclude
-- that workspace from ever being selected. created_at breaks ties between
-- two workspaces that have never been claimed (last_claimed_at IS NULL
-- for both) - see claim_next_job()'s own docstring for the full ORDER BY.
CREATE TABLE workspace_queue_state (
    workspace_id     TEXT PRIMARY KEY REFERENCES workspaces(id),
    created_at       TEXT NOT NULL,
    last_claimed_at  TEXT
);

-- D-107 (backend/migrations/0009_commercial_usage.sql's mirror) - see that
-- migration for the full reasoning behind each table.
CREATE TABLE scan_credits (
    id           TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    status       TEXT NOT NULL CHECK (status IN ('available', 'reserved', 'consumed')),
    job_id       TEXT UNIQUE REFERENCES analysis_jobs(id),
    granted_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);
CREATE INDEX idx_scan_credits_workspace_status ON scan_credits(workspace_id, status, granted_at);

CREATE TABLE usage_periods (
    workspace_id  TEXT NOT NULL REFERENCES workspaces(id),
    period_start  TEXT NOT NULL,
    period_end    TEXT NOT NULL,
    limit_loc     INTEGER NOT NULL,
    reserved_loc  INTEGER NOT NULL DEFAULT 0,
    consumed_loc  INTEGER NOT NULL DEFAULT 0,
    updated_at    TEXT NOT NULL,
    PRIMARY KEY (workspace_id, period_start),
    CHECK (reserved_loc >= 0 AND consumed_loc >= 0 AND limit_loc >= 0),
    CHECK (period_end > period_start)
);

CREATE TABLE job_usage (
    job_id         TEXT PRIMARY KEY REFERENCES analysis_jobs(id),
    workspace_id   TEXT NOT NULL REFERENCES workspaces(id),
    plan           TEXT NOT NULL CHECK (plan IN ('quick', 'standard', 'pro')),
    usage_model    TEXT NOT NULL CHECK (usage_model IN ('scan_credit', 'service_month')),
    effective_loc  INTEGER NOT NULL CHECK (effective_loc >= 0),
    period_start   TEXT,
    credit_id      TEXT REFERENCES scan_credits(id),
    status         TEXT NOT NULL CHECK (status IN ('reserved', 'consumed', 'released')),
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL,
    tech_units     INTEGER NOT NULL DEFAULT 0 CHECK (tech_units >= 0),   -- D-108
    CHECK (
        (usage_model = 'scan_credit' AND credit_id IS NOT NULL AND period_start IS NULL)
        OR (usage_model = 'service_month' AND period_start IS NOT NULL AND credit_id IS NULL)
    )
);
CREATE INDEX idx_job_usage_workspace ON job_usage(workspace_id, status);

-- D-108 (backend/migrations/0010_commercial_guards.sql's mirror) - see that
-- migration's header for what each table is for.
CREATE TABLE technical_budget_periods (
    workspace_id    TEXT NOT NULL REFERENCES workspaces(id),
    period_start    TEXT NOT NULL,
    period_end      TEXT NOT NULL,
    limit_units     INTEGER NOT NULL,
    reserved_units  INTEGER NOT NULL DEFAULT 0,
    consumed_units  INTEGER NOT NULL DEFAULT 0,
    updated_at      TEXT NOT NULL,
    PRIMARY KEY (workspace_id, period_start),
    CHECK (reserved_units >= 0 AND consumed_units >= 0 AND limit_units >= 0),
    CHECK (period_end > period_start)
);

CREATE TABLE submit_attempts (
    id            TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL REFERENCES users(id),
    workspace_id  TEXT NOT NULL REFERENCES workspaces(id),
    created_at    TEXT NOT NULL
);
CREATE INDEX idx_submit_attempts_user_created ON submit_attempts(user_id, created_at);
