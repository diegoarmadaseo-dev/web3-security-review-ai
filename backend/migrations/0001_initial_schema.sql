-- Phase 1 data foundation for the standalone Security Review Analyzer SaaS
-- backend (Capafy-independent architecture). This file is the AUTHORITATIVE
-- schema definition, targeting PostgreSQL 13+.
--
-- Scope, explicitly: structure only. No Stripe integration, no auth logic,
-- no worker/execution code, no Capafy removal happens in this migration -
-- see backend/README.md (none yet - this comment IS the scope note) for
-- what later phases add on top of this foundation.
--
-- Design rules followed throughout:
--   * every tenant-owned table carries its own `workspace_id` column,
--     even where it could be derived by joining through a parent table
--     (e.g. contracts.workspace_id could be derived via project_id) -
--     denormalized deliberately so a tenant-scope filter is always a
--     direct, unmissable column on the row being queried, never an
--     implicit join a future query could forget.
--   * status/lifecycle fields use CHECK (col IN (...)) rather than native
--     Postgres ENUM types: adding an allowed value later is a plain
--     ALTER TABLE, and CHECK is portable to the SQLite test-mirror schema
--     (backend/schema_sqlite.sql) used by this phase's own tests, whereas
--     SQLite has no native ENUM type at all.
--   * TIMESTAMPTZ everywhere (Postgres always stores this as UTC
--     internally regardless of session timezone) - never naive TIMESTAMP.
--   * soft-delete (deleted_at) only on rows where a tombstone genuinely
--     matters (users/workspaces/projects/contracts - deletion policy and
--     retention are product decisions layered on top of this column
--     later). audit_events and webhook_events are deliberately NEVER
--     soft-deletable - they are append-only by design.
--   * no secrets, API keys or payment data anywhere in this file - only
--     opaque references (Stripe customer/subscription IDs, storage keys,
--     a session TOKEN HASH never the raw token).

CREATE EXTENSION IF NOT EXISTS pgcrypto;  -- gen_random_uuid(); harmless no-op on Postgres 13+ where it is built in.

CREATE TABLE schema_migrations (
    version     TEXT PRIMARY KEY,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Identity (structure only - backend/repository.py has no auth flow yet)
-- ---------------------------------------------------------------------------

CREATE TABLE users (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email               TEXT NOT NULL UNIQUE,
    email_verified_at   TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at          TIMESTAMPTZ,
    CONSTRAINT users_email_lowercase CHECK (email = lower(email))
);

CREATE TABLE workspaces (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    owner_user_id   UUID NOT NULL REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at      TIMESTAMPTZ
);
CREATE INDEX idx_workspaces_owner ON workspaces(owner_user_id);

CREATE TABLE workspace_members (
    workspace_id    UUID NOT NULL REFERENCES workspaces(id),
    user_id         UUID NOT NULL REFERENCES users(id),
    role            TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id, user_id)
);
CREATE INDEX idx_workspace_members_user ON workspace_members(user_id);

-- Structure only: token_hash is a placeholder for "never store the raw
-- session token" (hash it, same principle as a password) - the actual
-- issuance/verification/rotation logic is a later phase.
CREATE TABLE sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id),
    token_hash      TEXT NOT NULL UNIQUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ,
    last_seen_at    TIMESTAMPTZ,
    CONSTRAINT sessions_expiry_after_creation CHECK (expires_at > created_at)
);
CREATE INDEX idx_sessions_user ON sessions(user_id);

-- ---------------------------------------------------------------------------
-- Billing mirror (Stripe remains the source of truth; this table is a
-- cache this backend updates from signed webhooks in a later phase - no
-- Stripe call happens on the request hot path).
-- ---------------------------------------------------------------------------

CREATE TABLE entitlements (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id                UUID NOT NULL UNIQUE REFERENCES workspaces(id),
    plan                        TEXT NOT NULL CHECK (plan IN ('quick', 'standard', 'pro')),
    status                      TEXT NOT NULL CHECK (status IN ('active', 'trialing', 'past_due', 'canceled', 'incomplete')),
    stripe_customer_id          TEXT,
    stripe_subscription_id      TEXT UNIQUE,
    current_period_end          TIMESTAMPTZ,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Application data
-- ---------------------------------------------------------------------------

CREATE TABLE projects (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id    UUID NOT NULL REFERENCES workspaces(id),
    name            TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at      TIMESTAMPTZ
);
CREATE INDEX idx_projects_workspace ON projects(workspace_id);
CREATE UNIQUE INDEX uq_projects_workspace_name_live ON projects(workspace_id, name) WHERE deleted_at IS NULL;

-- storage_ref is an OPAQUE key/URI into an object store added in a later
-- phase (local filesystem today, S3-compatible later) - the source
-- payload itself is never a column in this table (report metadata stays
-- separate from large source/report payloads, per Phase 1 scope).
CREATE TABLE contracts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id    UUID NOT NULL REFERENCES workspaces(id),
    project_id      UUID REFERENCES projects(id),
    name            TEXT NOT NULL,
    storage_ref     TEXT NOT NULL,
    content_hash    TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at      TIMESTAMPTZ
);
CREATE INDEX idx_contracts_workspace ON contracts(workspace_id);
CREATE INDEX idx_contracts_project ON contracts(project_id);

-- The queue table. status/created_at is indexed to support the Postgres
-- claim query this schema is designed for:
--   UPDATE analysis_jobs SET status='claimed', claimed_by=$1, claimed_at=now()
--   WHERE id = (SELECT id FROM analysis_jobs WHERE status='queued'
--               ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1)
--   RETURNING id;
-- idempotency_key is an OPTIONAL caller-supplied dedup token (distinct
-- from id, which is generated at enqueue time and is itself already an
-- idempotent identity for the job) - a UNIQUE violation on a retried
-- enqueue call is how the caller detects "this job already exists"
-- instead of creating a duplicate.
CREATE TABLE analysis_jobs (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id            UUID NOT NULL REFERENCES workspaces(id),
    contract_id             UUID NOT NULL REFERENCES contracts(id),
    requested_by_user_id    UUID NOT NULL REFERENCES users(id),
    mode                    TEXT NOT NULL CHECK (mode IN ('quick', 'standard', 'pro')),
    status                  TEXT NOT NULL DEFAULT 'queued'
                                CHECK (status IN ('queued', 'claimed', 'running', 'succeeded', 'failed', 'canceled')),
    claimed_by              TEXT,
    claimed_at              TIMESTAMPTZ,
    started_at              TIMESTAMPTZ,
    completed_at            TIMESTAMPTZ,
    attempt_count           INTEGER NOT NULL DEFAULT 0,
    last_error              TEXT,
    idempotency_key         TEXT UNIQUE,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT analysis_jobs_attempt_count_non_negative CHECK (attempt_count >= 0)
);
CREATE INDEX idx_analysis_jobs_workspace ON analysis_jobs(workspace_id);
CREATE INDEX idx_analysis_jobs_claim_queue ON analysis_jobs(status, created_at);

-- 1:1 with analysis_jobs (job_id UNIQUE). score_status/risk_band mirror
-- report-schema.json's own scoreStatus/riskIndicator.band vocabulary so
-- this row can be filtered/sorted without opening the full payload.
CREATE TABLE reports (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id          UUID NOT NULL UNIQUE REFERENCES analysis_jobs(id),
    workspace_id    UUID NOT NULL REFERENCES workspaces(id),
    storage_ref     TEXT NOT NULL,
    score_status    TEXT NOT NULL CHECK (score_status IN ('computed', 'not_computed')),
    score           INTEGER CHECK (score IS NULL OR (score BETWEEN 0 AND 100)),
    risk_band       TEXT CHECK (risk_band IS NULL OR risk_band IN ('LOW', 'MODERATE', 'HIGH', 'CRITICAL')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Mirrors report-schema.json's own R-08 rule exactly, for the two
    -- fields this table denormalizes from riskIndicator: 'computed'
    -- REQUIRES both score and risk_band to be present (R-08 says "requires
    -- riskIndicator.score/band to be non-null"), not merely ALLOWS them -
    -- the original version of this constraint only enforced the
    -- 'not_computed' direction and silently permitted a 'computed' row
    -- with a NULL score, weaker than R-08 (docs/decisiones.md D-077
    -- follow-up). riskIndicator.message (required by R-08 for
    -- not_computed) is not a column here - this table only denormalizes
    -- score/band for filtering, never the full riskIndicator object.
    CONSTRAINT reports_score_and_band_match_status CHECK (
        (score_status = 'computed' AND score IS NOT NULL AND risk_band IS NOT NULL)
        OR (score_status = 'not_computed' AND score IS NULL AND risk_band IS NULL)
    )
);
CREATE INDEX idx_reports_workspace ON reports(workspace_id);

-- Append-only. Never soft-deleted, never updated after insert.
-- event_type is deliberately free-text (not a closed CHECK enum) - it
-- will grow over time and a rigid enum would need a migration for every
-- new event, the same reasoning pr_gate.py's blockingCategories already
-- documents for the analysis pipeline (docs/decisiones.md D-068).
CREATE TABLE audit_events (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id        UUID REFERENCES workspaces(id),
    actor_user_id       UUID REFERENCES users(id),
    event_type          TEXT NOT NULL,
    metadata            JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_events_workspace ON audit_events(workspace_id);
CREATE INDEX idx_audit_events_actor ON audit_events(actor_user_id);

-- ---------------------------------------------------------------------------
-- Stripe webhook idempotency (later phase wires the receiver; this table
-- exists now so that phase never has to design its own dedup mechanism).
-- Deliberately has NO workspace_id: a webhook event is platform/billing
-- plumbing received before we necessarily know which workspace it maps
-- to, not tenant-owned application data - the one intentional exception
-- to this schema's "every tenant-owned row has workspace_id" rule.
-- ---------------------------------------------------------------------------

CREATE TABLE webhook_events (
    id                  TEXT PRIMARY KEY,  -- Stripe's own event.id, used directly as the dedup key.
    event_type          TEXT NOT NULL,
    received_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    processed_at        TIMESTAMPTZ,
    processing_error    TEXT
);
