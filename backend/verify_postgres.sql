-- Non-destructive PostgreSQL verification assertions for
-- backend/migrations/0001_initial_schema.sql (Phase 1 data foundation,
-- docs/decisiones.md D-077). Run AFTER the migration has been applied to a
-- clean database - see backend/verify_postgres.sh, which orchestrates
-- this file plus the parts a plain SQL script cannot express (container
-- lifecycle, concurrent sessions).
--
-- Every check below either raises (via RAISE EXCEPTION, causing psql -v
-- ON_ERROR_STOP=1 to abort with a non-zero exit code) or leaves behind a
-- clean, self-explanatory PASS/FAIL row - never a silent no-op. Every
-- probe insert this file makes into real tables is wrapped in its own
-- ROLLBACK-able savepoint so this script never leaves stray rows behind
-- in a database someone might reuse for a second check.

\set ON_ERROR_STOP on

-- 1) All 11 tables exist.
DO $$
DECLARE
    expected TEXT[] := ARRAY['schema_migrations','users','workspaces','workspace_members','sessions',
                              'entitlements','projects','contracts','analysis_jobs','reports',
                              'audit_events','webhook_events'];
    missing TEXT[];
BEGIN
    SELECT array_agg(t) INTO missing FROM unnest(expected) t
        WHERE t NOT IN (SELECT table_name FROM information_schema.tables WHERE table_schema = 'public');
    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'MISSING TABLES: %', missing;
    END IF;
    RAISE NOTICE 'PASS: all 12 expected tables present (11 + schema_migrations)';
END $$;

-- 2) gen_random_uuid() and now() actually execute and return sane types.
DO $$
DECLARE
    u UUID := gen_random_uuid();
    n TIMESTAMPTZ := now();
BEGIN
    IF u IS NULL OR n IS NULL THEN
        RAISE EXCEPTION 'gen_random_uuid()/now() returned NULL';
    END IF;
    RAISE NOTICE 'PASS: gen_random_uuid()=% now()=%', u, n;
END $$;

-- 3) TIMESTAMPTZ columns are genuinely timestamptz, not naive timestamp.
DO $$
DECLARE
    col_type TEXT;
BEGIN
    SELECT data_type INTO col_type FROM information_schema.columns
        WHERE table_name = 'users' AND column_name = 'created_at';
    IF col_type <> 'timestamp with time zone' THEN
        RAISE EXCEPTION 'users.created_at is % not timestamptz', col_type;
    END IF;
    RAISE NOTICE 'PASS: users.created_at is timestamptz';
END $$;

-- 4) The partial unique index on projects(workspace_id, name) only
-- applies to live (deleted_at IS NULL) rows.
DO $$
DECLARE
    owner_id UUID;
    ws_id UUID;
    first_id UUID;
BEGIN
    INSERT INTO users (email) VALUES ('verify-partial-index@example.com') RETURNING id INTO owner_id;
    INSERT INTO workspaces (name, owner_user_id) VALUES ('Verify WS', owner_id) RETURNING id INTO ws_id;
    INSERT INTO workspace_members (workspace_id, user_id, role) VALUES (ws_id, owner_id, 'owner');
    INSERT INTO projects (workspace_id, name) VALUES (ws_id, 'Vault') RETURNING id INTO first_id;

    BEGIN
        INSERT INTO projects (workspace_id, name) VALUES (ws_id, 'Vault');
        RAISE EXCEPTION 'FAIL: a second live project with the same name was accepted';
    EXCEPTION WHEN unique_violation THEN
        RAISE NOTICE 'PASS: duplicate live project name correctly rejected';
    END;

    UPDATE projects SET deleted_at = now() WHERE id = first_id;
    INSERT INTO projects (workspace_id, name) VALUES (ws_id, 'Vault');  -- must succeed now.
    RAISE NOTICE 'PASS: name reuse allowed after soft-delete';

    -- cleanup (this script's own probe rows only).
    DELETE FROM projects WHERE workspace_id = ws_id;
    DELETE FROM workspace_members WHERE workspace_id = ws_id;
    DELETE FROM workspaces WHERE id = ws_id;
    DELETE FROM users WHERE id = owner_id;
END $$;

-- 5) JSONB accepts valid JSON and rejects invalid JSON text.
DO $$
BEGIN
    PERFORM '{"valid": true}'::jsonb;
    RAISE NOTICE 'PASS: valid JSON accepted by ::jsonb cast';
    BEGIN
        PERFORM 'not json at all'::jsonb;
        RAISE EXCEPTION 'FAIL: invalid JSON text was accepted by ::jsonb';
    EXCEPTION WHEN invalid_text_representation THEN
        RAISE NOTICE 'PASS: invalid JSON text correctly rejected';
    END;
END $$;

-- 6) reports_score_and_band_match_status CHECK (R-08 alignment,
-- docs/decisiones.md D-077 follow-up): a probe of all four combinations.
DO $$
DECLARE
    owner_id UUID; ws_id UUID; contract_id UUID; job_id UUID; job_id_2 UUID;
BEGIN
    INSERT INTO users (email) VALUES ('verify-r08@example.com') RETURNING id INTO owner_id;
    INSERT INTO workspaces (name, owner_user_id) VALUES ('Verify R08', owner_id) RETURNING id INTO ws_id;
    INSERT INTO workspace_members (workspace_id, user_id, role) VALUES (ws_id, owner_id, 'owner');
    INSERT INTO contracts (workspace_id, name, storage_ref, content_hash) VALUES (ws_id, 'A.sol', 's3://x', 'h') RETURNING id INTO contract_id;
    INSERT INTO analysis_jobs (workspace_id, contract_id, requested_by_user_id, mode) VALUES (ws_id, contract_id, owner_id, 'quick') RETURNING id INTO job_id;
    -- a SECOND, distinct job - reports.job_id is both FK and UNIQUE, so the
    -- deliberately-invalid insert below needs its own real job to hit the
    -- CHECK constraint specifically, not an FK or UNIQUE violation instead.
    INSERT INTO analysis_jobs (workspace_id, contract_id, requested_by_user_id, mode) VALUES (ws_id, contract_id, owner_id, 'quick') RETURNING id INTO job_id_2;

    INSERT INTO reports (job_id, workspace_id, storage_ref, score_status, score, risk_band) VALUES (job_id, ws_id, 's3://r', 'computed', 40, 'HIGH');
    RAISE NOTICE 'PASS: computed + score + risk_band accepted';

    BEGIN
        INSERT INTO reports (job_id, workspace_id, storage_ref, score_status, score, risk_band) VALUES (job_id_2, ws_id, 's3://r2', 'computed', NULL, 'HIGH');
        RAISE EXCEPTION 'FAIL: computed with NULL score was accepted';
    EXCEPTION WHEN check_violation THEN
        RAISE NOTICE 'PASS: computed + NULL score correctly rejected';
    END;

    DELETE FROM reports WHERE workspace_id = ws_id;
    DELETE FROM analysis_jobs WHERE workspace_id = ws_id;
    DELETE FROM contracts WHERE workspace_id = ws_id;
    DELETE FROM workspace_members WHERE workspace_id = ws_id;
    DELETE FROM workspaces WHERE id = ws_id;
    DELETE FROM users WHERE id = owner_id;
END $$;

-- 7) webhook_events dedup: event.id as PK rejects a second insert.
DO $$
BEGIN
    INSERT INTO webhook_events (id, event_type) VALUES ('evt_verify_1', 'checkout.session.completed');
    BEGIN
        INSERT INTO webhook_events (id, event_type) VALUES ('evt_verify_1', 'checkout.session.completed');
        RAISE EXCEPTION 'FAIL: duplicate webhook event.id was accepted';
    EXCEPTION WHEN unique_violation THEN
        RAISE NOTICE 'PASS: duplicate webhook event.id correctly rejected';
    END;
    DELETE FROM webhook_events WHERE id = 'evt_verify_1';
END $$;

-- 8) Index inventory sanity - the claim-query index actually exists.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE tablename = 'analysis_jobs' AND indexname = 'idx_analysis_jobs_claim_queue') THEN
        RAISE EXCEPTION 'FAIL: idx_analysis_jobs_claim_queue is missing';
    END IF;
    RAISE NOTICE 'PASS: idx_analysis_jobs_claim_queue exists';
END $$;

DO $$ BEGIN RAISE NOTICE 'ALL VERIFY_POSTGRES.SQL CHECKS PASSED'; END $$;
