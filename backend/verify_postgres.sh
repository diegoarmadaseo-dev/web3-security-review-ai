#!/usr/bin/env bash
# Reproducible, disposable PostgreSQL 13+ verification for
# backend/migrations/0001_initial_schema.sql (Phase 1 data foundation,
# docs/decisiones.md D-077).
#
# PREPARED, NOT YET RUN: this script starts and destroys a throwaway
# Docker container. It must only be executed with the user's explicit,
# separate approval for THIS run - never invoked automatically. Nothing
# it does touches any persistent volume, real credentials, or any table
# outside its own single-use container.
#
# Usage (after approval):
#   bash backend/verify_postgres.sh
#
# What it proves, in order:
#   1. 0001_initial_schema.sql applies cleanly to a brand-new PostgreSQL
#      13+ database as ONE atomic transaction (--single-transaction).
#   2. A migration file with a deliberate syntax error rolls back
#      completely (no partial schema left behind) - proves point 1's
#      atomicity claim isn't accidental.
#   3. Re-running the SAME migration file a second time (raw, no
#      schema_migrations tracking) fails, because these are real DDL
#      statements with no IF NOT EXISTS silently masking a broken
#      migration - NOT a claim that migrate.py's own tracked-idempotent
#      rerun was exercised (that needs a psycopg2 adapter, not built in
#      Phase 1 - see this phase's own audit notes).
#   4. backend/verify_postgres.sql's assertions (tables, gen_random_uuid/
#      now(), TIMESTAMPTZ, JSONB, partial unique index, R-08 CHECK,
#      webhook dedup, the claim-queue index).
#   5. A REAL two-session FOR UPDATE SKIP LOCKED concurrent claim: two
#      psql processes race for the one queued job this script seeds;
#      exactly one must win, the other must get nothing.
#
# Exits non-zero on the first failure. Always tears the container down,
# even on failure (trap on EXIT).
set -euo pipefail

CONTAINER_NAME="phase1-verify-pg"
PG_PORT="55432"  # non-default, avoids colliding with any local Postgres.
PG_IMAGE="postgres:15"
PGPASSWORD_VALUE="verify-throwaway"  # this container is --rm, localhost-only, torn down at script exit - never a real credential.
DB_NAME="phase1verify"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MIGRATION_FILE="$REPO_ROOT/backend/migrations/0001_initial_schema.sql"
VERIFY_SQL="$REPO_ROOT/backend/verify_postgres.sql"

cleanup() {
    echo "--- tearing down $CONTAINER_NAME ---"
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

run_psql() {
    PGPASSWORD="$PGPASSWORD_VALUE" docker exec -i "$CONTAINER_NAME" \
        psql -h localhost -U postgres -d "$DB_NAME" -v ON_ERROR_STOP=1 "$@"
}

echo "--- starting disposable $PG_IMAGE on 127.0.0.1:$PG_PORT ---"
docker run --rm -d --name "$CONTAINER_NAME" \
    -e POSTGRES_PASSWORD="$PGPASSWORD_VALUE" -e POSTGRES_DB="$DB_NAME" \
    -p "127.0.0.1:${PG_PORT}:5432" "$PG_IMAGE" >/dev/null

echo "--- waiting for readiness ---"
for _ in $(seq 1 30); do
    if docker exec "$CONTAINER_NAME" pg_isready -U postgres >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
docker exec "$CONTAINER_NAME" pg_isready -U postgres

echo "--- [1] applying 0001_initial_schema.sql (single transaction, stop on error) ---"
run_psql --single-transaction -f - < "$MIGRATION_FILE"
echo "PASS: clean apply succeeded"

echo "--- [2] rollback-on-failure: a deliberately broken migration must leave nothing behind ---"
docker exec "$CONTAINER_NAME" psql -U postgres -c "DROP DATABASE $DB_NAME;" >/dev/null
docker exec "$CONTAINER_NAME" psql -U postgres -c "CREATE DATABASE ${DB_NAME}_broken;" >/dev/null
{ cat "$MIGRATION_FILE"; echo "THIS IS NOT VALID SQL;"; } > /tmp/broken_migration.sql
if PGPASSWORD="$PGPASSWORD_VALUE" docker exec -i "$CONTAINER_NAME" \
    psql -h localhost -U postgres -d "${DB_NAME}_broken" -v ON_ERROR_STOP=1 --single-transaction -f - < /tmp/broken_migration.sql >/dev/null 2>&1; then
    echo "FAIL: broken migration did not fail as expected"; exit 1
fi
TABLE_COUNT=$(docker exec "$CONTAINER_NAME" psql -U postgres -d "${DB_NAME}_broken" -t -c \
    "SELECT count(*) FROM information_schema.tables WHERE table_schema='public';")
if [ "$(echo "$TABLE_COUNT" | tr -d '[:space:]')" != "0" ]; then
    echo "FAIL: rollback left $TABLE_COUNT table(s) behind"; exit 1
fi
echo "PASS: broken migration rolled back completely, zero tables left behind"
docker exec "$CONTAINER_NAME" psql -U postgres -c "CREATE DATABASE $DB_NAME;" >/dev/null
run_psql --single-transaction -f - < "$MIGRATION_FILE"

echo "--- [3] raw re-apply (no schema_migrations tracking) must fail, never silently no-op ---"
if run_psql -f - < "$MIGRATION_FILE" >/dev/null 2>&1; then
    echo "FAIL: re-applying the same migration file raw did not fail"; exit 1
fi
echo "PASS: raw re-apply correctly fails (these are real DDL statements, not accidentally idempotent)"

echo "--- [4] running verify_postgres.sql assertions ---"
run_psql -f - < "$VERIFY_SQL"

echo "--- [5] concurrent FOR UPDATE SKIP LOCKED claim: two sessions race for one queued job ---"
run_psql -c "
INSERT INTO users (id, email) VALUES ('11111111-1111-1111-1111-111111111111', 'claimtest@example.com');
INSERT INTO workspaces (id, name, owner_user_id) VALUES ('22222222-2222-2222-2222-222222222222', 'Claim Test', '11111111-1111-1111-1111-111111111111');
INSERT INTO workspace_members (workspace_id, user_id, role) VALUES ('22222222-2222-2222-2222-222222222222', '11111111-1111-1111-1111-111111111111', 'owner');
INSERT INTO contracts (id, workspace_id, name, storage_ref, content_hash) VALUES ('33333333-3333-3333-3333-333333333333', '22222222-2222-2222-2222-222222222222', 'A.sol', 's3://x', 'h');
INSERT INTO analysis_jobs (id, workspace_id, contract_id, requested_by_user_id, mode) VALUES ('44444444-4444-4444-4444-444444444444', '22222222-2222-2222-2222-222222222222', '33333333-3333-3333-3333-333333333333', '11111111-1111-1111-1111-111111111111', 'quick');
"

CLAIM_SQL="
BEGIN;
SELECT pg_sleep(0.2);
WITH picked AS (
    SELECT id FROM analysis_jobs WHERE status = 'queued' ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1
)
UPDATE analysis_jobs SET status = 'claimed', claimed_by = :'worker' WHERE id = (SELECT id FROM picked)
RETURNING id;
COMMIT;
"
# NOTE: psql's "-c" does NOT perform :'var' interpolation (verified against
# the real postgres:15 image - -c sends the string to the server verbatim;
# only script mode, -f/stdin, runs it through psql's own variable lexer
# first). Feed CLAIM_SQL via stdin (-f -) so :'worker' is actually substituted.
run_psql -v worker=worker_A -f - <<< "$CLAIM_SQL" > /tmp/claim_a.out 2>&1 &
PID_A=$!
run_psql -v worker=worker_B -f - <<< "$CLAIM_SQL" > /tmp/claim_b.out 2>&1 &
PID_B=$!
wait "$PID_A" "$PID_B"

CLAIMED_COUNT=$(docker exec "$CONTAINER_NAME" psql -U postgres -d "$DB_NAME" -t -c \
    "SELECT count(*) FROM analysis_jobs WHERE status = 'claimed';")
if [ "$(echo "$CLAIMED_COUNT" | tr -d '[:space:]')" != "1" ]; then
    echo "FAIL: expected exactly 1 claimed job, got: $CLAIMED_COUNT"
    cat /tmp/claim_a.out /tmp/claim_b.out
    exit 1
fi
echo "PASS: exactly one of the two concurrent sessions claimed the job (see /tmp/claim_a.out, /tmp/claim_b.out for which)"

echo "=== ALL POSTGRESQL VERIFICATION STEPS PASSED ==="
