-- Private API (docs/decisiones.md D-113). Mirrored in
-- backend/schema_sqlite.sql. No existing row changes meaning.
--
-- 1. api_keys - credentials of the authenticated Private API (/api/v1/).
--    A key belongs to ONE workspace and acts as the member who created it
--    (user_id): every request re-resolves that member's current role, so a
--    removed member's keys stop working. Only a SHA-256 hash of the full
--    secret is stored (key_hash); the secret is shown once, at creation, and
--    never again. key_prefix is the public, non-secret lookup id embedded in
--    the key itself (vcx_<key_prefix>_<secret>). Revocation sets revoked_at
--    (the row is kept for audit; the workspace is untouched); rotation =
--    create a new key, then revoke the old one.
--
-- 2. analysis_jobs.request_fingerprint - SHA-256 of a submission's canonical
--    content (mode, project, input shape and source digest or GitHub spec),
--    stored with the job so a Private API client reusing an idempotency key
--    with a DIFFERENT request gets a deterministic 409 instead of the first
--    job. NULL for every job enqueued before this migration.

CREATE TABLE api_keys (
    id                  UUID PRIMARY KEY,
    workspace_id        UUID NOT NULL REFERENCES workspaces(id),
    user_id             UUID NOT NULL REFERENCES users(id),
    name                TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
    key_prefix          TEXT NOT NULL UNIQUE CHECK (key_prefix ~ '^[0-9a-f]{12}$'),
    key_hash            TEXT NOT NULL UNIQUE CHECK (key_hash ~ '^[0-9a-f]{64}$'),
    created_at          TIMESTAMPTZ NOT NULL,
    last_used_at        TIMESTAMPTZ,
    revoked_at          TIMESTAMPTZ,
    revoked_by_user_id  UUID REFERENCES users(id)
);
CREATE INDEX idx_api_keys_workspace ON api_keys(workspace_id);

ALTER TABLE analysis_jobs ADD COLUMN request_fingerprint TEXT CHECK (request_fingerprint IS NULL OR request_fingerprint ~ '^[0-9a-f]{64}$');
