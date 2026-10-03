-- GitHub Actions (docs/decisiones.md D-114). Mirrored in
-- backend/schema_sqlite.sql. No existing row changes meaning.
--
-- contract_ci_sources - for a scan submitted by the Vericexa GitHub Action
-- through the Private API (POST /api/v1/scans with a "ci" object), the CI
-- context it reported: repository, exact commit SHA scanned, ref, event
-- (push / pull_request), workflow run id/attempt and PR number. Written in
-- the SAME transaction as the contract row. It is metadata REPORTED by the
-- client (Vericexa never holds a GitHub token and does not verify it with
-- GitHub); the analysed content is always the files actually submitted.

CREATE TABLE contract_ci_sources (
    contract_id          UUID PRIMARY KEY REFERENCES contracts(id),
    workspace_id         UUID NOT NULL REFERENCES workspaces(id),
    provider             TEXT NOT NULL CHECK (provider = 'github_actions'),
    repository           TEXT NOT NULL CHECK (char_length(repository) BETWEEN 3 AND 140),
    commit_sha           TEXT NOT NULL CHECK (commit_sha ~ '^[0-9a-f]{40}$'),
    ref                  TEXT CHECK (ref IS NULL OR char_length(ref) BETWEEN 1 AND 255),
    event                TEXT NOT NULL CHECK (event IN ('push', 'pull_request')),
    run_id               BIGINT NOT NULL CHECK (run_id > 0),
    run_attempt          INTEGER NOT NULL CHECK (run_attempt BETWEEN 1 AND 10000),
    pull_request_number  INTEGER CHECK (pull_request_number IS NULL OR pull_request_number > 0),
    created_at           TIMESTAMPTZ NOT NULL,
    CONSTRAINT contract_ci_sources_pr_matches_event CHECK ((event = 'pull_request') = (pull_request_number IS NOT NULL))
);
CREATE INDEX idx_contract_ci_sources_workspace ON contract_ci_sources(workspace_id);
