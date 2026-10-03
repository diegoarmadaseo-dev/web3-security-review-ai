-- Private GitHub source for Standard/Pro (docs/decisiones.md D-111).
-- Purely additive: three new tables; no existing column or constraint is
-- touched (contracts.source_kind keeps its D-109 values - a GitHub scan is
-- stored as the same 'files' bundle, and contract_git_sources says where it
-- came from). Trivial rollback. Mirrored in backend/schema_sqlite.sql.
--
-- 1. github_connections - one GitHub App user authorization per (workspace,
--    member). Only what is needed: the GitHub account id and login, the
--    status, the scopes GitHub reported, timestamps, and the user access /
--    refresh tokens ENCRYPTED by backend/github_integration.TokenCipher
--    (authenticated, bound to this workspace+user, key from
--    GITHUB_TOKEN_ENCRYPTION_KEY - never stored here). A revoked or invalid
--    connection keeps its row for history with both tokens wiped (NULL).
--    At most one active connection per (workspace, user).
--
-- 2. github_oauth_states - the OAuth "state" of an authorization in flight:
--    only its SHA-256 is stored, it is bound to the member and workspace
--    that started it, expires after a few minutes and is consumed exactly
--    once (consumed_at). Expired rows are pruned when new ones are created.
--
-- 3. contract_git_sources - reproducibility of a GitHub scan: repository
--    (GitHub's numeric id and the full name GitHub reported), the branch,
--    and the EXACT commit SHA whose tree was analysed. Metadata only - never
--    a token. Kept with the contract row, like contract_files.

CREATE TABLE github_connections (
    id                        UUID PRIMARY KEY,
    workspace_id              UUID NOT NULL REFERENCES workspaces(id),
    user_id                   UUID NOT NULL REFERENCES users(id),
    provider                  TEXT NOT NULL DEFAULT 'github' CHECK (provider = 'github'),
    github_account_id         BIGINT NOT NULL,
    github_login              TEXT NOT NULL,
    status                    TEXT NOT NULL CHECK (status IN ('active', 'revoked', 'invalid')),
    access_token_enc          TEXT,
    access_token_expires_at   TIMESTAMPTZ,
    refresh_token_enc         TEXT,
    refresh_token_expires_at  TIMESTAMPTZ,
    scopes                    TEXT NOT NULL DEFAULT '',
    created_at                TIMESTAMPTZ NOT NULL,
    updated_at                TIMESTAMPTZ NOT NULL,
    revoked_at                TIMESTAMPTZ,
    CONSTRAINT github_connections_active_has_token CHECK (status <> 'active' OR access_token_enc IS NOT NULL)
);
CREATE UNIQUE INDEX uq_github_connections_live ON github_connections(workspace_id, user_id) WHERE status = 'active';

CREATE TABLE github_oauth_states (
    state_hash    TEXT PRIMARY KEY,
    workspace_id  UUID NOT NULL REFERENCES workspaces(id),
    user_id       UUID NOT NULL REFERENCES users(id),
    created_at    TIMESTAMPTZ NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL,
    consumed_at   TIMESTAMPTZ
);
CREATE INDEX idx_github_oauth_states_expires ON github_oauth_states(expires_at);

CREATE TABLE contract_git_sources (
    contract_id           UUID PRIMARY KEY REFERENCES contracts(id),
    workspace_id          UUID NOT NULL REFERENCES workspaces(id),
    provider              TEXT NOT NULL CHECK (provider = 'github'),
    connection_id         UUID REFERENCES github_connections(id),
    repository_id         BIGINT NOT NULL,
    repository_full_name  TEXT NOT NULL,
    ref                   TEXT NOT NULL,
    commit_sha            TEXT NOT NULL CHECK (length(commit_sha) = 40),
    created_at            TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_contract_git_sources_workspace ON contract_git_sources(workspace_id);
