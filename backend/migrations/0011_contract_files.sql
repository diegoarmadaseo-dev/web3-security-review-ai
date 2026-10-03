-- Projects + multi-file + ZIP submissions (docs/decisiones.md D-109).
-- Purely additive: one column with a default and one new table; no data
-- migration, trivial rollback. Mirrored in backend/schema_sqlite.sql.
--
-- 1. contracts.source_kind - how the stored source object was submitted:
--    'single' (the original raw "source" text, unchanged behaviour),
--    'files' (a JSON array of files) or 'archive' (a ZIP). For 'files' and
--    'archive' the stored object is the engine's own multi-file bundle
--    built by backend/submission_input.py; the original archive bytes are
--    never stored.
--
-- 2. contract_files - per-file traceability for a 'files'/'archive'
--    submission: each analysed file's relative path (validated, unique per
--    contract), language, byte size, SHA-256 of its submitted bytes and its
--    own effective LOC as the engine counts it (their sum is the scan's
--    effective LOC). METADATA only - file content lives solely in the
--    contract's object-storage bundle, so retention (which purges content
--    and keeps rows) treats it exactly like the contract row itself.

ALTER TABLE contracts ADD COLUMN source_kind TEXT NOT NULL DEFAULT 'single' CHECK (source_kind IN ('single', 'files', 'archive'));

CREATE TABLE contract_files (
    contract_id     UUID NOT NULL REFERENCES contracts(id),
    workspace_id    UUID NOT NULL REFERENCES workspaces(id),
    path            TEXT NOT NULL,
    language        TEXT NOT NULL,
    size_bytes      INTEGER NOT NULL CHECK (size_bytes >= 0),
    content_sha256  TEXT NOT NULL,
    effective_loc   INTEGER NOT NULL CHECK (effective_loc >= 0),
    PRIMARY KEY (contract_id, path)
);
CREATE INDEX idx_contract_files_workspace ON contract_files(workspace_id);
