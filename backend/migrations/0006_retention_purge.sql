-- Phase 6A production hardening (docs/decisiones.md D-077 follow-up).
-- reports.purged_at - marks a report row whose OBJECT STORAGE content
-- (the actual rendered report bytes at reports.storage_ref) has been
-- deleted by backend/retention.py's age-based purge, while the METADATA
-- row itself (score/risk_band/created_at/job_id) is deliberately KEPT -
-- audit/job history stays queryable even after content retention
-- expires (Phase 6A's own explicit "audit/job history where
-- appropriate" scoping). Nullable: NULL means the content still exists
-- (the normal, expected state for every report until it ages past
-- whatever retention_days value is configured at purge time - never a
-- hardcoded default here, see backend/retention.py's own docstring on
-- why no specific period is invented). Mirrors the existing
-- contracts.deleted_at column's own nullable/idempotent-marker shape -
-- retention.py reuses that column for source objects rather than adding
-- a second, differently-named one for the same concept.

ALTER TABLE reports ADD COLUMN purged_at TIMESTAMPTZ;
