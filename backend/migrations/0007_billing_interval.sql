-- Phase 7 commercial pricing (docs/decisiones.md D-086).
-- entitlements.billing_interval - which Stripe Price interval (monthly or
-- annual) the workspace's active subscription was purchased at. Nullable,
-- same reasoning as reports.purged_at (migration 0006): an entitlement
-- row created before this column existed has no known interval, and this
-- codebase never guesses/backfills a value it does not actually know -
-- see backend/repository.py's create_entitlement()/update_entitlement_
-- status() docstrings for how a real value is derived (always from a
-- Stripe webhook's own metadata, never client-supplied) and never
-- defaulted. CHECK mirrors the existing plan/status columns' own
-- allowlist-in-the-schema discipline.

ALTER TABLE entitlements ADD COLUMN billing_interval TEXT CHECK (billing_interval IN ('monthly', 'annual'));
