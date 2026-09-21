-- Phase 3 billing (docs/decisiones.md D-077 follow-up). Expands
-- entitlements.status to cover the full set of real Stripe Subscription
-- statuses - the original CHECK (Phase 1, structure-only, written before
-- any real Stripe integration existed) only had 5 of Stripe's 7 values:
-- 'incomplete_expired' and 'unpaid' were missing entirely, which would
-- have made a real webhook handler unable to even INSERT a row for a
-- subscription that legitimately reaches either state.
--
-- Postgres has no ALTER TABLE ... ALTER CHECK - an inline CHECK
-- constraint must be dropped and recreated under its name. An unnamed
-- inline CHECK gets Postgres's default generated name
-- <table>_<column>_check; entitlements_status_check is exactly that name
-- for the constraint 0001_initial_schema.sql defined inline on
-- entitlements.status.
--
-- No data migration needed: this only WIDENS the allowed set, so every
-- existing row (which can only already hold one of the 5 original
-- values) remains valid without being touched.

ALTER TABLE entitlements DROP CONSTRAINT entitlements_status_check;

ALTER TABLE entitlements ADD CONSTRAINT entitlements_status_check
    CHECK (status IN ('active', 'trialing', 'past_due', 'canceled', 'incomplete', 'incomplete_expired', 'unpaid'));
