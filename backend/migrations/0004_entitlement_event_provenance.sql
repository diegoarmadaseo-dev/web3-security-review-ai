-- Phase 3 webhook hardening (docs/decisiones.md D-077 follow-up).
-- Adds the smallest field needed to stop a stale/out-of-order Stripe
-- webhook event from overwriting a newer entitlement state: Stripe
-- explicitly documents that webhook delivery is at-least-once and NOT
-- guaranteed to arrive in order. stripe_event_created_at records the
-- `created` timestamp (Stripe's own event, not any local processing
-- time - see backend/repository.py's update_entitlement_status()) of
-- the last event actually ACCEPTED to change this row, so a later
-- arrival carrying an older (or equal - see that function's docstring
-- on the deterministic tie-break) timestamp can be recognized and
-- ignored rather than blindly applied.
--
-- Nullable and no default: every EXISTING row predates this column and
-- has no Stripe event to attribute a baseline to - NULL is treated
-- throughout this codebase as "no provenance yet, any event supersedes
-- it", never as a reason to reject a legitimate first update (see
-- update_entitlement_status()).

ALTER TABLE entitlements ADD COLUMN stripe_event_created_at TIMESTAMPTZ;
