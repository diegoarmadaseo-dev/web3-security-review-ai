-- Stripe billing (docs/decisiones.md D-115). Mirrored in
-- backend/schema_sqlite.sql. No existing row changes meaning.
--
-- billing_checkout_sessions - one row per Stripe Checkout Session this
-- backend created (POST /billing/checkout): which workspace and which user
-- started it, the plan/interval/Price sold and the customer it was created
-- for. A Checkout webhook only grants something for a session listed here
-- for the SAME workspace (a session created anywhere else in the Stripe
-- account - dashboard, payment link, another product - grants nothing), and
-- a subscription is bound to its workspace through the session that
-- created it (stripe_subscription_id, set when the session completes).
-- status only moves forward:
--   open -> awaiting_payment (completed, asynchronous payment pending)
--   open | awaiting_payment -> completed | payment_failed
--   open -> expired (expired by Stripe, or by the backend before a new checkout)
--
-- webhook_events.outcome - what processing a delivered event decided
-- (applied / ignored / rejected, with a short reason code). Diagnostics
-- only: never a secret, never a payload.

CREATE TABLE billing_checkout_sessions (
    id                      TEXT PRIMARY KEY CHECK (id ~ '^cs_[A-Za-z0-9_]+$'),
    workspace_id            UUID NOT NULL REFERENCES workspaces(id),
    user_id                 UUID NOT NULL REFERENCES users(id),
    plan                    TEXT NOT NULL CHECK (plan IN ('quick', 'standard', 'pro')),
    billing_interval        TEXT NOT NULL CHECK (billing_interval IN ('one_time', 'monthly', 'annual')),
    price_id                TEXT NOT NULL CHECK (price_id ~ '^price_[A-Za-z0-9_]+$'),
    checkout_mode           TEXT NOT NULL CHECK (checkout_mode IN ('payment', 'subscription')),
    stripe_customer_id      TEXT,
    stripe_subscription_id  TEXT UNIQUE,
    status                  TEXT NOT NULL CHECK (status IN ('open', 'awaiting_payment', 'completed', 'payment_failed', 'expired')),
    created_at              TIMESTAMPTZ NOT NULL,
    updated_at              TIMESTAMPTZ NOT NULL,
    CONSTRAINT billing_checkout_sessions_mode_matches_plan CHECK ((checkout_mode = 'payment') = (plan = 'quick')),
    CONSTRAINT billing_checkout_sessions_interval_matches_plan CHECK ((billing_interval = 'one_time') = (plan = 'quick'))
);
CREATE INDEX idx_billing_checkout_sessions_workspace ON billing_checkout_sessions(workspace_id, status);

ALTER TABLE webhook_events ADD COLUMN outcome TEXT CHECK (outcome IS NULL OR char_length(outcome) <= 120);
