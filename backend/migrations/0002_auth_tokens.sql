-- Phase 2 identity/access: passwordless magic-link one-time tokens
-- (docs/decisiones.md D-077/D-078 follow-up). Additive only -
-- 0001_initial_schema.sql is never edited in place (forward-only
-- migrations, see backend/migrate.py's own docstring).
--
-- Deliberately separate from `sessions` (Phase 1, structure only until
-- now): a magic-link token authenticates a LOGIN ATTEMPT, before a user
-- necessarily has an account yet (first click = implicit signup); a
-- session authenticates an ALREADY-ESTABLISHED identity. Mirrors
-- `sessions`' own shape (id + separate token_hash, never the id itself
-- used as a lookup secret) for the same reason: only the hash of the
-- caller-held secret is ever stored, never the secret itself.
--
-- requested_ip is nullable and used ONLY for the per-IP half of the
-- rate-limit check in backend/auth.py - deliberately NOT a new
-- subsystem/table of its own (the smallest secure addition: one column
-- on the row already being written for the token itself). It is always
-- the immediate TCP peer address (never a client-supplied
-- X-Forwarded-For header - same rule website/server.py's rate limiter
-- already documents: trusting a spoofable header would let an attacker
-- defeat the limit by varying it per request).
CREATE TABLE auth_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           TEXT NOT NULL,
    token_hash      TEXT NOT NULL UNIQUE,
    requested_ip    TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    consumed_at     TIMESTAMPTZ,
    CONSTRAINT auth_tokens_expiry_after_creation CHECK (expires_at > created_at),
    CONSTRAINT auth_tokens_email_lowercase CHECK (email = lower(email))
);
-- Rate-limit queries (backend/auth.py's check_rate_limit): count rows for
-- an email/ip created after a cutoff timestamp.
CREATE INDEX idx_auth_tokens_email_created ON auth_tokens(email, created_at);
CREATE INDEX idx_auth_tokens_ip_created ON auth_tokens(requested_ip, created_at);
