# Staging configuration template (Phase 6C, docs/decisiones.md D-084)

A filled-in-SHAPE, zero-real-secrets checklist for a real staging
deployment - every variable name and its purpose is the SAME as
`docs/production-config.md` (the authoritative reference; this file never
duplicates that table's content, only annotates it for a STAGING
deployment specifically). No value below is a real credential, domain, or
price - every `<...>` is a placeholder Diego fills in.

Legend: **SUPPLIED** = the code/this phase already handles it, nothing
more to do. **DIEGO** = a real external decision/account only Diego can
supply - see `docs/production-config.md`'s own Required?/Secret? columns
for the full detail on each.

## Staging vs. production, by design

| Concern | Staging | Production |
|---|---|---|
| Stripe | **TEST mode** key/webhook secret + TEST mode Price IDs (`STRIPE_SECRET_KEY=sk_test_...`, `STRIPE_PRICE_*` from Stripe's own test-mode dashboard) - no real charge is ever possible. | Live mode. |
| LLM | A real Anthropic key, but CAPPED: keep `LLM_MAX_OUTPUT_TOKENS` at or below its own default (8000) and consider a cheaper/faster model for staging specifically (`LLM_MODEL`) - `repository.DEFAULT_BUDGET_LIMIT_UNITS` (100, non-configurable) already bounds per-workspace spend regardless. | Live key, production model choice. |
| Email | Real SMTP credentials (`EMAIL_SENDER_MODE=smtp`), but point `EMAIL_FROM_ADDRESS` at a staging-only address/subdomain so a bounce or misconfiguration never touches the production sending domain's reputation. | Live sending domain, SPF/DKIM/DMARC fully configured there. |
| Domain | A dedicated staging (sub)domain, e.g. `staging.<real-domain>` - never the production domain, never `vericexa.com`'s own `DEFAULT_BASE_URL` default (see `website/content.py`). | The real, owned production domain. |
| PostgreSQL | A disposable/cheap managed instance (or the same provider's free/staging tier) - never the production database. | Managed, backed up (see `backend/backup_postgres.py`). |
| S3-compatible storage | A disposable bucket, ideally with a lifecycle rule auto-expiring objects after a few days (belt-and-suspenders alongside `RETENTION_DAYS`, which this repo never sets by default - see `docs/production-config.md`). | The real production bucket. |
| Alerts | A real webhook (`ALERT_SENDER_MODE=webhook`) pointed at a staging-only channel, so staging noise never pages whoever watches production alerts. | Production on-call channel. |
| Black Friday backend gate (D-086) | Leave `BLACK_FRIDAY_ENABLED` unset for ordinary staging work; enable with a TEST PromotionCode id only for a dedicated campaign drill. Website presentation needs no config either way (D-087, runtime-evaluated - see below). | Real dates (2026-11-23 00:00 UTC -> 2026-11-30 23:59:59 UTC), a real, already-configured Stripe PromotionCode id. |

## Checklist

### Database
- `DATABASE_URL` - **DIEGO**: a disposable staging Postgres instance's DSN.

### HTTP server
- `HOST_ALLOWLIST` - **DIEGO**: the staging hostname, e.g. `staging.<real-domain>`.
- `SECURE_COOKIES` - **SUPPLIED** (defaults `true`; set `false` only if staging is plain HTTP with no TLS terminator in front of it).
- `HTTP_HOST` / `HTTP_PORT` - **SUPPLIED** (defaults are fine behind any reverse proxy/load balancer).
- `SHUTDOWN_GRACE_SECONDS` - **SUPPLIED** (default 30).
- `MAX_PENDING_JOBS_PER_WORKSPACE` / `SUBMIT_RATE_LIMIT_PER_MINUTE` - **SUPPLIED** (defaults 5 and 10, D-108).

### Object storage
- `S3_BUCKET` / `S3_REGION` - **DIEGO**: a disposable staging bucket.
- `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` - **DIEGO** (or an IAM role, if the staging host supports one - then omit both).

### Stripe (TEST mode)
- `STRIPE_SECRET_KEY` / `STRIPE_WEBHOOK_SECRET` - **DIEGO**: from Stripe's TEST mode dashboard.
- Launch catalog (D-107, `backend/plans.py`): 3 Products, 5 Prices. TEST-mode IDs supplied by Diego (Price IDs are not secrets):

  | Variable | Price mode | Product | TEST-mode Price ID |
  |---|---|---|---|
  | `STRIPE_PRICE_QUICK_ONETIME` | Quick, $29.99 one-time (1 scan) | Vericexa Quick `prod_VKuyOnzsrUifKK` | `price_1UMFnY1jc8PYYLrPXxSbSEUF` |
  | `STRIPE_PRICE_STANDARD_MONTHLY` | Standard, $199.99/month | Vericexa Standard `prod_VMzvv0HgxygXcz` | `price_1UMFvU1jc8PYYLrPsrZuTqJl` |
  | `STRIPE_PRICE_STANDARD_ANNUAL` | Standard, $1,999.90/year | Vericexa Standard `prod_VMzvv0HgxygXcz` | `price_1UMFvU1jc8PYYLrPg7Kia6bO` |
  | `STRIPE_PRICE_PRO_MONTHLY` | Pro, $289.99/month | Vericexa Pro `prod_VMzwG1pHzS0d5t` | `price_1UMFwj1jc8PYYLrP2rA1xonm` |
  | `STRIPE_PRICE_PRO_ANNUAL` | Pro, $2,899.90/year | Vericexa Pro `prod_VMzwG1pHzS0d5t` | `price_1UMFy51jc8PYYLrPLyQHT8Fh` |

  Live-mode IDs are different objects and must come from the live dashboard. The retired D-086 variables `STRIPE_PRICE_QUICK_MONTHLY` / `_ANNUAL` must not be set (startup error).
- `BLACK_FRIDAY_ENABLED` / `_START` / `_END` / `_PROMOTION_CODE_ID` (D-086) - **DIEGO**: leave `BLACK_FRIDAY_ENABLED` unset/false for ordinary staging; set all four (a TEST-mode PromotionCode id for the last one) only when specifically drilling the campaign flow. See `docs/production-config.md`'s own Black Friday section for the exact validation rules.

### LLM
- `LLM_API_KEY` - **DIEGO**: a real Anthropic key (staging analysis is real analysis, not mocked, per the task's own "capped real LLM" requirement).
- `LLM_MODEL` - **DIEGO**: pick a model; not invented here.
- `LLM_MAX_OUTPUT_TOKENS` / `LLM_PER_ATTEMPT_TIMEOUT_SECONDS` - **SUPPLIED** (defaults 8000 / 120 - keep the default cap for staging).
- `LLM_API_ALLOWLIST_HOST` / `_PORT` - **SUPPLIED** (default `api.anthropic.com:443`).

### Worker resource limits / retention
- `WORKER_*` (memory/cpu/pids/tmpfs/timeout/output) - **SUPPLIED** (defaults, Phase 6B).
- `RETENTION_DAYS` - **DIEGO** if staging should ever purge content (stays disabled, same as production, unless explicitly set - never invented).
- `EGRESS_PROXY_HOST` / `WORKER_DOCKER_IMAGE` / `WORKER_NETWORK_NAME` - **DIEGO**: deployment-topology-specific (build `Dockerfile.worker` for staging too, tag it distinctly from any production tag).

### Alerting
- `ALERT_SENDER_MODE=webhook` + `ALERT_WEBHOOK_URL` - **DIEGO**: a real webhook (Slack/Discord/PagerDuty/custom), pointed at a staging-only destination.

### Email
- `EMAIL_SENDER_MODE=smtp` + `SMTP_HOST`/`PORT`/`USERNAME`/`PASSWORD`/`EMAIL_FROM_ADDRESS`/`SMTP_USE_TLS` - **DIEGO**: real SMTP credentials, staging-only `EMAIL_FROM_ADDRESS`.

### Website build
- `VERICEXA_BASE_URL` - **DIEGO**: the staging domain (`https://staging.<real-domain>`).
- `VERICEXA_APP_URL` (Phase 6C) - **DIEGO**: the staging web container's own public URL. Build with `--env staging` (`python website/build_site.py --env staging --app-url https://staging-app.<real-domain>`) so a missing value fails the build loudly instead of silently shipping without a login CTA - see `website/build_site.py`'s own docstring.
- Black Friday presentation needs **no build/env configuration at all** (Phase 7, D-087 - supersedes an earlier build-time-env-var design, D-086, that had a real staleness bug: a site built before the campaign start would never show it without a rebuild exactly at that moment). `website/content.py`'s `BLACK_FRIDAY_START_UTC`/`END_UTC` are fixed, source-controlled constants; a small inline script evaluates them against the VISITOR's own browser clock at RUNTIME on every page load - always correct, any day, with zero staging/production difference to configure. Still PRESENTATION ONLY - `backend/black_friday.py` remains the real, independently-configured enforcement point (see above).

## What "capped real LLM" means operationally

Nothing in this phase adds a NEW cap beyond what already exists:
`LLM_MAX_OUTPUT_TOKENS` (default 8000, configurable), `MAX_STEP6_ATTEMPTS`
(hardcoded 3, deliberately not configurable - see
`docs/production-config.md`), and `repository.DEFAULT_BUDGET_LIMIT_UNITS`
(100 units, non-configurable, enforced per-workspace before a job is even
claimed). Staging should simply not raise `LLM_MAX_OUTPUT_TOKENS` above
its own default and should use a real (not mocked) `LLM_API_KEY` so the
E2E drill (`docs/decisiones.md`'s Phase 6/6B/6C audit entries) exercises
the real provider path at least once before production.
