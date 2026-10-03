# Production configuration reference

Every environment variable `backend/main.py` reads, and only what it reads -
`backend/main.py` is the ONE place in this backend allowed to read
`os.environ` (see that module's own docstring); every other module takes
its configuration as explicit constructor arguments. This file documents
what exists in the code today - it does not invent, recommend, or assume
any real value (a real Stripe key, a real domain, a real price). See
`docs/decisiones.md` (D-077 line of work, D-081 Phase 6A, current Phase 6B
entry) for the design decisions behind each subsystem.

Update this file whenever `backend/main.py`'s own `_load_web_config()`/
`_load_worker_config()` gain or lose a variable - it must never drift from
what the code actually reads.

## ROLE dispatch

| Variable | Purpose | Role | Required? | Secret? |
|---|---|---|---|---|
| `ROLE` | Selects `web` or `worker` - the two roles never run combined in one process (see `backend/main.py`'s own module docstring on why). | both | Yes, no default | No |

## Database

| Variable | Purpose | Role | Required? | Secret? |
|---|---|---|---|---|
| `DATABASE_URL` | PostgreSQL DSN (`backend/db.py`'s `connect_postgres()`). Never falls back to SQLite. | both | Yes | **Yes** |

## HTTP server (ROLE=web)

| Variable | Purpose | Required? | Secret? | Default |
|---|---|---|---|---|
| `HOST_ALLOWLIST` | Comma-separated hostnames trusted for the Host header / CSRF Origin check. | Yes | No | - |
| `SECURE_COOKIES` | `Secure` cookie flag. Set `false` only for plain-HTTP local/staging. | No | No | `true` |
| `HTTP_HOST` / `HTTP_PORT` | Bind address for the HTTP server. | No | No | `0.0.0.0` / `8080` |
| `SHUTDOWN_GRACE_SECONDS` | Seconds `_serve_until_shutdown()` waits for in-flight requests to finish after SIGTERM/SIGINT before closing anyway. | No | No | `30` |
| `MAX_PENDING_JOBS_PER_WORKSPACE` | D-108: queued + claimed + running scans allowed per workspace; the next submission gets `429 too_many_pending_jobs`. Positive integer. | No | No | `5` |
| `SUBMIT_RATE_LIMIT_PER_MINUTE` | D-108: scan-submission requests (`POST /workspaces/<id>/jobs`, and `POST /api/v1/scans` from the Private API, D-113 - one shared budget per user) per user per 60 s; the next one gets `429 submit_rate_limited` with `Retry-After`. Every request from an identified member counts, including ones that end in 402/413 and retries with the same `idempotency_key`; only a request refused by this limit is not counted. Abuse protection only, independent of the LOC allowance. Positive integer. | No | No | `10` |

## Object storage (both roles)

| Variable | Purpose | Required? | Secret? | Default |
|---|---|---|---|---|
| `S3_BUCKET` / `S3_REGION` | `backend/object_storage.S3Storage` target. | Yes | No | - |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | Explicit S3 credentials. If unset, boto3's own default credential chain (IAM role, etc.) applies. | No | **Yes** | - |

## Stripe billing (ROLE=web)

| Variable | Purpose | Required? | Secret? |
|---|---|---|---|
| `STRIPE_SECRET_KEY` | Stripe API secret key. | Yes | **Yes** |
| `STRIPE_WEBHOOK_SECRET` | Verifies `Stripe-Signature` on `/billing/webhook`. | Yes | **Yes** |
| `STRIPE_PRICE_STANDARD_MONTHLY` / `_ANNUAL`, `STRIPE_PRICE_PRO_MONTHLY` / `_ANNUAL` | Stripe Price IDs of the 4 subscription price modes of the Launch catalog (`backend/plans.py`, D-107: Standard $199.99/month or $1,999.90/year, Pro $289.99/month or $2,899.90/year; annual = 12 service months, usage still metered per service month). Validated at startup (`price_...` shape, no ID reused). | Yes (all 4) | No |
| `STRIPE_PRICE_QUICK_ONETIME` | Stripe Price ID of Quick ($29.99, one-time payment - Checkout `mode=payment`, never a subscription - exactly 1 scan of up to 3,000 effective LOC). Same validation as the other four. The retired D-086 variables `STRIPE_PRICE_QUICK_MONTHLY` / `_ANNUAL` are a startup error if set. | Yes | No |

Business decisions confirmed in D-086 (prices, billing interval, Black
Friday) are no longer open - see that entry. Still NOT in code: currency,
cancellation/refund policy, VAT handling.

## Private GitHub (ROLE=web, D-111)

Optional: with none of the four required variables set the feature is unconfigured (its endpoints answer `503 github_not_configured`; Quick is refused with `403 feature_not_available` before that). Setting only some of them is a startup error. The GitHub App needs read-only repository permissions (Contents: read, Metadata: read) and its callback URL set to `GITHUB_OAUTH_REDIRECT_URI`.

| Variable | Purpose | Required? | Secret? | Default |
|---|---|---|---|---|
| `GITHUB_APP_CLIENT_ID` | Client ID of the Vericexa GitHub App (user authorization web flow). | All four or none | No | - |
| `GITHUB_APP_CLIENT_SECRET` | Client secret of that GitHub App (code exchange, token refresh, token revocation). | All four or none | **Yes** | - |
| `GITHUB_OAUTH_REDIRECT_URI` | Must be `https://<host>/github/callback` (plain `http://` only for `localhost`/`127.0.0.1`). | All four or none | No | - |
| `GITHUB_TOKEN_ENCRYPTION_KEY` | Base64 of at least 32 random bytes; encrypts the stored GitHub user tokens (`backend/github_integration.TokenCipher`). Changing it makes every existing connection require a reconnect. | All four or none | **Yes** | - |
| `GITHUB_APP_SLUG` | The App's URL slug, used only for the "Choose repositories on GitHub" link. | No | No | - |

## Free Trial and sign-up (ROLE=web, D-112)

| Variable | Purpose | Required? | Secret? | Default |
|---|---|---|---|---|
| `DISPOSABLE_EMAIL_DOMAINS_FILE` | Optional path to an operator-maintained list of disposable/temporary email domains (one per line, `#` comments), ADDED to the bundled `backend/data/disposable_email_domains.txt`. Addresses on these domains (and their subdomains) cannot sign up for, or be granted, the free Trial; paid plans and ordinary sign-in are unaffected. Unreadable file → startup error. | No | No | - |

The Trial needs no other configuration: no Stripe price, no checkout, no portal. Sign-up verification links use the existing email sender (`EMAIL_SENDER_MODE`).

## Black Friday campaign (ROLE=web, Phase 7, D-086)

| Variable | Purpose | Required? | Default |
|---|---|---|---|
| `BLACK_FRIDAY_ENABLED` | Explicit gate - **disabled means START/END/PROMOTION_CODE_ID are never even read**, so preparing next year's values ahead of time can never half-activate the campaign early. | No | `false` |
| `BLACK_FRIDAY_START` / `BLACK_FRIDAY_END` | ISO-8601 timestamps, MUST include a UTC offset (`+00:00` or `Z`) - a naive value fails fast rather than being guessed as UTC. Required only if enabled; END must be strictly after START. | Conditional | - |
| `BLACK_FRIDAY_PROMOTION_CODE_ID` | A real Stripe PromotionCode id (not a Coupon id) - expected to already carry `restrictions.first_time_transaction=True` and its own `expires_at` (both configured directly in Stripe, never in this codebase). Required only if enabled. | Conditional | - |

Re-evaluated fresh on every `/billing/checkout` request
(`backend/black_friday.py`'s `resolve_promotion_code()`) - never cached,
never trusted from a client-supplied field. Annual-interval-only is
enforced in code, not just by this config - see that module's own
docstring.

## LLM provider (ROLE=worker)

| Variable | Purpose | Required? | Secret? | Default |
|---|---|---|---|---|
| `LLM_API_KEY` | API key for whichever provider `LLM_PROVIDER` selects, held only in the worker process's memory and the one job container's stdin - never a host file, never `docker create -e`. | Yes | **Yes** | - |
| `LLM_MODEL` | Model id for whichever provider `LLM_PROVIDER` selects (e.g. an Anthropic Claude model id, or `deepseek-flash` for DeepSeek). | Yes | No | - |
| `LLM_PROVIDER` | Which concrete `backend.llm_client` provider class `worker_entrypoint.py` constructs - `anthropic` or `deepseek`; any other value fails the job closed with a clear config error before any real work begins. Passed host->container the same way as `LLM_MODEL`. | No | No | `anthropic` |
| `LLM_MAX_OUTPUT_TOKENS` | Per-attempt output token cap - read here on the HOST, then passed into the container as the SAME-named env var (`backend/worker_entrypoint.py` reads it back out). | No | No | `8000` |
| `LLM_PER_ATTEMPT_TIMEOUT_SECONDS` | Timeout for one Step 6 provider attempt. Its meaning depends on the mode. Single-pass (`LLM_MAX_PASSES=1`): the value is handed to the provider SDK as its request timeout, which the SDK applies to each network operation (connect, each read), not to the whole call, and the SDK keeps its historical internal retries - so it is NOT a total wall-clock limit for the call. Multi-pass with the Step 6 deadline (`LLM_MAX_PASSES` > 1): the attempt gets the smaller of this value and the time the deadline leaves; that value is still handed to the SDK, the SDK does not retry internally (`max_retries=0`), and the TOTAL duration of the call is enforced by `IsolatedCallProvider` (the call runs in a child process that is killed when it expires). Same host->container name reuse as above. | No | No | `120` |
| `LLM_MAX_PASSES` | Deterministic multi-pass Step 6 (docs/decisiones.md D-097): maximum passes when one prompt cannot hold the whole submission. `1` keeps the single-pass path exactly as before. Between `1` and `8`; with a value above `1` the worker applies a Step 6 deadline (`WORKER_WALL_CLOCK_TIMEOUT_SECONDS` minus a 15 s startup reserve, passed to the container as `STEP6_DEADLINE_SECONDS`), and startup fails fast unless `WORKER_WALL_CLOCK_TIMEOUT_SECONDS` >= 15 + 20 + 15 x passes. Under that deadline the provider SDK does not retry internally (`max_retries=0`) and every provider call runs in an isolated child process that is killed when its timeout expires, so `LLM_PER_ATTEMPT_TIMEOUT_SECONDS` (or the smaller share the deadline leaves) is a limit on the whole call, not only on each network read. Each pass is a full-size prompt, so input tokens grow with the pass count. Same host->container name reuse as above. | No | No | `1` |
| `LLM_API_ALLOWLIST_HOST` / `LLM_API_ALLOWLIST_PORT` | The exact `(host, port)` the egress proxy allows a job container to reach - never a substring/wildcard match. Must match whichever host `LLM_PROVIDER`'s API actually lives at (e.g. `api.anthropic.com` or `api.deepseek.com`) - this is a separate, host-side-only setting never passed into the container itself (the container only receives `HTTPS_PROXY`, never the allowlist host directly). | No | No | `api.anthropic.com` / `443` |

**Not configurable anywhere, by deliberate design**: `MAX_STEP6_ATTEMPTS`
(`backend/llm_client.py`, hardcoded `3`) - its own comment states it must
never drift independently from `analyze_pipeline.py`'s own
SKILL.md-documented "3 attempts total" cap. Per-job spend ceiling
(`repository.DEFAULT_BUDGET_LIMIT_UNITS = 100`, a units ledger, not a
dollar figure) is likewise hardcoded today - no environment variable
exists for it.

## Worker resource limits (ROLE=worker, Phase 6B)

Every default below is imported directly from `backend/worker_supervisor.py`'s
own `DEFAULT_*` constants - setting none of these reproduces the exact
pre-Phase-6B behavior.

| Variable | Purpose | Default | Validated as |
|---|---|---|---|
| `WORKER_MEMORY_LIMIT` | `docker create --memory` | `512m` | Docker byte-size (`\d+[bkmg]?`) |
| `WORKER_CPU_LIMIT` | `docker create --cpus` | `1` | positive decimal |
| `WORKER_PIDS_LIMIT` | `docker create --pids-limit` | `128` | positive integer |
| `WORKER_TMPFS_SIZE` | `/scratch` tmpfs `size=` | `64m` | Docker byte-size |
| `WORKER_WALL_CLOCK_TIMEOUT_SECONDS` | Max seconds one job's container may run | `300` | positive integer |
| `WORKER_OUTPUT_SIZE_LIMIT_BYTES` | Max bytes of container stdout accepted | `2097152` (2 MiB) | positive integer |

All six fail fast (`ConfigError`) on an invalid value - never silently
clamped or passed through to `docker create` unchecked.

## Egress proxy (ROLE=worker)

| Variable | Purpose | Required? | Default |
|---|---|---|---|
| `EGRESS_PROXY_HOST` | The address a job CONTAINER dials to reach the allowlist proxy over the Docker network it joins. No safe default is guessed - Docker network topology is deployment-specific. | Yes | - |
| `EGRESS_PROXY_PORT` | Port this process itself binds the proxy to (also told to the container as the same value). | No | `0` (OS-assigned) |
| `WORKER_DOCKER_IMAGE` / `WORKER_NETWORK_NAME` | The built worker image tag and the dedicated, non-default Docker network job containers join. | Yes | - |
| `WORKER_ID` | This worker instance's own identifier (`analysis_jobs.claimed_by`). | No | `worker-<pid>` |

## Retention (ROLE=worker, Phase 6B)

| Variable | Purpose | Required? | Default |
|---|---|---|---|
| `RETENTION_DAYS` | Age (days) past which `backend/retention.py`'s purge functions delete source/report OBJECT CONTENT (never the metadata row). **Unset = retention completely disabled** - this codebase never invents a legal retention period; see `backend/retention.py`'s own module docstring. | No | *(disabled)* |
| `RETENTION_CHECK_INTERVAL_SECONDS` | How often the worker loop checks whether a purge is due. | No | `3600` |
| `RETENTION_DRY_RUN` | `true` runs the check without deleting anything - proves the mechanism without risk. | No | `false` |

## Alerting (both roles, Phase 6A/6B)

| Variable | Purpose | Required? | Allowed values |
|---|---|---|---|
| `ALERT_SENDER_MODE` | Explicitly selects the alert channel - never inferred from whether a URL happens to be set. | No | `logging` (default), `webhook` |
| `ALERT_WEBHOOK_URL` | Required only when `ALERT_SENDER_MODE=webhook`. A provider-neutral JSON POST target (Slack/Discord/PagerDuty/custom - any webhook receiver), never a vendor SDK. May itself be secret-bearing (some providers embed a token in the path) - never logged on delivery failure, only the exception type name. | Conditional | - |

## Email (ROLE=web, Phase 6B)

| Variable | Purpose | Required? | Secret? |
|---|---|---|---|
| `EMAIL_SENDER_MODE` | Explicitly selects `logging` (dev/test, default - still a legitimate choice for an early deployment) or `smtp` (real delivery). | No | No |
| `SMTP_HOST` / `SMTP_PORT` | SMTP relay address - works with any provider that exposes one (SES, Postmark, SendGrid, Mailgun, ...). Required only when `EMAIL_SENDER_MODE=smtp`. | Conditional | No |
| `SMTP_USERNAME` / `SMTP_PASSWORD` | SMTP auth. Required only when `EMAIL_SENDER_MODE=smtp`. Never logged - `backend/email_sender.SMTPEmailSender` logs only the exception type name on failure. | Conditional | **Yes** |
| `EMAIL_FROM_ADDRESS` | The `From:` address on every sent magic-link email. Required only when `EMAIL_SENDER_MODE=smtp`. | Conditional | No |
| `SMTP_USE_TLS` | Whether to call `STARTTLS` before authenticating. | No | No (default `true`) |

## Templates

No email template configuration exists - `backend/http_app.py`'s
`_handle_request_link()` builds the magic-link email's subject/body as a
plain hardcoded string today (see that function). A real template system
was not part of this phase's scope.

## Resolved gap (D-083, email hardening)

`backend/http_app.py`'s `_handle_request_link()` previously called
`email_sender.send()` outside any exception handling - an `SMTPEmailSender`
delivery failure (vs. the old `LoggingEmailSender`, which could never
fail) propagated as an unhandled exception with no HTTP response at all
(`do_POST` has no wrapping handler either). Fixed: `send()` is now called
inside a try/except that emits `alerting.EVENT_EMAIL_DELIVERY_FAILURE`
(exception TYPE NAME only, never the message) and always falls through to
the SAME generic 200 the success path already returns - both closing the
leak and keeping delivery outcome indistinguishable from account
existence (anti-enumeration). The `auth_tokens` row itself needs no
special handling either way: it was already committed before delivery is
attempted, and simply expires unconsumed like any link a user never
clicked. See `docs/decisiones.md` D-083.
