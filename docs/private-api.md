# Private API v1 — documentación interna (D-113)

Documento interno (no publicado). API autenticada para clientes de los planes
**Quick, Standard y Pro**. El **Trial no tiene acceso** (403
`feature_not_available`). No hay API pública ni anónima, ni SDK, ni CLI.
GitHub Actions no existe todavía.

La Private API **no es un segundo backend**. `backend/http_app.py`
(`_dispatch_api()`) autentica la key y después llama a los **mismos handlers**
que usa la web app (proyectos, envío de scans, reports). El pipeline es
idéntico: auth → validación de workspace/proyecto → validación de entrada D-109
→ effective LOC → admisión comercial → guardas D-108 → idempotencia → cola →
worker → report.

## Autenticación

```
Authorization: Bearer vcx_<prefijo>_<secreto>
```

- Formato de la key:
  - `vcx_` como literal fijo;
  - un prefijo de 12 caracteres hex: es público, sirve de identificador de búsqueda y aparece en los listados;
  - un secreto de 43 caracteres base64url, que son 32 bytes de `secrets` (256 bits).
- En la BD solo se guarda `SHA-256(key completa)`, en `api_keys.key_hash`. La comparación es en tiempo constante (`hmac.compare_digest`). Con 256 bits de entropía basta un hash rápido; un KDF lento solo aporta con secretos adivinables.
- La key completa aparece **una sola vez**, en la respuesta de creación. Después:
  - no se lista;
  - no se loguea;
  - no se guarda en metadata de jobs ni en reports.
- Cada key pertenece a **un workspace** y actúa como el **miembro que la creó**. En cada request se vuelve a resolver la cadena key → miembro → workspace → plan:
  - si el miembro sale del workspace, su key deja de funcionar;
  - si el workspace se borra, `retention.delete_workspace_data` revoca sus keys.
- El workspace sale **siempre de la key**, nunca de la URL. Por eso desde la API no se puede ni nombrar otro workspace.
- Sobre `/api/v1` las cookies de sesión se ignoran, y la bearer key se ignora en cualquier otra ruta.
- Errores de autenticación:

  | Situación | Respuesta |
  |---|---|
  | Sin header | 401 `authentication_required` + `WWW-Authenticate: Bearer` |
  | Header mal formado (esquema distinto, espacios, varios headers `Authorization`, key con formato inválido) | 401 `invalid_authorization_header` |
  | Key desconocida, revocada o cuyo miembro salió del workspace | 401 `invalid_api_key` (mismo error en los tres casos: sin oráculo) |
  | Plan sin la feature (Trial, sin plan) | 403 `feature_not_available` con `feature: "private_api"` |
  | Suscripción inactiva (`past_due`, `canceled`, …) | 402 `no_active_subscription` |

## Gestión de keys

Hay dos vías:
- **Web app (sesión):** sección "API keys". Rutas `GET/POST /workspaces/<id>/api-keys` y `DELETE /workspaces/<id>/api-keys/<key_id>`, con la defensa CSRF por Origin de siempre. La primera key se crea necesariamente por aquí.
- **API (bearer):** `GET/POST /api/v1/keys` y `DELETE /api/v1/keys/<key_id>`.

Operaciones:
- **Crear:** `POST {"name": "CI pipeline"}`.
  - Respuesta: `{"key": {metadata}, "secret": "vcx_..."}`, con `Cache-Control: no-store`.
  - El nombre debe tener entre 1 y 100 caracteres, sin caracteres de control (si no, 400 `invalid_key_name`).
  - Requiere un plan con la feature y una suscripción activa.
  - Límite técnico anti-abuso (no comercial, igual para los tres planes): 25 keys **activas** por workspace (409 `key_limit_reached`). La cuenta y el INSERT se hacen bajo el lock de admisión por workspace, así que el límite se respeta también en concurrencia.
- **Listar:** devuelve solo metadata: `id, workspace_id, user_id, name, key_prefix, created_at, last_used_at, revoked_at`.
  - Nunca devuelve la key ni su hash.
  - Owner y admin ven todas las keys del workspace; un member ve solo las suyas.
  - No depende del plan, para que tras un cambio de plan se pueda seguir viendo y revocando.
- **Revocar:** `DELETE`.
  - Owner y admin pueden revocar cualquier key; un member solo las suyas. Si no, 404 `key_not_found`.
  - Es idempotente.
  - No toca el workspace, sus datos ni las demás keys.
- **Rotar:** crear una key nueva y revocar la antigua.
- **`last_used_at`:** se escribe como mucho una vez por minuto y key.

## Endpoints `/api/v1`

Esta tabla es la lista blanca completa; cualquier otra ruta da 404 `not_found`, y un método no admitido da 405 `method_not_allowed` con `Allow`.

| Método y ruta | Handler reutilizado |
|---|---|
| `GET /api/v1/keys` · `POST /api/v1/keys` · `DELETE /api/v1/keys/<id>` | gestión de keys (ver arriba) |
| `GET /api/v1/projects?limit&offset` | `_handle_project_list` |
| `POST /api/v1/projects` `{"name"}` | `_handle_project_create` (límite de proyectos del plan, solo Trial) |
| `GET /api/v1/projects/<id>` | `_handle_project_get` |
| `PATCH /api/v1/projects/<id>` `{"name"}` | `_handle_project_rename` |
| `DELETE /api/v1/projects/<id>` | `_handle_project_delete` (owner/admin) |
| `POST /api/v1/scans` | `_handle_job_submit` |
| `GET /api/v1/scans?status&project_id&limit&offset` | `_handle_job_list` |
| `GET /api/v1/scans/<job_id>` | `_handle_job_get` (estado, origen, uso, resumen del report) |
| `GET /api/v1/reports/<report_id>` | `_handle_report_document` (JSON puntuado, Markdown, advisory, contexto) |
| `GET /api/v1/reports/<report_id>/json` | `_handle_report_download` con formato `json` |
| `GET /api/v1/reports/<report_id>/markdown` | `_handle_report_download` con formato `markdown` |
| `GET /api/v1/usage` | vista de solo lectura: uso comercial, presupuesto técnico, cola, rate limit |
| `GET /api/v1/billing` | vista de solo lectura: plan, estado, intervalo, periodo, features |

- **Cancelación de scans:** no se expone, porque el backend no tiene un flujo de cancelación por HTTP.
- **Billing:** no devuelve identificadores ni secretos de Stripe. El checkout y el portal siguen solo en la web app.
- **Reports:** se aplican las reglas existentes, decididas por el plan con el que se **admitió** el scan. Un report admitido como Trial sigue sin descargas ni capa 2 aunque el workspace haya pasado después a Standard.

### `POST /api/v1/scans`

Las entradas son las mismas que en D-109; debe darse exactamente una de ellas:
- `{"mode", "source", "filename"?}`: un solo archivo, o un bundle que el cliente ya construyó.
- `{"mode", "files": [{"path", "content"}, ...]}`: varios archivos.
- `{"mode", "archive": {"format": "zip", "content_base64"}}`: ZIP, con todas las protecciones de D-109 (rutas, symlinks, cifrado, tamaño descomprimido, número de archivos…).

Campos opcionales en todos los casos: `project_id`, `idempotency_key` y `dry_run` (vista previa: no guarda ni reserva nada).

D-114: `ci` (metadatos de GitHub Actions: `provider`, `repository`, `commit_sha`, `ref`, `event`, `run_id`, `run_attempt`, `pull_request`) marca la petición como de GitHub Actions; solo Standard/Pro (403 `feature_not_available` con `feature: "github_actions"`). Ver `docs/github-actions.md`.

Qué no se acepta:
- `github`: 400 `source_not_supported`. GitHub sigue disponible por su integración propia en la web app.
- URLs: `source` es texto. Una URL no es código, así que da 422 `no_source_code`.

Respuesta: `{"job_id", "status": "queued", "effective_loc", "source_kind", "project_id", "files"?}`. Después se consulta `GET /api/v1/scans/<job_id>` hasta que `job.status` es `succeeded`; entonces `report.id` lleva al report.

Errores comerciales y técnicos (códigos existentes):

| Código | Estado HTTP |
|---|---|
| `no_scan_credit` | 402 |
| `loc_quota_exceeded` | 402 |
| `trial_already_used` | 402 |
| `no_active_subscription` | 402 |
| `loc_per_scan_limit_exceeded` | 413 |
| `source_too_large` | 413 |
| `request_too_large` | 413 |
| `no_source_code` | 422 |
| `no_source_files` | 422 |
| `too_many_pending_jobs` | 429 |
| `technical_budget_exhausted` | 429 |
| `submit_rate_limited` | 429 + `Retry-After` |
| `mode_not_allowed` | 403 |
| `project_not_found` | 404 |
| Errores de entrada D-109 (`invalid_path`, `duplicate_path`, `archive_*`, …) | 400/413/422 |

## Idempotencia

- La key de idempotencia se envía en el body (`idempotency_key`) o en el header estándar `Idempotency-Key`, que funciona como alias. Si llegan los dos y son distintos: 400 `idempotency_key_conflict`.
- Se guarda con ámbito de workspace (`scoped_idempotency_key`, D-109). La misma key en dos workspaces da dos jobs distintos.
- **Misma key + misma request:**
  - responde 200 con el **mismo** `job_id` y `"duplicate": true`;
  - no se crea un segundo job;
  - no hay segunda reserva de uso: ni de crédito Quick, ni de LOC del mes, ni de Trial;
  - no se salta la cuota.
- **Misma key + request distinta:** 409 `idempotency_key_reused`, con `details.job_id`.
  - "Request" significa la huella SHA-256 (`analysis_jobs.request_fingerprint`, migración 0014) de: modo, proyecto, forma de entrada, `filename` y digest del bundle de código que recibiría el motor.
  - Nunca se guarda el código.
- **Concurrencia:** se mantiene la protección existente, el UNIQUE de `idempotency_key` y la recuperación del perdedor de la carrera. Probado con 8 hilos en SQLite y 10 en Postgres real: un solo job y una sola fila de `job_usage`.
- **Web app:** conserva su comportamiento previo (genera una key nueva por envío; una reutilización devuelve el primer job). La huella se guarda para todos los jobs, pero el 409 solo se aplica a requests de la Private API.

## Rate limits y límites

La API reutiliza D-108 y no crea un limitador contradictorio. Hay que distinguir cuatro cosas:

1. **Rate limit HTTP/API (protección técnica):**
   - El límite de envíos por usuario de D-108 (`SUBMIT_RATE_LIMIT_PER_MINUTE`, ventana de 60 s) se cuenta antes de leer el body y es **compartido** entre la web app y la API del mismo miembro.
   - No se añade un límite nuevo propio de la API.
   - Las lecturas (GET) no tienen limitador propio; ver riesgos pendientes.
2. **Cuota comercial:** crédito Quick, LOC del mes de servicio de Standard/Pro, Trial. Sin cambios.
3. **Jobs pendientes:** `MAX_PENDING_JOBS_PER_WORKSPACE` (D-108). Sin cambios.
4. **Presupuesto técnico:** unidades por mes de servicio de Standard/Pro (D-108). Sin cambios.

Límites técnicos propios de este bloque (ninguno es cuota comercial):
- 25 keys activas por workspace;
- cuerpo de `POST /scans` ≤ `JOB_SUBMIT_MAX_BODY_BYTES`, rechazado por `Content-Length` antes de leer el body;
- el resto de bodies ≤ 64 KiB.

## Formato de error

```json
{"error": {"code": "loc_quota_exceeded", "message": "...", "request_id": "3f9c…", "details": {"loc_remaining": 1000}}}
```

- `code`: estable. Se usan los códigos existentes; los errores antiguos con frase humana se traducen a un código fijo (`not_found`, `authentication_required`, `invalid_json`, `mode_not_allowed`, `source_required`, `internal_error`…).
- `message`: texto para personas.
- `request_id`: igual al header `X-Request-Id`.
- `details`: campos extra de la respuesta original (`effective_loc`, `max_pending_jobs`, `retry_after_seconds`, `feature`, `plan`…).
- Nunca se incluye: stack traces, SQL, `storage_ref`, tokens, secretos ni detalles internos de proveedores.

Las respuestas de éxito conservan el cuerpo de la web app (`"ok": true`, …) y añaden `X-Request-Id` y `Cache-Control: no-store`.

## Request IDs y logs

- Cada request a `/api/v1` lleva un `X-Request-Id`: 32 caracteres hex aleatorios, generados por el servidor.
- Cada request escribe una línea JSON en stderr: `{"event": "api_request", "ts", "request_id", "method", "path", "status", "error_code", "workspace_id", "api_key_id", "duration_ms"}`.
- Nunca se loguea:
  - el header `Authorization` ni la key;
  - bodies ni código fuente;
  - secretos de Stripe ni tokens de GitHub.
- Cualquier texto con forma de key (`vcx_…`) se enmascara en todas las líneas de log, también en el access log, aunque un cliente la ponga por error en la URL.

## CSRF y CORS

- **CSRF:** no aplica a `/api/v1`. Un navegador nunca envía una bearer key de forma automática, y las cookies se ignoran en esa ruta. Las rutas con cookie (incluida la gestión de keys desde la web app) siguen protegidas por la comprobación de Origin.
- **CORS:** no se envía ninguna cabecera `Access-Control-*` y `OPTIONS` no está implementado (501). Una página de otro origen no puede adjuntar la key, porque eso exige preflight, ni leer la respuesta. La API no está pensada para llamarse desde navegadores de terceros.

## Ejemplo (Quick)

```bash
curl -s -H "Authorization: Bearer $VERICEXA_KEY" -H "Content-Type: application/json" \
  -d '{"mode":"quick","source":"pragma solidity ^0.8.20; contract C { }","idempotency_key":"build-42"}' \
  https://<host>/api/v1/scans
curl -s -H "Authorization: Bearer $VERICEXA_KEY" https://<host>/api/v1/scans/<job_id>
curl -s -H "Authorization: Bearer $VERICEXA_KEY" https://<host>/api/v1/reports/<report_id>/json
curl -s -H "Authorization: Bearer $VERICEXA_KEY" https://<host>/api/v1/usage
```
