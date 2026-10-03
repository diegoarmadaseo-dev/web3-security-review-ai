# GitHub Actions — documentación interna (D-114)

Integración de Vericexa con GitHub Actions para los planes **Standard y Pro**. **Trial y Quick no están soportados**: el backend los rechaza con 403 `feature_not_available` (`feature: "github_actions"` para Quick; `feature: "private_api"` para Trial, que ni siquiera tiene Private API).

La Action **no es un pipeline alternativo**. Es un cliente fino de la Private API (D-113):
1. recoge los archivos del checkout;
2. llama a `POST /api/v1/scans` (el mismo endpoint, admisión, cola, worker y report que cualquier otro scan);
3. hace polling de `GET /api/v1/scans/<id>`;
4. lee `GET /api/v1/reports/<id>`;
5. publica el resultado en GitHub.

No cuenta LOC, no admite, no detecta y no genera reports: todo eso lo hace Vericexa.

## Archivos

| Archivo | Función |
|---|---|
| `.github/actions/vericexa-scan/action.yml` | Composite action: la unidad reutilizable. Todas las entradas llegan al script por `env:`, nunca interpoladas en el shell. |
| `.github/actions/vericexa-scan/vericexa_scan.py` | Cliente. Solo biblioteca estándar de Python 3.8+, que todo runner hospedado de GitHub tiene. |
| `.github/workflows/vericexa.yml` | Workflow de ejemplo usable, con `push` y `pull_request`. En este repo el job se salta mientras no exista la variable `VERICEXA_API_URL`. |

**Distribución:** para que otros repos lo usen con `uses: <owner>/<repo>/.github/actions/vericexa-scan@<tag>`, el repositorio que lo aloja debe ser accesible para ellos (público o de la misma organización). Elegir ese repositorio y la etiqueta queda pendiente para producción.

## Configuración (cliente)

1. Tener plan **Standard o Pro**.
2. En la web app de Vericexa: **API keys → Create key**. Copiar la key, que se muestra una sola vez.
3. En GitHub, en el repositorio: **Settings → Secrets and variables → Actions**:
   - **secret** `VERICEXA_API_KEY` = la key;
   - **variable** `VERICEXA_API_URL` = `https://<host de Vericexa>`.
4. Copiar `.github/workflows/vericexa.yml`. Nada secreto ni ninguna URL concreta se escribe en el YAML.

**Entradas de la Action:**
- `api-key`: siempre desde `secrets.VERICEXA_API_KEY`.
- `api-url`.
- `mode`: `standard` por defecto. Standard admite quick/standard y Pro admite quick/standard/pro; el backend lo valida.
- `path`: `.` por defecto.
- `exclude`: `lib,out,cache,artifacts,build,coverage` por defecto, para no enviar (ni pagar LOC por) dependencias ni salidas de build.
- `project-id`.
- `blocking-severities`: `CRITICAL,HIGH` por defecto; vacío = solo informe.
- `min-confidence`.
- `timeout-minutes`: 30 por defecto.
- `github-token`: opcional, solo para publicar la Check Run.

## Qué se envía

- Solo archivos regulares `.sol` y `.vy` bajo `path`.
- Se saltan siempre:
  - el conjunto ignorado de D-109 (`.git`, `node_modules`, `__pycache__`, `.venv`, `venv`, `__MACOSX`);
  - cualquier directorio oculto (`.github`, `.env.d`…);
  - los directorios de `exclude`;
  - los symlinks (nunca se siguen);
  - las rutas con caracteres fuera de `A-Z a-z 0-9 . _ @ + -`, que D-109 también ignoraría.
- Nunca se envían `.env`, README ni ningún otro tipo de archivo.
- Formato: el multi-archivo de D-109 (`"files": [{"path", "content"}]`). El servidor aplica toda su política de entrada: rutas, duplicados, límites, effective LOC y admisión comercial.
- Límites previos en el cliente, iguales a los del servidor: 500 archivos y 2 MiB. El servidor sigue siendo la autoridad.

Además viaja el objeto **`ci`** (metadatos, D-114): `provider: "github_actions"`, `repository`, `commit_sha` (el commit exacto del checkout, obtenido con `git rev-parse HEAD`), `ref` (`refs/heads/...` en push, `refs/pull/<n>/head` en PR), `event`, `run_id`, `run_attempt` y `pull_request`.
- Vericexa lo valida estrictamente (400 `invalid_ci_source`) y lo guarda junto al contrato en `contract_ci_sources`, migración 0015. Aparece en `source.ci` del job y del report.
- Son datos **declarados por el cliente**, no verificados con GitHub: Vericexa nunca tiene un token de GitHub. Lo analizado son siempre los archivos enviados.
- El SHA registrado es exactamente el del checkout, nunca "latest".

## Plan gating (backend)

- **La presencia de `ci` es lo que convierte la petición en "GitHub Actions".** Sin `Standard`/`Pro` → 403 `feature_not_available` con `feature: "github_actions"`. Se comprueba antes de guardar nada, de reservar crédito o LOC, y también en `dry_run`.
- `ci` solo se acepta por la Private API; en la ruta de sesión de la web app da 400 `ci_not_supported`.
- **Límite honesto:** un cliente Quick puede seguir llamando a la Private API sin `ci`, porque Quick incluye la Private API (D-113). Lo que no tiene es la integración de Actions: CI registrado, Check Run y gate.

## Eventos y SHA

| Evento | Commit analizado | Dónde se publica |
|---|---|---|
| `push` | `github.sha`, el commit empujado | Check Run sobre ese SHA y job summary |
| `pull_request` | El workflow de ejemplo hace checkout de `github.event.pull_request.head.sha` (el commit del PR, no el merge commit de GitHub) | Check Run sobre ese SHA, que es el que muestra el PR, y job summary |

- Si el checkout no coincide con el head del PR (otro workflow), se analiza el checkout y se avisa en el log.
- `pull_request_target` y cualquier otro evento se rechazan con exit 2 (`unsupported_event`).

## Resultado en GitHub

- **Job summary** (`$GITHUB_STEP_SUMMARY`):
  - resultado y commit;
  - enlace al scan (`<api-url>/app#/scans/<id>`) y al report (`<api-url>/app#/reports/<id>`); ambos piden sesión en Vericexa;
  - Automated Risk Indicator y score;
  - tabla de findings por severidad;
  - findings bloqueantes (hasta 20);
  - las fórmulas obligatorias de `docs/commercial-claims.md`.
- **Annotations:** `::error` por cada finding bloqueante y por cada error de ejecución.
- **Check Run** "Vericexa automated review":
  - **Permiso:** `checks: write` sobre el `GITHUB_TOKEN` del propio workflow (`github-token: ${{ github.token }}`). No hace falta ningún secret adicional ni otro permiso.
  - **Datos:** se envían a `api.github.com` (o a `GITHUB_API_URL`) el SHA, el estado, la conclusión y el mismo resumen que el job summary.
  - En PRs desde forks el token es de solo lectura: la Check Run no se publica, se avisa, y queda el job summary.
- **Outputs del step:** `result` (`passed` | `gate_failed` | `error` | `skipped`), `exit-code`, `job-id`, `report-id`, `job-url`, `report-url`, `risk-band`, `score`, `findings-total`, `findings-<severidad>`, `blocking-findings`, `error-code`.

## Security gate y exit codes (estables)

| Exit | Significado |
|---|---|
| **0** | Scan completado y gate superado (o gate desactivado), o run omitido (PR desde fork sin secret) |
| **1** | Scan completado y **gate fallido**: hay findings bloqueantes |
| **2** | Error de ejecución, de API o de configuración. **No es un finding** |

- **Gate:** sigue la convención del gate existente de la Skill (`pr_gate.py`: `blockingSeverities` y `minConfidence`). Un finding bloquea si su severidad está en `blocking-severities`, su confianza ≥ `min-confidence` (si se fija) y su `status` no es `informational`.
- **Errores que dan exit 2:**
  - key ausente;
  - key inválida o revocada (`invalid_api_key`);
  - plan sin la feature (`feature_not_available`);
  - suscripción inactiva;
  - cuota (`no_scan_credit`, `loc_quota_exceeded`);
  - `too_many_pending_jobs`;
  - `technical_budget_exhausted`;
  - entrada inválida (`invalid_path`, `no_source_files`, `file_not_utf8`, `too_many_files`…);
  - scan fallido (`scan_failed`; un scan fallido no consume uso);
  - `timeout`;
  - Vericexa inalcanzable (`api_unavailable`);
  - report no disponible;
  - evento no soportado.
- "Hay vulnerabilidades" nunca se convierte en "fallo de API", ni al revés.

## Idempotencia, reintentos y polling

- **Idempotency key:** `gha:<repo>:<run_id>:<event>:<sha>` (si supera 200 caracteres, su SHA-256 con prefijo `gha:`).
  - Distingue repositorio, run, evento y commit.
  - **No** incluye `run_attempt`: un *re-run* del mismo run reutiliza el mismo scan (sin duplicado y sin volver a consumir LOC) y continúa esperándolo.
  - Un run nuevo, por un push o por *Run workflow*, crea un scan nuevo.
  - Se respeta la semántica de D-113: misma key con otro contenido → 409 `idempotency_key_reused`, que la Action trata como error 2.
- **Reintentos del envío:** solo ante error de transporte, 5xx o `submit_rate_limited` (respetando `Retry-After`, máximo 120 s). Hasta 4 intentos, siempre con la misma key.
- **Polling:** empieza a 5 s, multiplica por 1,5 y tope de 30 s; se toleran hasta 6 fallos transitorios seguidos. Con `timeout-minutes` vence con error 2 sin reenviar nada; un re-run retoma el mismo scan.
- **`timeout-minutes` del job:** en el ejemplo es 45, por encima del de la Action.
- **Concurrencia del ejemplo:** `concurrency` sin cancelación, para no abortar scans en curso.

## Seguridad

- **Key:**
  - solo en GitHub Secrets;
  - se envía únicamente a `VERICEXA_API_URL`: https obligatorio, sin credenciales, query ni fragmento, y **sin seguir redirecciones**. Solo se admite http hacia localhost, para pruebas;
  - nunca se imprime: todo el output pasa por un redactor, además del enmascarado propio de GitHub;
  - no va en artifacts, summary ni outputs.
- **Token de GitHub:** solo se envía a `GITHUB_API_URL`; **nunca a Vericexa**.
- **Mínimo privilegio:** el workflow de ejemplo declara solo `contents: read` y `checks: write`, y el checkout usa `persist-credentials: false`.
- **PRs desde forks:** se usa `pull_request` (nunca `pull_request_target`), así que GitHub no entrega secrets al workflow y la Action **se omite** con exit 0 y un aviso, sin contactar con ningún servidor. Si un mantenedor activa "send secrets to fork pull requests", la Check Run sigue sin publicarse porque el token es de solo lectura. **No se recomienda** activarlo.
- **Contenido del repositorio = datos:**
  - Ningún valor de `github.event.*` se interpola en un shell; el workflow no tiene ningún paso `run:`.
  - La composite action pasa las entradas por `env:`.
  - El único subproceso es `git rev-parse HEAD` con argumentos fijos.
  - Nombres de archivo, textos de findings y mensajes del servidor:
    - se limpian de caracteres de control, para que ninguna línea pueda empezar un *workflow command*;
    - en el log se prefijan con `[vericexa]`;
    - en annotations se escapan (`%25`, `%0D`, `%0A`);
    - en summary y Check Run se escapan Markdown y HTML.
- **Lectura de archivos:** no se siguen symlinks y `path` debe quedar dentro del checkout.
- **Logs:** nunca se imprime código fuente.

## Tests

- `tests/test_github_action.py` (36 tests):
  - ejecuta la Action en proceso contra el **servidor real de Vericexa** (SQLite, Private API, admisión y cola reales) y un **servidor falso de la API de GitHub**;
  - el worker lo simula el test y el reloj es falso;
  - cubre plan, auth, entrada, eventos, resultados, seguridad, idempotencia, concurrencia y la definición de los YAML.
- En `tests/test_backend_postgres_integration.py`, `GitHubActionsIntegrationTests` cubre Postgres real.

**Requiere GitHub real (no ejecutado en este bloque, porque implica push y configurar secrets):**
- runner hospedado;
- enmascarado de secrets por GitHub;
- token de fork de solo lectura;
- Check Run visible en un PR de github.com;
- `vars` / `secrets` reales.
