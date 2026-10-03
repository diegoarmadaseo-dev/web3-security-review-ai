# Stripe billing - Sandbox (D-115)

Integración de cobro con Stripe del backend (`backend/billing.py`, `backend/http_app.py`,
`backend/repository.py`, migración `0016_billing_checkout_sessions.sql`). Este documento describe el
modelo, la configuración, las pruebas y cómo ejecutar el E2E real en Stripe Sandbox. No contiene
ningún secreto: los Price IDs son identificadores públicos.

Estado: la integración está verificada de forma determinista (sin red), con el catálogo real de
Sandbox. El E2E contra Stripe real está preparado, pero requiere que Diego haga una acción (ver
"E2E Sandbox").

## 1. Qué es Sandbox

- Stripe Sandbox ("test mode") es un entorno aislado de Stripe donde nunca hay cargos reales. Las
  claves son `sk_test_...` (secretas) o `rk_test_...` (restringidas). Productos, Prices, clientes y
  eventos son objetos distintos de los de live.
- El backend funciona en un único modo, `STRIPE_MODE`, que vale `test` por defecto. En `test`:
  - una clave `sk_live_`/`rk_live_` es un error de arranque;
  - un evento de webhook con `livemode: true` se rechaza con 400, aunque venga firmado.
- El modo `live` existe, pero queda fuera de D-115 (ver §13).

## 2. Variables

| Variable | Uso | Obligatoria | Secreta |
|---|---|---|---|
| `STRIPE_MODE` | `test` (por defecto) o `live`. La clave tiene que pertenecer a ese modo. | No | No |
| `STRIPE_SECRET_KEY` | Clave de la API (`sk_test_`/`rk_test_` en Sandbox). | Sí | **Sí** |
| `STRIPE_WEBHOOK_SECRET` | Secreto de firma del endpoint `/billing/webhook` (`whsec_...`). | Sí | **Sí** |
| `STRIPE_PRICE_QUICK_ONETIME` | Price de Quick (pago único). | Sí | No |
| `STRIPE_PRICE_STANDARD_MONTHLY` / `_ANNUAL` | Prices de Standard. | Sí | No |
| `STRIPE_PRICE_PRO_MONTHLY` / `_ANNUAL` | Prices de Pro. | Sí | No |

Al arrancar se valida todo esto:
- la clave pertenece al modo configurado;
- el webhook secret tiene la forma `whsec_`;
- hay 5 Prices con la forma `price_` y ninguna se repite;
- las variables retiradas de D-086 no están definidas.

Los mensajes de error nunca incluyen ninguna parte de una clave.

## 3. Price IDs por plan (Sandbox, D-107)

| Variable | Plan | Precio | Checkout | Price ID de Sandbox |
|---|---|---|---|---|
| `STRIPE_PRICE_QUICK_ONETIME` | Quick, 1 escaneo de hasta 3.000 LOC | $29.99 pago único | `mode=payment` | `price_1UMFnY1jc8PYYLrPXxSbSEUF` |
| `STRIPE_PRICE_STANDARD_MONTHLY` | Standard, 20.000 LOC/mes, 10.000 LOC por escaneo | $199.99/mes | `mode=subscription` | `price_1UMFvU1jc8PYYLrPsrZuTqJl` |
| `STRIPE_PRICE_STANDARD_ANNUAL` | Standard, 12 meses de servicio | $1,999.90/año | `mode=subscription` | `price_1UMFvU1jc8PYYLrPg7Kia6bO` |
| `STRIPE_PRICE_PRO_MONTHLY` | Pro, 60.000 LOC/mes, 20.000 LOC por escaneo | $289.99/mes | `mode=subscription` | `price_1UMFwj1jc8PYYLrP2rA1xonm` |
| `STRIPE_PRICE_PRO_ANNUAL` | Pro, 12 meses de servicio | $2,899.90/año | `mode=subscription` | `price_1UMFy51jc8PYYLrPLyQHT8Fh` |

La fuente de verdad de importes y límites es `backend/plans.py`, y D-115 no los cambia. El harness E2E
comprueba en Stripe que cada Price cumple lo siguiente; si algo no coincide falla, nunca lo "corrige":
- existe en la cuenta de la clave;
- es de Sandbox y está activa;
- tiene el tipo y el intervalo correctos;
- su importe coincide con el del catálogo.

## 4. Configurar los secretos sin exponerlos

Hay dos formas de dárselos al harness E2E (la web real los lee siempre del entorno):

1. **Fichero fuera del repositorio** (recomendado en Windows: no hace falta reiniciar ninguna
   sesión). Por ejemplo `%USERPROFILE%\.vericexa\stripe-sandbox.env`:
   ```
   STRIPE_SECRET_KEY=rk_test_...
   STRIPE_PRICE_QUICK_ONETIME=price_1UMFnY1jc8PYYLrPXxSbSEUF
   STRIPE_PRICE_STANDARD_MONTHLY=price_1UMFvU1jc8PYYLrPsrZuTqJl
   STRIPE_PRICE_STANDARD_ANNUAL=price_1UMFvU1jc8PYYLrPg7Kia6bO
   STRIPE_PRICE_PRO_MONTHLY=price_1UMFwj1jc8PYYLrP2rA1xonm
   STRIPE_PRICE_PRO_ANNUAL=price_1UMFy51jc8PYYLrPLyQHT8Fh
   ```
   Se pasa con `--env-file <ruta>`. El harness:
   - rechaza un fichero que esté dentro del repositorio;
   - solo lee las variables `STRIPE_*`;
   - no imprime nunca un valor: solo PRESENTE/AUSENTE y la clase de clave (`sk_test`/`rk_test`).
2. **Variables de entorno** del proceso que lo ejecuta. En Windows, una variable definida después de
   abrir Claude Code o una terminal no la ven los procesos ya abiertos.

Si se usa una clave restringida (`rk_test_`), necesita estos permisos mínimos:

| Recurso | Permiso |
|---|---|
| Checkout Sessions | escritura |
| Subscriptions | lectura y escritura (el harness cancela la suscripción de prueba) |
| Prices | lectura |
| Events | lectura |
| Customer portal | escritura (solo para la web) |

`STRIPE_WEBHOOK_SECRET` no hace falta para el harness: si no está, genera uno efímero en memoria (ver §9).

## 5. Modelo de estado y entidades locales

| Entidad de Stripe | Dónde queda en local |
|---|---|
| Workspace / usuario | `billing_checkout_sessions.workspace_id` y `.user_id`: quién inició cada checkout. `entitlements.workspace_id` es único: un plan por workspace. |
| Checkout Session | `billing_checkout_sessions` (id `cs_...`, plan, intervalo, Price, modo, cliente, estado). Una sesión que no está aquí no concede nada. |
| Customer | `entitlements.stripe_customer_id`, y el cliente con el que se creó cada checkout. El checkout reutiliza siempre el cliente del workspace. |
| Subscription | `entitlements.stripe_subscription_id` (único entre workspaces) y `billing_checkout_sessions.stripe_subscription_id` (la sesión que la creó). |
| Invoice / pago | No se guarda. Una factura solo dispara la relectura de su propia suscripción: el resultado del pago es el `status` que Stripe da a la suscripción. |
| Event | `webhook_events` (id `evt_...`, tipo, `processed_at`, `processing_error`, `outcome`). |

Estados de `billing_checkout_sessions`, que solo avanzan:
- `open` → `awaiting_payment`: completada con un pago asíncrono todavía pendiente.
- `open` | `awaiting_payment` → `completed` | `payment_failed`.
- `open` → `expired`: la expiró Stripe, o el backend al crear un checkout nuevo.

Una transición que no está permitida (un replay o un evento tardío) no cambia nada y devuelve
`ignored:checkout_already_<estado>`.

Estado de acceso (`entitlements.status`):
- es exactamente el `status` de la suscripción en Stripe;
- `paused` se guarda como `unpaid`;
- solo `active` y `trialing` permiten escanear;
- `past_due` y `unpaid` no permiten escanear, pero bloquean un segundo checkout: la suscripción
  sigue existiendo y el pago se arregla en el portal.

## 6. Flujo de Checkout

1. `POST /billing/checkout` con `{workspace_id, plan, interval}`, que pasa por estas comprobaciones:
   - sesión de usuario, mismo origen (CSRF) y rol owner/admin en ese workspace;
   - el cliente solo elige el plan: la Price la decide el servidor (`resolve_price_id`);
   - 409 si el workspace tiene una suscripción en `active`/`trialing`/`past_due`/`unpaid`, o un Quick
     sin usar.
2. Bajo el lock de facturación del workspace:
   - si hay un checkout de los últimos 10 minutos que ya se pagó pero aún no se ha aplicado, se
     rechaza el nuevo con 409 `checkout_already_completed`;
   - una sesión anterior en `awaiting_payment` da 409 `checkout_payment_pending`;
   - una sesión anterior en `open` se expira en Stripe; si Stripe responde que ya estaba pagada, se
     marca `completed` y se rechaza el nuevo checkout con 409;
   - se crea la Checkout Session en Stripe (metadata `workspace_id/plan/interval`, también en la
     suscripción) y se guarda su fila (`open`).

   Así nunca hay dos Checkouts pagables a la vez, y no se puede pagar dos veces.
3. El cliente paga en la página de Stripe. `success_url` no concede nada; solo concede el webhook.

## 7. Eventos procesados

| Evento | Efecto |
|---|---|
| `checkout.session.completed` (Quick, `paid`) | Se comprueba con Stripe que los line items son exactamente 1 unidad de la Price Quick. Entonces se concede 1 crédito (id = sesión) y el plan pasa a quick/active. |
| `checkout.session.completed` (Quick, `unpaid`) | `awaiting_payment`, sin conceder nada. |
| `checkout.session.async_payment_succeeded` | Igual que un `completed` pagado. |
| `checkout.session.async_payment_failed` | `payment_failed`, sin conceder nada. |
| `checkout.session.expired` | `expired`, sin conceder nada. |
| `checkout.session.completed` (suscripción) | Guarda la suscripción en la fila de la sesión y aplica su estado actual. |
| `customer.subscription.created` / `.updated` / `.deleted` | Relee la suscripción en Stripe y aplica su estado: activación, renovación, cambio de plan o intervalo, `past_due`, cancelación. |
| `invoice.paid` / `invoice.payment_failed` | Relee la suscripción de esa factura (nunca "la del workspace") y aplica su estado. |
| Cualquier otro | Se registra y se responde 200 con `ignored:unhandled_event_type`. |

Las suscripciones siguen estas reglas:
- el plan y el intervalo salen **solo** de la Price de la suscripción; una Price fuera de las 4
  configuradas se rechaza con `rejected:unknown_price`;
- una suscripción solo se asocia a un workspace si la creó un checkout de este backend para ese
  workspace. La sesión se busca en local por la suscripción o con
  `checkout.sessions.list(subscription=…)`.

## 8. Idempotencia, duplicados, orden y coherencia

- **Firma**: se verifica sobre el cuerpo crudo y antes de parsear (`stripe.Webhook.construct_event`,
  con una tolerancia de 300 s), y después se comprueba `livemode`. Si falla: 400 y no se registra nada.
- **Duplicados**: se deduplica por `event.id`. Un evento que ya se procesó con éxito devuelve
  `{"duplicate": true}`; uno que falló sigue siendo reintentable y solo lo reclama un reintento.
- **Doble crédito o doble entitlement**:
  - el crédito Quick usa como clave el id de la sesión, con `ON CONFLICT DO NOTHING`;
  - crédito, entitlement y estado de la sesión se escriben en una sola transacción bajo el lock;
  - `entitlements.workspace_id` y `stripe_subscription_id` son únicos.

  Está probado con entregas concurrentes en SQLite y en Postgres real.
- **Fuera de orden**:
  - Stripe emite varios eventos en el mismo segundo (`subscription.created` en `incomplete`,
    `.updated` en `active`, `invoice.paid`, `checkout.session.completed`) y no los entrega en orden;
    el `created` tiene resolución de un segundo y no sirve para ordenarlos;
  - por eso cada evento de suscripción solo **dispara** una relectura de la suscripción en Stripe, que
    se aplica bajo el lock del workspace: gana siempre el estado más reciente;
  - está probado con las 24 permutaciones de la ráfaga.
- **Eventos tardíos de una suscripción vieja**:
  - una suscripción distinta de la guardada, y que no está viva, nunca sustituye a la actual, ni a un
    Quick ni a un Trial;
  - al pasar a Quick se olvida el id de la suscripción muerta.
- **Segunda suscripción viva** (dos pagos en carrera): se relee la guardada en Stripe; si sigue viva,
  se responde `rejected:duplicate_subscription` y se lanza una alerta para que un operador reembolse
  una de las dos.
- **Pago fallido**: Stripe pone la suscripción en `past_due`, el plan queda sin acceso, el checkout da
  409 y el pago se arregla en el portal. Cuando la factura se paga, vuelve a `active`.
- **Cancelación**: `customer.subscription.deleted` deja el plan en `canceled`, sin acceso. El historial
  se conserva y se puede comprar de nuevo.
- **Renovación**: el nuevo `current_period_start` abre un nuevo mes de servicio, con la cuota a 0.
  En el plan anual el ancla se mantiene durante los 12 meses y la cuota es mensual, sin rollover
  (`plans.service_month`).
- **Stripe caído durante una relectura**: se responde 500, el evento queda reintentable, se lanza una
  alerta `error` y Stripe lo reenvía.

## 9. Resultados (outcome), alertas y logs

Cada evento procesado guarda `webhook_events.outcome` y lo devuelve en la respuesta:

- `applied:<qué>`, por ejemplo:
  - `applied:quick_credit_granted`, `applied:quick_credit_already_granted`;
  - `applied:subscription_active` y el resto de `applied:subscription_<status>`;
  - `applied:awaiting_payment`, `applied:payment_failed`, `applied:checkout_expired`.
- `ignored:<motivo>`: no había nada que hacer. Por ejemplo `unknown_checkout_session`, `duplicate`,
  `stale_subscription`, `unhandled_event_type`, `malformed_object`, `checkout_already_<estado>`,
  `subscription_without_workspace`, `not_a_subscription_invoice`.
- `rejected:<motivo>`: el evento contradice lo que hay asociado en local, así que no se cambia nada,
  se responde 200 (reintentarlo daría el mismo resultado) y se lanza una alerta
  `stripe.webhook_failure` de nivel `warning`. Los motivos son:
  - `workspace_mismatch`, `customer_mismatch`, `subscription_mismatch`, `mode_mismatch`;
  - `unbound_subscription`, `duplicate_subscription`;
  - `unknown_price`, `unknown_workspace`;
  - `line_items_mismatch`, `quick_with_live_subscription`.

Por cada entrega se escribe una línea JSON en stderr:
`{"event":"stripe_webhook","event_id","event_type","outcome","status"}`. Nunca incluye el payload, la
firma, secretos ni datos del cliente. `processing_error` guarda solo el tipo de excepción.

## 10. Pruebas automatizadas (sin red, sin secretos)

| Suite | Qué cubre |
|---|---|
| `tests/test_backend_stripe_billing.py` | Cadena completa por HTTP con los Price IDs de Sandbox y el simulador de Stripe (`tests/stripe_simulator.py`): modos, checkout, Quick, las 4 suscripciones, ráfaga en 24 órdenes, renovación, plan anual, pago fallido, cancelación, cambio de plan, caída de Stripe y asociación con su seguridad. |
| `tests/test_backend_billing.py` | Firma, `livemode`, payload malformado, duplicados, outcomes; construcción de sesiones y portal. |
| `tests/test_backend_commercial.py` | Webhook → entitlement con el catálogo de Sandbox; reglas comerciales. |
| `tests/test_backend_main.py` | `STRIPE_MODE`, clave live rechazada, `whsec_`. |
| `tests/test_stripe_sandbox_e2e.py` | El propio harness E2E en modo simulado: PASS, BLOCKED, WAITING/resume y diagnósticos. |
| `tests/test_backend_postgres_integration.py` (`StripeBillingIntegrationTests`, `WebhookHardeningIntegrationTests`, migraciones) | Concurrencia y restricciones en Postgres real (Docker). |

Se ejecutan desde la raíz del repositorio:
```
python -m unittest tests.test_backend_stripe_billing tests.test_backend_billing tests.test_backend_commercial tests.test_stripe_sandbox_e2e
python -m unittest tests.test_backend_postgres_integration     # requiere Docker; si no, se salta
python -m unittest                                              # suite completa
```

## 11. E2E Sandbox (real)

`tests/stripe_sandbox_e2e.py` ejecuta el camino real contra Stripe Sandbox desde un único proceso de
Python, sin Stripe CLI, sin túnel y sin depender del estado de otra terminal. Las etapas son:

1. **Configuración**: clave de Sandbox presente (nunca live), 5 Price IDs y webhook secret opcional.
2. **Price IDs verificados en Stripe**: existen, son de Sandbox, están activas y su importe e
   intervalo coinciden con el catálogo.
3. **Servidor local**: la web real (`http_app` + `StripeBilling` real) con SQLite y almacenamiento
   temporales.
4. **Checkout creado**: `POST /billing/checkout` y la fila de la sesión en `billing_checkout_sessions`.
5. **Payment confirmado**: **acción humana mínima**. Se abre la URL que imprime el harness y se paga
   con la tarjeta de prueba `4242 4242 4242 4242`, cualquier fecha futura, cualquier CVC y cualquier
   email. El harness consulta la sesión hasta que esté `complete/paid`.
6. **Webhook recibido / Webhook verificado**:
   - lee de la API de Stripe los eventos de esa sesión y de esa suscripción (llegan por TLS con la
     clave, así que son auténticos);
   - los firma con el webhook secret con el que arrancó el servidor local (el de
     `STRIPE_WEBHOOK_SECRET`, o uno efímero en memoria);
   - los entrega a `/billing/webhook`, de modo que se ejecuta la verificación de firma real.

   Cualquier `rejected:*` hace fallar el E2E.
7. **Entitlement actualizado** y **Quota actualizado**: plan, status e intervalo; Quick = 1 escaneo,
   suscripción = cuota del mes.
8. **Consumo verificado**: se envía un escaneo y comprueba que reserva el crédito o la cuota.
9. **Idempotencia verificada**: reenvía todos los eventos y todos son duplicados, sin cambios.
   **Firma inválida rechazada**: 400.
10. Para las suscripciones, **Cancelación verificada**: cancela la suscripción de prueba en Stripe
    (salvo con `--keep-subscription`) y relaya `customer.subscription.deleted` → `canceled`.
11. **E2E PASS**.

Comandos:
```
python -m tests.stripe_sandbox_e2e --check-config --env-file %USERPROFILE%\.vericexa\stripe-sandbox.env
python -m tests.stripe_sandbox_e2e --plan quick --env-file %USERPROFILE%\.vericexa\stripe-sandbox.env
python -m tests.stripe_sandbox_e2e --plan all --env-file %USERPROFILE%\.vericexa\stripe-sandbox.env    # los 5, un pago cada uno
python -m tests.stripe_sandbox_e2e --plan all --simulate                                              # sin Stripe: comprueba el harness
```

Códigos de salida:

| Código | Significado |
|---|---|
| 0 | PASS |
| 1 | FAIL: indica la etapa y el motivo, más las últimas líneas de log de webhook del servidor |
| 2 | BLOCKED: configuración; nombra cada variable con problema, nunca su valor |
| 3 | WAITING: no se pagó a tiempo; imprime `--resume <dir>` para continuar en el mismo punto |

`--timeout` (900 s por defecto) controla cuánto espera al pago; `--shuffle` entrega los eventos en
orden aleatorio.

Qué **no** cubre: que Stripe entregue a un endpoint público registrado. Eso se comprueba en staging,
registrando `https://<host>/billing/webhook` en el Dashboard de Sandbox con los 9 eventos de §7 y su
`whsec_` como `STRIPE_WEBHOOK_SECRET`, y usando "Send test webhook" o un checkout real.

## 12. Diagnóstico de webhooks

| Síntoma | Causa probable | Acción |
|---|---|---|
| 400 `invalid signature` | El `STRIPE_WEBHOOK_SECRET` no es el del endpoint, el cuerpo fue alterado por un proxy, o el reloj está desfasado más de 300 s | Copiar el `whsec_` del endpoint correcto; no reescribir el cuerpo; sincronizar NTP |
| 400 `livemode mismatch` | Evento live en un despliegue Sandbox, o al revés | Revisar el endpoint del Dashboard y `STRIPE_MODE` |
| 400 `malformed event` | Falta `id`/`type`, o el id no tiene la forma `evt_` | No es un evento de Stripe |
| 500 + `processing_error` | Error de API de Stripe o de base de datos; Stripe reintentará | Ver el tipo en `webhook_events.processing_error` y la alerta `error` |
| `ignored:unknown_checkout_session` | Sesión creada fuera de este backend (Dashboard, payment link) o en otra base de datos | Esperado; comprar desde la web |
| `rejected:unbound_subscription` | Suscripción creada a mano en el Dashboard | No concede acceso, por diseño |
| `rejected:customer_mismatch` / `workspace_mismatch` / `subscription_mismatch` | El evento contradice lo asociado en local | Investigar (alerta `warning`); no se ha cambiado nada |
| `rejected:duplicate_subscription` | Dos suscripciones vivas del mismo workspace | Reembolsar o cancelar una en Stripe; la otra se aplica en su siguiente evento |
| `rejected:line_items_mismatch` | Quick pagado con un importe o Price distintos | Revisar la Price o reembolsar |
| Harness: `No such price` / `InvalidRequestError` | La clave pertenece a otra cuenta Sandbox que no tiene estos Prices | Usar la clave de la Sandbox de Vericexa |
| Harness: `no generó invoice.paid…` | El pago no terminó o Stripe tarda | Revisar la sesión en el Dashboard; reintentar con `--resume` |

## 13. Fuera de alcance (explícito)

- Modo live, claves live y endpoint live: requieren un despliegue y una revisión aparte. Impuestos,
  IVA, facturación legal, política de reembolsos y de cancelación: **LEGAL REVIEW REQUIRED**.
- Reembolsos y disputas (`charge.refunded`, `charge.dispute.*`): no revocan acceso automáticamente.
- Prorrateos y la configuración del Customer Portal: el portal debe limitarse en Stripe a las 4 Prices
  de suscripción. Si se cambia a una Price fuera del catálogo, el evento se rechaza con
  `unknown_price` y el plan no cambia.
- `cancel_at_period_end` no se muestra en la UI: el acceso sigue hasta el `deleted`.
- Un crédito Quick sin usar no se convierte al pasar a una suscripción (comportamiento previo, sin
  cambios).
- Cambios de precios, límites, capa 1/2, scoring y las semánticas de D-108…D-114: no se tocan.
