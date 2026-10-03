# Stripe Sandbox E2E — runbook (D-115)

Documento interno. Prueba el flujo real **Checkout → Stripe Sandbox → webhook → entitlement → acceso → scan → consumo** contra Stripe **Sandbox** (nunca live). Precios y límites no cambian (D-107).

## Tres niveles distintos

| Nivel | Qué prueba | Dónde |
|---|---|---|
| **Tests automáticos** | Toda la lógica de Vericexa: checkout (Price IDs de Sandbox), webhooks firmados, idempotencia, orden, concurrencia, entitlement, admisión de scans, cuota/crédito, renovación, pago fallido, cancelación, aislamiento, firma. Stripe simulado: un cliente falso con el estado actual de cada suscripción y las líneas de cada Checkout Session. | `tests/test_backend_stripe_e2e.py`, `tests/test_backend_billing.py`, `tests/test_backend_commercial.py`, `StripeBillingIntegrationTests` + `WebhookHardeningIntegrationTests` (Postgres real) |
| **E2E Stripe Sandbox real** | El comportamiento propio de Stripe: página de Checkout hospedada, tarjetas de prueba, forma real de los eventos y de las suscripciones, ráfagas reales en el mismo segundo, firmas generadas por Stripe, portal, test clocks. | Este runbook (manual / semiautomático). **No ejecutado todavía**: ver "Estado". |
| **Producción / live** | Endpoint de webhook live, claves live, portal live, dominio real, impuestos/facturación legal. | Fuera de D-115 (LEGAL REVIEW REQUIRED para términos y facturación). |

## Estado (2026-10-03)

- El Stripe CLI de esta máquina (v1.52.0) está autenticado en **otra cuenta**: "Sandbox di Nautic Desk" (`acct_1UKwUg…`). Stripe responde `No such price` para `price_1UMFnY1jc8PYYLrPXxSbSEUF`, así que los productos de Vericexa (`prod_VKuy…`, `prod_VMzv…`, `prod_VMzw…`) viven en otra cuenta Sandbox.
- No hay `STRIPE_SECRET_KEY` de esa Sandbox en el entorno, y no se ha leído ninguna clave del llavero del CLI.
- Por eso el E2E real queda **pendiente de que Diego** inicie sesión en el CLI en la Sandbox de Vericexa y exporte su `sk_test`. Todo lo demás está preparado.

## Requisitos

1. Iniciar sesión en el CLI en la Sandbox de **Vericexa**:
   ```bash
   stripe login
   ```
   Comprobar que es la cuenta correcta; debe devolver el precio Quick ($29.99, `one_time`, `usd`):
   ```bash
   stripe prices retrieve price_1UMFnY1jc8PYYLrPXxSbSEUF
   ```
2. Clave secreta de **test** de esa Sandbox: Dashboard → Developers → API keys. Puede ser `sk_test_...` o, mejor, una restricted `rk_test_...` con permisos de escritura en Checkout Sessions y Customer Portal y de lectura en Subscriptions y Checkout Session line items. Nunca se escribe en el repo.
3. Python con `stripe` instalado (`pip install -r backend/requirements.txt`).

## Arranque (dos terminales)

**Terminal A**: reenviar a localhost solo los eventos que Vericexa usa. Primero obtener el secreto de firma (`whsec_...`):

```bash
stripe listen --print-secret
```

Después dejar el reenvío en marcha:

```bash
stripe listen --events checkout.session.completed,checkout.session.async_payment_succeeded,customer.subscription.created,customer.subscription.updated,customer.subscription.deleted,invoice.paid,invoice.payment_failed --forward-to http://127.0.0.1:8790/billing/webhook
```

**Terminal B**: en el shell propio de Diego, exportar `STRIPE_SECRET_KEY` (la `sk_test`/`rk_test`), `STRIPE_WEBHOOK_SECRET` (el `whsec_` de arriba) y los cinco Price IDs de `docs/staging-config.md`:

- `STRIPE_PRICE_QUICK_ONETIME=price_1UMFnY1jc8PYYLrPXxSbSEUF`
- `STRIPE_PRICE_STANDARD_MONTHLY=price_1UMFvU1jc8PYYLrPsrZuTqJl`
- `STRIPE_PRICE_STANDARD_ANNUAL=price_1UMFvU1jc8PYYLrPg7Kia6bO`
- `STRIPE_PRICE_PRO_MONTHLY=price_1UMFwj1jc8PYYLrP2rA1xonm`
- `STRIPE_PRICE_PRO_ANNUAL=price_1UMFy51jc8PYYLrPLyQHT8Fh`

Luego arrancar:

```bash
python tests/stripe_sandbox_smoke.py
```

El harness:
- arranca la web app real con SQLite y el `StripeBilling` real contra Sandbox;
- rechaza cualquier clave live;
- imprime un enlace de acceso por workspace de prueba (`quick`, `standard-m`, `standard-a`, `pro-m`, `pro-a`);
- muestra una línea `[smoke] ... entitlement=(plan, status, interval, subscription, period_start, scans_available, loc_used)` cada vez que cambia;
- usa un worker sustituto que completa los scans (el motor no forma parte de este smoke).

Tarjetas de prueba de Stripe: `4242 4242 4242 4242` (éxito), cualquier fecha futura y cualquier CVC.

## Flujos a comprobar (anotar el resultado de cada uno)

| # | Flujo | Pasos | Esperado |
|---|---|---|---|
| 1 | **Quick** | Enlace `quick` → Billing → Quick "Choose" → Checkout con 4242 → volver | `quick, active, scans_available=1`. Scan ≤3.000 LOC → admitido y completado; 2º scan → `402 no_scan_credit`. En `stripe listen`: `checkout.session.completed` → 200. |
| 2 | **Standard monthly** | `standard-m` → Standard $199.99/mes → Checkout | `standard, active, monthly, sub_…, period_start`. Scan de 10.000 LOC admitido; 10.001 → 413. `loc_used` sube; al pasar de 20.000 → `402 loc_quota_exceeded`. |
| 3 | **Standard annual** | `standard-a` → $1,999.90/año | `standard, active, annual`. Cuota **mensual** de 20.000 (Usage muestra el mes de servicio, no 240K). |
| 4 | **Pro monthly** | `pro-m` → $289.99/mes | `pro, active, monthly`. 20.000/scan, 60.000/mes. |
| 5 | **Pro annual** | `pro-a` → $2,899.90/año | `pro, active, annual`, 60.000 por mes de servicio. |
| 6 | **Ráfaga real** | Durante 2–5, mirar `stripe listen` | Varios eventos en el mismo segundo y en cualquier orden. El estado final es siempre `active`; ninguno queda en `incomplete`. |
| 7 | **Webhook duplicado** | `stripe events resend <evt_id>` sobre un evento ya procesado | 200 `{"ok": true, "duplicate": true}`; sin cambios en el entitlement. |
| 8 | **Cancelación** | Billing → Manage subscription → Cancel (al final del periodo) | Sigue `active` hasta el fin de periodo. Cancelación inmediata (`stripe subscriptions cancel <sub_id>`) → `canceled`, scans → 402, se puede volver a comprar. |
| 9 | **Renovación** (test clock) | Ver abajo | Nuevo `current_period_start`; `loc_used=0` en el nuevo mes (sin rollover). |
| 10 | **Pago fallido** (test clock) | Ver abajo | `invoice.payment_failed` y la suscripción en `past_due` → entitlement `past_due`, scans → 402, checkout → 409 (arreglar en el portal); al pagar → `active`. |

### Renovación y pago fallido con Test Clocks

Checkout no puede crear clientes en un test clock, así que la suscripción se crea con la API. La metadata `workspace_id` es la que el checkout de Vericexa pondría.

1. Crear el test clock, congelado en el instante actual:
   ```bash
   stripe test_helpers test_clocks create --frozen-time 1790000000
   ```
   (usar el timestamp Unix actual en lugar de `1790000000`).
2. Crear un cliente en ese clock con una tarjeta de prueba:
   ```bash
   stripe customers create -d test_clock=clock_... -d email=renew.owner@smoke.test -d payment_method=pm_card_visa -d "invoice_settings[default_payment_method]=pm_card_visa"
   ```
3. Crear la suscripción con la metadata del workspace (por ejemplo el de `standard-m`, sin una suscripción viva):
   ```bash
   stripe subscriptions create -d customer=cus_... -d "items[0][price]=price_1UMFvU1jc8PYYLrPsrZuTqJl" -d "metadata[workspace_id]=<workspace standard-m>"
   ```
   Hacer un scan para tener consumo en el mes 1.
4. **Renovación:** avanzar el reloj algo más de un mes:
   ```bash
   stripe test_helpers test_clocks advance clock_... --frozen-time 1792700000
   ```
   Esperado: `invoice.paid` y `customer.subscription.updated` con el nuevo periodo; en el harness, nuevo `period_start` y `loc_used=0`.
5. **Pago fallido:** cambiar el método de pago por defecto a una tarjeta que se adjunta pero falla al cobrar:
   ```bash
   stripe customers update cus_... -d "invoice_settings[default_payment_method]=pm_card_chargeCustomerFail"
   ```
   Avanzar otro mes:
   ```bash
   stripe test_helpers test_clocks advance clock_... --frozen-time 1795400000
   ```
   Esperado: `invoice.payment_failed`, la suscripción pasa a `past_due` y el entitlement también. Volver a `pm_card_visa` y pagar la factura con `stripe invoices pay in_...`: `invoice.paid` → `active`.

### Anual con cuota mensual

Con un test clock y la Price anual, avanzar 1, 2… meses **sin** renovación de Stripe: Vericexa calcula el mes de servicio desde `current_period_start` (`plans.service_month`). En el harness, `loc_used` vuelve a 0 cada mes y el límite es siempre 20.000/60.000, nunca acumulado.

## Qué comprobar en cada flujo

- En `stripe listen`, cada evento responde 200. Un 500 solo es aceptable ante un fallo de la API de Stripe, y su reintento debe dar 200.
- El entitlement lo cambia **solo** el webhook: volver a `success_url` no concede nada.
- Ningún secreto aparece en la salida del harness ni en sus logs.

## Variables / secrets

| Variable | Sandbox (este runbook) | Producción |
|---|---|---|
| `STRIPE_SECRET_KEY` | `sk_test_…`/`rk_test_…` de la Sandbox de Vericexa (shell de Diego) | live, en el gestor de secretos |
| `STRIPE_WEBHOOK_SECRET` | `whsec_…` de `stripe listen` | el del endpoint live del Dashboard |
| `STRIPE_PRICE_*` (5) | los de `docs/staging-config.md` | los Price IDs live (otros IDs) |

## Riesgos de producción (no resueltos en D-115)

- **Endpoint live:**
  - Configurar exactamente los 7 eventos de arriba, con su propio `whsec_`.
  - Con el modelo de D-115, la forma del payload importa poco: Vericexa relee la suscripción con la versión de API de su SDK y del evento solo usa ids y metadata. Aun así conviene fijar la misma versión de API en el endpoint.
- **Dependencia de la API de Stripe en el webhook:** cada evento de suscripción hace una lectura (~100–300 ms). Si Stripe no responde, el webhook da 500, el evento queda reintentable y Stripe lo reenvía hasta 3 días.
- **Customer Portal:** debe ofrecer **solo** las 4 Prices de suscripción del catálogo. Un cambio a una Price ajena se ignora y el entitlement se queda con el plan anterior.
- **Doble suscripción:** dos Checkouts completados en paralelo (dos pestañas) crean dos suscripciones de pago en Stripe. Vericexa aplica la más reciente, pero Stripe cobra ambas. Mitigación pendiente: alerta o cancelación de la duplicada.
- **Reembolsos y disputas:** no se tratan. Un Quick reembolsado conserva su crédito y una disputa no revoca acceso. Pendiente de decisión de producto.
- **Impuestos, facturas legales y precios en otras monedas:** fuera de alcance; LEGAL REVIEW REQUIRED.
