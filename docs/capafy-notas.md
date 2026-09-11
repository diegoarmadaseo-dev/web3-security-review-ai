# Notas de Capafy (verificadas en el repo público)

Fuente: `github.com/Capafy/Capafy-skills`, commit `c70e817` (2026-09-11), clonado en carpeta temporal fuera del proyecto; ni instalado ni ejecutado. Lo no demostrado allí va como `[CAPAFY-VERIFY]` y como duda en `docs/decisiones.md`.

## Verificado en código y documentación del repo
- Skill publicable = directorio con `SKILL.md` (+ scripts, references, config). Con `--env claude_code` el descubrimiento busca `.claude/skills/<nombre>/`; el nombre sale del directorio/frontmatter y solo se parsean las claves `name` y `description` (admite bloques `>` y `|`). Una skill anidada dentro de otra se suprime.
- CLI real (`packager.py`): `publish-init --env claude_code --runtime-dir <raíz absoluta del proyecto> [--skill-dir <raíz de UNA skill que contiene SKILL.md>]`, `publish-submit --agent-id <id> --action prepare [--deep-scan]`, `publish-submit --action continue_upload`, `publish-remote-status`, `publish-status`, `publish-list`, `publish-refresh-url`. README/AGENTS.md citan alias `publish-configure`/`publish-ship`; el `SKILL.md` del publisher es la fuente de verdad.
- Flujo: Phase A (init sin selecciones) → selecciones confirmadas (`title`, `description`, `skills[].purpose`) → `review_url` web (caduca en 1 h) → `prepare` (escaneo de secretos por reglas, deep scan opcional con el LLM del host, staging con placeholders `PLATFORM_MANAGED_*`; nunca edita el código fuente) → `continue_upload` (validar, empaquetar, subir) → revisión web final y botón Submit. `status 0 / auditStatus 0` = borrador sin enviar.
- `CLAUDE.md` (raíz del proyecto, `.claude/CLAUDE.md` y `~/.claude/CLAUDE.md`), `README.md` y cualquier `.md/.txt` de la raíz se descubren como "workspace documents": candidatos que empiezan como `excluded` y solo se empaquetan si el creador los marca en la web (Run Online). En Download nunca se empaquetan. Regla nuestra: no marcarlos jamás.
- Exclusiones automáticas del staging: directorios `.git .github __pycache__ node_modules .venv venv memory .temp .temp-fallback .ssh .gnupg`, sufijos `.pyc .pyo .log .pem .key .p12 .pfx .ppk .jks …`, ficheros tipo `id_rsa`/`.credentials.json`, virtualenvs y symlinks absolutos. Dentro de una skill, `eval`, `temp`, `.research`, `.serena` se tratan como ruido y `run` como salidas de runtime.
- Señales "suspicious" (no bloqueantes): >200 archivos, >5 MiB, archivos con sufijos de credenciales, `SKILL.md` sin description ni sinopsis. No hay límite duro documentado.
- Invariantes del paquete: los archivos de texto no pueden contener rutas locales del creador (`C:\Users\…`, `/home/…`, `/Users/…`); el escaneo PII marca emails, teléfonos, IPs privadas y claves SSH públicas. Nada de eso en archivos publicados.
- Runtime Claude Code: `ANTHROPIC_BASE_URL`/`ANTHROPIC_API_KEY` se reservan como `url_proxy` (credencial alojada por la plataforma, formato Anthropic Messages; modelo leído de `~/.claude/settings.json` o `ANTHROPIC_MODEL`/`CLAUDE_MODEL`). Es el mecanismo con el que el creador aporta y paga su clave LLM.
- Modos de venta (`billingMode`): `download` (`oneTimeFee`), `hourly` (`hourlyPrice`, `minPurchaseHours`, `hourlyMaxMessageCount`; 1–24 h por pedido) y `subscription` (`cycleType` `week`|`month`, `cyclePrice`, `cycleMaxMessageCount`); varias líneas de billing por Agent; moneda "usually usd". No existe pago por llamada. Download entrega todos los archivos al comprador; Run Online mantiene el código cerrado.
- Ficha: `title`, `shortDescription`, `detailedDescription`, `versionUpdateInfo`, `welcomeMessage`, `logoUrl`, `tags` (cadena separada por comas), `categoryId`/`categoryName`, `purpose` por skill (visible en el listado) y `lang` inicial (en, es, fr, de, it, ja, zh, zh-TW, ar, nl, ko, pt).
- Logs: los mensajes de chat persisten en el historial de la instancia y puede leerlos cualquiera con acceso a ella (README y capafy-user). Las instancias tienen un periodo de almacenamiento temporal con purga programada y renovación de pago.
- El login exige aceptar explícitamente los Terms of Service y la Privacy Policy de Capafy. "Developer certification" en Capafy es el KYC del vendedor, no una certificación del producto: nunca usarlo como claim.

## [CAPAFY-VERIFY] — no demostrado en el repo público
- Disponibilidad de `python3` en el runtime Run Online (el "Python 3.8+" del README es requisito de la máquina del creador/usuario). Condiciona el score determinista y el fallback `not_computed`.
- Suscripción diaria: el repo solo muestra ciclos `week`/`month`.
- Retención de logs de ejecución durante 90 días: no aparece en el repo (solo un límite de 90 días en consultas de estadísticas).
- Lista real de categorías (solo se ve el ejemplo "Productivity Tools"), existencia de "Developer Tools / Security" y límite de 5 tags.
- Proveedor/modelo LLM efectivo en runtime, su política de retención y si el comprador lo ve.
- Si el publisher puede fijar condiciones comerciales propias además de los ToS de Capafy.
- Límites duros de tamaño/número de archivos del paquete y longitud máxima de `description`.
