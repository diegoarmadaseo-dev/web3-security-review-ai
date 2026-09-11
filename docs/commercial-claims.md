# Control de claims comerciales

Lista de control para todo texto visible por compradores o usuarios: ficha de Capafy (`capafy/`),
`SKILL.md`, references, plantillas de informe, mensajes de la Skill y cualquier material de marketing.
Todo contenido nuevo se comprueba contra este documento antes del commit (ver "Procedimiento").
Nada de este documento se publica; la lista literal que necesita el runtime vivirá en
`references/guardrails.md` (D-008).

## Posicionamiento oficial

> **Automated AI-assisted smart contract security review.**

Frase de marketing preferente:

> Review your smart contract code for common security risks with AI-assisted analysis.

La Skill describe lo que hace (análisis automatizado, asistido por IA, con alcance limitado) y nunca
lo que no puede garantizar (seguridad, ausencia de vulnerabilidades, idoneidad para desplegar).

## Permitted — términos y expresiones permitidos

- automated
- AI-assisted
- preliminary
- scoped / within the analyzed scope / according to the analyzed scope
- security review
- findings
- risk indicator / Automated Risk Indicator
- recommendations
- suggested remediation / suggested remediation patch
- heuristic signals
- limitations / out of scope
- confidence (high / medium / low)
- NOT_DETECTED / NOT_ASSESSED

## Restricted / prohibited — nivel A: prohibidos en cualquier uso afirmativo

Estos términos no aparecen en ningún archivo publicado ni en la ficha, salvo dentro de la lista literal
de `references/guardrails.md`. Es la lista que ejecuta el grep automático.

| Término | Motivo |
|---|---|
| certified / certificación | implica certificación formal |
| audited / audit completed / complete audit / professional audit | implica auditoría profesional realizada |
| official | implica respaldo institucional |
| safe to deploy | recomendación de despliegue |
| guaranteed | garantía |
| 100% secure | seguridad absoluta |
| vulnerability-free | ausencia total de vulnerabilidades |
| no vulnerabilities / no vulnerabilities found / no vulnerabilities exist | ausencia total de vulnerabilidades |
| production-ready (referido a patches) | patch validado para producción |
| zero retention / no logs / never stored / private by default | promesas de retención que la Skill no controla |
| deploy with confidence / secure your contract / eliminate vulnerabilities / audit your contract | eslóganes que prometen resultado |

## Restricted — nivel B: solo en negación o limitación (revisión manual)

Palabras necesarias para explicar lo que la Skill NO es. Se admiten únicamente en frases negativas o
limitativas y se revisan a mano en cada commit.

| Término | Uso admitido | Uso prohibido |
|---|---|---|
| audit | "This is NOT a formal security audit."; frases de activación en `SKILL.md` que reconocen la petición del usuario ("audit smart contract") | "audit report", "we audit your contract", "audit completed" |
| certification | "It is NOT a certification." | cualquier afirmación |
| guarantee | "not a guarantee that…", "No statement… creates a warranty, certification, guarantee" | "we guarantee", "guaranteed" |
| secure | "not a guarantee that the code is secure" | "your contract is secure", "make it secure" |
| private / confidential | "This does not control platform… retention"; nunca como promesa | "your code is private", "confidential processing", "no third-party processing", "we do not retain your data", "your code is never stored" |
| Security Score | solo para explicar que NO se usa ese nombre | como nombre del resultado (usar "Automated Risk Indicator") |

## Fórmulas obligatorias

- Ausencia de hallazgos: **"No findings matching the configured detection criteria were identified within the analyzed scope."** Nunca "No vulnerabilities found."
- Indicador de riesgo: **"This indicator reflects findings detected within the analyzed scope. It is not a measure of overall protocol security."** y, cuando la banda sea LOW: **"A LOW automated risk indicator does not mean that deployment is safe."**
- Patches: **"Suggested remediation only. Review, compile, test and validate independently before use."**
- Retención: **"The Skill deletes its local temporary working copy at the end of execution. This does not control platform, runtime, provider, billing, security or execution-log retention outside the Skill."**
- Procesamiento LLM: **"LLM processing via Capafy infrastructure."** Proveedor y modelo solo con `[CAPAFY-VERIFY]` hasta tener confirmación documental.
- Gas: nunca cifras exactas ("saves 17,392 gas") sin medición real; impacto cualitativo low / medium / high.
- Ausencia de score: **"Automated deterministic scoring was unavailable in this runtime."** con `scoreStatus: "not_computed"`.

## Ficha de Capafy

- Categoría sugerida: `Developer Tools / Security` (existencia pendiente `[CAPAFY-VERIFY]`). Nunca Crypto, Finance, professional auditor ni certification service.
- Máximo 5 tags; ninguno de la lista de nivel A.
- Tres propuestas de título sin "certified", "official", "audited" ni "auditoría profesional".
- La descripción deja claro: IA, automatización, alcance y limitaciones; `purpose` orientado al comprador; input requerido explícito.
- "Developer certification" en Capafy es el KYC del vendedor: no se menciona como aval del producto.

## Procedimiento de comprobación

Antes de cada commit, sobre `.claude/skills/` y `capafy/` (no sobre `docs/`, que define la lista):

```bash
grep -rniE "certified|certificaci[oó]n|audited|audit completed|complete audit|professional audit|official|safe to deploy|guaranteed|100% secure|vulnerability-free|no vulnerabilities|production-ready|zero retention|no logs|never stored|private by default|deploy with confidence|secure your contract|eliminate vulnerabilities|audit your contract" --exclude=guardrails.md --exclude=preprocess.py --exclude=render_report.py .claude/skills capafy
```

- Resultado esperado: sin coincidencias.
- `references/guardrails.md` se revisa a mano: los términos solo pueden aparecer dentro de su lista de prohibidos.
- `scripts/preprocess.py` también se excluye del grep automático y se revisa a mano: contiene, dentro de `INJECTION_PATTERNS` (detector de intentos de prompt injection multilingüe), los patrones que RECONOCEN frases como "this contract is safe/secure/audited/certified" en el CÓDIGO/COMENTARIOS APORTADOS POR EL USUARIO — es decir, usa esas palabras para detectarlas como manipulación en contenido ajeno, nunca para afirmarlas sobre la propia Skill. Ver D-020 en `docs/decisiones.md`. Cualquier otro uso de estos términos en `preprocess.py` (fuera de `INJECTION_PATTERNS` y sus tests) sigue siendo una violación.
- `scripts/render_report.py` también se excluye y se revisa a mano: contiene, dentro de `MANDATORY_NOTICE_LINES`, el disclaimer obligatorio §6.2 verbatim aportado por Diego, que usa "audit"/"certification"/"guarantee" en negación ("It is NOT... No statement... creates a warranty, certification, guarantee, or professional audit engagement"). Ver D-021. Ningún otro texto de `render_report.py` puede reproducir estos términos sin la misma justificación de negación explícita.
- Nivel B: `grep -rniwE "audit|certification|guarantee|secure|private|confidential" --exclude=preprocess.py --exclude=render_report.py .claude/skills capafy` y comprobar que cada coincidencia está en negación o limitación.
- Las plantillas de informe y los evals de 3.1 comprueban además que la salida generada no contiene términos de nivel A ("forbidden terms" en `evals/results/summary.md`).
