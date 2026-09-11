# Registro de riesgos legales y de producto

> Este documento NO es asesoramiento jurídico ni contiene opiniones jurídicas definitivas. Recoge los
> riesgos identificados durante el desarrollo, su impacto, la mitigación técnica prevista, el estado y
> la duda legal pendiente. Toda entrada marcada `LEGAL REVIEW REQUIRED` debe revisarla un profesional
> antes de publicar la Skill. Punto de partida asumido: una limitación de responsabilidad escrita en la
> documentación NO equivale por sí sola a una exclusión de responsabilidad jurídicamente válida.
> Nada de este documento se publica.

Estados: `abierto` (sin mitigación aplicada) · `planificado` (mitigación asignada a una subfase) ·
`mitigado-técnicamente` (implementada y probada; la duda legal puede seguir abierta).

Principios de mitigación transversales: wording preciso, alcance explícito, trazabilidad de versiones,
limitaciones visibles, transparencia sobre la IA, pruebas (tests y evals), ausencia de claims engañosos
y separación estricta entre el análisis técnico y cualquier condición comercial.

## RISK-001 · Product/software liability
- **Descripción:** la Skill entrega un análisis automatizado que puede ser incorrecto o incompleto; un usuario podría reclamar daños (p. ej. pérdida de fondos) por haber confiado en él.
- **Impacto:** alto. Los smart contracts custodian valor y los errores on-chain suelen ser irreversibles.
- **Mitigación técnica:** aviso previo antes de analizar; sección "Important Security Review Notice" en todo informe; posicionamiento "review", nunca "audit"; `scope.completeness`; `confidence` por hallazgo; el informe nunca recomienda desplegar; trazabilidad (`skillVersion`, `checklistVersion`, `scoreVersion`, `inputHash`).
- **Estado:** planificado (1.2 informe, 2.1 runtime).
- **Duda legal pendiente:** alcance real de cualquier limitación de responsabilidad según la jurisdicción del comprador y el papel de Capafy como intermediario. `LEGAL REVIEW REQUIRED`.

## RISK-002 · False negative security findings
- **Descripción:** una vulnerabilidad real no se detecta y el usuario interpreta la ausencia de hallazgos como ausencia de riesgo.
- **Impacto:** alto (despliegue de código vulnerable).
- **Mitigación técnica:** distinguir `NOT_DETECTED` de `NOT_ASSESSED`; frase obligatoria "the absence of a reported finding does NOT mean that no vulnerability exists"; fórmula fija para ausencia de hallazgos (`docs/commercial-claims.md`); objetivo de evals de detección ≥ 8/10 en SC01–SC10; sección de limitaciones y fuera de alcance.
- **Estado:** planificado (1.1, 1.2, 3.1).
- **Duda legal pendiente:** si el aviso de posibles falsos negativos basta como información precontractual al comprador. `LEGAL REVIEW REQUIRED`.

## RISK-003 · False positive findings
- **Descripción:** se reporta como vulnerabilidad algo que no lo es; el usuario aplica cambios innecesarios, retrasa un despliegue o pierde confianza en la herramienta.
- **Impacto:** medio (coste y posibles regresiones al "corregir" código correcto).
- **Mitigación técnica:** `confidence` (high/medium/low) con evidencia ≤ 5 líneas; señales heurísticas nunca elevadas automáticamente a HIGH/CRITICAL; SC02–SC04 exigen contexto; objetivo de evals ≤ 1 falso positivo HIGH/CRITICAL en contratos limpios; caso de eval de posible falso positivo.
- **Estado:** planificado (1.1, 3.1).
- **Duda legal pendiente:** ninguna específica más allá de RISK-001.

## RISK-004 · User reliance on risk indicator
- **Descripción:** el usuario trata el número como una puntuación global de seguridad del protocolo o como aval para desplegar.
- **Impacto:** alto.
- **Mitigación técnica:** nombre "Automated Risk Indicator" (nunca "Security Score" a secas); explicación fija "This indicator reflects findings detected within the analyzed scope. It is not a measure of overall protocol security."; bandas siempre "according to the analyzed scope"; frase "A LOW automated risk indicator does not mean that deployment is safe."; score determinista solo en `score.py`, tope 40 con CRITICAL de confianza alta, `scoreStatus: "not_computed"` sin Python.
- **Estado:** planificado (1.2).
- **Duda legal pendiente:** si un indicador numérico puede interpretarse como declaración de conformidad; wording a validar. `LEGAL REVIEW REQUIRED`.

## RISK-005 · Patch-induced regression
- **Descripción:** un patch/diff sugerido altera lógica de negocio, introduce un error o no compila, y el usuario lo aplica sin validar.
- **Impacto:** alto (modos `standard` y `pro`).
- **Mitigación técnica:** patches solo como "suggested remediation patches" con la frase obligatoria "Suggested remediation only. Review, compile, test and validate independently before use."; unified diff limitado a la corrección; sin dependencias ni interfaces inventadas; caso de eval donde un patch ingenuo cambia la lógica; nunca describirlos como production-ready, guaranteed o validated.
- **Estado:** planificado (1.2, 3.1).
- **Duda legal pendiente:** responsabilidad por código sugerido que el usuario incorpora voluntariamente. `LEGAL REVIEW REQUIRED`.

## RISK-006 · Data retention
- **Descripción:** el código del usuario persiste en logs, historial de instancia o almacenamiento de la plataforma aunque la Skill borre sus temporales; el usuario podría esperar confidencialidad o borrado total.
- **Impacto:** medio-alto (código no publicado, información confidencial).
- **Mitigación técnica:** distinguir "temporary runtime files" (bajo control de la Skill, se borran al terminar) de "platform/provider retention" (fuera de su control); fórmula fija de retención (`docs/commercial-claims.md`); nunca afirmar zero retention, no logs, private by default o never stored; no volcar código en logs ni metadatos; `capafy/data-declaration.md` con `[CAPAFY-VERIFY]` y huecos `[DIEGO]`.
- **Estado:** planificado (2.1, 3.2).
- **Duda legal pendiente:** obligaciones de información sobre el tratamiento de datos y reparto de roles entre publisher y Capafy; el repo público confirma que el historial de instancia persiste, pero no el plazo de 90 días. `LEGAL REVIEW REQUIRED`.

## RISK-007 · Third-party LLM processing
- **Descripción:** el código se procesa por un modelo LLM a través de la infraestructura de Capafy; el proveedor, el modelo y sus condiciones de retención no están verificados documentalmente.
- **Impacto:** medio-alto.
- **Mitigación técnica:** declarar únicamente "LLM processing via Capafy infrastructure"; proveedor/modelo marcados `[CAPAFY-VERIFY]`; ningún claim de confidential processing o no third-party processing; los scripts nunca llaman a un LLM.
- **Estado:** abierto hasta verificar (3.2).
- **Duda legal pendiente:** condiciones contractuales del proveedor y posibles transferencias internacionales de datos. `LEGAL REVIEW REQUIRED`.

## RISK-008 · Copyright/licensing
- **Descripción:** uso de la taxonomía OWASP Smart Contract Top 10:2026, de contratos de terceros en evals o de plantillas de informe protegidas.
- **Impacto:** medio (retirada del producto, reclamación del titular).
- **Mitigación técnica:** OWASP solo como taxonomía/referencia y contenido interno redactado con palabras propias (D-011); casos de eval creados desde cero; `evals/SOURCES.md` con origen, licencia, URL, fecha de acceso y permiso de uso comercial de cualquier material externo.
- **Estado:** planificado (1.1, 3.1).
- **Duda legal pendiente:** términos de licencia de OWASP para citar el nombre de la taxonomía en la ficha comercial. `LEGAL REVIEW REQUIRED`.

## RISK-009 · Misleading commercial claims
- **Descripción:** la ficha o el marketing sugieren auditoría, certificación, garantía o seguridad total; posible publicidad engañosa o práctica comercial desleal.
- **Impacto:** alto (sanciones, retirada de la ficha, reclamaciones).
- **Mitigación técnica:** `docs/commercial-claims.md` como lista de control; grep de términos prohibidos antes de cada commit; tres propuestas de título sin términos prohibidos; categoría "Developer Tools / Security" y no Crypto/Finance; descripción que deja claro IA, automatización, alcance y limitaciones.
- **Estado:** planificado (3.2).
- **Duda legal pendiente:** normativa de publicidad y consumo aplicable a los mercados donde Capafy vende. `LEGAL REVIEW REQUIRED`.

## RISK-010 · Consumer contract limitations
- **Descripción:** una limitación de responsabilidad puede ser inaplicable frente a consumidores o exceder lo que permite la ley; además, la venta se rige por los ToS de Capafy y no está verificado que el publisher pueda añadir condiciones propias.
- **Impacto:** alto.
- **Mitigación técnica:** la cláusula del Anexo A se trata solo como "PROPOSED COMMERCIAL TERMS LANGUAGE — LEGAL REVIEW REQUIRED"; no se incluye en la Skill ni en los informes como mecanismo automático; conserva la salvedad de derechos que no pueden excluirse; separación entre aviso técnico y términos comerciales (D-012).
- **Estado:** abierto.
- **Duda legal pendiente:** validez y forma de incorporación de condiciones del publisher en Capafy (`[CAPAFY-VERIFY]`, Q-007). `LEGAL REVIEW REQUIRED`.

## RISK-011 · AI transparency
- **Descripción:** obligaciones de informar de que el contenido está generado por IA y de sus limitaciones.
- **Impacto:** medio.
- **Mitigación técnica:** `generatedBy: "ai"` en todo informe; aviso previo al análisis; "automated, AI-assisted" en informes, ficha y descripción; metadatos de versión que identifican el motor y el checklist.
- **Estado:** planificado (1.2, 2.1, 3.2).
- **Duda legal pendiente:** qué obligaciones concretas de transparencia aplican al producto y a los mercados de venta. `LEGAL REVIEW REQUIRED`.

## RISK-012 · Dependency/context incompleteness
- **Descripción:** faltan imports, dependencias, interfaces o contexto del protocolo, y el análisis extrae conclusiones sobre componentes que no ha visto.
- **Impacto:** medio-alto.
- **Mitigación técnica:** `preprocess.py` inventaría imports no aportados; `scope.completeness` (`complete`/`partial`/`unknown`); `NOT_ASSESSED` con la frase "This component was not fully assessed because the referenced dependency source was not provided."; lista de fuera de alcance; el modo `pro` pide descripción del protocolo y dependencias externas; casos de eval de contexto incompleto y dependencia no aportada.
- **Estado:** planificado (1.1, 1.2, 3.1).
- **Duda legal pendiente:** ninguna específica más allá de RISK-001/002.

## RISK-013 · Compiler/version assumptions
- **Descripción:** los hallazgos dependen de la versión del compilador (p. ej. comprobaciones de overflow en 0.8.x); una suposición errónea produce falsos positivos o negativos y sugerencias de gas incompatibles.
- **Impacto:** medio.
- **Mitigación técnica:** detección de `pragma`; pedir la versión si no se deduce; `compilerVersion` en el informe; señales de pragma flotante y compilador obsoleto; comprobación de compatibilidad de cada sugerencia de gas con la versión; cobertura limitada declarada para versiones antiguas y Vyper.
- **Estado:** planificado (1.1, 2.1).
- **Duda legal pendiente:** ninguna específica.

## RISK-014 · Protocol/economic risk outside code
- **Descripción:** manipulación de oráculos, flash loans, gobernanza, MEV, tokenomics o infraestructura requieren contexto que el código no contiene; el informe podría leerse como si los cubriera.
- **Impacto:** alto.
- **Mitigación técnica:** SC02–SC04 con `confidence` acorde a la evidencia y nunca elevados automáticamente; sección explícita de fuera de alcance (off-chain, despliegue, claves, infraestructura, tokenomics, gobernanza externa, oráculos, estado desplegado, bridges, terceros); el indicador de riesgo se define como separado de la seguridad global del protocolo.
- **Estado:** planificado (1.2, 2.1, 2.2).
- **Duda legal pendiente:** ninguna específica más allá de RISK-004.

## Anexo A · PROPOSED COMMERCIAL TERMS LANGUAGE — LEGAL REVIEW REQUIRED

Borrador aportado por Diego para unas eventuales condiciones comerciales. Reglas de uso: (1) no forma
parte de la Skill ni de sus informes; (2) no se presenta nunca como protección jurídica, eliminación de
responsabilidad, garantía de cumplimiento ni cláusula "enforceable"; (3) su incorporación en Capafy
depende de Q-007; (4) requiere revisión profesional antes de cualquier uso.

```text
IMPORTANT – PLEASE READ

This Agent produces an automated, AI-generated preliminary security review. It is not a professional
smart contract audit, a certification, or a guarantee that the code is free of vulnerabilities.
Findings may be incomplete or incorrect.

You must independently review and test your code, and obtain a manual audit before deploying any
contract that holds or manages value. Deployment, configuration and use of any smart contract are
solely your decision and responsibility.

Nothing in this output is financial, investment or legal advice.

To the maximum extent permitted by applicable law, the publisher's total liability is limited to the
amount you paid for the access period in which the claim arose, and the publisher is not liable for
indirect or consequential losses, including lost funds, tokens, profits or data.

Nothing in these terms limits any liability that cannot be limited under applicable law, including
liability for fraud, gross negligence or mandatory consumer rights.
```
