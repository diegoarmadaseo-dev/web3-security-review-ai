# Severity, Confidence, Deduplication and Scoring

This document defines the rules implemented by `scripts/score.py` and enforced by
`scripts/validate_report.py`. Both scripts read this file's tables as their single source of truth;
neither script contains a second, divergent copy of these numbers.

## 1. Severity and confidence

Severity: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`.
Confidence: `high`, `medium`, `low` - how much the available evidence supports the finding, not how
severe it would be if true.

`INFORMATIONAL` findings (for example a detected prompt-injection attempt, see
`references/checklist.md`) always carry `status: "informational"` and are excluded from scoring
entirely - not just weighted at zero, but skipped before the formula runs.

## 2. Finding identity and deduplication (before scoring)

Findings are only ever produced by the analysis step (`generatedBy: "ai"`); `score.py` never invents
one from a `preprocess.py` signal. But `score.py` never trusts an `id`/`stableKey` supplied by that
step either - it always recomputes both, so root-cause deduplication is a deterministic guarantee
rather than something that depends on the analysis step behaving consistently.

```
normalizedLocation = "file#contract#function" of the finding's PRIMARY location only
                      (its locations[0]; missing contract/function segments stay empty,
                      e.g. "A.sol##"; no locations at all normalizes to "")
stableKey           = sha256(category + "|" + normalizedLocation + "|" + signature)
id                  = "F-" + first 8 hex chars of the stableKey's digest
```

Identity is anchored on the *primary* location only, not the full `locations[]` set. A single draft
finding may already list several affected sites for one root cause directly in its own `locations[]`;
keying on the full set instead would make two draft findings for the same root cause fail to match the
moment their location lists were not byte-identical, defeating deduplication before it could do
anything. The analysis step is expected to put the most representative site first.

`signature` is a short, kebab-case slug authored by the analysis step to identify the root cause
(e.g. `unprotected-admin-function`). Two draft findings that share `category`, `signature` and the same
primary location collapse into one:

- **severity/confidence**: the highest of the group survives (severity by the CRITICAL > HIGH > MEDIUM
  > LOW > INFORMATIONAL order; confidence by high > medium > low).
- **locations**: every distinct location across the group is kept (a single root cause can affect
  several places - see `docs/decisiones.md`, original requirement in section 9).
- **evidence**: the union of evidence lines, de-duplicated, capped at 5.
- **description / recommendation / patch**: taken from the first occurrence in input order; later
  duplicates in the same group do not get a second voice.
- **mergedCount**: how many draft findings collapsed into this entry, kept for traceability.

A finding is never counted twice in the score just because two different signal families or two
slightly different descriptions pointed at the same underlying cause.

## 3. Deterministic score

Base score: `100`.

Penalty per finding (skipped entirely for `status: "informational"`):

```
penalty = severityPenalty[severity] * confidenceWeight[confidence]

severityPenalty:
  CRITICAL       25
  HIGH           15
  MEDIUM          7
  LOW             3
  INFORMATIONAL   0

confidenceWeight:
  high     1.0
  medium   0.7
  low      0.4
```

```
score = 100 - sum(penalty for every non-informational, post-deduplication finding)
score = max(score, 0)
if any surviving finding has severity == CRITICAL and confidence == "high":
    score = min(score, 40)
score = round(score) to the nearest integer
```

Score runs strictly **after** deduplication (section 2); the same root cause detected by three
overlapping signals is one penalty, not three.

## 4. Bands

```
85-100  LOW
60-84   MODERATE
40-59   HIGH
0-39    CRITICAL
```

Every rendered score is shown together with the fixed sentence **"according to the analyzed scope"**.
The result is named the **Automated Risk Indicator**, never "Security Score" alone, and is always
rendered with: *"This indicator reflects findings detected within the analyzed scope. It is not a
measure of overall protocol security."* A `LOW` band additionally carries: *"A LOW automated risk
indicator does not mean that deployment is safe."*

## 5. When no score is computed

`score.py` only ever produces `scoreStatus: "computed"` - if it can run at all, Python is available.
`scoreStatus: "not_computed"` is written directly by the Skill runtime when it cannot invoke `score.py`
in the first place (for example, no Python interpreter in that runtime), never by `score.py` itself.
In that case `riskIndicator.score` and `riskIndicator.band` are `null` and `riskIndicator.message`
carries the fixed sentence: *"Automated deterministic scoring was unavailable in this runtime."* The
qualitative analysis and `findings[]` can still be produced without a computed score; a missing score
must never be replaced by a number the model reasoned out on its own.

## 6. Category coverage vs. findings

`findings[]` holds only real, detected items. Coverage of the SC01-SC10 checklist - including the
cases where nothing was found, or where a category could not be assessed at all - lives separately in
`categoryCoverage[]` (see `report-schema.json`). This keeps deduplication and scoring simple (they only
ever look at real findings) and keeps the completeness story honest: a category with `NOT_ASSESSED`
never gets silently rendered the same way as one that was actually checked and came back clean.

## 7. Consistency the validator enforces

`validate_report.py` checks, in addition to shape and enums:

- Every category referenced by a non-informational finding has `categoryCoverage` status `DETECTED`.
- `scope.completeness` other than `complete` implies at least one `NOT_ASSESSED` category. Single
  exception, for the merged multi-pass report only: a `partial` report whose ten categories are all
  `DETECTED`, each backed by a non-informational finding, is accepted - the rule above forbids any
  `NOT_ASSESSED` there, and `scope` and `limitations` still state that the analysis is partial.
- Per-mode feature gating - which modes allow `patch`, `gasSuggestions`, an HTML report,
  `architectureNotes`, or `executiveSummary` - lives in `config/modes.json`, not here (rules R-06/R-09);
  this file only owns the score formula and deduplication rules above.
- `status: "informational"` implies `severity: "INFORMATIONAL"`.
- The top-level `scoreStatus` and `riskIndicator.scoreStatus` agree, and `riskIndicator.score`/`band`
  are present only when `scoreStatus` is `computed`.

None of this logic lives twice: `score.py` computes, `validate_report.py` checks, `render_report.py`
only lays out what already passed validation.
