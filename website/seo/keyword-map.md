# Keyword map - Vericexa website

Maps each target keyword to the page(s) that own it, the search intent, and
where it is actually implemented in `website/content.py` / `build_site.py`.
No keyword is placed on a page unless real content already supports it -
this map follows the copy, it does not justify padding a page to fit a term.

| Keyword | Intent | Primary page | Implemented as |
|---|---|---|---|
| automated smart contract security review | Navigational/branded | `index.html` | `<title>`, H1 area (`POSITIONING_TAGLINE`), meta description |
| smart contract security | Broad/informational | `index.html`, `methodology.html` | Meta description, "What Vericexa reviews" section, category table |
| smart contract security audit tools | Comparison/category | `features.html` | Page title/meta; "Available"/"Partial" framing answers "what tool does X" intent honestly |
| automated vulnerability scanners for Web3 | Comparison/category | `features.html`, `index.html` | Differentiators section (own-scanner-vs-basic-scanner framing) |
| Solidity security analyzer | Product-category | `index.html`, `methodology.html` | Meta description ("Solidity and Vyper"), pipeline steps |
| Solidity code scanner | Product-category | `methodology.html` | SC01-SC10 category table, pipeline "Deterministic detectors" step |
| blockchain security platforms | Broad/category | `index.html` | `PAGE_TITLES["index.html"]` ("Security Review Platform"), Organization/SoftwareApplication JSON-LD |
| smart contract security scanner | Product-category | `features.html` | "Pre-Deployment Review" card |
| pre-deployment smart contract security | Intent-specific | `features.html`, `index.html` | "Pre-Deployment Review" feature (AVAILABLE), home "What Vericexa reviews" |
| smart contract security diff | Intent-specific, low competition | `features.html`, `developers.html` | "Security Diff" feature card; `diff`/`monitor` CLI reference entries |
| deployed contract source verification | Intent-specific, low competition | `features.html` | "Deployed-Source Verification" feature card (`ingest_onchain.py`) |
| smart contract upgrade security | Intent-specific | `features.html` | "Upgrade Review" feature card - explicitly marked Partial, scope stated |
| multi-contract security analysis | Intent-specific | `features.html` | "Multi-Contract Review" feature card - explicitly marked Partial (Pro-tier system graph) |
| Solidity CI security | Intent-specific, developer | `developers.html`, `features.html` | "CI Security Gate" card; live `pr-gate`/`analyze-pipeline` CLI reference |
| Web3 CI security | Intent-specific, developer | `developers.html` | Developers page intro + full CLI/CI reference (all 10 commands, live `--help`) |
| smart contract monitoring | Broad/category, competitive (Tenderly, OpenZeppelin Monitor) | `features.html`, `faq.html` | "Monitoring" feature card - explicitly marked Partial: CLI-only, self-run, no hosted alerts. FAQ answer repeats the same limitation so the page never ranks on a claim it can't back. |

## Deliberately not targeted

- Any keyword implying a finished, paid audit ("smart contract audit
  service", "get your contract certified") - would require claims
  `docs/commercial-claims.md` Level-A forbids (`certified`, `audited`,
  `professional audit`). `disclaimer.html` and `NOT_AN_AUDIT_NOTE` exist
  precisely to keep the site out of that intent.
- Any keyword implying hosted/real-time monitoring ("24/7 smart contract
  monitoring", "smart contract alerts") - `monitor_diff.py` has no alerting
  mechanism; see `content.FEATURES_PARTIAL["Monitoring"]`.
- Competitor brand names (Slither, Mythril, CertiK, Tenderly, etc.) - not
  used as comparison keywords anywhere in on-page copy; see
  `seo-research.md`.

## Page → primary keyword summary

| Page | Primary keyword(s) |
|---|---|
| `index.html` | automated smart contract security review, blockchain security platforms |
| `features.html` | smart contract security audit tools, smart contract security scanner, pre-deployment smart contract security, smart contract security diff, deployed contract source verification, smart contract upgrade security, multi-contract security analysis, smart contract monitoring |
| `demo.html` | (supports `features.html` intent with a concrete example; not keyword-primary) |
| `methodology.html` | smart contract security, Solidity security analyzer, Solidity code scanner |
| `developers.html` | Solidity CI security, Web3 CI security |
| `pricing.html` | (transactional; no informational keyword target) |
| `faq.html` | long-tail questions matching the FAQPage JSON-LD content verbatim |
