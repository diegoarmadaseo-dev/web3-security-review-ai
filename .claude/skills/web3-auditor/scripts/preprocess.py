#!/usr/bin/env python3
"""Deterministic preprocessing for smart contract source files.

Reads Solidity / Vyper sources (files, directories or a stdin bundle), masks
comments and string literals while preserving line numbers, inventories the
code structure and emits heuristic *signals* as JSON.

Signals are hints for a later analysis step. They are never findings, they
carry no severity and they never decide anything by themselves. Everything
in the input is treated as data: comments, strings and documentation are
inventoried for context but cannot create, hide or alter a signal.

Standard library only. No network access, no LLM calls. Python 3.8+.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

PREPROCESS_VERSION = "1.0.0"
SIGNAL_REGISTRY_VERSION = "2026.1"
CHECKLIST_VERSION = "2026.1"
GENERATED_BY = "preprocess.py"

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2

# Provisional limits. config/modes.json (subphase 2.2) becomes the source of
# truth; until then these values mirror the roadmap and can be overridden with
# --max-loc.
PROVISIONAL_LIMITS: Dict[str, Dict[str, Optional[int]]] = {
    "quick": {"maxEffectiveLoc": 500, "maxSourceFiles": 1},
    "standard": {"maxEffectiveLoc": 1500, "maxSourceFiles": None},
    "pro": {"maxEffectiveLoc": 4000, "maxSourceFiles": None},
}
DEFAULT_MODE = "standard"

SOURCE_EXTENSIONS = {".sol": "solidity", ".vy": "vyper"}
DOCUMENT_EXTENSIONS = {".md", ".markdown", ".txt", ".rst"}
DOCUMENT_BASENAMES = {"readme", "license", "notice", "changelog"}

MAX_SNIPPET_CHARS = 160
MAX_COMMENT_CHARS = 600
MAX_DOCUMENT_CHARS = 20000

CATEGORIES: Dict[str, str] = {
    "SC01": "Access Control",
    "SC02": "Business Logic",
    "SC03": "Price Oracle Manipulation",
    "SC04": "Flash Loan-Facilitated Attacks",
    "SC05": "Lack of Input Validation",
    "SC06": "Unchecked External Calls",
    "SC07": "Arithmetic Errors (rounding and precision)",
    "SC08": "Reentrancy",
    "SC09": "Integer Overflow/Underflow",
    "SC10": "Proxy and Upgradeability",
    "EXTRA-tx-origin": "tx.origin usage",
    "EXTRA-delegatecall": "Unsafe delegatecall",
    "EXTRA-selfdestruct": "selfdestruct",
    "EXTRA-weak-randomness": "Weak randomness / timestamp dependence",
    "EXTRA-dos-gas": "Denial of service / gas griefing",
    "EXTRA-replay-permit": "Replay attacks / signatures / permit",
    "EXTRA-front-running-mev": "Front-running / MEV",
    "EXTRA-floating-pragma": "Floating or missing pragma",
    "EXTRA-obsolete-compiler": "Obsolete compiler",
    "EXTRA-assembly": "Inline assembly",
    "EXTRA-ownership": "Ownership handling",
    "EXTRA-config": "Hardcoded configuration",
    "EXTRA-prompt-injection": "Prompt injection attempt (informational, zero weight)",
}

# Signal registry: family -> metadata. needsContext=False marks the only
# families that are purely deterministic facts; every other family is a hint
# that requires semantic review. fpRisk is the expected false-positive risk of
# treating the raw signal as a finding without that review.
SIGNAL_FAMILIES: Dict[str, Dict[str, Any]] = {
    "tx-origin": {"categories": ["SC01", "EXTRA-tx-origin"], "needsContext": True, "fpRisk": "medium"},
    "delegatecall": {"categories": ["SC10", "EXTRA-delegatecall"], "needsContext": True, "fpRisk": "medium"},
    "selfdestruct": {"categories": ["SC01", "EXTRA-selfdestruct"], "needsContext": True, "fpRisk": "medium"},
    "low-level-call": {"categories": ["SC06", "SC08"], "needsContext": True, "fpRisk": "medium"},
    "token-transfer-unchecked": {"categories": ["SC06"], "needsContext": True, "fpRisk": "high"},
    "external-call": {"categories": ["SC06", "SC08"], "needsContext": True, "fpRisk": "high"},
    "reentrancy-pattern": {"categories": ["SC08"], "needsContext": True, "fpRisk": "high"},
    "unchecked-block": {"categories": ["SC09"], "needsContext": True, "fpRisk": "high"},
    "assembly-block": {"categories": ["EXTRA-assembly", "SC06", "SC10"], "needsContext": True, "fpRisk": "high"},
    "timestamp-dependence": {"categories": ["EXTRA-weak-randomness", "SC02"], "needsContext": True, "fpRisk": "high"},
    "weak-randomness": {"categories": ["EXTRA-weak-randomness"], "needsContext": True, "fpRisk": "medium"},
    "unbounded-loop": {"categories": ["EXTRA-dos-gas"], "needsContext": True, "fpRisk": "high"},
    "msg-value-in-loop": {"categories": ["SC02", "EXTRA-dos-gas"], "needsContext": True, "fpRisk": "medium"},
    "initializer-unprotected": {"categories": ["SC10", "SC01"], "needsContext": True, "fpRisk": "medium"},
    "zero-address-unchecked": {"categories": ["SC05"], "needsContext": True, "fpRisk": "high"},
    "floating-pragma": {"categories": ["EXTRA-floating-pragma"], "needsContext": False, "fpRisk": "low"},
    "pragma-missing": {"categories": ["EXTRA-floating-pragma"], "needsContext": False, "fpRisk": "low"},
    "obsolete-compiler": {"categories": ["EXTRA-obsolete-compiler", "SC09"], "needsContext": False, "fpRisk": "low"},
    "legacy-arithmetic": {"categories": ["SC09"], "needsContext": True, "fpRisk": "medium"},
    "proxy-pattern": {"categories": ["SC10"], "needsContext": True, "fpRisk": "low"},
    "upgrade-function": {"categories": ["SC10", "SC01"], "needsContext": True, "fpRisk": "medium"},
    "admin-function-unprotected": {"categories": ["SC01"], "needsContext": True, "fpRisk": "high"},
    "single-step-ownership-transfer": {"categories": ["SC01", "EXTRA-ownership"], "needsContext": True, "fpRisk": "medium"},
    "arbitrary-from-transfer": {"categories": ["SC01", "SC02"], "needsContext": True, "fpRisk": "high"},
    "arbitrary-external-call": {"categories": ["SC06", "SC01"], "needsContext": True, "fpRisk": "medium"},
    "unlimited-approval": {"categories": ["SC02", "SC01"], "needsContext": True, "fpRisk": "high"},
    "signature-replay-surface": {"categories": ["EXTRA-replay-permit"], "needsContext": True, "fpRisk": "medium"},
    "slippage-unprotected": {"categories": ["EXTRA-front-running-mev", "SC03"], "needsContext": True, "fpRisk": "high"},
    "oracle-usage": {"categories": ["SC03", "SC04"], "needsContext": True, "fpRisk": "high"},
    "flash-loan-surface": {"categories": ["SC04"], "needsContext": True, "fpRisk": "high"},
    "division-before-multiplication": {"categories": ["SC07"], "needsContext": True, "fpRisk": "high"},
    "hardcoded-address": {"categories": ["SC05", "EXTRA-config"], "needsContext": True, "fpRisk": "high"},
}

COMPLETENESS_REASON_CODES = (
    "MISSING_IMPORT",
    "UNRESOLVED_BASE",
    "UNDEFINED_INTERFACE",
    "TRUNCATED_FILE",
    "UNTERMINATED_COMMENT",
    "EMPTY_FILE",
    "ENCODING_ERROR",
    "UNSUPPORTED_LANGUAGE",
    "VYPER_LIMITED",
    "LOC_LIMIT_EXCEEDED",
    "FILE_LIMIT_EXCEEDED",
    "LOW_PARSE_CONFIDENCE",
    "NO_ANALYZABLE_SOURCE",
)


class PreprocessError(Exception):
    """Raised for usage errors (bad paths, no input)."""


# ---------------------------------------------------------------------------
# Text utilities
# ---------------------------------------------------------------------------

def normalize_text(data: bytes) -> Tuple[Optional[str], str, Optional[str]]:
    """Decode bytes as UTF-8 and normalise line endings to LF.

    Returns (text, lineEndings, error). text is None on decoding failure.
    """
    raw = data
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        return None, "unknown", "invalid UTF-8 at byte %d" % exc.start
    crlf = text.count("\r\n")
    lone_cr = text.count("\r") - crlf
    lf = text.count("\n") - crlf
    if crlf and (lf or lone_cr):
        endings = "mixed"
    elif crlf:
        endings = "crlf"
    elif lone_cr:
        endings = "cr"
    else:
        endings = "lf"
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text, endings, None


def sha256_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def normalize_path(path: str) -> str:
    cleaned = path.strip().replace("\\", "/")
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    parts = [part for part in cleaned.split("/") if part not in ("", ".")]
    return "/".join(parts)


def collapse_ws(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def truncate(text: str, limit: int) -> Tuple[str, bool]:
    if len(text) <= limit:
        return text, False
    return text[: limit - 1] + "…", True


class LineIndex:
    """Maps character offsets to 1-based line numbers and 0-based columns."""

    def __init__(self, text: str) -> None:
        self.starts: List[int] = [0]
        for idx, char in enumerate(text):
            if char == "\n":
                self.starts.append(idx + 1)
        self.lines = text.split("\n")

    def line_of(self, offset: int) -> int:
        lo, hi = 0, len(self.starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self.starts[mid] <= offset:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    def col_of(self, offset: int) -> int:
        return offset - self.starts[self.line_of(offset) - 1]

    def line_text(self, line: int) -> str:
        if 1 <= line <= len(self.lines):
            return self.lines[line - 1]
        return ""

    def offset_of_line(self, line: int) -> int:
        return self.starts[line - 1]

    @property
    def count(self) -> int:
        return len(self.lines)


# ---------------------------------------------------------------------------
# Input bundle parsing
# ---------------------------------------------------------------------------

BUNDLE_START_RE = re.compile(r"^=== FILE: (.+?) ===\s*$")
BUNDLE_END_RE = re.compile(r"^=== END FILE ===\s*$")


def looks_like_bundle(text: str) -> bool:
    for line in text.split("\n"):
        if line.strip():
            return BUNDLE_START_RE.match(line.rstrip()) is not None
    return False


def parse_bundle(text: str, origin: str) -> List[Dict[str, Any]]:
    """Split a multi-file bundle into entries.

    Entry keys: path, text, issues (list of strings).
    """
    entries: List[Dict[str, Any]] = []
    current_path: Optional[str] = None
    buffer: List[str] = []
    seen: Dict[str, int] = {}
    for line in text.split("\n"):
        start = BUNDLE_START_RE.match(line.rstrip())
        if start and current_path is None:
            current_path = normalize_path(start.group(1)) or "unnamed"
            buffer = []
            continue
        if start and current_path is not None:
            # A new file starts before the previous END marker: close the
            # previous entry and record the problem.
            entries.append({"path": current_path, "text": "\n".join(buffer), "issues": ["missing END FILE marker"]})
            current_path = normalize_path(start.group(1)) or "unnamed"
            buffer = []
            continue
        if BUNDLE_END_RE.match(line.rstrip()) and current_path is not None:
            entries.append({"path": current_path, "text": "\n".join(buffer), "issues": []})
            current_path = None
            buffer = []
            continue
        if current_path is not None:
            buffer.append(line)
    if current_path is not None:
        entries.append({"path": current_path, "text": "\n".join(buffer), "issues": ["missing END FILE marker"]})
    for entry in entries:
        count = seen.get(entry["path"], 0)
        if count:
            entry["path"] = "%s#%d" % (entry["path"], count + 1)
        seen[entry["path"].split("#")[0]] = count + 1
        entry["origin"] = origin
    return entries


# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------

SOLIDITY_HINT_RE = re.compile(r"pragma\s+solidity|\b(contract|interface|library)\s+\w+[^;]*\{")
VYPER_HINT_RE = re.compile(r"^\s*#\s*@version|^\s*#\s*pragma\s+version|^\s*@(external|internal|view|pure|payable|deploy)\b|^\s*def\s+\w+\s*\(", re.M)


def detect_language(path: str, text: Optional[str]) -> str:
    """Return solidity | vyper | documentation | unknown."""
    lowered = path.lower()
    _, ext = os.path.splitext(lowered)
    if ext in SOURCE_EXTENSIONS:
        return SOURCE_EXTENSIONS[ext]
    base = os.path.basename(lowered)
    stem = base.split(".")[0]
    if ext in DOCUMENT_EXTENSIONS or stem in DOCUMENT_BASENAMES:
        return "documentation"
    if text is None:
        return "unknown"
    if SOLIDITY_HINT_RE.search(text):
        return "solidity"
    if VYPER_HINT_RE.search(text):
        return "vyper"
    return "unknown"


# ---------------------------------------------------------------------------
# Masking: comments and string literals become spaces, newlines are kept, so
# every offset in the masked text maps to the same line/column as the source.
# ---------------------------------------------------------------------------

def _blank(chars: List[str], start: int, end: int) -> None:
    for idx in range(start, end):
        if chars[idx] != "\n":
            chars[idx] = " "


def mask_solidity(text: str) -> Dict[str, Any]:
    chars = list(text)
    comments: List[Dict[str, Any]] = []
    strings: List[Dict[str, Any]] = []
    issues: List[str] = []
    n = len(text)
    i = 0
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            end = text.find("\n", i)
            if end == -1:
                end = n
            kind = "natspec" if text.startswith("///", i) and not text.startswith("////", i) else "line"
            comments.append({"start": i, "end": end, "kind": kind, "text": text[i:end]})
            _blank(chars, i, end)
            i = end
            continue
        if c == "/" and nxt == "*":
            close = text.find("*/", i + 2)
            if close == -1:
                issues.append("unterminated block comment")
                end = n
            else:
                end = close + 2
            kind = "natspec" if text.startswith("/**", i) and not text.startswith("/**/", i) else "block"
            comments.append({"start": i, "end": end, "kind": kind, "text": text[i:end]})
            _blank(chars, i, end)
            i = end
            continue
        if c == '"' or c == "'":
            quote = c
            j = i + 1
            terminated = False
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == quote:
                    terminated = True
                    break
                if text[j] == "\n":
                    break
                j += 1
            if j > n:
                j = n
            if not terminated:
                issues.append("unterminated string literal")
            strings.append({"start": i, "end": j, "text": text[i + 1:j]})
            _blank(chars, i + 1, j)
            i = j + 1 if terminated else j
            continue
        i += 1
    return {"masked": "".join(chars), "comments": comments, "strings": strings, "issues": issues}


def mask_vyper(text: str) -> Dict[str, Any]:
    chars = list(text)
    comments: List[Dict[str, Any]] = []
    strings: List[Dict[str, Any]] = []
    issues: List[str] = []
    n = len(text)
    i = 0
    while i < n:
        c = text[i]
        if c == "#":
            end = text.find("\n", i)
            if end == -1:
                end = n
            comments.append({"start": i, "end": end, "kind": "line", "text": text[i:end]})
            _blank(chars, i, end)
            i = end
            continue
        if text.startswith('"""', i) or text.startswith("'''", i):
            quote = text[i:i + 3]
            close = text.find(quote, i + 3)
            if close == -1:
                issues.append("unterminated docstring")
                end = n
            else:
                end = close + 3
            comments.append({"start": i, "end": end, "kind": "docstring", "text": text[i:end]})
            _blank(chars, i, end)
            i = end
            continue
        if c == '"' or c == "'":
            quote = c
            j = i + 1
            terminated = False
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == quote:
                    terminated = True
                    break
                if text[j] == "\n":
                    break
                j += 1
            if j > n:
                j = n
            if not terminated:
                issues.append("unterminated string literal")
            strings.append({"start": i, "end": j, "text": text[i + 1:j]})
            _blank(chars, i + 1, j)
            i = j + 1 if terminated else j
            continue
        i += 1
    return {"masked": "".join(chars), "comments": comments, "strings": strings, "issues": issues}


def line_metrics(text: str, masked: str) -> Dict[str, int]:
    total = text.count("\n") + 1 if text else 0
    if text.endswith("\n"):
        total -= 1
    blank = 0
    effective = 0
    comment_only = 0
    source_lines = text.split("\n")
    masked_lines = masked.split("\n")
    if text.endswith("\n"):
        source_lines = source_lines[:-1]
        masked_lines = masked_lines[:-1]
    for src, msk in zip(source_lines, masked_lines):
        if not src.strip():
            blank += 1
        elif msk.strip():
            effective += 1
        else:
            comment_only += 1
    return {"total": total, "effective": effective, "blank": blank, "commentOnly": comment_only}


# ---------------------------------------------------------------------------
# Secrets: detection and redaction. Values are never echoed.
# ---------------------------------------------------------------------------

KNOWN_PUBLIC_SLOTS = {
    "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",  # EIP-1967 implementation
    "b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103",  # EIP-1967 admin
    "a3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50",  # EIP-1967 beacon
    "c5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7",  # EIP-1822 proxiable
}
HEX64_RE = re.compile(r"(?<![0-9a-zA-Z])(?:0x)?([0-9a-fA-F]{64})(?![0-9a-zA-Z])")
API_KEY_RE = re.compile(r"\b(sk-ant-[A-Za-z0-9_\-]{10,}|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9\-]{10,})")
PEM_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)")
SECRET_CONTEXT_RE = re.compile(r"private\s*key|privkey|secret|mnemonic|seed\s*phrase|frase\s*semilla|password|passphrase|api[_\s-]?key", re.I)
MNEMONIC_QUOTED_RE = re.compile(r"[\"']((?:[a-z]{3,8}\s+){11,23}[a-z]{3,8})[\"']")


def find_secrets(text: str, context: str) -> List[Dict[str, Any]]:
    """Return secret matches as dicts with start, end, kind. context is
    'code', 'comment', 'string' or 'document'."""
    found: List[Dict[str, Any]] = []
    for match in API_KEY_RE.finditer(text):
        found.append({"start": match.start(), "end": match.end(), "kind": "api-key-like"})
    for match in PEM_RE.finditer(text):
        found.append({"start": match.start(), "end": match.end(), "kind": "pem-private-key"})
    for match in HEX64_RE.finditer(text):
        if match.group(1).lower() in KNOWN_PUBLIC_SLOTS:
            continue
        if context == "code":
            line_start = text.rfind("\n", 0, match.start()) + 1
            line_end = text.find("\n", match.end())
            if line_end == -1:
                line_end = len(text)
            if not SECRET_CONTEXT_RE.search(text[line_start:line_end]):
                continue
        found.append({"start": match.start(), "end": match.end(), "kind": "hex64-possible-private-key"})
    if SECRET_CONTEXT_RE.search(text):
        for match in MNEMONIC_QUOTED_RE.finditer(text):
            found.append({"start": match.start(1), "end": match.end(1), "kind": "mnemonic-suspect"})
    found.sort(key=lambda item: (item["start"], item["end"]))
    return found


def redact(text: str, context: str = "document") -> str:
    """Replace secret-looking values with placeholders."""
    matches = find_secrets(text, context)
    if not matches:
        return text
    out: List[str] = []
    cursor = 0
    for item in matches:
        if item["start"] < cursor:
            continue
        out.append(text[cursor:item["start"]])
        out.append("[REDACTED-%s]" % item["kind"])
        cursor = item["end"]
    out.append(text[cursor:])
    return "".join(out)


# ---------------------------------------------------------------------------
# Prompt injection patterns (multilingual). Matches are informational only.
# ---------------------------------------------------------------------------

INJECTION_PATTERNS: List[Tuple[str, str, "re.Pattern[str]"]] = [
    ("en", "ignore-instructions", re.compile(r"\b(ignore|disregard|forget)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all)\b[^.\n]{0,20}\b(instructions?|prompts?|rules?|guidelines?)\b", re.I)),
    ("en", "role-override", re.compile(r"\b(you are now|from now on you are|act as (?:a|an|if)|pretend (?:to be|you are)|new system prompt|system prompt:)\b", re.I)),
    ("en", "suppress-report", re.compile(r"\b(do not|don't|never|do NOT)\s+(report|flag|mention|include)\b|\breport (?:no|zero) (?:findings|issues|vulnerabilit)", re.I)),
    ("en", "force-verdict", re.compile(r"\b(mark|treat|consider|classify|rate)\b[^.\n]{0,30}\b(as|is)\s+(safe|secure|clean|risk[- ]free)\b|\b(set|override|change)\b[^.\n]{0,20}\b(score|severity|risk (?:indicator|band))\b", re.I)),
    ("en", "false-assurance", re.compile(r"\bthis (?:contract|code) (?:is|has been) (?:fully )?(?:safe|secure|audited|verified|certified)\b", re.I)),
    ("en", "chat-template", re.compile(r"<\|im_start\|>|\[INST\]|###\s*(?:system|instruction)\b|^\s*(?:system|assistant)\s*:", re.I | re.M)),
    ("es", "ignore-instructions", re.compile(r"\b(ignora|ignorar|olvida|omite)\b[^.\n]{0,40}\b(instrucciones|indicaciones)\b", re.I)),
    ("es", "role-override", re.compile(r"\b(ahora eres|a partir de ahora eres|actúa como|actua como|finge (?:ser|que eres))\b", re.I)),
    ("es", "suppress-report", re.compile(r"\bno\s+(informes|reportes|menciones|incluyas)\b", re.I)),
    ("es", "force-verdict", re.compile(r"\b(marca|considera|clasifica|trata)\b[^.\n]{0,30}\bcomo\s+(seguro|segura|limpio|sin riesgo)\b|\beste contrato es (?:totalmente )?seguro\b", re.I)),
    ("it", "ignore-instructions", re.compile(r"\b(ignora|ignorare|dimentica)\b[^.\n]{0,40}\b(istruzioni|regole|indicazioni)\b", re.I)),
    ("it", "role-override", re.compile(r"\b(ora sei|da ora sei|agisci come|fingi di essere)\b", re.I)),
    ("it", "suppress-report", re.compile(r"\bnon\s+(segnalare|riportare|menzionare|includere)\b", re.I)),
    ("it", "force-verdict", re.compile(r"\b(segna|contrassegna|considera|classifica)\b[^.\n]{0,30}\bcome\s+(sicuro|sicura|pulito)\b|\bquesto contratto è (?:completamente )?sicuro\b", re.I)),
    ("fr", "ignore-instructions", re.compile(r"\b(ignore[zr]?|oublie[zr]?)\b[^.\n]{0,40}\b(instructions|consignes|règles)\b", re.I)),
    ("fr", "role-override", re.compile(r"\b(tu es maintenant|vous êtes maintenant|agis comme|agissez comme|fais semblant)\b", re.I)),
    ("fr", "suppress-report", re.compile(r"\bne\s+(signale|rapporte|mentionne|inclus)[zr]?\s+(?:pas|jamais)\b", re.I)),
    ("fr", "force-verdict", re.compile(r"\b(marque[zr]?|considère[zr]?|classe[zr]?)\b[^.\n]{0,30}\bcomme\s+(sûr|sûre|sécurisé|sain)\b|\bce contrat est (?:totalement )?(?:sûr|sécurisé)\b", re.I)),
    ("de", "ignore-instructions", re.compile(r"\b(ignoriere?|vergiss|missachte)\b[^.\n]{0,40}\b(anweisungen|regeln|vorgaben)\b", re.I)),
    ("de", "role-override", re.compile(r"\b(du bist jetzt|ab jetzt bist du|verhalte dich wie|tu so als)\b", re.I)),
    ("de", "suppress-report", re.compile(r"\b(nicht melden|nicht berichten|nicht erwähnen)\b|\bmelde\b[^.\n]{0,30}\bnicht\b", re.I)),
    ("de", "force-verdict", re.compile(r"\b(markiere|betrachte|stufe)\b[^.\n]{0,30}\bals\s+(sicher|unbedenklich)\b|\bdieser vertrag ist (?:vollkommen )?sicher\b", re.I)),
    ("pt", "ignore-instructions", re.compile(r"\b(ignore|ignora|esqueça|esquece)\b[^.\n]{0,40}\b(instruções|instrucoes|regras|orientações)\b", re.I)),
    ("pt", "role-override", re.compile(r"\b(agora você é|agora és|a partir de agora você é|aja como|age como|finja ser)\b", re.I)),
    ("pt", "suppress-report", re.compile(r"\bn[aã]o\s+(informe|reporte|relate|mencione|inclua)\b", re.I)),
    ("pt", "force-verdict", re.compile(r"\b(marque|considere|classifique|trate)\b[^.\n]{0,30}\bcomo\s+(seguro|segura|limpo|sem risco)\b|\beste contrato é (?:totalmente )?seguro\b", re.I)),
]


def find_injections(text: str) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    for language, pattern_id, regex in INJECTION_PATTERNS:
        for match in regex.finditer(text):
            if not match.group(0).strip():
                continue
            hits.append({"start": match.start(), "end": match.end(), "language": language, "pattern": pattern_id})
    hits.sort(key=lambda item: (item["start"], item["language"], item["pattern"]))
    return hits


# ---------------------------------------------------------------------------
# Solidity structure parsing (on the masked text)
# ---------------------------------------------------------------------------

IDENT = r"[A-Za-z_$][A-Za-z0-9_$]*"
PRAGMA_RE = re.compile(r"\bpragma\s+solidity\s+([^;]+);")
IMPORT_RE = re.compile(r"\bimport\s+([^;]+);")
CONTRACT_RE = re.compile(r"\b(abstract\s+)?(contract|interface|library)\s+(" + IDENT + r")\s*(?:\bis\s+([^{]*?))?\s*\{")
FUNCTION_RE = re.compile(r"\b(?:function\s+(" + IDENT + r")|(constructor|fallback|receive))\s*\(")
MODIFIER_RE = re.compile(r"\bmodifier\s+(" + IDENT + r")")
USING_RE = re.compile(r"\busing\s+(" + IDENT + r"(?:\." + IDENT + r")*|\{[^}]*\})\s+for\s+([^;]+?)\s*(global)?\s*;")
VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")
VISIBILITIES = {"public", "private", "internal", "external"}
MUTABILITIES = {"view", "pure", "payable", "constant"}
HEADER_KEYWORDS = VISIBILITIES | MUTABILITIES | {"virtual", "override", "returns", "memory", "calldata", "storage", "nonpayable"}
STATEMENT_KEYWORDS = {"function", "constructor", "fallback", "receive", "modifier", "event", "error", "using", "struct", "enum", "pragma", "import", "emit", "return", "mapping"}
STATE_VAR_RE = re.compile(r"^(?P<type>.+?)\s+(?P<attrs>(?:(?:public|private|internal|constant|immutable|override|transient)\s+)*)(?P<name>" + IDENT + r")\s*(?:=\s*(?P<init>[\s\S]*))?$")
ELEMENTARY_TYPES = re.compile(r"^(u?int\d*|address(\s+payable)?|bool|bytes\d*|string|mapping|function|fixed\d*x?\d*|ufixed\d*x?\d*)$")
OWNER_LIKE_RE = re.compile(r"^_?(owner|admin|governance|governor|guardian|operator|controller|manager|treasury|authority|pendingOwner|_pendingOwner)$", re.I)
ACCESS_MODIFIER_RE = re.compile(r"^(only|auth|requires?|restricted|isOwner|isAdmin|when|has|check|protected|guarded|permissioned)", re.I)
NON_ACCESS_MODIFIERS = {"whenNotPaused", "whenPaused", "nonReentrant", "noReentrant", "nonreentrant", "lock", "initializer", "reinitializer", "onlyInitializing", "payable"}
BODY_GUARD_RE = re.compile(r"msg\.sender\s*[!=]=|[!=]=\s*msg\.sender|require\s*\(\s*msg\.sender|_checkOwner\s*\(|_checkRole\s*\(|hasRole\s*\(|_onlyOwner\s*\(|_onlyAdmin\s*\(|isOwner\s*\(|_msgSender\s*\(\s*\)\s*[!=]=|[!=]=\s*_msgSender\s*\(\s*\)|revert\s+\w*(Unauthorized|NotOwner|NotAdmin|OnlyOwner|Forbidden)|onlyOwner\s*\(|_requireOwner|_authorizeCaller|_checkAuth|auth\s*\(")
REENTRANCY_GUARD_RE = re.compile(r"^(nonReentrant|noReentrant|nonreentrant|lock|locked|mutex|reentrancyGuard|noReentrancy|nonReentrantView)$", re.I)


def brace_pairs(masked: str) -> Tuple[Dict[int, int], List[str]]:
    pairs: Dict[int, int] = {}
    stack: List[int] = []
    issues: List[str] = []
    for idx, char in enumerate(masked):
        if char == "{":
            stack.append(idx)
        elif char == "}":
            if stack:
                pairs[stack.pop()] = idx
            else:
                issues.append("unmatched closing brace")
    if stack:
        issues.append("%d unclosed brace(s)" % len(stack))
    return pairs, issues


def matching_paren(masked: str, open_idx: int) -> int:
    depth = 0
    for idx in range(open_idx, len(masked)):
        char = masked[idx]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return idx
    return -1


def split_top_level(text: str, separator: str = ",") -> List[str]:
    parts: List[str] = []
    depth = 0
    current: List[str] = []
    for char in text:
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        if char == separator and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    if "".join(current).strip():
        parts.append("".join(current))
    return [part.strip() for part in parts if part.strip()]


def parse_params(text: str) -> List[Dict[str, Any]]:
    params: List[Dict[str, Any]] = []
    for part in split_top_level(text):
        tokens = part.split()
        if not tokens:
            continue
        location = None
        name = None
        type_tokens = list(tokens)
        if len(type_tokens) >= 2 and re.match(r"^" + IDENT + r"$", type_tokens[-1]) and type_tokens[-1] not in ("memory", "calldata", "storage", "payable"):
            name = type_tokens.pop()
        for keyword in ("memory", "calldata", "storage"):
            if keyword in type_tokens:
                location = keyword
                type_tokens = [tok for tok in type_tokens if tok != keyword]
        type_text = " ".join(type_tokens)
        params.append({
            "type": type_text,
            "name": name,
            "location": location,
            "isAddress": bool(re.match(r"^address(\s+payable)?$", type_text)),
        })
    return params


def strip_base_args(base: str) -> str:
    base = base.strip()
    cut = base.find("(")
    if cut != -1:
        base = base[:cut]
    return base.strip()


def parse_pragma(masked: str) -> Dict[str, Any]:
    match = PRAGMA_RE.search(masked)
    if not match:
        return {"present": False, "expression": None, "minVersion": None, "floating": None, "line": None}
    expr = collapse_ws(match.group(1))
    versions = [tuple(int(part) for part in m.groups()) for m in VERSION_RE.finditer(expr)]
    lower_bounds: List[Tuple[int, int, int]] = []
    for m in VERSION_RE.finditer(expr):
        prefix = expr[:m.start()].rstrip()
        operator = ""
        while prefix and prefix[-1] in "<>=^~!":
            operator = prefix[-1] + operator
            prefix = prefix[:-1]
        if operator.startswith("<"):
            continue
        lower_bounds.append(tuple(int(part) for part in m.groups()))
    candidates = lower_bounds or versions
    min_version = ".".join(str(part) for part in min(candidates)) if candidates else None
    exact = bool(re.match(r"^=?\s*\d+\.\d+\.\d+$", expr))
    floating = not exact
    return {"present": True, "expression": expr, "minVersion": min_version, "floating": floating, "line": None, "offset": match.start()}


def version_tuple(version: Optional[str]) -> Optional[Tuple[int, int, int]]:
    if not version:
        return None
    match = VERSION_RE.match(version)
    if not match:
        return None
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def parse_imports(masked: str) -> List[Dict[str, Any]]:
    imports: List[Dict[str, Any]] = []
    for match in IMPORT_RE.finditer(masked):
        body = collapse_ws(match.group(1))
        symbols: List[str] = []
        alias = None
        # The literal path was blanked by the masker; recover it from the
        # original text in the caller via the offset. Here we keep the shape.
        shape = "plain"
        if body.startswith("{"):
            shape = "symbols"
            inner = body[1:body.find("}")]
            symbols = [collapse_ws(part).split(" as ")[0] for part in inner.split(",") if part.strip()]
        elif body.startswith("*"):
            shape = "wildcard"
            alias_match = re.search(r"\bas\s+(" + IDENT + ")", body)
            alias = alias_match.group(1) if alias_match else None
        else:
            alias_match = re.search(r"\bas\s+(" + IDENT + ")", body)
            alias = alias_match.group(1) if alias_match else None
        imports.append({"offset": match.start(), "end": match.end(), "shape": shape, "symbols": symbols, "alias": alias})
    return imports


def recover_import_path(original: str, start: int, end: int) -> Optional[str]:
    segment = original[start:end]
    match = re.search(r"[\"']([^\"']+)[\"']", segment)
    return match.group(1) if match else None


def parse_header(masked: str, open_paren: int, pairs: Dict[int, int]) -> Optional[Dict[str, Any]]:
    """Parse a function/modifier header starting at its parameter list."""
    close_paren = matching_paren(masked, open_paren)
    if close_paren == -1:
        return None
    params_text = masked[open_paren + 1:close_paren]
    idx = close_paren + 1
    depth = 0
    header_end = -1
    terminator = None
    n = len(masked)
    while idx < n:
        char = masked[idx]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif depth == 0 and char == "{":
            header_end = idx
            terminator = "{"
            break
        elif depth == 0 and char == ";":
            header_end = idx
            terminator = ";"
            break
        idx += 1
    if header_end == -1:
        return None
    tail = masked[close_paren + 1:header_end]
    returns_text = None
    returns_match = re.search(r"\breturns\s*\(", tail)
    if returns_match:
        rel_open = returns_match.end() - 1
        rel_close = matching_paren(tail, rel_open)
        if rel_close != -1:
            returns_text = collapse_ws(tail[rel_open + 1:rel_close])
            tail = tail[:returns_match.start()] + " " + tail[rel_close + 1:]
    modifiers: List[Dict[str, Any]] = []
    visibility = None
    mutability = None
    is_virtual = False
    is_override = False
    override_bases: List[str] = []
    pos = 0
    while pos < len(tail):
        match = re.compile(IDENT).match(tail, pos)
        if not match:
            pos += 1
            continue
        token = match.group(0)
        pos = match.end()
        args = None
        look = pos
        while look < len(tail) and tail[look] in " \t\n":
            look += 1
        if look < len(tail) and tail[look] == "(":
            rel_close = matching_paren(tail, look)
            if rel_close != -1:
                args = collapse_ws(tail[look + 1:rel_close])
                pos = rel_close + 1
        if token in VISIBILITIES:
            visibility = token
        elif token in MUTABILITIES:
            mutability = "view" if token == "constant" else token
        elif token == "virtual":
            is_virtual = True
        elif token == "override":
            is_override = True
            if args:
                override_bases = [collapse_ws(part) for part in args.split(",") if part.strip()]
        elif token in HEADER_KEYWORDS:
            continue
        else:
            modifiers.append({"name": token, "args": args})
    body_end = None
    if terminator == "{":
        body_end = pairs.get(header_end)
    return {
        "paramsText": params_text,
        "params": parse_params(params_text),
        "headerEnd": header_end,
        "terminator": terminator,
        "bodyStart": header_end if terminator == "{" else None,
        "bodyEnd": body_end,
        "visibility": visibility,
        "mutability": mutability or "nonpayable",
        "modifiers": modifiers,
        "virtual": is_virtual,
        "override": is_override,
        "overrideBases": override_bases,
        "returns": returns_text,
    }


def blank_nested_blocks(body: str) -> str:
    """Replace every nested {...} block with spaces and a ';' so top-level
    declarations of a contract body can be split by ';'."""
    chars = list(body)
    depth = 0
    start = -1
    for idx, char in enumerate(body):
        if char == "{":
            if depth == 0:
                start = idx
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0 and start != -1:
                for j in range(start, idx + 1):
                    if chars[j] != "\n":
                        chars[j] = " "
                chars[idx] = ";"
                start = -1
    return "".join(chars)


def parse_state_variables(body_masked: str, body_offset: int, line_index: LineIndex) -> List[Dict[str, Any]]:
    flattened = blank_nested_blocks(body_masked)
    variables: List[Dict[str, Any]] = []
    cursor = 0
    for statement in flattened.split(";"):
        stmt_start = cursor
        cursor += len(statement) + 1
        text = statement.strip()
        if not text:
            continue
        if re.match(r"^(function|constructor|fallback|receive|modifier|event|error|using|struct|enum|pragma|import|emit|return|revert|assembly|unchecked)\b", text):
            continue
        match = STATE_VAR_RE.match(collapse_ws(text))
        if not match:
            continue
        attrs = match.group("attrs").split()
        type_text = match.group("type").strip()
        if not type_text or type_text in ("return", "emit", "revert", "assembly", "unchecked"):
            continue
        name = match.group("name")
        leading = len(statement) - len(statement.lstrip())
        offset = body_offset + stmt_start + leading
        variables.append({
            "name": name,
            "type": type_text,
            "visibility": next((attr for attr in attrs if attr in VISIBILITIES), "internal"),
            "constant": "constant" in attrs,
            "immutable": "immutable" in attrs,
            "line": line_index.line_of(offset),
            "ownerLike": bool(OWNER_LIKE_RE.match(name)),
            "userType": None if ELEMENTARY_TYPES.match(type_text.split("[")[0].split(" ")[0]) else re.sub(r"\[.*$", "", type_text).strip(),
        })
    return variables


def parse_functions(masked: str, span_start: int, span_end: int, pairs: Dict[int, int], line_index: LineIndex, issues: List[str]) -> List[Dict[str, Any]]:
    functions: List[Dict[str, Any]] = []
    pos = span_start
    while True:
        match = FUNCTION_RE.search(masked, pos, span_end)
        if not match:
            break
        name = match.group(1) or match.group(2)
        kind = match.group(2) or "function"
        open_paren = match.end() - 1
        header = parse_header(masked, open_paren, pairs)
        if header is None:
            issues.append("could not parse function header near line %d" % line_index.line_of(match.start()))
            pos = match.end()
            continue
        if header["terminator"] == "{" and header["bodyEnd"] is None:
            issues.append("unclosed function body near line %d" % line_index.line_of(match.start()))
            end_offset = span_end - 1
        elif header["terminator"] == "{":
            end_offset = header["bodyEnd"]
        else:
            end_offset = header["headerEnd"]
        body_text = masked[header["bodyStart"] + 1:end_offset] if header["terminator"] == "{" and header["bodyEnd"] is not None else ""
        visibility = header["visibility"]
        if kind in ("constructor",):
            visibility = visibility or "public"
        elif kind in ("fallback", "receive"):
            visibility = visibility or "external"
        signature_text = collapse_ws(masked[match.start():header["headerEnd"]])
        functions.append({
            "name": name,
            "kind": kind,
            "lineStart": line_index.line_of(match.start()),
            "lineEnd": line_index.line_of(end_offset),
            "visibility": visibility,
            "mutability": header["mutability"],
            "modifiers": header["modifiers"],
            "params": header["params"],
            "returns": header["returns"],
            "virtual": header["virtual"],
            "override": header["override"],
            "hasBody": header["terminator"] == "{",
            "signatureText": signature_text[:200],
            "_bodyStart": header["bodyStart"],
            "_bodyEnd": header["bodyEnd"],
            "_body": body_text,
            "_headStart": match.start(),
        })
        pos = end_offset + 1 if end_offset >= match.end() else match.end()
    return functions


def parse_modifiers(masked: str, span_start: int, span_end: int, pairs: Dict[int, int], line_index: LineIndex) -> List[Dict[str, Any]]:
    modifiers: List[Dict[str, Any]] = []
    for match in MODIFIER_RE.finditer(masked, span_start, span_end):
        name = match.group(1)
        idx = match.end()
        while idx < span_end and masked[idx] in " \t\n":
            idx += 1
        params: List[Dict[str, Any]] = []
        end_offset = idx
        if idx < span_end and masked[idx] == "(":
            header = parse_header(masked, idx, pairs)
            if header:
                params = header["params"]
                end_offset = header["bodyEnd"] if header["bodyEnd"] is not None else header["headerEnd"]
        else:
            brace = masked.find("{", idx, span_end)
            semi = masked.find(";", idx, span_end)
            if brace != -1 and (semi == -1 or brace < semi):
                end_offset = pairs.get(brace, brace)
            elif semi != -1:
                end_offset = semi
        modifiers.append({
            "name": name,
            "lineStart": line_index.line_of(match.start()),
            "lineEnd": line_index.line_of(end_offset),
            "params": params,
            "_start": match.start(),
            "_end": end_offset,
        })
    return modifiers


def parse_solidity_structure(masked: str, original: str, line_index: LineIndex) -> Dict[str, Any]:
    pairs, brace_issues = brace_pairs(masked)
    issues: List[str] = list(brace_issues)
    pragma = parse_pragma(masked)
    if pragma.get("offset") is not None:
        pragma["line"] = line_index.line_of(pragma.pop("offset"))
    imports = []
    for item in parse_imports(masked):
        path = recover_import_path(original, item["offset"], item["end"])
        imports.append({
            "path": path,
            "line": line_index.line_of(item["offset"]),
            "shape": item["shape"],
            "symbols": item["symbols"],
            "alias": item["alias"],
        })
    contracts: List[Dict[str, Any]] = []
    covered: List[Tuple[int, int]] = []
    for match in CONTRACT_RE.finditer(masked):
        open_brace = match.end() - 1
        close_brace = pairs.get(open_brace)
        truncated = close_brace is None
        end_offset = close_brace if close_brace is not None else len(masked) - 1
        bases_raw = match.group(4) or ""
        bases = [strip_base_args(part) for part in split_top_level(bases_raw)]
        bases = [base for base in bases if base]
        body_start = open_brace + 1
        body_end = end_offset
        body_masked = masked[body_start:body_end]
        functions = parse_functions(masked, body_start, body_end, pairs, line_index, issues)
        modifiers = parse_modifiers(masked, body_start, body_end, pairs, line_index)
        using_for = []
        for using in USING_RE.finditer(masked, body_start, body_end):
            using_for.append({"library": collapse_ws(using.group(1)), "type": collapse_ws(using.group(2)), "line": line_index.line_of(using.start())})
        kind = match.group(2)
        if match.group(1):
            kind = "abstract"
        contracts.append({
            "name": match.group(3),
            "kind": kind,
            "lineStart": line_index.line_of(match.start()),
            "lineEnd": line_index.line_of(end_offset),
            "bases": bases,
            "functions": functions,
            "modifiers": modifiers,
            "stateVariables": parse_state_variables(body_masked, body_start, line_index),
            "usingFor": using_for,
            "truncated": truncated,
            "_start": match.start(),
            "_bodyStart": body_start,
            "_bodyEnd": body_end,
            "_body": body_masked,
        })
        covered.append((match.start(), end_offset))
    free_functions: List[Dict[str, Any]] = []
    cursor = 0
    for start, end in sorted(covered) + [(len(masked), len(masked))]:
        if start > cursor:
            free_functions.extend(parse_functions(masked, cursor, start, pairs, line_index, issues))
        cursor = max(cursor, end + 1)
    file_using = [{"library": collapse_ws(m.group(1)), "type": collapse_ws(m.group(2)), "line": line_index.line_of(m.start())} for m in USING_RE.finditer(masked) if not any(s <= m.start() <= e for s, e in covered)]
    return {
        "pragma": pragma,
        "imports": imports,
        "contracts": contracts,
        "freeFunctions": free_functions,
        "usingFor": file_using,
        "issues": issues,
        "pairs": pairs,
    }


# ---------------------------------------------------------------------------
# Signal helpers
# ---------------------------------------------------------------------------

ADMIN_NAME_RE = re.compile(r"^(set|update|change|configure|withdraw|sweep|rescue|drain|emergency|pause|unpause|mint|burn|upgrade|migrate|whitelist|blacklist|add|remove|grant|revoke|kill|destroy|transferOwnership|renounce|register|unregister|enable|disable|toggle|reset|claim(All|Fees)?)", re.I)
ADMIN_NAME_EXCLUDE_RE = re.compile(r"^(addLiquidity|removeLiquidity|mintTo|burnFrom|setApprovalForAll|withdrawTo)$")
INITIALIZER_NAME_RE = re.compile(r"^(initialize|initialise|init|__\w+_init(?:_unchained)?|setUp|setup)$", re.I)
INITIALIZER_GUARD_RE = re.compile(r"^(initializer|reinitializer|onlyInitializing|only\w+|auth\w*|when\w+)$")
INITIALIZED_BODY_RE = re.compile(r"\binitializ(?:ed|ing)\b|_initialized|_initializing|AlreadyInitialized|alreadyInit|require\s*\(\s*!\s*init", re.I)
UPGRADE_FUNCTION_RE = re.compile(r"^(upgradeTo|upgradeToAndCall|_authorizeUpgrade|_upgradeTo|_upgradeToAndCall|setImplementation|_setImplementation|changeAdmin|_changeAdmin|upgrade|migrate|upgradeBeaconToAndCall)$")
PROXY_BASE_RE = re.compile(r"upgradeable|uups|proxy|initializable|erc1967|beacon", re.I)
PROXY_FUNCTION_RE = re.compile(r"^(upgradeTo|upgradeToAndCall|_authorizeUpgrade|_upgradeTo|_setImplementation|setImplementation|changeAdmin|_changeAdmin|implementation|_implementation|proxiableUUID|_getImplementation)$")
TWO_STEP_RE = re.compile(r"Ownable2Step|acceptOwnership|pendingOwner", re.I)
OWNERSHIP_TRANSFER_RE = re.compile(r"^(transferOwnership|setOwner|changeOwner|_transferOwnership)$")
INTERNAL_STATE_CALL_RE = re.compile(r"\b(_mint|_burn|_transfer|_update|_set\w*|_add\w*|_remove\w*|_write\w*|_increase\w*|_decrease\w*|_deposit\w*|_withdraw\w*|_credit\w*|_debit\w*)\s*\(")
ORACLE_METHOD_RE = re.compile(r"\.(latestRoundData|latestAnswer|getReserves|slot0|observe|consult|getPrice\w*|price|getAmountsOut|getAmountOut|getAmountsIn|quote\w*|getRate\w*|exchangeRate\w*|pricePerShare|getPricePerFullShare|convertToAssets|convertToShares|totalAssets)\s*\(")
FLASH_RE = re.compile(r"\b(flashLoan\w*|onFlashLoan|executeOperation|uniswapV2Call|uniswapV3FlashCallback|receiveFlashLoan|IERC3156\w*|IFlashLoan\w*|flashSwap|flash|maxFlashLoan|flashFee)\b")
SWAP_CALL_RE = re.compile(r"\b(swap\w*|exactInput\w*|exactOutput\w*|addLiquidity\w*|removeLiquidity\w*)\s*\(")
MIN_AMOUNT_ZERO_RE = re.compile(r"\b(amountOutMin\w*|amountOutMinimum|minAmountOut|amountAMin|amountBMin|minReturn\w*|minOut\w*|minimumAmount\w*|sqrtPriceLimitX96)\s*:\s*0\b")
SIGNATURE_RE = re.compile(r"\becrecover\s*\(|\.recover\s*\(|\.tryRecover\s*\(|\bECDSA\.|\bSignatureChecker\.|\bisValidSignature\s*\(")
RANDOM_SOURCE_RE = re.compile(r"\bblock\.timestamp\b|\bnow\b|\bblock\.prevrandao\b|\bblock\.difficulty\b|\bblockhash\s*\(|\bblock\.number\b|\bblock\.coinbase\b|\bgasleft\s*\(")
RANDOM_USE_RE = re.compile(r"keccak256|abi\.encodePacked|abi\.encode\b|%|\brandom|\bseed\b|\blottery|\bwinner|\bdraw\b|\bdice|\broll\b|\braffle", re.I)
RANDOM_FUNCTION_RE = re.compile(r"random|lottery|draw|winner|seed|dice|roll|raffle|jackpot", re.I)
TOKEN_TYPE_RE = re.compile(r"^(I?ERC20\w*|IERC721\w*|IERC1155\w*|I[A-Z]\w*|[A-Z]\w*Token\w*)$")
ETH_LIKE_BASE_RE = re.compile(r"^(payable\s*\(|address\s*\(|msg\.sender$|tx\.origin$|owner$|_owner$|recipient$|to$|_to$|receiver$|beneficiary$)")
ZERO_ADDRESS_RE_TEMPLATE = r"\b{p}\b\s*[!=]=\s*(address\s*\(\s*0x?0*\s*\)|ZERO_ADDRESS|address\s*\(\s*0x0+\s*\))|(address\s*\(\s*0x?0*\s*\)|ZERO_ADDRESS)\s*[!=]=\s*\b{p}\b|_?(check|require|validate|nonZero|notZero|assert|ensure|verify)\w*\s*\([^;]*\b{p}\b"
LOOP_RE = re.compile(r"\b(for|while)\s*\(")
DIVISION_RE = re.compile(r"[\w\)\]]\s*/(?![/=*])\s*[\w\(\[][^;{}]*?(?<![*/])\*(?!\*|/)")
HARDCODED_ADDRESS_RE = re.compile(r"\b0x[0-9a-fA-F]{40}\b")
ASSEMBLY_OPCODES_RE = re.compile(r"\b(call|delegatecall|staticcall|callcode|sstore|sload|create2?|selfdestruct|mstore|mload|return|revert|extcodesize|extcodecopy|origin|gas|balance|calldatacopy|returndatacopy|log[0-4]|tstore|tload)\b")


def snippet_for(line_index: LineIndex, line: int) -> str:
    text, _ = truncate(redact(line_index.line_text(line).strip(), "code"), MAX_SNIPPET_CHARS)
    return text


def statement_at(masked: str, offset: int, lower: int, upper: int) -> Tuple[str, int]:
    """Return the statement fragment containing offset and its start."""
    start = offset
    while start > lower and masked[start - 1] not in ";{}":
        start -= 1
    end = offset
    while end < upper and masked[end] not in ";{}":
        end += 1
    return masked[start:end], start


def locate_scope(contract: Optional[Dict[str, Any]], offset: int) -> Dict[str, Optional[str]]:
    scope: Dict[str, Optional[str]] = {"function": None, "modifier": None, "kind": None}
    if contract is None:
        return scope
    for fn in contract.get("functions", []):
        if fn.get("_headStart") is not None and fn["_headStart"] <= offset <= (fn.get("_bodyEnd") or fn["_headStart"]):
            scope["function"] = fn["name"] or fn["kind"]
            scope["kind"] = fn["kind"]
            return scope
    for mod in contract.get("modifiers", []):
        if mod["_start"] <= offset <= mod["_end"]:
            scope["modifier"] = mod["name"]
            return scope
    return scope


class SignalCollector:
    def __init__(self, path: str, line_index: LineIndex) -> None:
        self.path = path
        self.line_index = line_index
        self.signals: List[Dict[str, Any]] = []

    def add(self, family: str, offset: int, contract: Optional[str], scope: Dict[str, Optional[str]], details: Dict[str, Any], line: Optional[int] = None) -> Dict[str, Any]:
        meta = SIGNAL_FAMILIES[family]
        line_no = line if line is not None else self.line_index.line_of(offset)
        signal = {
            "family": family,
            "categories": list(meta["categories"]),
            "needsContext": meta["needsContext"],
            "fpRisk": meta["fpRisk"],
            "file": self.path,
            "line": line_no,
            "column": self.line_index.col_of(offset) if line is None else 0,
            "contract": contract,
            "function": scope.get("function"),
            "modifier": scope.get("modifier"),
            "snippet": snippet_for(self.line_index, line_no),
            "details": details,
        }
        self.signals.append(signal)
        return signal


def function_access_info(fn: Dict[str, Any]) -> Dict[str, Any]:
    access_modifiers = [m["name"] for m in fn["modifiers"] if ACCESS_MODIFIER_RE.match(m["name"]) and m["name"] not in NON_ACCESS_MODIFIERS]
    body = fn.get("_body", "")
    guards = sorted(set(collapse_ws(m.group(0)) for m in BODY_GUARD_RE.finditer(body)))
    return {"modifiers": access_modifiers, "bodyGuards": guards, "guarded": bool(access_modifiers or guards)}


def is_reentrancy_guarded(fn: Dict[str, Any]) -> bool:
    if any(REENTRANCY_GUARD_RE.match(m["name"]) for m in fn["modifiers"]):
        return True
    body = fn.get("_body", "")
    return bool(re.search(r"_nonReentrantBefore|_status\s*=\s*_?ENTERED|locked\s*=\s*true|require\s*\(\s*!\s*locked|_reentrancyGuardEntered|ReentrancyGuard", body))


def find_state_writes(body: str, body_start: int, after_offset: int, state_names: List[str], line_index: LineIndex) -> Tuple[List[int], List[str]]:
    writes: List[int] = []
    internal_calls: List[str] = []
    rel = after_offset - body_start
    tail = body[rel:]
    for name in state_names:
        pattern = re.compile(r"\b" + re.escape(name) + r"\b(\s*\[[^\]]*\])*(\s*\.\w+)*\s*(=(?!=)|\+=|-=|\*=|/=|\|=|&=|\+\+|--)|\bdelete\s+" + re.escape(name) + r"\b|\b" + re.escape(name) + r"\s*\.\s*(push|pop)\s*\(")
        for match in pattern.finditer(tail):
            writes.append(line_index.line_of(after_offset + match.start()))
    for match in INTERNAL_STATE_CALL_RE.finditer(tail):
        internal_calls.append(match.group(1))
    return sorted(set(writes)), sorted(set(internal_calls))


def loop_spans(masked: str, start: int, end: int, pairs: Dict[int, int]) -> List[Dict[str, Any]]:
    loops: List[Dict[str, Any]] = []
    for match in LOOP_RE.finditer(masked, start, end):
        open_paren = match.end() - 1
        close_paren = matching_paren(masked, open_paren)
        if close_paren == -1 or close_paren > end:
            continue
        header = collapse_ws(masked[open_paren + 1:close_paren])
        idx = close_paren + 1
        while idx < end and masked[idx] in " \t\n":
            idx += 1
        if idx < end and masked[idx] == "{":
            body_end = pairs.get(idx, end)
            body_start = idx
        else:
            body_start = idx
            body_end = masked.find(";", idx, end)
            if body_end == -1:
                body_end = end
        loops.append({"kind": match.group(1), "start": match.start(), "header": header, "bodyStart": body_start, "bodyEnd": body_end})
    return loops


def classify_call_hint(method: str) -> List[str]:
    hints: List[str] = []
    if re.match(r"^(latestRoundData|latestAnswer|getReserves|slot0|observe|consult|getPrice\w*|price|getAmountsOut|getAmountOut|getRate\w*|exchangeRate\w*|pricePerShare|getPricePerFullShare)$", method):
        hints.append("SC03")
    if re.match(r"^(flashLoan\w*|flash|flashSwap|maxFlashLoan|flashFee)$", method):
        hints.append("SC04")
    if re.match(r"^(swap\w*|exactInput\w*|exactOutput\w*)$", method):
        hints.append("EXTRA-front-running-mev")
    return hints


# ---------------------------------------------------------------------------
# Solidity signal detection
# ---------------------------------------------------------------------------

def detect_solidity_signals(entry: Dict[str, Any], declared_types: Dict[str, str]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Run every detector family over one Solidity file.

    Returns (signals, calls). declared_types maps type names declared anywhere
    in the bundle to their kind (contract/interface/library/abstract).
    """
    masked: str = entry["masked"]
    original: str = entry["text"]
    line_index: LineIndex = entry["lineIndex"]
    structure = entry["structure"]
    pairs: Dict[int, int] = structure["pairs"]
    collector = SignalCollector(entry["path"], line_index)
    calls: List[Dict[str, Any]] = []

    # --- file level -------------------------------------------------------
    pragma = structure["pragma"]
    pragma_line = pragma.get("line") or 1
    pragma_offset = line_index.offset_of_line(pragma_line)
    if not pragma["present"]:
        collector.add("pragma-missing", pragma_offset, None, {}, {"language": "solidity"}, line=1)
    else:
        if pragma["floating"]:
            collector.add("floating-pragma", pragma_offset, None, {}, {"expression": pragma["expression"], "minVersion": pragma["minVersion"]}, line=pragma_line)
        min_version = version_tuple(pragma["minVersion"])
        if min_version is not None and min_version < (0, 8, 0):
            collector.add("obsolete-compiler", pragma_offset, None, {}, {"expression": pragma["expression"], "minVersion": pragma["minVersion"], "checkedArithmetic": False}, line=pragma_line)
            uses_safemath = bool(re.search(r"\bSafeMath\b", masked))
            if not uses_safemath and re.search(r"[\w\)\]]\s*[+\-*]\s*[\w\(]", masked):
                collector.add("legacy-arithmetic", pragma_offset, None, {}, {"minVersion": pragma["minVersion"], "safeMathDetected": False}, line=pragma_line)

    all_scopes: List[Tuple[Optional[Dict[str, Any]], int, int]] = []
    for contract in structure["contracts"]:
        all_scopes.append((contract, contract["_bodyStart"], contract["_bodyEnd"]))
    for fn in structure["freeFunctions"]:
        if fn["_bodyStart"] is not None and fn["_bodyEnd"] is not None:
            all_scopes.append(({"name": None, "functions": [fn], "modifiers": [], "stateVariables": [], "usingFor": [], "bases": []}, fn["_bodyStart"], fn["_bodyEnd"]))

    for contract, span_start, span_end in all_scopes:
        cname = contract["name"]
        body = masked[span_start:span_end]
        state_names = [var["name"] for var in contract["stateVariables"]]
        state_types = {var["name"]: var["type"] for var in contract["stateVariables"]}
        state_user_types = {var["name"]: var["userType"] for var in contract["stateVariables"] if var.get("userType")}
        assembly_spans: List[Tuple[int, int]] = []

        def in_assembly(offset: int) -> bool:
            return any(s <= offset <= e for s, e in assembly_spans)

        def fn_at(offset: int) -> Optional[Dict[str, Any]]:
            for fn in contract["functions"]:
                if fn["_bodyStart"] is not None and fn["_bodyEnd"] is not None and fn["_bodyStart"] <= offset <= fn["_bodyEnd"]:
                    return fn
            return None

        def param_names(fn: Optional[Dict[str, Any]]) -> List[str]:
            if not fn:
                return []
            return [p["name"] for p in fn["params"] if p.get("name")]

        # assembly blocks first (other detectors consult the spans)
        for match in re.finditer(r"\bassembly\b[^{]*\{", masked[span_start:span_end]):
            open_brace = span_start + match.end() - 1
            close_brace = pairs.get(open_brace, span_end)
            assembly_spans.append((open_brace, close_brace))
            block = masked[open_brace:close_brace]
            opcodes = sorted(set(ASSEMBLY_OPCODES_RE.findall(block)))
            memory_safe = "memory-safe" in original[span_start + match.start():open_brace]
            scope = locate_scope(contract, open_brace)
            collector.add("assembly-block", span_start + match.start(), cname, scope, {"opcodes": opcodes, "memorySafe": memory_safe, "lineEnd": line_index.line_of(close_brace)})

        # token-level detectors over the whole contract body
        for match in re.finditer(r"\btx\.origin\b", body):
            offset = span_start + match.start()
            scope = locate_scope(contract, offset)
            stmt, _ = statement_at(masked, offset, span_start, span_end)
            in_condition = bool(re.search(r"\b(require|if|assert)\s*\(|[!=]=", stmt))
            collector.add("tx-origin", offset, cname, scope, {"inCondition": in_condition})

        for match in re.finditer(r"([A-Za-z_$][\w$.\[\]()]*?)\s*\.delegatecall\s*(\{[^}]*\})?\s*\(|(?<![.\w])delegatecall\s*\(", body):
            offset = span_start + match.start()
            scope = locate_scope(contract, offset)
            assembly_hit = match.group(0).lstrip().startswith("delegatecall")
            if assembly_hit and not in_assembly(offset):
                continue
            target = collapse_ws(match.group(1) or "") if not assembly_hit else None
            fn = fn_at(offset)
            collector.add("delegatecall", offset, cname, scope, {
                "target": target,
                "inAssembly": assembly_hit or in_assembly(offset),
                "targetIsParameter": bool(target and target in param_names(fn)),
                "inFallback": scope.get("kind") == "fallback",
                "guarded": function_access_info(fn)["guarded"] if fn else False,
            })

        for match in re.finditer(r"\b(selfdestruct|suicide)\s*\(", body):
            offset = span_start + match.start()
            scope = locate_scope(contract, offset)
            fn = fn_at(offset)
            collector.add("selfdestruct", offset, cname, scope, {"guarded": function_access_info(fn)["guarded"] if fn else False, "inAssembly": in_assembly(offset)})

        external_call_offsets: List[Tuple[int, str]] = []
        for match in re.finditer(r"([A-Za-z_$][\w$.\[\]()]*?)\s*\.(call|send|staticcall|callcode)\s*(\{[^}]*\})?\s*\(", body):
            offset = span_start + match.start()
            if in_assembly(offset):
                continue
            scope = locate_scope(contract, offset)
            stmt, stmt_start = statement_at(masked, offset, span_start, span_end)
            prefix = collapse_ws(masked[stmt_start:offset])
            checked = bool(re.search(r"(=|\brequire\s*\(|\bassert\s*\(|\bif\s*\(|\breturn\b|\(\s*bool\b|&&|\|\|)", prefix))
            value_forwarded = "{" in (match.group(3) or "") and "value" in (match.group(3) or "")
            kind = match.group(2)
            target = collapse_ws(match.group(1))
            fn = fn_at(offset)
            collector.add("low-level-call", offset, cname, scope, {
                "kind": kind,
                "target": target,
                "returnChecked": checked,
                "valueForwarded": value_forwarded,
                "targetIsParameter": target in param_names(fn),
            })
            if kind != "staticcall":
                external_call_offsets.append((offset, "low-level-call"))
            if kind == "call":
                data_match = re.match(r"\s*([A-Za-z_$][\w$]*)\s*\)", masked[span_start + match.end():span_start + match.end() + 80])
                base_ident = re.sub(r"^(address|payable)\s*\(\s*", "", target).rstrip(") ")
                if fn and data_match and data_match.group(1) in param_names(fn) and base_ident in param_names(fn):
                    collector.add("arbitrary-external-call", offset, cname, scope, {"targetParam": base_ident, "dataParam": data_match.group(1), "guarded": function_access_info(fn)["guarded"]})

        for match in re.finditer(r"([A-Za-z_$][\w$]*(?:\s*\([^()]*\))?)\s*\.(transfer|transferFrom|safeTransfer|safeTransferFrom)\s*\(", body):
            offset = span_start + match.start()
            if in_assembly(offset):
                continue
            base = collapse_ws(match.group(1))
            method = match.group(2)
            base_ident = re.sub(r"\s*\(.*$", "", base)
            fn = fn_at(offset)
            base_type = state_types.get(base_ident) or next((p["type"] for p in (fn["params"] if fn else []) if p.get("name") == base_ident), None)
            if base_type is None and "(" in base and base_ident[:1].isupper():
                base_type = base_ident
            is_eth_transfer = method == "transfer" and (ETH_LIKE_BASE_RE.match(base) is not None or (base_type is not None and base_type.startswith("address")))
            if is_eth_transfer:
                external_call_offsets.append((offset, "eth-transfer"))
                continue
            external_call_offsets.append((offset, "token-transfer"))
            scope = locate_scope(contract, offset)
            stmt, stmt_start = statement_at(masked, offset, span_start, span_end)
            prefix = collapse_ws(masked[stmt_start:offset])
            checked = bool(re.search(r"(=|\brequire\s*\(|\bassert\s*\(|\bif\s*\(|\breturn\b|\(\s*bool\b|&&|\|\|)", prefix))
            if method in ("safeTransfer", "safeTransferFrom"):
                checked = True
            if not checked:
                collector.add("token-transfer-unchecked", offset, cname, scope, {"method": method, "callee": base_ident, "calleeType": base_type, "typeKnown": base_type is not None})
            if method in ("transferFrom", "safeTransferFrom") and fn:
                args = masked[span_start + match.end():span_start + match.end() + 120]
                first = re.match(r"\s*([A-Za-z_$][\w$]*)\s*,", args)
                if first and first.group(1) in param_names(fn) and first.group(1) not in ("msg", "this"):
                    collector.add("arbitrary-from-transfer", offset, cname, scope, {"fromParam": first.group(1), "method": method, "guarded": function_access_info(fn)["guarded"]})

        for match in re.finditer(r"\b([A-Za-z_$][\w$]*)\s*(\(([^()]*)\))?\s*\.\s*([A-Za-z_$][\w$]*)\s*(\{[^}]*\})?\s*\(", body):
            offset = span_start + match.start()
            if in_assembly(offset):
                continue
            base = match.group(1)
            cast_args = match.group(3)
            method = match.group(4)
            if base in ("msg", "abi", "block", "tx", "type", "bytes", "string", "address", "payable", "super", "keccak256", "require", "assert", "revert", "unchecked"):
                continue
            if method in ("call", "delegatecall", "staticcall", "callcode", "send", "transfer", "transferFrom", "safeTransfer", "safeTransferFrom", "push", "pop", "length", "selector", "encode", "encodePacked", "decode", "encodeWithSelector", "encodeWithSignature", "code", "balance", "max", "min"):
                continue
            fn = fn_at(offset)
            callee_type = None
            if cast_args is not None:
                if base[0].isupper() and base not in ("Math", "SafeMath", "SafeCast", "Strings", "Address"):
                    callee_type = base
                else:
                    continue
            elif base == "this":
                callee_type = cname
            elif base in state_user_types:
                callee_type = state_user_types[base]
            else:
                ptype = next((p["type"] for p in (fn["params"] if fn else []) if p.get("name") == base), None)
                if ptype and not ELEMENTARY_TYPES.match(ptype.split("[")[0].split(" ")[0]):
                    callee_type = re.sub(r"\[.*$", "", ptype)
                else:
                    continue
            if callee_type and declared_types.get(callee_type) == "library":
                continue
            scope = locate_scope(contract, offset)
            hints = classify_call_hint(method)
            signal = collector.add("external-call", offset, cname, scope, {
                "callee": base,
                "calleeType": callee_type,
                "method": method,
                "valueForwarded": bool(match.group(5) and "value" in match.group(5)),
                "categoryHints": hints,
            })
            calls.append({"contract": cname, "function": scope.get("function"), "line": signal["line"], "callee": base, "calleeType": callee_type, "method": method})
            external_call_offsets.append((offset, "external-call"))

        for match in ORACLE_METHOD_RE.finditer(body):
            offset = span_start + match.start()
            scope = locate_scope(contract, offset)
            fn = fn_at(offset)
            fbody = fn.get("_body", "") if fn else body
            method = match.group(1)
            provider = "generic"
            if method in ("latestRoundData", "latestAnswer"):
                provider = "chainlink"
            elif method == "getReserves":
                provider = "uniswap-v2"
            elif method in ("slot0", "observe"):
                provider = "uniswap-v3"
            collector.add("oracle-usage", offset, cname, scope, {
                "method": method,
                "provider": provider,
                "stalenessCheckInFunction": bool(re.search(r"updatedAt|answeredInRound|roundId|stale|heartbeat|maxAge|MAX_DELAY|timestamp\s*[<>]", fbody, re.I)),
                "balanceOfThisInFunction": bool(re.search(r"balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)", fbody)),
                "spotSource": method in ("getReserves", "slot0"),
            })

        for match in FLASH_RE.finditer(body):
            offset = span_start + match.start()
            scope = locate_scope(contract, offset)
            preceding = masked[max(span_start, offset - 12):offset]
            role = "reference"
            if re.search(r"function\s+$", preceding):
                role = "provider" if match.group(1).startswith("flash") else "receiver"
            elif preceding.rstrip().endswith("."):
                role = "caller"
            collector.add("flash-loan-surface", offset, cname, scope, {"identifier": match.group(1), "role": role})

        for match in SWAP_CALL_RE.finditer(body):
            offset = span_start + match.start()
            open_paren = span_start + match.end() - 1
            close_paren = matching_paren(masked, open_paren)
            if close_paren == -1:
                continue
            preceding = masked[max(span_start, offset - 10):offset]
            if re.search(r"function\s+$", preceding):
                continue
            args_text = masked[open_paren + 1:close_paren]
            args = [collapse_ws(part) for part in split_top_level(args_text)]
            zero_min = any(arg == "0" for arg in args) or MIN_AMOUNT_ZERO_RE.search(args_text) is not None
            deadline_now = any(arg == "block.timestamp" for arg in args) or re.search(r"deadline\s*:\s*block\.timestamp\b", args_text) is not None
            if zero_min or deadline_now:
                scope = locate_scope(contract, offset)
                collector.add("slippage-unprotected", offset, cname, scope, {"call": match.group(1), "zeroMinAmount": zero_min, "deadlineIsBlockTimestamp": deadline_now})

        for match in re.finditer(r"\.(approve|safeApprove|forceApprove|increaseAllowance)\s*\(", body):
            offset = span_start + match.start()
            open_paren = span_start + match.end() - 1
            close_paren = matching_paren(masked, open_paren)
            if close_paren == -1:
                continue
            args_text = collapse_ws(masked[open_paren + 1:close_paren])
            if re.search(r"type\s*\(\s*uint(256)?\s*\)\s*\.max|2\s*\*\*\s*256\s*-\s*1|uint256\s*\(\s*-\s*1\s*\)|MAX_UINT|MAX_INT|0x[fF]{64}", args_text):
                scope = locate_scope(contract, offset)
                collector.add("unlimited-approval", offset, cname, scope, {"method": match.group(1), "spender": split_top_level(args_text)[0] if split_top_level(args_text) else None})

        for match in SIGNATURE_RE.finditer(body):
            offset = span_start + match.start()
            scope = locate_scope(contract, offset)
            fn = fn_at(offset)
            fbody = fn.get("_body", "") if fn else ""
            collector.add("signature-replay-surface", offset, cname, scope, {
                "api": collapse_ws(match.group(0)).rstrip("("),
                "nonceFound": bool(re.search(r"\bnonces?\b", body, re.I)),
                "chainIdFound": bool(re.search(r"chainid|DOMAIN_SEPARATOR|EIP712|_domainSeparator|_hashTypedData|typedData", body, re.I)),
                "deadlineFound": bool(re.search(r"deadline|expir|validUntil|validBefore|notAfter", body, re.I)),
                "zeroAddressCheckInFunction": bool(re.search(r"address\s*\(\s*0\s*\)", fbody)),
                "usedSignatureTracking": bool(re.search(r"usedSignatures|_usedNonces|executed\s*\[|signatures\s*\[|usedHashes|processed\s*\[", body)),
            })

        for match in HARDCODED_ADDRESS_RE.finditer(body):
            offset = span_start + match.start()
            scope = locate_scope(contract, offset)
            stmt, _ = statement_at(masked, offset, span_start, span_end)
            collector.add("hardcoded-address", offset, cname, scope, {"value": match.group(0), "statement": truncate(collapse_ws(stmt), 120)[0]})

        for match in re.finditer(r"\bunchecked\s*\{", body):
            offset = span_start + match.start()
            open_brace = span_start + match.end() - 1
            close_brace = pairs.get(open_brace, span_end)
            block = masked[open_brace:close_brace]
            scope = locate_scope(contract, offset)
            collector.add("unchecked-block", offset, cname, scope, {
                "lineEnd": line_index.line_of(close_brace),
                "containsArithmetic": bool(re.search(r"[\w\)\]]\s*[+\-*]\s*[\w\(]|\+\+|--|[+\-*]=", block)),
                "containsSubtraction": bool(re.search(r"[\w\)\]]\s*-\s*[\w\(]|-=|--", block)),
            })

        for match in re.finditer(r"\bblock\.timestamp\b|(?<![\w.])now(?![\w(])", body):
            offset = span_start + match.start()
            scope = locate_scope(contract, offset)
            stmt, _ = statement_at(masked, offset, span_start, span_end)
            collapsed = collapse_ws(stmt)
            if RANDOM_USE_RE.search(collapsed):
                usage = "randomness"
            elif re.search(r"[<>]=?|==|!=", collapsed):
                usage = "comparison"
            elif re.search(r"[+\-*/]", collapsed):
                usage = "arithmetic"
            else:
                usage = "other"
            collector.add("timestamp-dependence", offset, cname, scope, {"usage": usage})

        seen_random: set = set()
        for match in RANDOM_SOURCE_RE.finditer(body):
            offset = span_start + match.start()
            stmt, stmt_start = statement_at(masked, offset, span_start, span_end)
            if stmt_start in seen_random:
                continue
            collapsed = collapse_ws(stmt)
            fn = fn_at(offset)
            fn_name = (fn["name"] or "") if fn else ""
            if not (RANDOM_USE_RE.search(collapsed) or RANDOM_FUNCTION_RE.search(fn_name)):
                continue
            seen_random.add(stmt_start)
            scope = locate_scope(contract, offset)
            sources = sorted(set(collapse_ws(m.group(0)).rstrip("(") for m in RANDOM_SOURCE_RE.finditer(collapsed)))
            collector.add("weak-randomness", offset, cname, scope, {
                "sources": sources,
                "usedWithHash": bool(re.search(r"keccak256|abi\.encodePacked|abi\.encode\b", collapsed)),
                "usedWithModulo": "%" in collapsed,
            })

        for match in DIVISION_RE.finditer(body):
            offset = span_start + match.start()
            if in_assembly(offset):
                continue
            stmt, _ = statement_at(masked, offset, span_start, span_end)
            collapsed = collapse_ws(stmt)
            if not re.search(r"=|\breturn\b", collapsed):
                continue
            scope = locate_scope(contract, offset)
            collector.add("division-before-multiplication", offset, cname, scope, {"expression": truncate(collapsed, 120)[0]})

        # loops
        for loop in loop_spans(masked, span_start, span_end, pairs):
            scope = locate_scope(contract, loop["start"])
            fn = fn_at(loop["start"])
            header = loop["header"]
            arrays: List[Dict[str, str]] = []
            for arr in re.findall(r"([A-Za-z_$][\w$.]*)\s*\.length\b", header):
                root = arr.split(".")[0]
                if root in state_types:
                    kind = "state"
                elif fn and root in param_names(fn):
                    kind = "parameter"
                else:
                    kind = "unknown"
                arrays.append({"name": arr, "kind": kind})
            no_condition = header.replace(" ", "") in ("", ";;", "true") or re.match(r"^\s*;\s*;\s*$", header) is not None
            loop_body = masked[loop["bodyStart"]:loop["bodyEnd"]]
            external_in_loop = any(loop["bodyStart"] <= off <= loop["bodyEnd"] for off, _ in external_call_offsets)
            msg_value_in_loop = re.search(r"\bmsg\.value\b", loop_body) is not None
            state_write_in_loop = bool(state_names) and any(re.search(r"\b" + re.escape(name) + r"\b(\s*\[[^\]]*\])*\s*(=(?!=)|\+=|-=|\+\+|--)|\b" + re.escape(name) + r"\s*\.\s*push\s*\(", loop_body) for name in state_names)
            unbounded = no_condition or any(a["kind"] in ("state", "unknown") for a in arrays) or (external_in_loop and bool(arrays))
            if unbounded:
                collector.add("unbounded-loop", loop["start"], cname, scope, {
                    "loopKind": loop["kind"],
                    "arrays": arrays,
                    "noCondition": no_condition,
                    "externalCallInLoop": external_in_loop,
                    "msgValueInLoop": msg_value_in_loop,
                    "stateWriteInLoop": state_write_in_loop,
                    "lineEnd": line_index.line_of(loop["bodyEnd"]),
                })
            if msg_value_in_loop:
                mv = re.search(r"\bmsg\.value\b", loop_body)
                mv_offset = loop["bodyStart"] + (mv.start() if mv else 0)
                collector.add("msg-value-in-loop", mv_offset, cname, locate_scope(contract, mv_offset), {"loopLine": line_index.line_of(loop["start"])})

        # function-level detectors
        for fn in contract["functions"]:
            if fn["_bodyStart"] is None or fn["_bodyEnd"] is None:
                continue
            access = function_access_info(fn)
            fn["accessControl"] = access
            fn["stateChanging"] = fn["mutability"] not in ("view", "pure") and fn["hasBody"]
            fn["reentrancyGuarded"] = is_reentrancy_guarded(fn)
            scope = {"function": fn["name"] or fn["kind"], "modifier": None, "kind": fn["kind"]}
            head_offset = fn["_headStart"]
            name = fn["name"] or ""
            public = fn["visibility"] in ("public", "external")

            if public and INITIALIZER_NAME_RE.match(name) and fn["stateChanging"]:
                guarded_by_modifier = any(INITIALIZER_GUARD_RE.match(m["name"]) for m in fn["modifiers"])
                guarded_by_body = bool(INITIALIZED_BODY_RE.search(fn["_body"])) or access["guarded"]
                if not (guarded_by_modifier or guarded_by_body):
                    collector.add("initializer-unprotected", head_offset, cname, scope, {"name": name, "visibility": fn["visibility"], "modifiers": [m["name"] for m in fn["modifiers"]]})

            if public and fn["stateChanging"] and fn["kind"] in ("function", "constructor"):
                unchecked_params: List[str] = []
                modifier_args = " ".join((m["args"] or "") for m in fn["modifiers"])
                for param in fn["params"]:
                    pname = param.get("name")
                    if not pname or not param.get("isAddress"):
                        continue
                    pattern = re.compile(ZERO_ADDRESS_RE_TEMPLATE.format(p=re.escape(pname)))
                    if pattern.search(fn["_body"]) or re.search(r"\b" + re.escape(pname) + r"\b", modifier_args):
                        continue
                    unchecked_params.append(pname)
                if unchecked_params:
                    collector.add("zero-address-unchecked", head_offset, cname, scope, {"params": unchecked_params, "kind": fn["kind"]})

            if public and fn["stateChanging"] and fn["kind"] == "function" and UPGRADE_FUNCTION_RE.match(name) is None and INITIALIZER_NAME_RE.match(name) is None and ADMIN_NAME_RE.match(name) and not ADMIN_NAME_EXCLUDE_RE.match(name) and not access["guarded"]:
                collector.add("admin-function-unprotected", head_offset, cname, scope, {"name": name, "visibility": fn["visibility"], "modifiers": [m["name"] for m in fn["modifiers"]], "writesState": bool(find_state_writes(fn["_body"], fn["_bodyStart"] + 1, fn["_bodyStart"] + 1, state_names, line_index)[0]) or bool(INTERNAL_STATE_CALL_RE.search(fn["_body"]))})

            if UPGRADE_FUNCTION_RE.match(name):
                body_stripped = re.sub(r"\s+", "", fn["_body"])
                collector.add("upgrade-function", head_offset, cname, scope, {"name": name, "visibility": fn["visibility"], "guarded": access["guarded"], "guards": access["modifiers"] + access["bodyGuards"], "emptyBody": body_stripped == "" or body_stripped == "{}"})

            if fn["stateChanging"] and not fn["reentrancyGuarded"]:
                in_fn = sorted(off for off, kind in external_call_offsets if fn["_bodyStart"] <= off <= fn["_bodyEnd"] and kind != "eth-transfer")
                if in_fn:
                    first_call = in_fn[0]
                    writes, internal_calls = find_state_writes(masked[fn["_bodyStart"]:fn["_bodyEnd"]], fn["_bodyStart"], first_call, state_names, line_index)
                    if writes or internal_calls:
                        collector.add("reentrancy-pattern", first_call, cname, scope, {
                            "callLine": line_index.line_of(first_call),
                            "stateWritesAfterCall": writes,
                            "internalCallsAfterCall": internal_calls,
                            "guarded": False,
                            "externalCallCount": len(in_fn),
                        })

        # contract-level detectors
        if cname is not None:
            function_names = [fn["name"] for fn in contract["functions"] if fn["name"]]
            indicators: List[str] = []
            for base in contract["bases"]:
                if PROXY_BASE_RE.search(base):
                    indicators.append("base:" + base)
            contract_original = original[contract["_start"]:contract["_bodyEnd"]]
            for slot in KNOWN_PUBLIC_SLOTS:
                if slot in contract_original.lower():
                    indicators.append("storage-slot-constant")
                    break
            for item in entry["strings"]:
                if contract["_start"] <= item["start"] <= contract["_bodyEnd"] and re.search(r"eip1967|org\.zeppelinos|PROXIABLE|eip1822", item["text"], re.I):
                    indicators.append("storage-slot-string")
                    break
            for fname in function_names:
                if PROXY_FUNCTION_RE.match(fname):
                    indicators.append("function:" + fname)
            for fn in contract["functions"]:
                if fn["kind"] == "fallback" and re.search(r"delegatecall", fn.get("_body", "")):
                    indicators.append("fallback-delegatecall")
            if re.search(r"\bsstore\s*\(", body) and assembly_spans:
                indicators.append("assembly-sstore")
            if indicators:
                has_initializer = any(INITIALIZER_NAME_RE.match(n) for n in function_names)
                ctor = next((fn for fn in contract["functions"] if fn["kind"] == "constructor"), None)
                collector.add("proxy-pattern", contract["_start"], cname, {"function": None, "modifier": None, "kind": None}, {
                    "indicators": sorted(set(indicators)),
                    "hasInitializer": has_initializer,
                    "constructorDisablesInitializers": bool(ctor and "_disableInitializers" in ctor.get("_body", "")),
                })
            transfer_fn = next((n for n in function_names if OWNERSHIP_TRANSFER_RE.match(n)), None)
            inherits_ownable = any(re.match(r"^Ownable(Upgradeable)?$", b) for b in contract["bases"])
            two_step = any(TWO_STEP_RE.search(b) for b in contract["bases"]) or any(TWO_STEP_RE.search(n) for n in function_names) or any(TWO_STEP_RE.search(v["name"]) for v in contract["stateVariables"])
            if (transfer_fn or inherits_ownable) and not two_step:
                fn = next((f for f in contract["functions"] if f["name"] == transfer_fn), None)
                offset = fn["_headStart"] if fn else contract["_start"]
                collector.add("single-step-ownership-transfer", offset, cname, locate_scope(contract, offset), {"function": transfer_fn, "inherited": transfer_fn is None and inherits_ownable})

    collector.signals.sort(key=lambda s: (s["line"], s["column"], s["family"]))
    return collector.signals, calls


# ---------------------------------------------------------------------------
# Vyper (limited coverage): inventory plus a small, explicit signal set
# ---------------------------------------------------------------------------

VYPER_VERSION_RE = re.compile(r"^\s*#\s*(?:@version|pragma\s+version)\s+(.+?)\s*$", re.M)
VYPER_DEF_RE = re.compile(r"^(?P<indent>[ \t]*)def\s+(?P<name>\w+)\s*\((?P<params>[^)]*)\)\s*(?:->\s*(?P<ret>[^:]+))?:", re.M)
VYPER_DECORATOR_RE = re.compile(r"^\s*@(\w+)(?:\(([^)]*)\))?\s*$")
VYPER_INTERFACE_RE = re.compile(r"^interface\s+(\w+)\s*:", re.M)
VYPER_IMPORT_RE = re.compile(r"^(?:from\s+([\w.]+)\s+)?import\s+([\w.]+)(?:\s+as\s+(\w+))?\s*$", re.M)
VYPER_IMPLEMENTS_RE = re.compile(r"^implements\s*:\s*(\w+)", re.M)
VYPER_STATE_RE = re.compile(r"^(?P<name>\w+)\s*:\s*(?P<type>(?:public|immutable|constant)\s*\(.+\)|[^=\n]+?)\s*(?:=\s*(?P<init>.+))?$", re.M)
VYPER_SIGNAL_FAMILIES = ("tx-origin", "selfdestruct", "timestamp-dependence", "weak-randomness", "low-level-call", "delegatecall", "reentrancy-pattern", "pragma-missing", "floating-pragma")


def parse_vyper_structure(masked: str, original: str, line_index: LineIndex, path: str) -> Dict[str, Any]:
    issues: List[str] = []
    version_match = VYPER_VERSION_RE.search(original)
    pragma = {"present": False, "expression": None, "minVersion": None, "floating": None, "line": None}
    if version_match:
        expr = collapse_ws(version_match.group(1))
        versions = [tuple(int(p) for p in m.groups()) for m in VERSION_RE.finditer(expr)]
        pragma = {
            "present": True,
            "expression": expr,
            "minVersion": ".".join(str(p) for p in min(versions)) if versions else None,
            "floating": not re.match(r"^=?\s*\d+\.\d+\.\d+$", expr),
            "line": line_index.line_of(version_match.start()),
        }
    imports = []
    for match in VYPER_IMPORT_RE.finditer(masked):
        module = match.group(2)
        package = match.group(1)
        imports.append({"path": (package + "." if package else "") + module, "line": line_index.line_of(match.start()), "shape": "module", "symbols": [], "alias": match.group(3)})
    implements = [m.group(1) for m in VYPER_IMPLEMENTS_RE.finditer(masked)]
    interfaces = [{"name": m.group(1), "line": line_index.line_of(m.start())} for m in VYPER_INTERFACE_RE.finditer(masked)]
    lines = masked.split("\n")
    functions: List[Dict[str, Any]] = []
    for match in VYPER_DEF_RE.finditer(masked):
        indent = len(match.group("indent").replace("\t", "    "))
        start_line = line_index.line_of(match.start())
        # decorators are the contiguous @lines immediately above
        decorators: List[Dict[str, Any]] = []
        probe = start_line - 1
        while probe >= 1:
            dec = VYPER_DECORATOR_RE.match(lines[probe - 1])
            if not dec:
                break
            decorators.insert(0, {"name": dec.group(1), "args": dec.group(2)})
            probe -= 1
        end_line = start_line
        for idx in range(start_line, len(lines)):
            text = lines[idx]
            if not text.strip():
                continue
            current_indent = len(text) - len(text.lstrip(" \t"))
            if current_indent <= indent and idx + 1 > start_line:
                break
            end_line = idx + 1
        names = [d["name"] for d in decorators]
        visibility = "external" if "external" in names else "internal" if "internal" in names else "deploy" if "deploy" in names else None
        mutability = "view" if "view" in names else "pure" if "pure" in names else "payable" if "payable" in names else "nonpayable"
        body = "\n".join(lines[start_line:end_line])
        is_interface_member = indent > 0
        functions.append({
            "name": match.group("name"),
            "kind": "function" if match.group("name") != "__init__" else "constructor",
            "lineStart": start_line - len(decorators),
            "lineEnd": end_line,
            "visibility": visibility,
            "mutability": mutability,
            "modifiers": [{"name": d["name"], "args": d["args"]} for d in decorators if d["name"] not in ("external", "internal", "view", "pure", "payable", "deploy")],
            "params": parse_params(match.group("params").replace(":", " ")),
            "returns": collapse_ws(match.group("ret")) if match.group("ret") else None,
            "virtual": False,
            "override": False,
            "hasBody": not is_interface_member,
            "signatureText": collapse_ws(match.group(0))[:200],
            "interfaceMember": is_interface_member,
            "_body": body,
            "_bodyStartLine": start_line + 1,
            "_headStart": match.start(),
        })
    state_vars: List[Dict[str, Any]] = []
    for match in VYPER_STATE_RE.finditer(masked):
        name = match.group("name")
        if name in ("implements", "interface", "event", "struct", "enum", "flag", "from", "import"):
            continue
        if match.group("type").strip().endswith(":"):
            continue
        type_text = collapse_ws(match.group("type"))
        state_vars.append({
            "name": name,
            "type": type_text,
            "visibility": "public" if type_text.startswith("public") else "internal",
            "constant": type_text.startswith("constant"),
            "immutable": type_text.startswith("immutable"),
            "line": line_index.line_of(match.start()),
            "ownerLike": bool(OWNER_LIKE_RE.match(name)),
            "userType": None,
        })
    stem = os.path.splitext(os.path.basename(path))[0]
    contract = {
        "name": stem,
        "kind": "contract",
        "lineStart": 1,
        "lineEnd": line_index.count,
        "bases": implements,
        "functions": [fn for fn in functions if not fn["interfaceMember"]],
        "modifiers": [],
        "stateVariables": state_vars,
        "usingFor": [],
        "truncated": False,
        "interfaces": interfaces,
    }
    return {"pragma": pragma, "imports": imports, "contracts": [contract], "freeFunctions": [], "usingFor": [], "issues": issues, "pairs": {}}


def detect_vyper_signals(entry: Dict[str, Any]) -> List[Dict[str, Any]]:
    masked: str = entry["masked"]
    line_index: LineIndex = entry["lineIndex"]
    structure = entry["structure"]
    collector = SignalCollector(entry["path"], line_index)
    contract = structure["contracts"][0]
    cname = contract["name"]
    pragma = structure["pragma"]
    if not pragma["present"]:
        collector.add("pragma-missing", 0, cname, {"function": None, "modifier": None, "kind": None}, {"language": "vyper"}, line=1)
    elif pragma["floating"]:
        collector.add("floating-pragma", line_index.offset_of_line(pragma["line"]), cname, {"function": None, "modifier": None, "kind": None}, {"expression": pragma["expression"], "minVersion": pragma["minVersion"]}, line=pragma["line"])

    def scope_for(offset: int) -> Dict[str, Optional[str]]:
        line = line_index.line_of(offset)
        for fn in contract["functions"]:
            if fn["lineStart"] <= line <= fn["lineEnd"]:
                return {"function": fn["name"], "modifier": None, "kind": fn["kind"]}
        return {"function": None, "modifier": None, "kind": None}

    for match in re.finditer(r"\btx\.origin\b", masked):
        collector.add("tx-origin", match.start(), cname, scope_for(match.start()), {"inCondition": True})
    for match in re.finditer(r"\bselfdestruct\s*\(", masked):
        collector.add("selfdestruct", match.start(), cname, scope_for(match.start()), {"guarded": False, "inAssembly": False})
    for match in re.finditer(r"\bblock\.timestamp\b", masked):
        stmt = collapse_ws(line_index.line_text(line_index.line_of(match.start())))
        usage = "randomness" if RANDOM_USE_RE.search(stmt) else "comparison" if re.search(r"[<>]=?|==|!=", stmt) else "other"
        collector.add("timestamp-dependence", match.start(), cname, scope_for(match.start()), {"usage": usage})
    for match in re.finditer(r"\bblock\.prevrandao\b|\bblock\.difficulty\b|\bblockhash\s*\(", masked):
        stmt = collapse_ws(line_index.line_text(line_index.line_of(match.start())))
        collector.add("weak-randomness", match.start(), cname, scope_for(match.start()), {"sources": [collapse_ws(match.group(0)).rstrip("(")], "usedWithHash": "keccak256" in stmt, "usedWithModulo": "%" in stmt})
    call_offsets: List[int] = []
    for match in re.finditer(r"\b(raw_call|send)\s*\(", masked):
        open_paren = match.end() - 1
        close_paren = matching_paren(masked, open_paren)
        args = collapse_ws(masked[open_paren + 1:close_paren]) if close_paren != -1 else ""
        is_delegate = "is_delegate_call=True" in args.replace(" ", "")
        scope = scope_for(match.start())
        if is_delegate:
            collector.add("delegatecall", match.start(), cname, scope, {"target": split_top_level(args)[0] if split_top_level(args) else None, "inAssembly": False, "targetIsParameter": False, "inFallback": scope.get("function") == "__default__", "guarded": False})
        line_text = collapse_ws(line_index.line_text(line_index.line_of(match.start())))
        prefix = line_text[:line_text.find(match.group(1))]
        checked = "=" in prefix or "assert" in prefix or "revert_on_failure=False" not in args.replace(" ", "")
        collector.add("low-level-call", match.start(), cname, scope, {"kind": match.group(1), "target": split_top_level(args)[0] if split_top_level(args) else None, "returnChecked": checked, "valueForwarded": "value=" in args.replace(" ", ""), "targetIsParameter": False})
        call_offsets.append(match.start())
    for fn in contract["functions"]:
        if fn["visibility"] != "external" or fn["mutability"] in ("view", "pure"):
            continue
        guarded = any(m["name"] == "nonreentrant" for m in fn["modifiers"])
        fn_calls = [off for off in call_offsets if fn["lineStart"] <= line_index.line_of(off) <= fn["lineEnd"]]
        if fn_calls and not guarded:
            first = fn_calls[0]
            after = masked[first:line_index.offset_of_line(fn["lineEnd"]) + len(line_index.line_text(fn["lineEnd"]))]
            writes = sorted(set(line_index.line_of(first + m.start()) for m in re.finditer(r"\bself\.\w+(\[[^\]]*\])?\s*(=(?!=)|\+=|-=)", after)))
            if writes:
                collector.add("reentrancy-pattern", first, cname, {"function": fn["name"], "modifier": None, "kind": fn["kind"]}, {"callLine": line_index.line_of(first), "stateWritesAfterCall": writes, "internalCallsAfterCall": [], "guarded": False, "externalCallCount": len(fn_calls)})
        fn["accessControl"] = {"modifiers": [], "bodyGuards": sorted(set(collapse_ws(m.group(0)) for m in re.finditer(r"msg\.sender\s*==\s*self\.\w+|assert\s+msg\.sender", fn["_body"]))), "guarded": bool(re.search(r"msg\.sender\s*==|assert\s+msg\.sender", fn["_body"]))}
        fn["stateChanging"] = True
        fn["reentrancyGuarded"] = guarded
    collector.signals.sort(key=lambda s: (s["line"], s["column"], s["family"]))
    return collector.signals


# ---------------------------------------------------------------------------
# Input collection
# ---------------------------------------------------------------------------

def collect_inputs(paths: List[str], stdin_text: Optional[str]) -> List[Dict[str, Any]]:
    """Return raw entries: path, data (bytes) or text, origin, issues."""
    entries: List[Dict[str, Any]] = []
    if stdin_text is not None:
        if looks_like_bundle(stdin_text):
            for item in parse_bundle(stdin_text, "stdin"):
                entries.append({"path": item["path"], "text": item["text"], "origin": "stdin-bundle", "issues": item["issues"]})
        else:
            language = detect_language("stdin", stdin_text)
            ext = ".vy" if language == "vyper" else ".sol"
            entries.append({"path": "stdin" + ext, "text": stdin_text, "origin": "stdin", "issues": []})
    for raw_path in paths:
        if not os.path.exists(raw_path):
            raise PreprocessError("input path does not exist: %s" % raw_path)
        if os.path.isdir(raw_path):
            for current, dirnames, filenames in os.walk(raw_path):
                dirnames[:] = sorted(d for d in dirnames if d not in (".git", "node_modules", "__pycache__", ".venv", "venv"))
                for filename in sorted(filenames):
                    full = os.path.join(current, filename)
                    _, ext = os.path.splitext(filename.lower())
                    stem = filename.lower().split(".")[0]
                    if ext in SOURCE_EXTENSIONS or ext in DOCUMENT_EXTENSIONS or stem in DOCUMENT_BASENAMES:
                        rel = normalize_path(os.path.relpath(full, raw_path))
                        with open(full, "rb") as handle:
                            entries.append({"path": rel, "data": handle.read(), "origin": "directory", "issues": []})
        else:
            with open(raw_path, "rb") as handle:
                data = handle.read()
            text, _, _ = normalize_text(data)
            if text is not None and looks_like_bundle(text):
                for item in parse_bundle(text, raw_path):
                    entries.append({"path": item["path"], "text": item["text"], "origin": "file-bundle", "issues": item["issues"]})
            else:
                entries.append({"path": normalize_path(os.path.basename(raw_path)), "data": data, "origin": "file", "issues": []})
    # Deterministic order and unique paths
    seen: Dict[str, int] = {}
    for entry in entries:
        count = seen.get(entry["path"], 0)
        seen[entry["path"]] = count + 1
        if count:
            entry["path"] = "%s#%d" % (entry["path"], count + 1)
    entries.sort(key=lambda item: item["path"])
    return entries


# ---------------------------------------------------------------------------
# Per-file processing
# ---------------------------------------------------------------------------

def process_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    if "text" in entry:
        text, endings, error = entry["text"], "lf", None
    else:
        text, endings, error = normalize_text(entry["data"])
    path = entry["path"]
    result: Dict[str, Any] = {
        "path": path,
        "origin": entry["origin"],
        "language": detect_language(path, text),
        "lineEndings": endings,
        "issues": list(entry.get("issues", [])),
        "text": text,
    }
    if text is None:
        result["kind"] = "unreadable"
        result["hash"] = "sha256:" + hashlib.sha256(entry.get("data", b"")).hexdigest()
        result["issues"].append(error or "unreadable")
        result["lines"] = {"total": 0, "effective": 0, "blank": 0, "commentOnly": 0}
        return result
    result["hash"] = sha256_text(text)
    if not text.strip():
        result["kind"] = "empty"
        result["lines"] = {"total": 0, "effective": 0, "blank": 0, "commentOnly": 0}
        return result
    language = result["language"]
    if language == "documentation":
        result["kind"] = "documentation"
        result["lines"] = {"total": text.count("\n") + (0 if text.endswith("\n") else 1), "effective": 0, "blank": 0, "commentOnly": 0}
        return result
    if language not in ("solidity", "vyper"):
        result["kind"] = "unsupported"
        result["lines"] = {"total": text.count("\n") + (0 if text.endswith("\n") else 1), "effective": 0, "blank": 0, "commentOnly": 0}
        return result
    result["kind"] = "source"
    mask = mask_solidity(text) if language == "solidity" else mask_vyper(text)
    result["masked"] = mask["masked"]
    result["commentSpans"] = mask["comments"]
    result["strings"] = mask["strings"]
    result["issues"].extend(mask["issues"])
    result["lines"] = line_metrics(text, mask["masked"])
    line_index = LineIndex(text)
    result["lineIndex"] = line_index
    if language == "solidity":
        result["structure"] = parse_solidity_structure(mask["masked"], text, line_index)
    else:
        result["structure"] = parse_vyper_structure(mask["masked"], text, line_index, path)
    result["issues"].extend(result["structure"]["issues"])
    return result


def parse_confidence(entry: Dict[str, Any]) -> Dict[str, Any]:
    score = 1.0
    issues = entry.get("issues", [])
    for issue in issues:
        if "unclosed" in issue or "unmatched" in issue:
            score -= 0.3
        elif "unterminated block comment" in issue or "missing END FILE" in issue:
            score -= 0.2
        elif "could not parse" in issue:
            score -= 0.1
        elif "unterminated" in issue:
            score -= 0.05
    if entry.get("language") == "vyper":
        score = min(score, 0.7)
    score = max(0.0, round(score, 2))
    label = "high" if score >= 0.9 else "medium" if score >= 0.6 else "low"
    return {"score": score, "label": label, "issues": sorted(set(issues))}


def build_comments(entry: Dict[str, Any], contract_public: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    line_index: LineIndex = entry["lineIndex"]
    declarations: List[Tuple[int, str, Optional[str], Optional[str]]] = []
    for contract in contract_public:
        declarations.append((contract["lineStart"], "contract", contract["name"], None))
        for fn in contract["functions"]:
            declarations.append((fn["lineStart"], "function", contract["name"], fn["name"] or fn["kind"]))
        for mod in contract["modifiers"]:
            declarations.append((mod["lineStart"], "modifier", contract["name"], mod["name"]))
    declarations.sort(key=lambda item: item[0])
    comments: List[Dict[str, Any]] = []
    for span in entry["commentSpans"]:
        start_line = line_index.line_of(span["start"])
        end_line = line_index.line_of(max(span["start"], span["end"] - 1))
        raw = span["text"]
        cleaned = re.sub(r"^\s*(///|//|/\*\*|/\*|\*/|\*|#)\s?", "", raw, flags=re.M)
        cleaned = re.sub(r"\*/\s*$", "", cleaned).strip()
        text, truncated = truncate(redact(cleaned, "comment"), MAX_COMMENT_CHARS)
        attached: Optional[Dict[str, Optional[str]]] = None
        for decl_line, decl_kind, contract_name, member in declarations:
            if end_line < decl_line <= end_line + 3:
                attached = {"kind": decl_kind, "contract": contract_name, "function": member if decl_kind == "function" else None, "modifier": member if decl_kind == "modifier" else None}
                break
        if attached is None:
            for contract in contract_public:
                if contract["lineStart"] <= start_line <= contract["lineEnd"]:
                    attached = {"kind": "inside", "contract": contract["name"], "function": None, "modifier": None}
                    for fn in contract["functions"]:
                        if fn["lineStart"] <= start_line <= fn["lineEnd"]:
                            attached["function"] = fn["name"] or fn["kind"]
                            break
                    break
        comments.append({
            "file": entry["path"],
            "lineStart": start_line,
            "lineEnd": end_line,
            "kind": span["kind"],
            "text": text,
            "truncated": truncated,
            "attachedTo": attached,
        })
    return comments


def scan_injections_and_secrets(entry: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    injections: List[Dict[str, Any]] = []
    secrets: List[Dict[str, Any]] = []
    path = entry["path"]
    text = entry.get("text") or ""
    kind = entry.get("kind")
    if kind == "documentation":
        line_index = LineIndex(text)
        for hit in find_injections(text):
            line = line_index.line_of(hit["start"])
            injections.append(_injection_record(path, line, "document", hit, line_index.line_text(line)))
        for item in find_secrets(text, "document"):
            secrets.append({"file": path, "line": line_index.line_of(item["start"]), "kind": item["kind"], "context": "document"})
        return injections, secrets
    if kind != "source":
        return injections, secrets
    line_index: LineIndex = entry["lineIndex"]
    for span in entry["commentSpans"]:
        for hit in find_injections(span["text"]):
            offset = span["start"] + hit["start"]
            line = line_index.line_of(offset)
            injections.append(_injection_record(path, line, "comment", hit, line_index.line_text(line)))
        for item in find_secrets(span["text"], "comment"):
            secrets.append({"file": path, "line": line_index.line_of(span["start"] + item["start"]), "kind": item["kind"], "context": "comment"})
    for span in entry["strings"]:
        for hit in find_injections(span["text"]):
            offset = span["start"] + hit["start"]
            line = line_index.line_of(offset)
            injections.append(_injection_record(path, line, "string", hit, line_index.line_text(line)))
        for item in find_secrets(span["text"], "string"):
            secrets.append({"file": path, "line": line_index.line_of(span["start"] + item["start"]), "kind": item["kind"], "context": "string"})
    for item in find_secrets(entry["masked"], "code"):
        secrets.append({"file": path, "line": line_index.line_of(item["start"]), "kind": item["kind"], "context": "code"})
    return injections, secrets


def _injection_record(path: str, line: int, source: str, hit: Dict[str, Any], line_text: str) -> Dict[str, Any]:
    snippet, _ = truncate(redact(collapse_ws(line_text)), 120)
    return {
        "file": path,
        "line": line,
        "source": source,
        "language": hit["language"],
        "pattern": hit["pattern"],
        "snippet": snippet,
        "categories": ["EXTRA-prompt-injection"],
        "weight": 0,
        "informational": True,
    }


# ---------------------------------------------------------------------------
# Cross-file resolution: declared types, imports, inheritance
# ---------------------------------------------------------------------------

def build_declared_types(processed: List[Dict[str, Any]]) -> Dict[str, str]:
    declared: Dict[str, str] = {}
    for entry in processed:
        if entry.get("language") != "solidity" or entry.get("kind") != "source":
            continue
        for contract in entry["structure"]["contracts"]:
            declared.setdefault(contract["name"], contract["kind"])
        for iface in entry["structure"].get("interfaces", []):
            declared.setdefault(iface["name"], "interface")
    return declared


def known_source_paths(processed: List[Dict[str, Any]]) -> Dict[str, str]:
    known: Dict[str, str] = {}
    for entry in processed:
        if entry.get("kind") != "source":
            continue
        path = entry["path"]
        known[path] = path
        stem = re.sub(r"\.(sol|vy)(#\d+)?$", "", path)
        known.setdefault(stem, path)
        known.setdefault(os.path.basename(path), path)
        known.setdefault(re.sub(r"\.(sol|vy)$", "", os.path.basename(path)), path)
    return known


def classify_import(import_path: Optional[str], importing_file: str, known_paths: Dict[str, str]) -> Dict[str, Any]:
    if not import_path:
        return {"path": import_path, "shape": "unknown", "resolved": False, "resolvedTo": None}
    if import_path.startswith("."):
        base_dir = os.path.dirname(importing_file)
        candidate = normalize_path(os.path.normpath(os.path.join(base_dir, import_path)).replace(os.sep, "/"))
        target = known_paths.get(candidate) or known_paths.get(re.sub(r"\.(sol|vy)$", "", candidate))
        if target is None:
            target = known_paths.get(os.path.basename(candidate))
        return {"path": import_path, "shape": "relative", "resolved": target is not None, "resolvedTo": target}
    if import_path.startswith("@") or "/" in import_path and not import_path.startswith(("contracts/", "src/")):
        return {"path": import_path, "shape": "package", "resolved": False, "resolvedTo": None}
    target = known_paths.get(import_path) or known_paths.get(os.path.basename(import_path))
    if target is not None:
        return {"path": import_path, "shape": "absolute-local", "resolved": True, "resolvedTo": target}
    return {"path": import_path, "shape": "absolute-local", "resolved": False, "resolvedTo": None}


def resolve_bases(contract: Dict[str, Any], file_imports: List[Dict[str, Any]], declared_types: Dict[str, str]) -> Dict[str, List[Dict[str, Any]]]:
    resolved: List[Dict[str, Any]] = []
    unresolved: List[Dict[str, Any]] = []
    has_unresolved_relative_import = any(imp["shape"] == "relative" and not imp["resolved"] for imp in file_imports)
    has_package_import = any(imp["shape"] == "package" for imp in file_imports)
    for base in contract["bases"]:
        if base in declared_types:
            resolved.append({"name": base, "source": "bundle", "kind": declared_types[base]})
            continue
        if has_package_import:
            unresolved.append({"name": base, "source": "assumed-external-package"})
        elif has_unresolved_relative_import:
            unresolved.append({"name": base, "source": "unresolved-import"})
        else:
            unresolved.append({"name": base, "source": "unknown"})
    return {"resolved": resolved, "unresolved": unresolved}


# ---------------------------------------------------------------------------
# Public projection (strip internal bookkeeping fields)
# ---------------------------------------------------------------------------

def to_public(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: to_public(v) for k, v in value.items() if not k.startswith("_")}
    if isinstance(value, list):
        return [to_public(item) for item in value]
    return value


# ---------------------------------------------------------------------------
# Completeness and priority
# ---------------------------------------------------------------------------

def add_reason(reasons: List[Dict[str, str]], code: str, detail: str) -> None:
    reasons.append({"code": code, "detail": detail})


def compute_priority_ranking(processed: List[Dict[str, Any]], signals_by_file: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    ranking: List[Dict[str, Any]] = []
    for entry in processed:
        if entry.get("kind") != "source":
            continue
        signal_count = len(signals_by_file.get(entry["path"], []))
        public_state_changing = 0
        for contract in entry["structure"]["contracts"]:
            for fn in contract["functions"]:
                if fn.get("visibility") in ("public", "external") and fn.get("hasBody") and fn.get("mutability") not in ("view", "pure"):
                    public_state_changing += 1
        score = signal_count * 2 + public_state_changing
        ranking.append({
            "file": entry["path"],
            "signalCount": signal_count,
            "publicStateChangingFunctions": public_state_changing,
            "effectiveLoc": entry["lines"]["effective"],
            "priorityScore": score,
        })
    ranking.sort(key=lambda item: (-item["priorityScore"], item["file"]))
    return ranking


def compute_completeness(
    processed: List[Dict[str, Any]],
    import_records: List[Dict[str, Any]],
    base_records: List[Dict[str, Any]],
    mode: str,
    limits: Dict[str, Optional[int]],
    priority_ranking: List[Dict[str, Any]],
) -> Dict[str, Any]:
    reasons: List[Dict[str, str]] = []
    source_entries = [e for e in processed if e.get("kind") == "source"]

    if not source_entries:
        add_reason(reasons, "NO_ANALYZABLE_SOURCE", "No Solidity or Vyper source file could be analyzed.")
        return {"status": "failed", "reasons": reasons}

    for entry in processed:
        path = entry["path"]
        if entry["kind"] == "empty":
            add_reason(reasons, "EMPTY_FILE", "%s is empty." % path)
        elif entry["kind"] == "unreadable":
            add_reason(reasons, "ENCODING_ERROR", "%s could not be decoded as UTF-8." % path)
        elif entry["kind"] == "unsupported":
            add_reason(reasons, "UNSUPPORTED_LANGUAGE", "%s is not a supported source language and was inventoried without analysis." % path)
        elif entry["kind"] == "source":
            if entry["language"] == "vyper":
                add_reason(reasons, "VYPER_LIMITED", "%s is Vyper; signal coverage for Vyper is limited compared to Solidity." % path)
            confidence = entry.get("parseConfidenceResult", {})
            if confidence.get("label") == "low":
                add_reason(reasons, "LOW_PARSE_CONFIDENCE", "%s parsed with low confidence (%.2f); structural results may be inaccurate." % (path, confidence.get("score", 0.0)))
            for issue in entry.get("issues", []):
                if "unterminated" in issue:
                    add_reason(reasons, "UNTERMINATED_COMMENT", "%s: %s." % (path, issue))
            for contract in entry["structure"].get("contracts", []):
                if contract.get("truncated"):
                    add_reason(reasons, "TRUNCATED_FILE", "Contract '%s' in %s has an unclosed brace; its boundaries may be inaccurate." % (contract["name"], path))

    for record in import_records:
        if record["shape"] == "relative" and not record["resolved"]:
            add_reason(reasons, "MISSING_IMPORT", "Import '%s' referenced in %s was not found among the provided files." % (record["path"], record["file"]))

    for record in base_records:
        if record["source"] in ("unresolved-import", "unknown"):
            add_reason(reasons, "UNRESOLVED_BASE", "Base contract '%s' used by %s#%s was not found among the provided files or resolvable imports." % (record["base"], record["file"], record["contract"]))

    total_effective_loc = sum(e["lines"]["effective"] for e in source_entries)
    max_loc = limits.get("maxEffectiveLoc")
    if max_loc is not None and total_effective_loc > max_loc:
        add_reason(reasons, "LOC_LIMIT_EXCEEDED", "Effective LOC (%d) exceeds the %s mode limit (%d); no file was truncated, see priorityRanking." % (total_effective_loc, mode, max_loc))

    max_files = limits.get("maxSourceFiles")
    if max_files is not None and len(source_entries) > max_files:
        add_reason(reasons, "FILE_LIMIT_EXCEEDED", "%d source files exceed the %s mode file limit (%d); no file was excluded, see priorityRanking." % (len(source_entries), mode, max_files))

    status = "partial" if reasons else "complete"
    return {"status": status, "reasons": reasons}


# ---------------------------------------------------------------------------
# Artifact assembly
# ---------------------------------------------------------------------------

def compute_input_hash(processed: List[Dict[str, Any]]) -> str:
    parts = sorted("%s:%s" % (e["path"], e["hash"]) for e in processed)
    digest = hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()
    return "sha256:" + digest


def build_artifact(
    processed: List[Dict[str, Any]],
    *,
    mode: str,
    limits: Dict[str, Optional[int]],
    include_timestamp: bool,
) -> Dict[str, Any]:
    declared_types = build_declared_types(processed)
    known_paths = known_source_paths(processed)

    signals_by_file: Dict[str, List[Dict[str, Any]]] = {}
    all_signals: List[Dict[str, Any]] = []
    all_calls: List[Dict[str, Any]] = []
    all_comments: List[Dict[str, Any]] = []
    context_documents: List[Dict[str, Any]] = []
    all_injections: List[Dict[str, Any]] = []
    all_secrets: List[Dict[str, Any]] = []
    files_out: List[Dict[str, Any]] = []
    contracts_out: List[Dict[str, Any]] = []
    free_functions_out: List[Dict[str, Any]] = []
    import_records: List[Dict[str, Any]] = []
    base_records: List[Dict[str, Any]] = []

    for entry in processed:
        path = entry["path"]
        confidence = parse_confidence(entry) if entry["kind"] == "source" else {"score": 1.0, "label": "high", "issues": []}
        entry["parseConfidenceResult"] = confidence

        if entry["kind"] == "documentation":
            text, truncated = truncate(redact(entry.get("text") or "", "document"), MAX_DOCUMENT_CHARS)
            context_documents.append({"path": path, "text": text, "truncated": truncated})
            injections, secrets = scan_injections_and_secrets(entry)
            all_injections.extend(injections)
            all_secrets.extend(secrets)

        file_record: Dict[str, Any] = {
            "path": path,
            "origin": entry["origin"],
            "language": entry["language"],
            "kind": entry["kind"],
            "hash": entry["hash"],
            "lineEndings": entry["lineEndings"],
            "lines": entry["lines"],
            "issues": sorted(set(entry.get("issues", []))),
        }
        if entry["kind"] == "source":
            file_record["parseConfidence"] = confidence
            file_record["pragma"] = entry["structure"]["pragma"]

            for imp in entry["structure"]["imports"]:
                classified = classify_import(imp["path"], path, known_paths)
                record = {"file": path, "line": imp["line"], "shape": classified["shape"], "path": imp["path"], "resolved": classified["resolved"], "resolvedTo": classified["resolvedTo"], "symbols": imp.get("symbols", []), "alias": imp.get("alias")}
                import_records.append(record)

            signals, calls = ([], [])
            if entry["language"] == "solidity":
                signals, calls = detect_solidity_signals(entry, declared_types)
            elif entry["language"] == "vyper":
                signals = detect_vyper_signals(entry)
            signals_by_file[path] = signals
            all_signals.extend(signals)
            all_calls.extend(calls)

            file_imports_classified = [classify_import(imp["path"], path, known_paths) for imp in entry["structure"]["imports"]]
            for contract in entry["structure"]["contracts"]:
                bases_resolution = resolve_bases(contract, file_imports_classified, declared_types)
                for item in bases_resolution["unresolved"]:
                    base_records.append({"file": path, "contract": contract["name"], "base": item["name"], "source": item["source"]})
                public_contract = to_public(contract)
                public_contract["file"] = path
                public_contract["key"] = "%s#%s" % (path, contract["name"]) if contract["name"] else None
                public_contract["basesResolved"] = bases_resolution["resolved"]
                public_contract["basesUnresolved"] = bases_resolution["unresolved"]
                contracts_out.append(public_contract)

            for fn in entry["structure"]["freeFunctions"]:
                public_fn = to_public(fn)
                public_fn["file"] = path
                free_functions_out.append(public_fn)

            all_comments.extend(build_comments(entry, entry["structure"]["contracts"]))
            injections, secrets = scan_injections_and_secrets(entry)
            all_injections.extend(injections)
            all_secrets.extend(secrets)

        files_out.append(file_record)

    all_signals.sort(key=lambda s: (s["file"], s["line"], s["column"], s["family"]))
    all_calls.sort(key=lambda c: (c.get("contract") or "", c.get("function") or "", c["line"]))
    all_comments.sort(key=lambda c: (c["file"], c["lineStart"]))
    all_injections.sort(key=lambda i: (i["file"], i["line"], i["pattern"]))
    all_secrets.sort(key=lambda s: (s["file"], s["line"]))
    contracts_out.sort(key=lambda c: (c["file"], c["lineStart"]))
    free_functions_out.sort(key=lambda f: (f["file"], f["lineStart"]))
    import_records.sort(key=lambda i: (i["file"], i["line"]))

    priority_ranking = compute_priority_ranking(processed, signals_by_file)
    completeness = compute_completeness(processed, import_records, base_records, mode, limits, priority_ranking)

    totals = {
        "sourceFiles": sum(1 for e in processed if e["kind"] == "source"),
        "totalFiles": len(processed),
        "totalEffectiveLoc": sum(e["lines"]["effective"] for e in processed if e["kind"] == "source"),
        "totalLoc": sum(e["lines"]["total"] for e in processed if e["kind"] == "source"),
    }

    artifact: Dict[str, Any] = {
        "generatedBy": GENERATED_BY,
        "preprocessVersion": PREPROCESS_VERSION,
        "checklistVersion": CHECKLIST_VERSION,
        "signalRegistryVersion": SIGNAL_REGISTRY_VERSION,
        "mode": mode,
        "limits": limits,
        "inputHash": compute_input_hash(processed),
        "totals": totals,
        "files": files_out,
        "contracts": contracts_out,
        "freeFunctions": free_functions_out,
        "imports": import_records,
        "signals": all_signals,
        "calls": all_calls,
        "comments": all_comments,
        "contextDocuments": context_documents,
        "injectionSignals": all_injections,
        "secretsDetected": bool(all_secrets),
        "secrets": all_secrets,
        "completeness": completeness,
        "priorityRanking": priority_ranking,
        "categories": CATEGORIES,
    }
    if include_timestamp:
        artifact["timestamp"] = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return artifact


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def resolve_limits(mode: str, max_loc_override: Optional[int]) -> Dict[str, Optional[int]]:
    limits = dict(PROVISIONAL_LIMITS.get(mode, PROVISIONAL_LIMITS[DEFAULT_MODE]))
    if max_loc_override is not None:
        limits["maxEffectiveLoc"] = max_loc_override
    return limits


def run(paths: List[str], *, mode: str, max_loc: Optional[int], use_stdin: bool, include_timestamp: bool) -> Dict[str, Any]:
    stdin_text = None
    if use_stdin:
        raw = sys.stdin.buffer.read()
        stdin_text, _, error = normalize_text(raw)
        if stdin_text is None:
            raise PreprocessError("stdin could not be decoded as UTF-8: %s" % error)
        if not stdin_text.strip():
            stdin_text = None
    if not paths and stdin_text is None:
        raise PreprocessError("no input provided: pass file/directory paths or pipe a bundle via stdin")
    entries = collect_inputs(paths, stdin_text)
    if not entries:
        raise PreprocessError("no analyzable input found")
    processed = [process_entry(entry) for entry in entries]
    limits = resolve_limits(mode, max_loc)
    return build_artifact(processed, mode=mode, limits=limits, include_timestamp=include_timestamp)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="preprocess.py",
        description="Deterministic preprocessing for smart contract source files. "
                     "Outputs a JSON artifact with inventory and heuristic signals. "
                     "Signals are hints, not findings.",
    )
    parser.add_argument("paths", nargs="*", help="Source files or directories to analyze.")
    parser.add_argument("--mode", choices=sorted(PROVISIONAL_LIMITS.keys()), default=DEFAULT_MODE, help="Review mode; sets provisional LOC limits.")
    parser.add_argument("--max-loc", type=int, default=None, help="Override the mode's maxEffectiveLoc limit.")
    parser.add_argument("--no-timestamp", action="store_true", help="Omit the timestamp field (useful for reproducibility tests).")
    parser.add_argument("--indent", type=int, default=2, help="JSON indentation (0 for compact output).")
    return parser


def _force_utf8_stdio() -> None:
    """Some platforms (notably Windows) default stdout/stdin to a legacy code
    page when not attached to a tty. Source may contain non-ASCII text in any
    language, so force UTF-8 explicitly rather than relying on locale."""
    for stream_name in ("stdin", "stdout"):
        stream = getattr(sys, stream_name, None)
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8")
            except (ValueError, OSError):
                pass


def main(argv: Optional[List[str]] = None) -> int:
    _force_utf8_stdio()
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    use_stdin = not args.paths and not sys.stdin.isatty()
    try:
        artifact = run(
            args.paths,
            mode=args.mode,
            max_loc=args.max_loc,
            use_stdin=use_stdin,
            include_timestamp=not args.no_timestamp,
        )
    except PreprocessError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stdout)
        return EXIT_FAILED
    indent = args.indent if args.indent > 0 else None
    print(json.dumps(artifact, ensure_ascii=False, indent=indent, sort_keys=True))
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
