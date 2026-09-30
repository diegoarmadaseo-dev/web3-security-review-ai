#!/usr/bin/env python3
"""Versioned, lossless serialization of the Step 6 context artifact
(phase 15K-A - docs/decisiones.md D-096).

WHY THIS EXISTS: the preprocess artifact embedded in the Step 6 prompt is
bounded by context_selection.APPLICATION_CONTEXT_BUDGET_BYTES, and a
measurement over real Solidity code showed that ~36% of its canonical
JSON bytes are repeated key names and that every file-scoped record
repeats its full "file" path. This module provides an alternative,
STRICTLY LOSSLESS representation of the very same JSON value that
removes that structural overhead, plus the one measuring function
context selection and the prompt both use, so the bytes the selector
counts are exactly the bytes the prompt embeds.

FORMATS (the identifier is the version - never reused for a different
encoding; a future change gets a new identifier):
  * CONTEXT_FORMAT_V1 ("canonical-json-v1") - the current, default
    representation: json.dumps(artifact, ensure_ascii=False), byte-for-byte
    what Step 6 always embedded. Always available as the fallback.
  * CONTEXT_FORMAT_V2 ("compact-v2") - opt-in. A self-identifying
    envelope {"contextArtifactFormat":"compact-v2","artifact":<encoded>}
    serialized with compact separators (no insignificant whitespace).

compact-v2 RULES (purely structural - no schema-dependent omission, no
semantic heuristic, nothing dropped: every null, false, empty string,
empty list and empty object is kept exactly as it was):
  1. Table: a maximal run of >= 2 CONSECUTIVE objects in a list whose key
     sequences are identical (same keys, same order, at least one key)
     becomes {"$t": [[k1, k2, ...], [v1, v2, ...], ...]} - the header
     once, then one positional row per object. The values are encoded
     recursively.
  2. Segments: a list mixing tables with other items becomes
     {"$l": [segment, ...]}, each segment either {"$t": ...} or
     {"$i": [item, ...]} (items encoded recursively), concatenated in
     order. A list with no table stays a plain list; a list that is one
     single table is just {"$t": ...}.
  3. File runs: ONLY for the top-level file-scoped sections
     (FILE_RUN_SECTIONS) and only when EVERY record there is an object
     whose "file" value is a string: consecutive records sharing the same
     "file" value and the same position of the "file" key are stored once
     as [file, position, <records without "file", encoded as a list>]
     inside {"$r": [...]}. Decoding re-inserts "file" at that exact
     position, so even key order is restored.
  4. Escape: an ORIGINAL object whose only key is one of the reserved
     directive names (RESERVED_KEYS) is wrapped as {"$o": {...}} (its
     values still encoded recursively), so no input can ever be mistaken
     for a directive. Every other object is encoded key by key; a
     single-key object whose key is reserved is therefore ALWAYS a
     directive, and nothing else ever is.

LOSSLESS, PROVEN BY CONSTRUCTION: each rule is a bijection on the JSON
data model (tables and runs only move keys that are provably identical
across the grouped records; escapes remove the only possible ambiguity),
and decode_context_artifact() applies the exact inverses. For any JSON
value x: decode(encode(x)) == x, and json.dumps(decode(encode(x)),
ensure_ascii=False) is byte-identical to the canonical v1 form (object
key order included) - see tests/test_backend_context_encoding.py.
"Lossless" is defined over the JSON data model, exactly as for v1
itself: a Python tuple serializes as a JSON array in both formats.

DETERMINISM: a pure function of the input value (including its key
order); no clock, no randomness, no set/dict-order dependence, no
sorting. Same input -> same bytes.

Standard library only. Never calls an LLM.
"""
from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Tuple

CONTEXT_FORMAT_V1 = "canonical-json-v1"
CONTEXT_FORMAT_V2 = "compact-v2"
SUPPORTED_CONTEXT_FORMATS = (CONTEXT_FORMAT_V1, CONTEXT_FORMAT_V2)

FORMAT_FIELD = "contextArtifactFormat"
DATA_FIELD = "artifact"

_TABLE = "$t"
_SEGMENTS = "$l"
_ITEMS = "$i"
_FILE_RUNS = "$r"
_ESCAPED = "$o"
RESERVED_KEYS = frozenset({_TABLE, _SEGMENTS, _ITEMS, _FILE_RUNS, _ESCAPED})

# The preprocess artifact's file-scoped record lists (the same six
# collections context_selection._filtered_artifact() filters by "file").
FILE_RUN_SECTIONS = ("contracts", "freeFunctions", "imports", "signals", "calls", "comments")


class ContextEncodingError(ValueError):
    """Unknown format identifier, or a document that is not a valid
    encoding of the format it claims to be."""


def check_context_format(context_format: str) -> str:
    if context_format not in SUPPORTED_CONTEXT_FORMATS:
        raise ContextEncodingError(
            "unknown context artifact format %r (supported: %s)" % (context_format, ", ".join(SUPPORTED_CONTEXT_FORMATS))
        )
    return context_format


# ---------------------------------------------------------------------------
# Encoding
# ---------------------------------------------------------------------------

def _encode_value(value: Any) -> Any:
    if isinstance(value, dict):
        return _encode_object(value)
    if isinstance(value, (list, tuple)):
        return _encode_list(list(value))
    return value


def _encode_object(obj: Dict[str, Any]) -> Dict[str, Any]:
    encoded = {key: _encode_value(item) for key, item in obj.items()}
    if len(obj) == 1 and next(iter(obj)) in RESERVED_KEYS:
        return {_ESCAPED: encoded}
    return encoded


def _key_signature(item: Any) -> Tuple[str, ...]:
    """The key sequence of an object (order-sensitive), or () for anything
    that can never join a table (non-objects, empty objects, and objects
    with a non-string key - JSON would coerce that key to a string, which a
    table header must not do on the model's behalf)."""
    if isinstance(item, dict) and item and all(isinstance(key, str) for key in item):
        return tuple(item.keys())
    return ()


def _encode_list(items: List[Any]) -> Any:
    segments: List[Tuple[str, Any]] = []
    index = 0
    while index < len(items):
        signature = _key_signature(items[index])
        end = index + 1
        if signature:
            while end < len(items) and _key_signature(items[end]) == signature:
                end += 1
        if signature and end - index >= 2:
            header = list(signature)
            rows = [[_encode_value(row[key]) for key in signature] for row in items[index:end]]
            segments.append(("table", {_TABLE: [header] + rows}))
        else:
            encoded_item = _encode_value(items[index])
            if segments and segments[-1][0] == "items":
                segments[-1][1].append(encoded_item)
            else:
                segments.append(("items", [encoded_item]))
        index = end
    if not any(kind == "table" for kind, _ in segments):
        return segments[0][1] if segments else []
    if len(segments) == 1:
        return segments[0][1]
    return {_SEGMENTS: [payload if kind == "table" else {_ITEMS: payload} for kind, payload in segments]}


def _encode_file_runs(records: List[Any]) -> Any:
    """Rule 3. Falls back to the generic list encoding unless every record
    is an object with a string "file" value."""
    if not records or not all(isinstance(r, dict) and isinstance(r.get("file"), str) for r in records):
        return _encode_list(records)
    runs: List[Tuple[str, int, List[Dict[str, Any]]]] = []
    for record in records:
        position = list(record.keys()).index("file")
        stripped = {key: item for key, item in record.items() if key != "file"}
        if runs and runs[-1][0] == record["file"] and runs[-1][1] == position:
            runs[-1][2].append(stripped)
        else:
            runs.append((record["file"], position, [stripped]))
    return {_FILE_RUNS: [[path, position, _encode_list(group)] for path, position, group in runs]}


def _encode_artifact_v2(artifact: Any) -> Any:
    if not isinstance(artifact, dict):
        return _encode_value(artifact)
    encoded = {
        key: (_encode_file_runs(item) if key in FILE_RUN_SECTIONS and isinstance(item, list) else _encode_value(item))
        for key, item in artifact.items()
    }
    if len(artifact) == 1 and next(iter(artifact)) in RESERVED_KEYS:
        return {_ESCAPED: encoded}
    return encoded


def encode_context_artifact(artifact: Any, context_format: str = CONTEXT_FORMAT_V1) -> str:
    """The exact text Step 6 embeds for `artifact` in `context_format`."""
    check_context_format(context_format)
    if context_format == CONTEXT_FORMAT_V1:
        return json.dumps(artifact, ensure_ascii=False)
    envelope = {FORMAT_FIELD: CONTEXT_FORMAT_V2, DATA_FIELD: _encode_artifact_v2(artifact)}
    return json.dumps(envelope, ensure_ascii=False, separators=(",", ":"))


def context_artifact_bytes(artifact: Any, context_format: str = CONTEXT_FORMAT_V1) -> int:
    """UTF-8 byte length of encode_context_artifact(artifact, context_format)."""
    return len(encode_context_artifact(artifact, context_format).encode("utf-8"))


def context_bytes_measure(context_format: str) -> Callable[[Any], int]:
    """The measuring function context_selection.select_context() is given,
    so selection counts exactly the representation the prompt embeds."""
    check_context_format(context_format)
    return lambda value: context_artifact_bytes(value, context_format)


# ---------------------------------------------------------------------------
# Decoding (the exact inverse; used by tests and by anyone auditing a prompt)
# ---------------------------------------------------------------------------

def _decode_value(value: Any) -> Any:
    if isinstance(value, list):
        return [_decode_value(item) for item in value]
    if not isinstance(value, dict):
        return value
    if len(value) == 1:
        (key, payload), = value.items()
        if key == _TABLE:
            return _decode_table(payload)
        if key == _SEGMENTS:
            return _decode_segments(payload)
        if key == _FILE_RUNS:
            return _decode_file_runs(payload)
        if key == _ESCAPED:
            if not isinstance(payload, dict):
                raise ContextEncodingError("%s payload must be an object" % _ESCAPED)
            return {inner_key: _decode_value(item) for inner_key, item in payload.items()}
        if key == _ITEMS:
            raise ContextEncodingError("%s is only valid as a %s segment" % (_ITEMS, _SEGMENTS))
    return {key: _decode_value(item) for key, item in value.items()}


def _decode_table(payload: Any) -> List[Dict[str, Any]]:
    if not isinstance(payload, list) or len(payload) < 3 or not isinstance(payload[0], list) or not payload[0]:
        raise ContextEncodingError("%s must be [header, row, row, ...] with a non-empty header and >= 2 rows" % _TABLE)
    header = payload[0]
    if not all(isinstance(key, str) for key in header) or len(set(header)) != len(header):
        raise ContextEncodingError("%s header must be distinct strings" % _TABLE)
    out = []
    for row in payload[1:]:
        if not isinstance(row, list) or len(row) != len(header):
            raise ContextEncodingError("%s row width does not match its header" % _TABLE)
        out.append({key: _decode_value(item) for key, item in zip(header, row)})
    return out


def _decode_segments(payload: Any) -> List[Any]:
    if not isinstance(payload, list):
        raise ContextEncodingError("%s payload must be a list of segments" % _SEGMENTS)
    out: List[Any] = []
    for segment in payload:
        if isinstance(segment, dict) and len(segment) == 1 and _TABLE in segment:
            out.extend(_decode_table(segment[_TABLE]))
        elif isinstance(segment, dict) and len(segment) == 1 and _ITEMS in segment and isinstance(segment[_ITEMS], list):
            out.extend(_decode_value(item) for item in segment[_ITEMS])
        else:
            raise ContextEncodingError("%s segments must be {%s: ...} or {%s: [...]}" % (_SEGMENTS, _TABLE, _ITEMS))
    return out


def _decode_file_runs(payload: Any) -> List[Dict[str, Any]]:
    if not isinstance(payload, list):
        raise ContextEncodingError("%s payload must be a list of runs" % _FILE_RUNS)
    out: List[Dict[str, Any]] = []
    for run in payload:
        if not (isinstance(run, list) and len(run) == 3 and isinstance(run[0], str) and isinstance(run[1], int) and not isinstance(run[1], bool)):
            raise ContextEncodingError("%s runs must be [file, position, records]" % _FILE_RUNS)
        path, position, records = run
        decoded = _decode_value(records)
        if not isinstance(decoded, list):
            raise ContextEncodingError("%s run records must decode to a list" % _FILE_RUNS)
        for record in decoded:
            if not isinstance(record, dict) or "file" in record or not 0 <= position <= len(record):
                raise ContextEncodingError("%s run record is inconsistent with its file position" % _FILE_RUNS)
            items = list(record.items())
            items.insert(position, ("file", path))
            out.append(dict(items))
    return out


def decode_context_artifact(text: str, context_format: str) -> Any:
    """Inverse of encode_context_artifact(). Strict: the document must be
    a valid encoding of exactly `context_format`."""
    check_context_format(context_format)
    document = json.loads(text)
    if context_format == CONTEXT_FORMAT_V1:
        return document
    if not (isinstance(document, dict) and set(document) == {FORMAT_FIELD, DATA_FIELD} and document[FORMAT_FIELD] == CONTEXT_FORMAT_V2):
        raise ContextEncodingError("document is not a %s envelope" % CONTEXT_FORMAT_V2)
    return _decode_value(document[DATA_FIELD])


# ---------------------------------------------------------------------------
# Prompt legend
# ---------------------------------------------------------------------------

_V2_PROMPT_LEGEND = (
    "Artifact encoding: the preprocessed artifact below is in the lossless \"compact-v2\" format "
    "(envelope {\"contextArtifactFormat\":\"compact-v2\",\"artifact\":...}); it carries exactly the same "
    "information as plain JSON. Read it as follows - an object whose ONLY key is one of these is an encoding "
    "directive, anything else is literal data: "
    "{\"$t\":[[k1,k2,...],[v1,v2,...],...]} is an array of objects, the first array being the keys and each "
    "following array one object's values in that key order; "
    "{\"$l\":[...]} is one array made by concatenating its segments in order, each segment being a {\"$t\":...} "
    "table or {\"$i\":[...]} plain items; "
    "{\"$r\":[[file,position,records],...]} (only in contracts, freeFunctions, imports, signals, calls, comments) "
    "is the section's records in order, where every record of a run has \"file\" equal to that run's file; "
    "{\"$o\":{...}} is a literal object whose keys are taken as-is. "
    "Report file paths exactly as they appear in the artifact.\n\n"
)


def prompt_legend(context_format: str) -> str:
    """Fixed-size explanation the prompt carries for a non-default format;
    "" for v1, so a v1 prompt is byte-identical to before this module."""
    check_context_format(context_format)
    return _V2_PROMPT_LEGEND if context_format == CONTEXT_FORMAT_V2 else ""
