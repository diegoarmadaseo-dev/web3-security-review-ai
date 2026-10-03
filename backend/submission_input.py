#!/usr/bin/env python3
"""Multi-file and ZIP scan submissions (docs/decisiones.md D-109).

ONE REPRESENTATION, THE ENGINE'S OWN: the analysis engine already accepts a
multi-file project as a single "=== FILE: <path> === ... === END FILE ==="
bundle (scripts/preprocess.py looks_like_bundle()/parse_bundle(), which keep
every path, so imports and inheritance resolve across files). This module
only VALIDATES a list of files - sent as JSON or inside a ZIP - and builds
that canonical bundle text. Everything downstream is the existing
single-source path, unchanged: the same 2 MiB raw-size ceiling, the same
effective-LOC count (backend/loc_count.py, the engine's own lexer), the same
commercial admission, the same object storage, the same worker. A ZIP and
the same files sent individually build byte-identical bundles, so they count
identically.

FILE POLICY = preprocess.collect_inputs()'s own directory policy: Solidity/
Vyper sources (.sol, .vy) and documentation (.md/.markdown/.txt/.rst,
README/LICENSE/NOTICE/CHANGELOG) are kept; anything else, and anything
under .git/, node_modules/, __pycache__/, .venv/, venv/ (plus __MACOSX/,
archive-tool residue) is IGNORED and reported back, never analysed or
counted. At least one source file is required (no_source_files).

PATH SAFETY (every entry, kept or ignored): no absolute path, drive letter,
backslash, NUL/control character, empty or "." segment, or ".." segment;
bounded length and depth. A kept path must also use a conservative charset
(letters, digits, . _ - @ +) - a source file outside it is refused, a
documentation file outside it is ignored. Exact and case-insensitive
duplicates are refused (ambiguous on case-insensitive filesystems and for
import resolution). A line in any kept file that would read as a bundle
marker is refused, so file content can never forge another file.

ZIP SAFETY: the archive is read from memory (io.BytesIO) and NOTHING is ever
extracted to disk - no temporary directory exists, so nothing can be written
outside one and nothing is left behind on success or failure. Compressed
size, number of entries, and total DECOMPRESSED bytes of kept files are all
bounded; decompression reads at most the remaining byte budget + 1, so a
ZIP bomb is stopped by what is actually decompressed, never by the sizes
the archive declares. Symlinks and encrypted entries are refused; ignored
entries are never decompressed at all; a malformed archive (bad structure,
bad CRC, unsupported compression) is refused as a whole.

Standard library only. No I/O besides reading the given bytes.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import io
import re
import stat
import zipfile
import zlib
from typing import Any, Dict, List, Optional, Tuple

import backend.loc_count as loc_count

MAX_SUBMISSION_FILES = 500            # kept files per scan (and items in a "files" array)
MAX_ARCHIVE_BYTES = 4 * 1024 * 1024   # compressed ZIP size
MAX_ARCHIVE_ENTRIES = 2000            # every central-directory entry, kept or not
MAX_PATH_LENGTH = 400
MAX_PATH_DEPTH = 32
MAX_REPORTED_IGNORED = 100            # ignored paths echoed back (the count is always exact)

IGNORED_DIRECTORIES = frozenset({".git", "node_modules", "__pycache__", ".venv", "venv", "__MACOSX"})
_SAFE_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._@+\-]{1,128}$")
_DRIVE_RE = re.compile(r"^[A-Za-z]:")

KIND_SOURCE = "source"
KIND_DOCUMENT = "document"
KIND_IGNORED = "ignored"


class SubmissionInputError(Exception):
    """A refused multi-file/ZIP submission. `code` is stable and
    machine-readable; `http_status` is what the HTTP layer answers."""

    def __init__(self, code: str, detail: str, http_status: int = 400) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail
        self.http_status = http_status


def _refuse(code: str, detail: str, http_status: int = 400) -> None:
    raise SubmissionInputError(code, detail, http_status)


def check_path(path: Any) -> str:
    """Universal path check for every entry (kept or ignored). Returns the
    path unchanged - it is already canonical - or raises invalid_path."""
    if not isinstance(path, str) or not path:
        _refuse("invalid_path", "every file needs a non-empty relative path")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in path):
        _refuse("invalid_path", "path %r contains a control character" % path)
    if "\\" in path:
        _refuse("invalid_path", "path %r uses a backslash; use '/' separators" % path)
    if path.startswith("/") or _DRIVE_RE.match(path):
        _refuse("invalid_path", "path %r is absolute; only relative paths are allowed" % path)
    if len(path) > MAX_PATH_LENGTH:
        _refuse("invalid_path", "path %r is longer than %d characters" % (path[:60] + "...", MAX_PATH_LENGTH))
    segments = path.split("/")
    if len(segments) > MAX_PATH_DEPTH:
        _refuse("invalid_path", "path %r is deeper than %d levels" % (path, MAX_PATH_DEPTH))
    for segment in segments:
        if segment == "..":
            _refuse("invalid_path", "path %r leaves the project root ('..')" % path)
        if segment in ("", "."):
            _refuse("invalid_path", "path %r has an empty or '.' segment" % path)
    return path


def classify(path: str) -> str:
    """source | document | ignored, by preprocess.py's own extension policy."""
    segments = path.split("/")
    if any(segment in IGNORED_DIRECTORIES for segment in segments[:-1]):
        return KIND_IGNORED
    base = segments[-1].lower()
    ext = ("." + base.rsplit(".", 1)[1]) if "." in base else ""
    if ext in loc_count.SOURCE_EXTENSIONS:
        return KIND_SOURCE
    if ext in loc_count.DOCUMENT_EXTENSIONS or base.split(".")[0] in loc_count.DOCUMENT_BASENAMES:
        return KIND_DOCUMENT
    return KIND_IGNORED


def _decode(data: bytes) -> Optional[str]:
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _has_bundle_marker(text: str) -> bool:
    for line in text.split("\n"):
        stripped = line.rstrip()
        if loc_count.BUNDLE_START_RE.match(stripped) or loc_count.BUNDLE_END_RE.match(stripped):
            return True
    return False


def build_bundle(files: List[Dict[str, str]]) -> str:
    """The canonical engine bundle for already-validated files, sorted by
    path. One trailing newline per file is folded into the END marker line,
    so the text the engine reads back for each file is the file itself."""
    parts = []
    for item in sorted(files, key=lambda f: f["path"]):
        text = item["text"][:-1] if item["text"].endswith("\n") else item["text"]
        parts.append("=== FILE: %s ===\n%s\n=== END FILE ===\n" % (item["path"], text))
    return "".join(parts)


def _assemble(raw_entries: List[Tuple[str, Optional[bytes]]], max_source_bytes: int, origin: str) -> Dict[str, Any]:
    """Shared validation for both input shapes. raw_entries holds every
    entry's path; content is None for an entry already known to be ignored
    (never decompressed)."""
    seen_exact = set()
    seen_folded: Dict[str, str] = {}
    kept: List[Dict[str, Any]] = []
    ignored: List[str] = []
    for path, data in raw_entries:
        check_path(path)
        if path in seen_exact:
            _refuse("duplicate_path", "path %r appears more than once" % path)
        seen_exact.add(path)
        kind = classify(path)
        if kind != KIND_IGNORED and not all(_SAFE_SEGMENT_RE.match(s) for s in path.split("/")):
            if kind == KIND_SOURCE:
                _refuse("invalid_path", "source path %r may only use letters, digits and . _ - @ +" % path)
            kind = KIND_IGNORED
        if kind == KIND_IGNORED or data is None:
            ignored.append(path)
            continue
        folded = path.lower()
        if folded in seen_folded:
            _refuse("duplicate_path", "paths %r and %r differ only by letter case" % (seen_folded[folded], path))
        seen_folded[folded] = path
        text = _decode(data)
        if text is None or _has_bundle_marker(text):
            if kind == KIND_DOCUMENT:
                ignored.append(path)
                continue
            if text is None:
                _refuse("file_not_utf8", "source file %r is not valid UTF-8 text" % path)
            _refuse("reserved_marker", "source file %r contains a line that reads as a '=== FILE: ... ===' / '=== END FILE ===' marker" % path)
        kept.append({"path": path, "kind": kind, "text": text, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    if len(kept) > MAX_SUBMISSION_FILES:
        _refuse("too_many_files", "%d files would be analysed; at most %d per scan" % (len(kept), MAX_SUBMISSION_FILES), 413)
    if not any(item["kind"] == KIND_SOURCE for item in kept):
        _refuse("no_source_files", "no Solidity (.sol) or Vyper (.vy) source file was found in the %s" % origin, 422)
    bundle = build_bundle(kept)
    if len(bundle.encode("utf-8")) > max_source_bytes:
        _refuse("submission_too_large", "the files exceed the maximum submission size (%d bytes)" % max_source_bytes, 413)
    manifest = []
    for item in sorted(kept, key=lambda f: f["path"]):
        language = loc_count.detect_language(item["path"], item["text"]) if item["kind"] == KIND_SOURCE else "documentation"
        manifest.append({"path": item["path"], "language": language, "size_bytes": item["bytes"], "sha256": item["sha256"],
                         "effective_loc": loc_count.entry_effective_loc(item["path"], item["text"])})
    ignored_sorted = sorted(ignored)
    return {"source": bundle, "files": manifest, "ignored": ignored_sorted[:MAX_REPORTED_IGNORED], "ignored_count": len(ignored_sorted)}


def from_files(files: Any, max_source_bytes: int) -> Dict[str, Any]:
    """A JSON "files" array: [{"path": "...", "content": "..."}, ...]."""
    if not isinstance(files, list) or not files:
        _refuse("invalid_files", "files must be a non-empty array of {path, content} objects")
    if len(files) > MAX_SUBMISSION_FILES:
        _refuse("too_many_files", "%d files sent; at most %d per scan" % (len(files), MAX_SUBMISSION_FILES), 413)
    entries: List[Tuple[str, Optional[bytes]]] = []
    total = 0
    for item in files:
        if not isinstance(item, dict) or set(item) - {"path", "content"} or not isinstance(item.get("path"), str) or not isinstance(item.get("content"), str):
            _refuse("invalid_files", "each file must be an object with exactly a string path and a string content")
        try:
            data = item["content"].encode("utf-8")
        except UnicodeEncodeError:
            _refuse("file_not_utf8", "file %r is not valid Unicode text (unpaired surrogate)" % item["path"])
        if classify(check_path(item["path"])) != KIND_IGNORED:   # ignored files are never analysed, so never budgeted (same as ZIP)
            total += len(data)
        if total > max_source_bytes:
            _refuse("submission_too_large", "the files exceed the maximum submission size (%d bytes)" % max_source_bytes, 413)
        entries.append((item["path"], data))
    return _assemble(entries, max_source_bytes, "submitted files")


def decode_archive(archive: Any) -> bytes:
    """{"format": "zip", "content_base64": "..."} -> the archive bytes."""
    if not isinstance(archive, dict) or set(archive) - {"format", "content_base64"}:
        _refuse("invalid_archive", "archive must be an object {format, content_base64}")
    if archive.get("format") != "zip":
        _refuse("unsupported_archive_format", "only format 'zip' is supported")
    encoded = archive.get("content_base64")
    if not isinstance(encoded, str) or not encoded:
        _refuse("invalid_archive", "archive.content_base64 must be a non-empty base64 string")
    if len(encoded) > (MAX_ARCHIVE_BYTES + 2) // 3 * 4 + 4:
        _refuse("archive_too_large", "the archive exceeds %d bytes" % MAX_ARCHIVE_BYTES, 413)
    try:
        data = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        _refuse("invalid_archive", "archive.content_base64 is not valid base64")
    if len(data) > MAX_ARCHIVE_BYTES:
        _refuse("archive_too_large", "the archive exceeds %d bytes" % MAX_ARCHIVE_BYTES, 413)
    return data


_MALFORMED = (zipfile.BadZipFile, zipfile.LargeZipFile, zlib.error, EOFError, OSError, ValueError, NotImplementedError, RuntimeError, KeyError, IndexError)


def from_zip(data: bytes, max_source_bytes: int) -> Dict[str, Any]:
    """A ZIP archive's bytes, validated and read entirely in memory."""
    if len(data) > MAX_ARCHIVE_BYTES:
        _refuse("archive_too_large", "the archive exceeds %d bytes" % MAX_ARCHIVE_BYTES, 413)
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        infos = archive.infolist()
    except _MALFORMED:
        _refuse("archive_malformed", "the archive is not a readable ZIP file")
    with archive:
        if len(infos) > MAX_ARCHIVE_ENTRIES:
            _refuse("too_many_files", "the archive has %d entries; at most %d" % (len(infos), MAX_ARCHIVE_ENTRIES), 413)
        entries: List[Tuple[str, Optional[bytes]]] = []
        remaining = max_source_bytes
        for info in infos:
            name = info.filename
            # zipfile rewrites "\\" to "/" in filename on Windows only;
            # orig_filename is the name exactly as stored, so a backslash is
            # refused identically on every platform.
            if "\\" in info.orig_filename:
                _refuse("invalid_path", "archive entry %r uses a backslash; use '/' separators" % info.orig_filename)
            is_dir = name.endswith("/")
            check_path(name[:-1] if is_dir else name)
            if stat.S_ISLNK(info.external_attr >> 16):
                _refuse("archive_symlink", "the archive entry %r is a symbolic link" % name)
            if info.flag_bits & 0x1:
                _refuse("archive_encrypted", "the archive entry %r is encrypted" % name)
            if is_dir:
                continue
            if classify(name) == KIND_IGNORED:
                entries.append((name, None))      # never decompressed
                continue
            try:
                with archive.open(info) as handle:
                    content = handle.read(remaining + 1)
            except _MALFORMED:
                _refuse("archive_malformed", "the archive entry %r cannot be read (corrupt or unsupported compression)" % name)
            if len(content) > remaining:
                _refuse("archive_uncompressed_too_large", "the archive's files decompress to more than %d bytes" % max_source_bytes, 413)
            remaining -= len(content)
            entries.append((name, content))
    return _assemble(entries, max_source_bytes, "archive")
