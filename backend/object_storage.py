#!/usr/bin/env python3
"""Object storage abstraction (Phase 4 execution infrastructure,
docs/decisiones.md D-077 follow-up). Source code and rendered reports
live here, never as a filesystem path or DB blob column - contracts.
storage_ref/reports.storage_ref (Phase 1) are always an opaque KEY into
whichever adapter is configured, never inspected or built from raw
client input.

Two adapters, same ObjectStorage interface:
  * LocalFilesystemStorage - dev/test only. Signed URLs are HMAC-signed
    opaque tokens (key + expiry, verified by verify_signed_url()) rather
    than a real cloud signature - same shape a real presigned URL has
    (short-lived, tamper-evident, no separate auth check needed to use
    it), fully testable with no cloud credentials.
  * S3Storage - production. boto3 is imported lazily/optionally, same
    pattern as backend/db.py's psycopg import and backend/billing.py's
    stripe import: an environment that only ever runs tests never needs
    it installed, and this module degrades to "S3Storage raises
    ObjectStorageError if constructed", never a silent fallback.

Key naming: workspace_key() is the ONE place a key is built - always
"<category>/<workspace_id>/<object_id>", every component validated
against path traversal/injection before use. No code path anywhere
accepts a caller-supplied full key from an HTTP request body - see
backend/http_app.py's job-submission handler.

Standard library only for the local adapter. No LLM calls.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import time
from typing import Any, Optional, Protocol
from urllib.parse import parse_qs, quote, unquote, urlsplit

try:
    import boto3
except ImportError:  # optional - see module docstring.
    boto3 = None


class ObjectStorageError(Exception):
    """Raised for storage-layer misuse or a genuine backend failure -
    never silently swallowed (mirrors backend/billing.BillingError)."""


class SignedUrlError(ObjectStorageError):
    """A signed URL failed to verify - missing/malformed/tampered
    signature or an expired timestamp. The caller (backend/http_app.py)
    must turn this into a clean 403/404, never leak which check failed."""


def workspace_key(workspace_id: str, category: str, object_id: str) -> str:
    """The one place an object key is constructed - every component
    validated (non-empty, no path separators, no '..') so a key can
    never escape its own category/workspace prefix or be built from
    unvalidated client input. category is a fixed, code-chosen string
    ("sources"/"reports"), never client-supplied."""
    for name, part in (("workspace_id", workspace_id), ("category", category), ("object_id", object_id)):
        if not isinstance(part, str) or not part or "/" in part or "\\" in part or ".." in part:
            raise ObjectStorageError("invalid key component %s=%r" % (name, part))
    return "%s/%s/%s" % (category, workspace_id, object_id)


class ObjectStorage(Protocol):
    def put_object(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> None: ...
    def get_object(self, key: str) -> bytes: ...
    def delete_object(self, key: str) -> None: ...
    def object_exists(self, key: str) -> bool: ...
    def generate_signed_url(self, key: str, expires_in_seconds: int) -> str: ...


def _sign(secret: bytes, key: str, expires_at: int) -> str:
    message = ("%s:%d" % (key, expires_at)).encode("utf-8")
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


class LocalFilesystemStorage:
    """Dev/test adapter - one file per key under root_dir. Never used in
    production (see S3Storage); exists so this whole module, and every
    caller of it, is testable with no cloud account at all."""

    def __init__(self, root_dir: str, sign_secret: str, base_path: str = "/storage/"):
        if not sign_secret:
            raise ObjectStorageError("sign_secret is required")
        os.makedirs(root_dir, exist_ok=True)
        self._root = os.path.abspath(root_dir)
        self._secret = sign_secret.encode("utf-8")
        self._base_path = base_path if base_path.endswith("/") else base_path + "/"

    def _path(self, key: str) -> str:
        # workspace_key() already rejects '..'/separators in each
        # component, but this is the storage layer's own last line of
        # defense against ever writing/reading outside root_dir.
        candidate = os.path.abspath(os.path.join(self._root, key))
        if candidate != self._root and not candidate.startswith(self._root + os.sep):
            raise ObjectStorageError("key escapes storage root: %r" % (key,))
        return candidate

    def put_object(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> None:
        path = self._path(key)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(data)

    def get_object(self, key: str) -> bytes:
        try:
            with open(self._path(key), "rb") as handle:
                return handle.read()
        except FileNotFoundError:
            raise ObjectStorageError("object not found: %r" % (key,))

    def delete_object(self, key: str) -> None:
        try:
            os.remove(self._path(key))
        except FileNotFoundError:
            pass  # already gone - idempotent, matches repository.py's own delete conventions.

    def object_exists(self, key: str) -> bool:
        return os.path.isfile(self._path(key))

    def generate_signed_url(self, key: str, expires_in_seconds: int) -> str:
        expires_at = int(time.time()) + expires_in_seconds
        signature = _sign(self._secret, key, expires_at)
        return "%s%s?expires=%d&sig=%s" % (self._base_path, quote(key, safe=""), expires_at, signature)

    def verify_signed_url(self, url: str) -> bytes:
        """Verifies a URL THIS adapter generated (signature + not
        expired) and returns the object's bytes, or raises
        SignedUrlError - never ObjectStorageError's other subtypes, so
        the caller can map this one exception type straight to 403."""
        parsed = urlsplit(url)
        if not parsed.path.startswith(self._base_path):
            raise SignedUrlError("not a signed URL this adapter issued")
        key = unquote(parsed.path[len(self._base_path):])
        params = parse_qs(parsed.query)
        try:
            expires_at = int(params["expires"][0])
            signature = params["sig"][0]
        except (KeyError, IndexError, ValueError):
            raise SignedUrlError("missing or malformed signature parameters")
        expected = _sign(self._secret, key, expires_at)
        if not hmac.compare_digest(expected, signature):
            raise SignedUrlError("signature does not match")
        if int(time.time()) >= expires_at:
            raise SignedUrlError("signed URL has expired")
        return self.get_object(key)


class S3Storage:
    """Production adapter. boto3 is optional/lazy - see module
    docstring. Server-side encryption is always requested explicitly
    (never relies on a bucket default that could be reconfigured)."""

    def __init__(self, bucket: str, region: str, access_key_id: Optional[str] = None, secret_access_key: Optional[str] = None) -> None:
        if boto3 is None:
            raise ObjectStorageError('the "boto3" package is not installed - object storage in production needs it; local/test use never does.')
        if not bucket:
            raise ObjectStorageError("bucket is required")
        self._bucket = bucket
        self._client = boto3.client(
            "s3", region_name=region,
            aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key,
        )

    def put_object(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> None:
        self._client.put_object(Bucket=self._bucket, Key=key, Body=data, ContentType=content_type, ServerSideEncryption="AES256")

    def get_object(self, key: str) -> bytes:
        try:
            response = self._client.get_object(Bucket=self._bucket, Key=key)
            return response["Body"].read()
        except self._client.exceptions.NoSuchKey:
            raise ObjectStorageError("object not found: %r" % (key,))

    def delete_object(self, key: str) -> None:
        self._client.delete_object(Bucket=self._bucket, Key=key)

    def object_exists(self, key: str) -> bool:
        try:
            self._client.head_object(Bucket=self._bucket, Key=key)
            return True
        except Exception:
            return False

    def generate_signed_url(self, key: str, expires_in_seconds: int) -> str:
        return self._client.generate_presigned_url("get_object", Params={"Bucket": self._bucket, "Key": key}, ExpiresIn=expires_in_seconds)
