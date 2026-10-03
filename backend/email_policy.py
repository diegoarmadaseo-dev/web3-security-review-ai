#!/usr/bin/env python3
"""Email rules for the free Trial (docs/decisiones.md D-112).

NORMALIZATION - one function everywhere: backend/auth.normalize_email()
(trim + lower-case, basic shape check). It is what sign-up, the magic-link
token, the users row, the Trial eligibility check and the trial_grants key
all use, so the same address can never be counted twice by being typed
differently. Deliberately NOT applied: provider-specific rewrites such as
removing dots or "+tag" suffixes for Gmail - they are not universal rules
and no decision has been taken to adopt them (an explicit future decision).

DISPOSABLE DOMAINS: DisposableDomainPolicy answers "is this address on a
known disposable/temporary/throwaway domain?" from a plain-text denylist
(backend/data/disposable_email_domains.txt, optionally extended by an
operator file - see backend/main.py). A listed domain also covers its
subdomains. The list is data: updating it never touches the Trial logic.
No external service is queried, nothing about the address is stored by
this module, and it is only consulted for the Trial - paid plans and
ordinary sign-in are unaffected.

Standard library only.
"""
from __future__ import annotations

import os
from typing import FrozenSet, Iterable, Optional, Sequence

import backend.auth as auth

DEFAULT_DENYLIST_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "disposable_email_domains.txt")
MAX_EMAIL_LENGTH = 254   # RFC 5321 path limit; longer input is refused before anything else


def normalize_email(email: object) -> str:
    """auth.normalize_email() plus a length ceiling for public sign-up input.
    Raises auth.AuthError."""
    if isinstance(email, str) and len(email.strip()) > MAX_EMAIL_LENGTH:
        raise auth.AuthError("invalid email address")
    return auth.normalize_email(email)


def email_domain(normalized_email: str) -> str:
    return normalized_email.rsplit("@", 1)[1].strip(".")


def _parse(lines: Iterable[str]) -> FrozenSet[str]:
    domains = set()
    for line in lines:
        value = line.strip().lower()
        if value and not value.startswith("#"):
            domains.add(value.strip("."))
    return frozenset(domains)


class DisposableDomainPolicy:
    def __init__(self, domains: Iterable[str]) -> None:
        self._domains = _parse(domains)

    @classmethod
    def from_files(cls, paths: Sequence[str]) -> "DisposableDomainPolicy":
        lines = []
        for path in paths:
            with open(path, "r", encoding="utf-8") as handle:
                lines.extend(handle.read().splitlines())
        return cls(lines)

    @property
    def size(self) -> int:
        return len(self._domains)

    def is_disposable(self, normalized_email: str) -> bool:
        domain = email_domain(normalized_email)
        labels = domain.split(".")
        return any(".".join(labels[i:]) in self._domains for i in range(len(labels) - 1))


def load_policy(extra_path: Optional[str] = None) -> DisposableDomainPolicy:
    """The bundled denylist, plus an operator-maintained file when given."""
    return DisposableDomainPolicy.from_files([DEFAULT_DENYLIST_PATH] + ([extra_path] if extra_path else []))
