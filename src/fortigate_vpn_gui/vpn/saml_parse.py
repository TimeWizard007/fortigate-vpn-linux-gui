# SPDX-License-Identifier: GPL-3.0-or-later
"""Parse openfortivpn --saml-login stdout without exposing secrets.

Matching is case-insensitive. Callers must not log the raw line; pass it
through redaction first for storage.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


class SamlEventKind(Enum):
    NONE = "none"
    LISTENER_READY = "listener_ready"
    AUTH_URL = "auth_url"
    WAITING = "waiting"
    SUCCESS = "success"
    FAILURE = "failure"
    TIMEOUT = "timeout"


@dataclass(frozen=True)
class SamlParseResult:
    kind: SamlEventKind
    url: str | None = None


_AUTH_URL = re.compile(
    r"authenticate\s+at\s+['\"]?(https?://[^\s'\"]+)['\"]?",
    re.IGNORECASE,
)
_LISTENER = re.compile(r"listening for saml login", re.IGNORECASE)
_WAITING = re.compile(
    r"waiting for (?:saml|browser|authentication|auth)",
    re.IGNORECASE,
)
_SUCCESS = (
    "incoming http connection",
    "retrieved saml",
    "got saml cookie",
    "saml authentication successful",
    "using saml authentication url",
    "received saml session",
)
_FAILURE = (
    "failed to retrieve saml",
    "failed to receive saml session",
    "finally failed to retrieve saml",
    "failed to retrieve saml cookie",
    "saml authentication failed",
)
_TIMEOUT = (
    "timeout listening for incoming http",
    "saml authentication timed out",
    "timeout waiting for saml",
)


def parse_saml_output(line: str) -> SamlParseResult:
    """Classify one openfortivpn line for the SAML state machine."""
    lowered = line.lower()
    url_match = _AUTH_URL.search(line)
    if url_match:
        return SamlParseResult(SamlEventKind.AUTH_URL, url_match.group(1))
    if _LISTENER.search(line):
        return SamlParseResult(SamlEventKind.LISTENER_READY)
    if _WAITING.search(line):
        return SamlParseResult(SamlEventKind.WAITING)
    if any(marker in lowered for marker in _FAILURE):
        return SamlParseResult(SamlEventKind.FAILURE)
    if any(marker in lowered for marker in _TIMEOUT):
        return SamlParseResult(SamlEventKind.TIMEOUT)
    if any(marker in lowered for marker in _SUCCESS):
        return SamlParseResult(SamlEventKind.SUCCESS)
    return SamlParseResult(SamlEventKind.NONE)
