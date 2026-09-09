# SPDX-License-Identifier: GPL-3.0-or-later
"""Redact secrets from openfortivpn and application log lines.

Every backend log line must pass through ``redact_log_line`` before it is
shown. Matching is case-insensitive. This module never writes to disk.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

_REDACTED = "***"

_SENSITIVE_QUERY_KEYS = frozenset(
    {
        "id",
        "session",
        "sessionid",
        "session_id",
        "sid",
        "code",
        "state",
        "relaystate",
        "samlresponse",
        "samlrequest",
        "access_token",
        "refresh_token",
        "id_token",
        "token",
        "cookie",
        "svpncookie",
        "client_secret",
        "password",
        "passwd",
        "authorization",
    }
)

_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(password\s*[=:]\s*)\S+", re.IGNORECASE),
    re.compile(r"(passwd\s*[=:]\s*)\S+", re.IGNORECASE),
    re.compile(r"(svpncookie\s*[=:]\s*)\S+", re.IGNORECASE),
    re.compile(r"(authorization:\s*bearer\s+)\S+", re.IGNORECASE),
    re.compile(r"(authorization:\s*basic\s+)\S+", re.IGNORECASE),
    re.compile(r"(authorization:\s*)(?!bearer\b)(?!basic\b)\S+", re.IGNORECASE),
    re.compile(r"(set-cookie:\s*)\S+", re.IGNORECASE),
    re.compile(r"(cookie:\s*)\S+", re.IGNORECASE),
    re.compile(r"((?:^|[;\s])cookie\s*[=:]\s*)\S+", re.IGNORECASE),
    re.compile(r"(bearer\s+)\S+", re.IGNORECASE),
    re.compile(r"(samlresponse\s*[=:]\s*)\S+", re.IGNORECASE),
    re.compile(r"(saml(?:response|token|assertion|request)?\s*[=:]\s*)\S+", re.IGNORECASE),
    re.compile(r"(relaystate\s*[=:]\s*)\S+", re.IGNORECASE),
    re.compile(r"(session[-_]?id\s*[=:]\s*)\S+", re.IGNORECASE),
    re.compile(r"((?:^|[?&;\s])id\s*[=:]\s*)[^\s&;]+", re.IGNORECASE),
    re.compile(r"(access[-_]?token\s*[=:]\s*)\S+", re.IGNORECASE),
    re.compile(r"(refresh[-_]?token\s*[=:]\s*)\S+", re.IGNORECASE),
    re.compile(r"(id[-_]?token\s*[=:]\s*)\S+", re.IGNORECASE),
    re.compile(r"(client[-_]?secret\s*[=:]\s*)\S+", re.IGNORECASE),
)

_URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)


def redact_log_line(line: str) -> str:
    """Return *line* with credentials and session material replaced by ``***``."""
    redacted = _URL_RE.sub(_redact_url_match, line)
    for pattern in _PATTERNS:
        redacted = pattern.sub(rf"\g<1>{_REDACTED}", redacted)
    return redacted


def _redact_url_match(match: re.Match[str]) -> str:
    return redact_url(match.group(0))


def redact_url(url: str) -> str:
    """Redact authentication/session query parameters in *url*."""
    parsed = urlparse(url)
    if not parsed.query and not parsed.fragment:
        return url
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    redacted_pairs: list[tuple[str, str]] = []
    for key, value in pairs:
        lowered = key.lower()
        if (
            lowered in _SENSITIVE_QUERY_KEYS
            or "token" in lowered
            or "saml" in lowered
            or "session" in lowered
            or "cookie" in lowered
            or "secret" in lowered
        ):
            redacted_pairs.append((key, _REDACTED))
        else:
            redacted_pairs.append((key, value))
    query = urlencode(redacted_pairs)
    fragment = _REDACTED if parsed.fragment else ""
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, fragment))
