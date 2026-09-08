# SPDX-License-Identifier: GPL-3.0-or-later
"""Redact secrets from openfortivpn and application log lines.

Every backend log line must pass through ``redact_log_line`` before it is
shown. Matching is case-insensitive. This module never writes to disk.
"""

from __future__ import annotations

import re

_REDACTED = "***"

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
    re.compile(r"(saml(?:response|token|assertion)?\s*[=:]\s*)\S+", re.IGNORECASE),
    re.compile(r"(session[-_]?id\s*[=:]\s*)\S+", re.IGNORECASE),
    re.compile(r"(access[-_]?token\s*[=:]\s*)\S+", re.IGNORECASE),
    re.compile(r"(refresh[-_]?token\s*[=:]\s*)\S+", re.IGNORECASE),
    re.compile(r"(client[-_]?secret\s*[=:]\s*)\S+", re.IGNORECASE),
)


def redact_log_line(line: str) -> str:
    """Return *line* with credentials and session material replaced by ``***``."""
    redacted = line
    for pattern in _PATTERNS:
        redacted = pattern.sub(rf"\g<1>{_REDACTED}", redacted)
    return redacted
