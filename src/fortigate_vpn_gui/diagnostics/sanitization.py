# SPDX-License-Identifier: GPL-3.0-or-later
"""Sanitize diagnostic text before it is shown or copied.

Builds on log redaction. Diagnostic reports must never include passwords,
tokens, cookies, SAML payloads, or helper request bodies.
"""

from __future__ import annotations

import re

from fortigate_vpn_gui.diagnostics.timeouts import MAX_OUTPUT_CHARS
from fortigate_vpn_gui.vpn.log_redaction import redact_log_line

_REDACTED = "***"

_EXTRA_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(secret\s*[=:]\s*)\S+", re.IGNORECASE),
    re.compile(r"(client[-_]?secret\s*[=:]\s*)\S+", re.IGNORECASE),
    re.compile(r"(svpncookie=)\S+", re.IGNORECASE),
    re.compile(r"(SVPNCOOKIE=)\S+"),
    re.compile(r"(psk\s*[=:]\s*)\S+", re.IGNORECASE),
    re.compile(r"(password=)\S+", re.IGNORECASE),
    re.compile(r"(passwd=)\S+", re.IGNORECASE),
    re.compile(r"(access_token=)\S+", re.IGNORECASE),
    re.compile(r"(refresh_token=)\S+", re.IGNORECASE),
    re.compile(r"(tokenid=)\S+", re.IGNORECASE),
    re.compile(r"(FCT_TOKEN_ID=)\S+"),
    re.compile(r"(FCT_UID=)\S+"),
    re.compile(r"(UID=)[^\r\n]+"),
    re.compile(r"(MAC=)[^\r\n]+"),
    re.compile(r"(HOST=)[^\r\n]+"),
    re.compile(r"(USER=)[^\r\n]+"),
    re.compile(r"(OSVER=)[^\r\n]+"),
    re.compile(r"(IP=)[^\r\n]+"),
    re.compile(r"(eap_id=)\S+", re.IGNORECASE),
    re.compile(
        r"(Authorization:\s*(?:Bearer|Basic)\s+)\S+",
        re.IGNORECASE,
    ),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL),
)

_JSON_SECRET_RE = re.compile(
    r'(?P<prefix>"(?:password|passwd|secret|psk|pre_shared_key|cookie|cookies|authorization|'
    r"access_token|refresh_token|id_token|samlresponse|saml_token|tokenid|token|"
    r'svpncookie|client_secret|fct_token_id|fct_uid|username|eap_id|eap_identity)"\s*:\s*")'
    r'(?P<value>[^"]*)(?P<suffix>")',
    re.IGNORECASE,
)

_HELPER_REQUEST_RE = re.compile(
    r"\{[^{}]{0,4000}?(?:\"operation\"\s*:\s*\"(?:connect|hello|disconnect|status|credentials)\")"
    r"[^{}]{0,4000}\}",
    re.IGNORECASE | re.DOTALL,
)


def sanitize_diagnostic_text(text: str | None, *, limit: int = MAX_OUTPUT_CHARS) -> str:
    """Return a redacted, length-limited string safe for diagnostics."""
    if not text:
        return ""
    redacted = redact_log_line(text)
    redacted = _HELPER_REQUEST_RE.sub("[redacted helper request]", redacted)
    redacted = _JSON_SECRET_RE.sub(rf"\g<prefix>{_REDACTED}\g<suffix>", redacted)
    for pattern in _EXTRA_PATTERNS:
        if pattern.groups == 0:
            redacted = pattern.sub("[redacted private key]", redacted)
        else:
            redacted = pattern.sub(rf"\g<1>{_REDACTED}", redacted)
    if len(redacted) > limit:
        return redacted[:limit].rstrip() + "…"
    return redacted
