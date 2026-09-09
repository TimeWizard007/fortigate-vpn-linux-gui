# SPDX-License-Identifier: GPL-3.0-or-later
"""Validate privileged helper input on both the GUI and helper sides.

Gateway, port, fingerprint, and operation checks never invoke a shell.
"""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any

from fortigate_vpn_gui.helper.protocol import (
    ALLOWED_AUTH_MODES,
    ALLOWED_OPERATIONS,
    ALLOWED_REQUEST_KEYS,
    FORBIDDEN_REQUEST_KEYS,
    ConnectRequest,
    HelperProtocolError,
)

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])$"
)
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_SHELL_META = frozenset(";&|<>$`(){}!\\\"'\n\r\t,*?~#")
_PORT_MSG = "Port must be an integer between 1 and 65535."
_GW_HOST_MSG = "Gateway must be a hostname or IP address."
_AUTH_MODE_MSG = "Authentication mode must be saml or standard."


def normalize_sha256_fingerprint(value: object) -> str | None:
    """Return a lowercase 64-hex SHA-256 digest, or None if invalid."""
    if value is None:
        return None
    if not isinstance(value, str):
        return None
    compact = re.sub(r"[\s:]", "", value.strip())
    if not _SHA256_HEX_RE.fullmatch(compact.lower()):
        return None
    return compact.lower()


def format_sha256_fingerprint(normalized: str) -> str:
    """Return colon-separated uppercase SHA-256 for display."""
    digest = normalize_sha256_fingerprint(normalized)
    if digest is None:
        return normalized
    return ":".join(digest[index : index + 2] for index in range(0, 64, 2)).upper()


def validate_port(value: object) -> int:
    """Return a TCP port in 1..65535."""
    if isinstance(value, bool) or not isinstance(value, int):
        if isinstance(value, str) and value.strip().isdigit():
            number = int(value.strip())
        else:
            raise HelperProtocolError("INVALID_PORT", _PORT_MSG)
    else:
        number = value
    if not 1 <= number <= 65535:
        raise HelperProtocolError("INVALID_PORT", _PORT_MSG)
    return number


def validate_gateway(value: object) -> str:
    """Return a hostname or IP with no whitespace, control, or shell syntax."""
    if not isinstance(value, str) or not value:
        raise HelperProtocolError("INVALID_GATEWAY", _GW_HOST_MSG)
    if value.strip() != value:
        raise HelperProtocolError(
            "INVALID_GATEWAY",
            "Gateway must not contain leading or trailing whitespace.",
        )
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise HelperProtocolError("INVALID_GATEWAY", "Gateway must not contain control characters.")
    if any(char in _SHELL_META or char.isspace() for char in value):
        raise HelperProtocolError(
            "INVALID_GATEWAY",
            "Gateway must not contain shell or whitespace characters.",
        )
    if "/" in value or "\\" in value:
        raise HelperProtocolError("INVALID_GATEWAY", "Gateway must not contain path separators.")
    candidate = value[1:-1] if value.startswith("[") and value.endswith("]") else value
    if _HOSTNAME_RE.fullmatch(candidate):
        return value
    try:
        ipaddress.ip_address(candidate)
    except ValueError as exc:
        raise HelperProtocolError("INVALID_GATEWAY", _GW_HOST_MSG) from exc
    return value


def validate_fingerprint(value: object, *, required: bool = False) -> str | None:
    """Return a normalized SHA-256 fingerprint or None when omitted."""
    if value is None or value == "":
        if required:
            raise HelperProtocolError(
                "INVALID_FINGERPRINT",
                "Certificate fingerprint must be a SHA-256 hex digest.",
            )
        return None
    normalized = normalize_sha256_fingerprint(value)
    if normalized is None:
        raise HelperProtocolError(
            "INVALID_FINGERPRINT",
            "Certificate fingerprint must be a SHA-256 hex digest.",
        )
    return normalized


def parse_request_payload(payload: object) -> tuple[str, ConnectRequest | None]:
    """Parse a JSON-object request. Rejects commands, argv, and extra keys."""
    if not isinstance(payload, dict):
        raise HelperProtocolError("INVALID_REQUEST", "Request must be a JSON object.")
    keys = {str(key) for key in payload}
    forbidden = keys & FORBIDDEN_REQUEST_KEYS
    extra = keys - ALLOWED_REQUEST_KEYS
    if forbidden:
        raise HelperProtocolError(
            "UNSUPPORTED_FIELD",
            "Request contains forbidden command or executable fields.",
        )
    if extra:
        raise HelperProtocolError("UNSUPPORTED_FIELD", "Request contains unsupported fields.")
    operation = payload.get("operation")
    if not isinstance(operation, str) or operation not in ALLOWED_OPERATIONS:
        raise HelperProtocolError("UNSUPPORTED_OPERATION", "Unsupported helper operation.")
    request_id = payload.get("id")
    ident = request_id if isinstance(request_id, str) else None
    if operation != "connect":
        return operation, None
    auth_mode = payload.get("auth_mode", "standard")
    if not isinstance(auth_mode, str) or auth_mode not in ALLOWED_AUTH_MODES:
        raise HelperProtocolError("INVALID_AUTH_MODE", _AUTH_MODE_MSG)
    request = ConnectRequest(
        gateway=validate_gateway(payload.get("gateway")),
        port=validate_port(payload.get("port")),
        auth_mode=auth_mode,
        trusted_certificate_fingerprint=validate_fingerprint(
            payload.get("trusted_certificate_fingerprint")
        ),
        request_id=ident,
    )
    return operation, request


def parse_request_line(line: str) -> tuple[str, ConnectRequest | None, str | None]:
    """Parse one JSON-lines request. Returns operation, connect payload, id."""
    try:
        payload: Any = json.loads(line)
    except json.JSONDecodeError as exc:
        raise HelperProtocolError("INVALID_REQUEST", "Request is not valid JSON.") from exc
    if isinstance(payload, dict):
        request_id = payload.get("id") if isinstance(payload.get("id"), str) else None
    else:
        request_id = None
    operation, request = parse_request_payload(payload)
    return operation, request, request_id


def connect_request_from_fields(
    *,
    gateway: object,
    port: object,
    auth_mode: object,
    trusted_certificate_fingerprint: object = None,
    request_id: str | None = None,
) -> ConnectRequest:
    """Validate GUI-side connect fields before they are sent to the helper."""
    if not isinstance(auth_mode, str) or auth_mode not in ALLOWED_AUTH_MODES:
        raise HelperProtocolError("INVALID_AUTH_MODE", _AUTH_MODE_MSG)
    return ConnectRequest(
        gateway=validate_gateway(gateway),
        port=validate_port(port),
        auth_mode=auth_mode,
        trusted_certificate_fingerprint=validate_fingerprint(trusted_certificate_fingerprint),
        request_id=request_id,
    )
