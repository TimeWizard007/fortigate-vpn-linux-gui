# SPDX-License-Identifier: GPL-3.0-or-later
"""Structured IPC schema for the privileged helper.

Requests are JSON objects. The GUI never sends a shell command, argv list, or
executable path. Unknown operations and forbidden keys are rejected.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

HELPER_VERSION = "0.5.0"
PROTOCOL_VERSION = 1
POLKIT_ACTION_ID = "com.fortigate-vpn-linux-gui.manage-vpn"
INSTALLED_HELPER_PATH = "/usr/libexec/fortigate-vpn-linux-gui/vpn-helper"
APPROVED_OPENFORTIVPN_PATHS: tuple[str, ...] = (
    "/usr/local/bin/openfortivpn",
    "/usr/bin/openfortivpn",
)

ALLOWED_OPERATIONS = frozenset({"hello", "connect", "disconnect", "status"})
ALLOWED_AUTH_MODES = frozenset({"saml", "standard"})
ALLOWED_REQUEST_KEYS = frozenset(
    {
        "id",
        "operation",
        "gateway",
        "port",
        "auth_mode",
        "trusted_certificate_fingerprint",
    }
)
FORBIDDEN_REQUEST_KEYS = frozenset(
    {
        "command",
        "argv",
        "args",
        "executable",
        "executable_path",
        "shell",
        "options",
        "extra_args",
        "password",
        "cookie",
        "token",
        "saml",
    }
)


class HelperError(Exception):
    """Base helper protocol error."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


class HelperProtocolError(HelperError):
    """The request is malformed or unsupported."""


class HelperEventKind(Enum):
    HELLO = "hello"
    ACK = "ack"
    ERROR = "error"
    STATE = "state"
    LOG = "log"
    SAML_URL = "saml_url"
    SAML_LISTENER = "saml_listener"
    SAML_WAITING = "saml_waiting"
    SAML_SUCCESS = "saml_success"
    SAML_FAILURE = "saml_failure"
    CERTIFICATE = "certificate"
    CONNECTED = "connected"
    STARTED = "started"
    EXIT = "exit"
    STATUS = "status"


@dataclass(frozen=True)
class ConnectRequest:
    """Validated connect parameters. No executable, command, or secrets."""

    gateway: str
    port: int
    auth_mode: str
    trusted_certificate_fingerprint: str | None = None
    request_id: str | None = None


@dataclass(frozen=True)
class CertificateInfo:
    """Gateway certificate metadata for an explicit trust decision."""

    subject: str
    issuer: str
    sha256: str


@dataclass(frozen=True)
class HelperEvent:
    """One structured event from the helper to the GUI."""

    kind: HelperEventKind
    request_id: str | None = None
    state: str | None = None
    pid: int | None = None
    line: str | None = None
    url: str | None = None
    certificate: CertificateInfo | None = None
    code: str | None = None
    message: str | None = None
    exit_code: int | None = None
    helper_version: str | None = None
    protocol_version: int | None = None
    running: bool | None = None
    argv: tuple[str, ...] = ()
    selected_executable: str | None = None
    openfortivpn_version: str | None = None
    supports_saml: bool | None = None


@dataclass(frozen=True)
class HelperProbe:
    """Unprivileged view of helper/polkit availability."""

    installed: bool
    helper_path: str | None
    helper_version: str | None
    polkit_available: bool
    authorization_mechanism: str
    status: str
    version_mismatch: bool = False
    startup_detail: str | None = None


def encode_event(event: HelperEvent) -> dict[str, Any]:
    """Serialise an event for JSON-lines IPC."""
    payload: dict[str, Any] = {"type": event.kind.value}
    if event.request_id is not None:
        payload["id"] = event.request_id
    if event.state is not None:
        payload["state"] = event.state
    if event.pid is not None:
        payload["pid"] = event.pid
    if event.line is not None:
        payload["line"] = event.line
    if event.url is not None:
        payload["url"] = event.url
    if event.certificate is not None:
        payload["subject"] = event.certificate.subject
        payload["issuer"] = event.certificate.issuer
        payload["sha256"] = event.certificate.sha256
    if event.code is not None:
        payload["code"] = event.code
    if event.message is not None:
        payload["message"] = event.message
    if event.exit_code is not None:
        payload["exit_code"] = event.exit_code
    if event.helper_version is not None:
        payload["helper_version"] = event.helper_version
    if event.protocol_version is not None:
        payload["protocol_version"] = event.protocol_version
    if event.running is not None:
        payload["running"] = event.running
    if event.argv:
        payload["argv"] = list(event.argv)
    if event.selected_executable is not None:
        payload["selected_executable"] = event.selected_executable
    if event.openfortivpn_version is not None:
        payload["openfortivpn_version"] = event.openfortivpn_version
    if event.supports_saml is not None:
        payload["supports_saml"] = event.supports_saml
    return payload


def event_from_payload(payload: dict[str, Any]) -> HelperEvent:
    """Parse a JSON event object from the helper."""
    raw_type = payload.get("type")
    if not isinstance(raw_type, str):
        raise HelperProtocolError("INVALID_EVENT", "Helper event is missing a type.")
    try:
        kind = HelperEventKind(raw_type)
    except ValueError as exc:
        raise HelperProtocolError("INVALID_EVENT", "Unknown helper event type.") from exc
    certificate = None
    subject = payload.get("subject")
    issuer = payload.get("issuer")
    sha256 = payload.get("sha256")
    if isinstance(subject, str) and isinstance(issuer, str) and isinstance(sha256, str):
        certificate = CertificateInfo(subject=subject, issuer=issuer, sha256=sha256)
    argv_raw = payload.get("argv", ())
    argv = tuple(str(item) for item in argv_raw) if isinstance(argv_raw, list) else ()
    return HelperEvent(
        kind=kind,
        request_id=_optional_str(payload.get("id")),
        state=_optional_str(payload.get("state")),
        pid=_optional_int(payload.get("pid")),
        line=_optional_str(payload.get("line")),
        url=_optional_str(payload.get("url")),
        certificate=certificate,
        code=_optional_str(payload.get("code")),
        message=_optional_str(payload.get("message")),
        exit_code=_optional_int(payload.get("exit_code")),
        helper_version=_optional_str(payload.get("helper_version")),
        protocol_version=_optional_int(payload.get("protocol_version")),
        running=_optional_bool(payload.get("running")),
        argv=argv,
        selected_executable=_optional_str(payload.get("selected_executable")),
        openfortivpn_version=_optional_str(payload.get("openfortivpn_version")),
        supports_saml=_optional_bool(payload.get("supports_saml")),
    )


def _optional_str(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _optional_int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _optional_bool(value: object) -> bool | None:
    return value if isinstance(value, bool) else None
