# SPDX-License-Identifier: GPL-3.0-or-later
"""Parse structured helper hello/version responses.

Helper version is taken only from a protocol hello event or a single stdout
line that is exactly a semantic version. Arbitrary stdout/stderr, including
Python tracebacks, is never treated as a version string.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from fortigate_vpn_gui.helper.protocol import (
    HELPER_VERSION,
    PROTOCOL_VERSION,
    HelperEvent,
    HelperEventKind,
    encode_event,
    event_from_payload,
)

_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_TRACEBACK_RE = re.compile(r"^\s*Traceback \(most recent call last\):", re.IGNORECASE)


@dataclass(frozen=True)
class HelperHelloResult:
    """Outcome of a helper version/hello probe."""

    helper_version: str | None
    protocol_version: int | None
    status: str
    detail: str


def is_valid_helper_version(value: object) -> bool:
    """Return True when *value* is exactly a ``X.Y.Z`` version token."""
    return isinstance(value, str) and bool(_VERSION_RE.fullmatch(value.strip()))


def encode_hello_line(
    *,
    helper_version: str = HELPER_VERSION,
    protocol_version: int = PROTOCOL_VERSION,
) -> str:
    """Return one JSON-lines hello event."""
    event = HelperEvent(
        kind=HelperEventKind.HELLO,
        helper_version=helper_version,
        protocol_version=protocol_version,
    )
    return json.dumps(encode_event(event), separators=(",", ":"))


def parse_helper_hello_output(
    *,
    stdout: str = "",
    stderr: str = "",
    returncode: int = 0,
) -> HelperHelloResult:
    """Parse helper ``--version`` / hello output. Never use stderr as version."""
    detail = stderr.strip()
    stdout_text = stdout or ""
    parsed = _parse_stdout_hello(stdout_text)
    if parsed is not None:
        version, protocol = parsed
        return HelperHelloResult(
            helper_version=version,
            protocol_version=protocol,
            status="ok",
            detail=detail,
        )
    if _looks_like_crash(stdout_text, stderr, returncode):
        return HelperHelloResult(
            helper_version=None,
            protocol_version=None,
            status="startup_failed",
            detail=detail,
        )
    if not stdout_text.strip():
        return HelperHelloResult(
            helper_version=None,
            protocol_version=None,
            status="no_response",
            detail=detail,
        )
    return HelperHelloResult(
        helper_version=None,
        protocol_version=None,
        status="malformed",
        detail=detail,
    )


def _parse_stdout_hello(stdout: str) -> tuple[str, int | None] | None:
    for raw in stdout.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("{"):
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(payload, dict):
                continue
            try:
                event = event_from_payload(payload)
            except Exception:
                continue
            if event.kind is not HelperEventKind.HELLO:
                continue
            version = event.helper_version
            if is_valid_helper_version(version) and version is not None:
                return version, event.protocol_version
            return None
        if is_valid_helper_version(line):
            return line.strip(), None
        # First non-empty line was neither hello JSON nor a version token.
        return None
    return None


def _looks_like_crash(stdout: str, stderr: str, returncode: int) -> bool:
    if returncode not in {0, None}:
        if _parse_stdout_hello(stdout) is None:
            return True
    if _TRACEBACK_RE.search(stdout) or _TRACEBACK_RE.search(stderr):
        return True
    return False
