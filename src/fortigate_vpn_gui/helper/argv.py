# SPDX-License-Identifier: GPL-3.0-or-later
"""Construct the privileged openfortivpn argv from approved paths only."""

from __future__ import annotations

from pathlib import Path

from fortigate_vpn_gui.command import (
    CommandConstructionError,
    build_openfortivpn_argv,
    is_openfortivpn_executable,
)
from fortigate_vpn_gui.helper.protocol import APPROVED_OPENFORTIVPN_PATHS, HelperProtocolError
from fortigate_vpn_gui.helper.validation import normalize_sha256_fingerprint


def is_approved_openfortivpn_path(path: str) -> bool:
    """Return True when *path* is an allowlisted openfortivpn location."""
    if not is_openfortivpn_executable(path):
        return False
    if path in APPROVED_OPENFORTIVPN_PATHS:
        return True
    try:
        real = Path(path).resolve()
    except OSError:
        return False
    return str(real) in APPROVED_OPENFORTIVPN_PATHS


def build_helper_argv(
    *,
    executable: str,
    gateway: str,
    port: int,
    auth_mode: str,
    trusted_certificate_fingerprint: str | None = None,
) -> list[str]:
    """Return a list argv. Raises if the executable or fingerprint is unsafe."""
    if not is_approved_openfortivpn_path(executable):
        raise HelperProtocolError(
            "INVALID_EXECUTABLE",
            "Refusing to execute a binary that is not an approved openfortivpn path.",
        )
    fingerprint = None
    if trusted_certificate_fingerprint:
        fingerprint = normalize_sha256_fingerprint(trusted_certificate_fingerprint)
        if fingerprint is None:
            raise HelperProtocolError(
                "INVALID_FINGERPRINT",
                "Certificate fingerprint must be a SHA-256 hex digest.",
            )
    try:
        return build_openfortivpn_argv(
            executable=executable,
            gateway=gateway,
            port=port,
            saml=auth_mode == "saml",
            trusted_cert_sha256=fingerprint,
        )
    except CommandConstructionError as exc:
        raise HelperProtocolError("INVALID_ARGV", str(exc)) from exc
