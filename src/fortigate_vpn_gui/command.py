# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared openfortivpn argv construction.

This module is a leaf: it does not import VpnBackend, the helper client, Qt,
or HelperService. Both the unprivileged GUI/backend and the privileged helper
build argv from these primitives.
"""

from __future__ import annotations

from pathlib import Path

from fortigate_vpn_gui.helper.validation import normalize_sha256_fingerprint

OPENFORTIVPN_NAME = "openfortivpn"
_ALLOWED_FLAGS = frozenset({"--saml-login", "--trusted-cert"})
_FORBIDDEN_FRAGMENTS = (
    "password",
    "passwd",
    "cookie",
    "token",
    "secret",
)


class CommandConstructionError(ValueError):
    """The connect argv would be unsafe or invalid."""


def is_openfortivpn_executable(path: str) -> bool:
    """Return True if *path* refers to the openfortivpn binary by name."""
    if not path or path.strip() != path:
        return False
    return Path(path).name == OPENFORTIVPN_NAME


def build_openfortivpn_argv(
    *,
    executable: str,
    gateway: str,
    port: int,
    saml: bool = False,
    trusted_cert_sha256: str | None = None,
) -> list[str]:
    """Return ``[openfortivpn, gateway:port, optional flags...]`` as a list."""
    if not is_openfortivpn_executable(executable):
        raise CommandConstructionError("refusing to execute a binary that is not openfortivpn")
    if not gateway or not gateway.strip():
        raise CommandConstructionError("profile gateway is empty")
    if not 1 <= port <= 65535:
        raise CommandConstructionError("profile port is out of range")
    if any(ch.isspace() for ch in gateway):
        raise CommandConstructionError("profile gateway must not contain whitespace")
    target = f"{gateway}:{port}"
    argv = [executable, target]
    if saml:
        argv.append("--saml-login")
    if trusted_cert_sha256:
        digest = normalize_sha256_fingerprint(trusted_cert_sha256)
        if digest is None:
            raise CommandConstructionError(
                "trusted certificate fingerprint is not a SHA-256 hex digest"
            )
        argv.extend(["--trusted-cert", digest])
    assert_argv_is_controlled(argv)
    return argv


def assert_argv_is_controlled(argv: list[str]) -> None:
    """Reject arbitrary flags and credential-like arguments."""
    skip_next = False
    for index, argument in enumerate(argv):
        if index == 0:
            continue
        if skip_next:
            skip_next = False
            if normalize_sha256_fingerprint(argument) is None:
                raise CommandConstructionError(
                    "trusted certificate fingerprint is not a SHA-256 hex digest"
                )
            continue
        if argument == "--trusted-cert":
            skip_next = True
            continue
        if argument.startswith("-") and argument not in _ALLOWED_FLAGS:
            raise CommandConstructionError("refusing arbitrary openfortivpn options")
        lowered = argument.lower()
        for fragment in _FORBIDDEN_FRAGMENTS:
            if fragment in lowered:
                raise CommandConstructionError("refusing to pass credential-like arguments")
    if skip_next:
        raise CommandConstructionError("trusted certificate flag is missing a fingerprint")


# Tests historically imported this private name from vpn.command.
_assert_argv_is_controlled = assert_argv_is_controlled
