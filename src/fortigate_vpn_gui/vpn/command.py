# SPDX-License-Identifier: GPL-3.0-or-later
"""Build the openfortivpn argument vector.

Arguments are always a list. This module never uses a shell and never adds
passwords, cookies, tokens, or certificate-bypass flags.
"""

from __future__ import annotations

from pathlib import Path

from fortigate_vpn_gui.profiles.model import ConnectionProfile

OPENFORTIVPN_NAME = "openfortivpn"

_FORBIDDEN_FRAGMENTS = (
    "password",
    "passwd",
    "cookie",
    "token",
    "secret",
    "trusted-cert",
)


class CommandConstructionError(ValueError):
    """The connect argv would be unsafe or invalid."""


def is_openfortivpn_executable(path: str) -> bool:
    """Return True if *path* refers to the openfortivpn binary by name."""
    if not path or path.strip() != path:
        return False
    return Path(path).name == OPENFORTIVPN_NAME


def build_connect_argv(profile: ConnectionProfile, executable: str) -> list[str]:
    """Return ``[openfortivpn, gateway:port]`` for the selected profile."""
    if not is_openfortivpn_executable(executable):
        raise CommandConstructionError("refusing to execute a binary that is not openfortivpn")
    if not profile.gateway or not profile.gateway.strip():
        raise CommandConstructionError("profile gateway is empty")
    if not 1 <= profile.port <= 65535:
        raise CommandConstructionError("profile port is out of range")
    if any(ch.isspace() for ch in profile.gateway):
        raise CommandConstructionError("profile gateway must not contain whitespace")
    target = f"{profile.gateway}:{profile.port}"
    argv = [executable, target]
    _assert_argv_has_no_secrets(argv)
    return argv


def _assert_argv_has_no_secrets(argv: list[str]) -> None:
    for index, argument in enumerate(argv):
        if index == 0:
            continue
        lowered = argument.lower()
        for fragment in _FORBIDDEN_FRAGMENTS:
            if fragment in lowered:
                raise CommandConstructionError("refusing to pass credential-like arguments")
