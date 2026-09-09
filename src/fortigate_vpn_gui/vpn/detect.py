# SPDX-License-Identifier: GPL-3.0-or-later
"""Locate openfortivpn and parse version/help output.

Version and help probing are for Diagnostics and SSO connect. Application
startup uses ``locate_openfortivpn`` (PATH lookup) and does not execute the
binary.
"""

from __future__ import annotations

from collections.abc import Sequence

from fortigate_vpn_gui.vpn.capabilities import (
    OpenfortivpnCapabilities,
    OpenfortivpnDetection,
    default_version_runner,
    detect_openfortivpn,
    locate_openfortivpn,
    parse_openfortivpn_version,
    query_openfortivpn_version,
)


def argv_uses_shell(kwargs: Sequence[object] | dict[str, object]) -> bool:
    """Helper for tests: True if a subprocess kwargs mapping requested a shell."""
    if isinstance(kwargs, dict):
        return bool(kwargs.get("shell", False))
    return False


__all__ = [
    "OpenfortivpnCapabilities",
    "OpenfortivpnDetection",
    "argv_uses_shell",
    "default_version_runner",
    "detect_openfortivpn",
    "locate_openfortivpn",
    "parse_openfortivpn_version",
    "query_openfortivpn_version",
]
