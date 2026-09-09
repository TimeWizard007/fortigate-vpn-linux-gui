# SPDX-License-Identifier: GPL-3.0-or-later
"""Profile-aware openfortivpn argv wrapper.

Command construction primitives live in ``fortigate_vpn_gui.command`` so the
privileged helper can import them without loading VpnBackend or Qt.
"""

from __future__ import annotations

from fortigate_vpn_gui.command import (
    OPENFORTIVPN_NAME,
    CommandConstructionError,
    assert_argv_is_controlled,
    build_openfortivpn_argv,
    is_openfortivpn_executable,
)
from fortigate_vpn_gui.profiles.model import ConnectionProfile

_assert_argv_is_controlled = assert_argv_is_controlled

__all__ = [
    "OPENFORTIVPN_NAME",
    "CommandConstructionError",
    "assert_argv_is_controlled",
    "build_connect_argv",
    "build_openfortivpn_argv",
    "is_openfortivpn_executable",
]


def build_connect_argv(
    profile: ConnectionProfile,
    executable: str,
    *,
    saml: bool = False,
    trusted_cert_sha256: str | None = None,
) -> list[str]:
    """Return a list argv for *profile*. Never a shell command string."""
    return build_openfortivpn_argv(
        executable=executable,
        gateway=profile.gateway,
        port=profile.port,
        saml=saml,
        trusted_cert_sha256=trusted_cert_sha256,
    )
