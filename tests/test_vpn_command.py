# SPDX-License-Identifier: GPL-3.0-or-later
"""openfortivpn argv construction tests. Never execute the binary."""

from __future__ import annotations

import pytest

from fortigate_vpn_gui.profiles.model import build_profile
from fortigate_vpn_gui.vpn.command import CommandConstructionError, build_connect_argv


def _profile(**kwargs):
    values = {"name": "Office", "gateway": "vpn.example.com", "port": 443, "use_sso": False}
    values.update(kwargs)
    return build_profile(**values)


def test_command_is_gateway_port_list() -> None:
    argv = build_connect_argv(_profile(port=8443), "/usr/bin/openfortivpn")
    assert argv == ["/usr/bin/openfortivpn", "vpn.example.com:8443"]
    assert all(isinstance(part, str) for part in argv)


def test_command_has_no_password_or_token_args() -> None:
    argv = build_connect_argv(_profile(), "/usr/bin/openfortivpn")
    joined = " ".join(argv).lower()
    assert "password" not in joined
    assert "passwd" not in joined
    assert "cookie" not in joined
    assert "token" not in joined
    assert "--trusted-cert" not in joined
    assert "-p" not in argv


def test_command_rejects_non_openfortivpn_binary() -> None:
    with pytest.raises(CommandConstructionError):
        build_connect_argv(_profile(), "/usr/bin/nmcli")
