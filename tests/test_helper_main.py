# SPDX-License-Identifier: GPL-3.0-or-later
"""Privileged helper CLI tests. Never run as root."""

from __future__ import annotations

from fortigate_vpn_gui.helper.handshake import parse_helper_hello_output
from fortigate_vpn_gui.helper.main import main
from fortigate_vpn_gui.helper.protocol import HELPER_VERSION, PROTOCOL_VERSION


def test_helper_version_flag(capsys) -> None:
    assert main(["--version"]) == 0
    parsed = parse_helper_hello_output(stdout=capsys.readouterr().out, returncode=0)
    assert parsed.status == "ok"
    assert parsed.helper_version == HELPER_VERSION


def test_helper_protocol_version_flag(capsys) -> None:
    assert main(["--protocol-version"]) == 0
    assert capsys.readouterr().out.strip() == str(PROTOCOL_VERSION)
