# SPDX-License-Identifier: GPL-3.0-or-later
"""Package import tests. These tests must not access the network."""

from __future__ import annotations


def test_package_imports() -> None:
    import fortigate_vpn_gui

    assert fortigate_vpn_gui.__version__ == "0.2.0"
    assert fortigate_vpn_gui.APP_NAME == "FortiGate VPN Linux GUI"


def test_placeholder_packages_import() -> None:
    from fortigate_vpn_gui import diagnostics, profiles, runtime, system, vpn
    from fortigate_vpn_gui.diagnostics import collector
    from fortigate_vpn_gui.profiles import manager
    from fortigate_vpn_gui.system import dependencies, privileges
    from fortigate_vpn_gui.vpn import backend

    assert runtime.__doc__
    assert vpn.__doc__
    assert backend.__doc__
    assert profiles.__doc__
    assert manager.__doc__
    assert system.__doc__
    assert privileges.__doc__
    assert dependencies.__doc__
    assert diagnostics.__doc__
    assert collector.__doc__
