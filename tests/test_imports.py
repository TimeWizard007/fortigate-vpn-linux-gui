# SPDX-License-Identifier: GPL-3.0-or-later
"""Package import tests. These tests must not access the network."""

from __future__ import annotations


def test_package_imports() -> None:
    import fortigate_vpn_gui

    assert fortigate_vpn_gui.__version__ == "0.9.0"
    assert fortigate_vpn_gui.APP_NAME == "FortiGate VPN Linux GUI"


def test_helper_protocol_version_unchanged() -> None:
    from fortigate_vpn_gui.helper.protocol import HELPER_VERSION

    assert HELPER_VERSION == "0.7.0"


def test_placeholder_packages_import() -> None:
    from fortigate_vpn_gui import desktop, diagnostics, metadata, profiles, runtime, system, vpn
    from fortigate_vpn_gui.diagnostics import collector
    from fortigate_vpn_gui.helper import main as helper_main
    from fortigate_vpn_gui.profiles import manager
    from fortigate_vpn_gui.system import dependencies, privileges
    from fortigate_vpn_gui.vpn import backend

    assert runtime.__doc__
    assert vpn.__doc__
    assert backend.__doc__
    assert helper_main.main is not None
    assert profiles.__doc__
    assert manager.__doc__
    assert system.__doc__
    assert privileges.__doc__
    assert dependencies.__doc__
    assert diagnostics.__doc__
    assert metadata.PROJECT_URL.startswith("https://github.com/")
    assert metadata.LICENSE_SPDX == "GPL-3.0-or-later"
    assert desktop.__doc__
    assert collector.__doc__
