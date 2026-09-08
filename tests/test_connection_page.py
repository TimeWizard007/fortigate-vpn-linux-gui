# SPDX-License-Identifier: GPL-3.0-or-later
"""Connection page profile integration tests. No network, sudo, or VPN tools."""

from __future__ import annotations

from fortigate_vpn_gui.gui.connection_page import ConnectionPage
from fortigate_vpn_gui.profiles.manager import ProfileManager


def test_connection_page_without_profiles(qapp, profile_manager: ProfileManager) -> None:
    page = ConnectionPage(profile_manager)
    assert page.status_text() == "Disconnected"
    assert page.gateway_text() == "Not configured"
    assert page.connect_enabled() is False
    assert page.empty_hint_visible() is True
    assert page.selected_profile() is None


def test_connection_page_with_profiles(qapp, profile_manager: ProfileManager) -> None:
    profile_manager.add(name="Office", gateway="vpn.example.com", port=8443, use_sso=True)
    page = ConnectionPage(profile_manager)
    assert page.connect_enabled() is True
    assert page.empty_hint_visible() is False
    assert page.gateway_text() == "vpn.example.com"
    assert page.port_text() == "8443"
    assert page.sso_text() == "Enabled"
    assert page.status_text() == "Disconnected"
    selected = page.selected_profile()
    assert selected is not None
    assert selected.name == "Office"


def test_connection_page_refreshes_when_profile_added(
    qapp, profile_manager: ProfileManager
) -> None:
    page = ConnectionPage(profile_manager)
    assert page.connect_enabled() is False
    profile_manager.add(name="Office", gateway="vpn.example.com")
    assert page.connect_enabled() is True
    assert page.gateway_text() == "vpn.example.com"
    assert page.status_text() == "Disconnected"
