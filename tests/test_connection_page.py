# SPDX-License-Identifier: GPL-3.0-or-later
"""Connection page VPN wiring tests. No real VPN or network."""

from __future__ import annotations

from fortigate_vpn_gui.gui.connection_page import ConnectionPage
from fortigate_vpn_gui.profiles.manager import ProfileManager
from fortigate_vpn_gui.vpn.models import ConnectionState
from tests.vpn_fakes import VpnHarness


def test_connection_page_without_profiles(qapp, profile_manager: ProfileManager) -> None:
    harness = VpnHarness()
    page = ConnectionPage(profile_manager, harness.backend, locator=lambda: "/usr/bin/openfortivpn")
    assert page.status_text() == "Disconnected"
    assert page.gateway_text() == "Not configured"
    assert page.connect_enabled() is False
    assert page.empty_hint_visible() is True
    assert page.selected_profile() is None


def test_connection_page_with_sso_profile(qapp, profile_manager: ProfileManager) -> None:
    profile_manager.add(name="Office", gateway="vpn.example.com", port=8443, use_sso=True)
    harness = VpnHarness()
    page = ConnectionPage(profile_manager, harness.backend, locator=lambda: "/usr/bin/openfortivpn")
    assert page.connect_enabled() is True
    assert page.action_text() == "Connect with SSO"
    assert page.sso_text() == "Enabled"
    page._on_action_clicked()
    assert harness.process is None
    assert harness.backend.current_state() is ConnectionState.DISCONNECTED


def test_connection_page_connect_disconnect_states(qapp, profile_manager: ProfileManager) -> None:
    profile_manager.add(name="Office", gateway="vpn.example.com", use_sso=False)
    harness = VpnHarness()
    page = ConnectionPage(profile_manager, harness.backend, locator=lambda: "/usr/bin/openfortivpn")
    assert page.action_text() == "Connect"
    page._on_action_clicked()
    page.apply_snapshot(harness.backend.snapshot())
    assert page.action_text() == "Connecting..."
    assert page.connect_enabled() is False
    harness.process.emit("Connected to gateway.")
    page.apply_snapshot(harness.backend.snapshot())
    assert page.status_text() == "Connected"
    assert page.action_text() == "Disconnect"
    harness.process.exit_on_terminate = False
    page._on_action_clicked()
    page.apply_snapshot(harness.backend.snapshot())
    assert page.action_text() == "Disconnecting..."
    assert page.connect_enabled() is False
    assert harness.process.terminate_called


def test_connection_page_missing_openfortivpn(qapp, profile_manager: ProfileManager) -> None:
    profile_manager.add(name="Office", gateway="vpn.example.com", use_sso=False)
    harness = VpnHarness()
    page = ConnectionPage(profile_manager, harness.backend, locator=lambda: None)
    assert page.missing_openfortivpn_visible() is True
    assert "openfortivpn" in page._missing_hint.text()


def test_connection_page_refreshes_when_profile_added(
    qapp, profile_manager: ProfileManager
) -> None:
    harness = VpnHarness()
    page = ConnectionPage(profile_manager, harness.backend, locator=lambda: "/usr/bin/openfortivpn")
    assert page.connect_enabled() is False
    profile_manager.add(name="Office", gateway="vpn.example.com", use_sso=False)
    assert page.connect_enabled() is True
    assert page.gateway_text() == "vpn.example.com"
    assert page.status_text() == "Disconnected"
    assert page.action_text() == "Connect"
