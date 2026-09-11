# SPDX-License-Identifier: GPL-3.0-or-later
"""Connect-from-Profiles uses the existing VPN backend. No real VPN."""

from __future__ import annotations

from fortigate_vpn_gui.gui.connection_page import ConnectionPage
from fortigate_vpn_gui.gui.profiles_page import ProfilesPage
from fortigate_vpn_gui.profiles.manager import ProfileManager
from fortigate_vpn_gui.vpn.models import ConnectionState
from tests.vpn_fakes import VpnHarness


def test_connect_from_profiles_uses_existing_backend(
    qapp, profile_manager: ProfileManager
) -> None:
    profile = profile_manager.add(name="Office", gateway="vpn.example.com", use_sso=True)
    harness = VpnHarness()
    connection = ConnectionPage(
        profile_manager, harness.backend, locator=lambda: "/usr/local/bin/openfortivpn"
    )
    navigated: list[str] = []
    page = ProfilesPage(
        profile_manager,
        harness.backend,
        on_connect=lambda: navigated.append("Connection"),
        select_profile=connection.select_profile,
    )
    assert page.connect_profile(profile.id) is True
    assert navigated == ["Connection"]
    assert connection.selected_profile() is not None
    assert connection.selected_profile().id == profile.id
    assert harness.process is not None
    assert harness.backend.snapshot().profile_id == profile.id
    assert "--saml-login" in harness.process.argv
    assert "Connecting" in page._feedback.text()


def test_connect_from_profiles_standard_auth_uses_same_backend(
    qapp, profile_manager: ProfileManager
) -> None:
    profile = profile_manager.add(name="Lab", gateway="192.0.2.10", use_sso=False)
    harness = VpnHarness()
    page = ProfilesPage(profile_manager, harness.backend)
    assert page.connect_profile(profile.id) is True
    assert harness.process is not None
    assert "--saml-login" not in harness.process.argv


def test_connect_disabled_while_busy(qapp, profile_manager: ProfileManager) -> None:
    first = profile_manager.add(name="Office", gateway="vpn.example.com", use_sso=False)
    second = profile_manager.add(name="Home", gateway="home.example", use_sso=False)
    harness = VpnHarness()
    page = ProfilesPage(profile_manager, harness.backend)
    assert page.connect_profile(first.id) is True
    page.apply_snapshot(harness.backend.snapshot())
    assert page.connect_enabled_for(first.id) is False
    assert page.connect_enabled_for(second.id) is False
    assert page.connect_profile(second.id) is False
    assert harness.helper.process is not None
    first_process = harness.process
    harness.process.emit("INFO:   Tunnel is up and running.")
    page.apply_snapshot(harness.backend.snapshot())
    assert harness.backend.snapshot().state is ConnectionState.CONNECTED
    assert page.connect_profile(second.id) is False
    assert harness.process is first_process


def test_connect_prevented_while_disconnecting(
    qapp, profile_manager: ProfileManager
) -> None:
    profile = profile_manager.add(name="Office", gateway="vpn.example.com", use_sso=False)
    other = profile_manager.add(name="Home", gateway="home.example", use_sso=False)
    harness = VpnHarness()
    page = ProfilesPage(profile_manager, harness.backend)
    page.connect_profile(profile.id)
    harness.process.emit("INFO:   Tunnel is up and running.")
    harness.process.exit_on_terminate = False
    harness.backend.disconnect()
    page.apply_snapshot(harness.backend.snapshot())
    assert harness.backend.snapshot().state is ConnectionState.DISCONNECTING
    assert page.connect_profile(other.id) is False


def test_edit_does_not_mutate_active_session(
    qapp, profile_manager: ProfileManager
) -> None:
    profile = profile_manager.add(name="Office", gateway="vpn.example.com", use_sso=False)
    harness = VpnHarness()
    page = ProfilesPage(profile_manager, harness.backend)
    page.connect_profile(profile.id)
    harness.process.emit("INFO:   Tunnel is up and running.")
    profile_manager.update(
        profile.id, name="Renamed", gateway="other.example", use_sso=False
    )
    snapshot = harness.backend.snapshot()
    assert snapshot.state is ConnectionState.CONNECTED
    assert snapshot.profile_name == "Office"
    assert snapshot.profile_id == profile.id


def test_delete_profile_does_not_disconnect(
    qapp, profile_manager: ProfileManager
) -> None:
    profile = profile_manager.add(name="Office", gateway="vpn.example.com", use_sso=False)
    harness = VpnHarness()
    page = ProfilesPage(profile_manager, harness.backend)
    page.connect_profile(profile.id)
    harness.process.emit("INFO:   Tunnel is up and running.")
    page.delete_profile(profile.id, confirmed=True)
    assert profile_manager.get(profile.id) is None
    assert harness.backend.snapshot().state is ConnectionState.CONNECTED
    assert harness.process is not None
    assert harness.process.terminate_called is False


def test_connect_button_uses_same_controller_as_connection_page(
    qapp, profile_manager: ProfileManager
) -> None:
    from PySide6.QtWidgets import QPushButton

    profile = profile_manager.add(name="Office", gateway="vpn.example.com", use_sso=True)
    harness = VpnHarness()
    connection = ConnectionPage(
        profile_manager, harness.backend, locator=lambda: "/usr/local/bin/openfortivpn"
    )
    page = ProfilesPage(
        profile_manager,
        harness.backend,
        select_profile=connection.select_profile,
    )
    button = page.findChild(QPushButton, f"connectProfileButton_{profile.id}")
    assert button is not None
    button.click()
    assert harness.backend is connection._vpn
    assert harness.process is not None
    assert connection._trust_prompt is None
