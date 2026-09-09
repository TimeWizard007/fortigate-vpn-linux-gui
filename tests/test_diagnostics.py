# SPDX-License-Identifier: GPL-3.0-or-later
"""Diagnostics snapshot tests. No real openfortivpn execution."""

from __future__ import annotations

from fortigate_vpn_gui.diagnostics.collector import build_diagnostics_snapshot
from fortigate_vpn_gui.gui.diagnostics_page import DiagnosticsPage
from fortigate_vpn_gui.profiles.manager import ProfileManager
from fortigate_vpn_gui.profiles.model import build_profile
from fortigate_vpn_gui.vpn.detect import OpenfortivpnDetection
from tests.vpn_fakes import VpnHarness

_AUTH_URL = "https://vpn.example.com:443/remote/saml/start?id=should-not-leak"


def test_diagnostics_snapshot_values() -> None:
    harness = VpnHarness()
    profile = build_profile(name="Office", gateway="vpn.example.com", port=443, use_sso=False)
    harness.backend.connect(profile)
    harness.process.emit("Connected to gateway.")

    def detect(**kwargs):
        return OpenfortivpnDetection(
            available=True,
            path="/usr/bin/openfortivpn",
            version="1.21.0",
            supports_saml=False,
            supports_cookie_stdin=True,
        )

    data = build_diagnostics_snapshot(
        harness.backend,
        profile,
        "/tmp/profiles.json",
        detect=detect,
    )
    assert data["openfortivpn_detected"] == "Yes"
    assert data["executable_path"] == "/usr/local/bin/openfortivpn"
    assert data["selected_executable"] == "/usr/local/bin/openfortivpn"
    assert data["version"] == "1.24.1"
    assert data["supports_saml"] == "No"
    assert data["vpn_state"] == "Connected"
    assert data["process_pid"] == "4242"
    assert "Office" in data["selected_profile"]
    assert data["auth_mode"] == "non-SSO"
    assert data["waiting_for_auth"] == "No"
    assert data["config_path"] == "/tmp/profiles.json"
    assert "should-not-leak" not in str(data.values())
    assert data["helper_installed"] == "Yes"
    assert data["authorization_mechanism"] == "polkit"
    assert data["helper_startup_detail"] == "—"
    assert data["certificate_pinned"] == "No"
    assert data["failure_reason"] == "—"
    assert data["privileged_pid"] == "4242"


def test_diagnostics_saml_waiting_state() -> None:
    harness = VpnHarness()
    profile = build_profile(name="Office", gateway="vpn.example.com", use_sso=True)
    harness.backend.connect(profile)
    harness.process.emit(f"INFO:   Authenticate at '{_AUTH_URL}'")

    def detect(**kwargs):
        return OpenfortivpnDetection(
            available=True,
            path="/usr/local/bin/openfortivpn",
            version="1.24.1",
            supports_saml=True,
            supports_cookie_stdin=True,
        )

    data = build_diagnostics_snapshot(harness.backend, profile, "/tmp/profiles.json", detect=detect)
    assert data["supports_saml"] == "Yes"
    assert data["auth_mode"] == "SAML/SSO"
    assert data["waiting_for_auth"] == "Yes"
    assert data["browser_status"] == "opened"
    assert "should-not-leak" not in str(data.values())
    assert "id=" not in str(data.values())


def test_diagnostics_page_missing_binary(qapp, profile_manager: ProfileManager) -> None:
    harness = VpnHarness(executable=None)

    def detect(**kwargs):
        return OpenfortivpnDetection(available=False, path=None, version=None)

    page = DiagnosticsPage(
        profile_manager,
        harness.backend,
        lambda: None,
        detect=detect,
    )
    page.refresh()
    assert page._detected.text() == "No"
    assert page._pid.text() == "—"
    assert page._state.text() == "Disconnected"
    assert page._saml.text() == "—"
    assert page._waiting.text() == "No"
