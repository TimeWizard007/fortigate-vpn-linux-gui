# SPDX-License-Identifier: GPL-3.0-or-later
"""Diagnostics snapshot tests. No real openfortivpn execution."""

from __future__ import annotations

from fortigate_vpn_gui.diagnostics.collector import build_diagnostics_snapshot
from fortigate_vpn_gui.gui.diagnostics_page import DiagnosticsPage
from fortigate_vpn_gui.profiles.manager import ProfileManager
from fortigate_vpn_gui.profiles.model import build_profile
from fortigate_vpn_gui.vpn.detect import OpenfortivpnDetection
from tests.vpn_fakes import VpnHarness


def test_diagnostics_snapshot_values() -> None:
    harness = VpnHarness()
    profile = build_profile(name="Office", gateway="vpn.example.com", port=443, use_sso=False)
    harness.backend.connect(profile)
    harness.process.emit("Connected to gateway.")

    def detect(*, include_version: bool = False):
        return OpenfortivpnDetection(
            available=True,
            path="/usr/bin/openfortivpn",
            version="1.22.1" if include_version else None,
        )

    data = build_diagnostics_snapshot(
        harness.backend,
        profile,
        "/tmp/profiles.json",
        detect=detect,
    )
    assert data["openfortivpn_detected"] == "Yes"
    assert data["executable_path"] == "/usr/bin/openfortivpn"
    assert data["version"] == "1.22.1"
    assert data["vpn_state"] == "Connected"
    assert data["process_pid"] == "4242"
    assert "Office" in data["selected_profile"]
    assert data["config_path"] == "/tmp/profiles.json"


def test_diagnostics_page_missing_binary(qapp, profile_manager: ProfileManager) -> None:
    harness = VpnHarness()

    def detect(*, include_version: bool = False):
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
