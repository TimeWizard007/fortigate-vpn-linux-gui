# SPDX-License-Identifier: GPL-3.0-or-later
"""GUI smoke tests. These tests must not access the network."""

from __future__ import annotations

from fortigate_vpn_gui import APP_NAME
from fortigate_vpn_gui.gui.main_window import MainWindow
from fortigate_vpn_gui.profiles.manager import ProfileManager
from fortigate_vpn_gui.vpn.detect import OpenfortivpnDetection
from tests.vpn_fakes import VpnHarness


def _no_openfortivpn(**kwargs) -> OpenfortivpnDetection:
    return OpenfortivpnDetection(available=False, path=None, version=None)


def test_main_window_can_be_instantiated(qapp, profile_manager: ProfileManager) -> None:
    harness = VpnHarness()
    window = MainWindow(
        profile_manager=profile_manager,
        vpn_backend=harness.backend,
        detect=_no_openfortivpn,
    )
    assert window.windowTitle() == APP_NAME
    assert window.connection_status() == "Disconnected"
    window.close()


def test_main_window_shows_profile_config_path(qapp, profile_manager: ProfileManager) -> None:
    harness = VpnHarness()
    window = MainWindow(
        profile_manager=profile_manager,
        vpn_backend=harness.backend,
        detect=_no_openfortivpn,
    )
    from PySide6.QtWidgets import QLineEdit

    field = window.findChild(QLineEdit, "profileConfigPath")
    assert field is not None
    assert "fortigate-vpn-linux-gui" in field.text()
    window.close()


def test_main_window_shutdown_stops_process(qapp, profile_manager: ProfileManager) -> None:
    harness = VpnHarness()
    profile_manager.add(name="Office", gateway="vpn.example.com", use_sso=False)
    window = MainWindow(
        profile_manager=profile_manager,
        vpn_backend=harness.backend,
        detect=_no_openfortivpn,
    )
    window.connection_page._on_action_clicked()
    assert harness.process is not None
    window.close()
    assert harness.process.terminate_called
