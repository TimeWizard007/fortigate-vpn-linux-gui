# SPDX-License-Identifier: GPL-3.0-or-later
"""GUI smoke tests. These tests must not access the network."""

from __future__ import annotations

from PySide6.QtCore import QSettings

from fortigate_vpn_gui import APP_NAME
from fortigate_vpn_gui.gui.main_window import MainWindow
from fortigate_vpn_gui.profiles.manager import ProfileManager
from fortigate_vpn_gui.vpn.detect import OpenfortivpnDetection
from tests.vpn_fakes import VpnHarness


def _no_openfortivpn(**kwargs) -> OpenfortivpnDetection:
    return OpenfortivpnDetection(available=False, path=None, version=None)


def _make_window(profile_manager: ProfileManager, tmp_path, harness=None) -> MainWindow:
    settings = QSettings(str(tmp_path / "ui.ini"), QSettings.Format.IniFormat)
    vpn = harness.backend if harness is not None else VpnHarness().backend
    return MainWindow(
        profile_manager=profile_manager,
        vpn_backend=vpn,
        detect=_no_openfortivpn,
        settings=settings,
    )


def test_main_window_can_be_instantiated(qapp, profile_manager: ProfileManager, tmp_path) -> None:
    window = _make_window(profile_manager, tmp_path)
    assert window.windowTitle() == APP_NAME
    assert window.connection_status() == "Disconnected"
    window.close()


def test_main_window_shows_profile_config_path(
    qapp, profile_manager: ProfileManager, tmp_path
) -> None:
    window = _make_window(profile_manager, tmp_path)
    from PySide6.QtWidgets import QLineEdit

    field = window.findChild(QLineEdit, "profileConfigPath")
    assert field is not None
    assert "fortigate-vpn-linux-gui" in field.text()
    window.close()


def test_main_window_shutdown_stops_process(
    qapp, profile_manager: ProfileManager, tmp_path
) -> None:
    harness = VpnHarness()
    profile_manager.add(name="Office", gateway="vpn.example.com", use_sso=False)
    window = _make_window(profile_manager, tmp_path, harness=harness)
    window.connection_page._on_action_clicked()
    assert harness.process is not None
    window.close()
    assert harness.process.terminate_called
