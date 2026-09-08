# SPDX-License-Identifier: GPL-3.0-or-later
"""GUI smoke tests. These tests must not access the network."""

from __future__ import annotations

from fortigate_vpn_gui import APP_NAME
from fortigate_vpn_gui.gui.main_window import MainWindow
from fortigate_vpn_gui.profiles.manager import ProfileManager


def test_main_window_can_be_instantiated(qapp, profile_manager: ProfileManager) -> None:
    window = MainWindow(profile_manager=profile_manager)
    assert window.windowTitle() == APP_NAME
    assert window.connection_status() == "Disconnected"
    window.close()


def test_main_window_shows_profile_config_path(qapp, profile_manager: ProfileManager) -> None:
    window = MainWindow(profile_manager=profile_manager)
    from PySide6.QtWidgets import QLineEdit

    field = window.findChild(QLineEdit, "profileConfigPath")
    assert field is not None
    assert "fortigate-vpn-linux-gui" in field.text()
    window.close()
