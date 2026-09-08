# SPDX-License-Identifier: GPL-3.0-or-later
"""GUI smoke tests. These tests must not access the network."""

from __future__ import annotations

from fortigate_vpn_gui import APP_NAME
from fortigate_vpn_gui.gui.main_window import MainWindow


def test_main_window_can_be_instantiated(qapp) -> None:
    window = MainWindow()
    assert window.windowTitle() == APP_NAME
    assert window.connection_status() == "Disconnected"
    window.close()
