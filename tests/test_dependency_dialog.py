# SPDX-License-Identifier: GPL-3.0-or-later
"""Missing-dependency dialog tests. These tests must not run apt or sudo."""

from __future__ import annotations

from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import QLineEdit

from fortigate_vpn_gui.gui.dependency_dialog import MissingDependencyDialog
from fortigate_vpn_gui.system.dependencies import DependencyChecker, HostProbes


def test_dialog_shows_static_ubuntu_command(qapp) -> None:
    probes = HostProbes(
        library_exists=lambda name: False,
        executable_exists=lambda name: False,
        read_os_release=lambda: 'ID=ubuntu\nPRETTY_NAME="Ubuntu 24.04.3 LTS"\n',
    )
    report = DependencyChecker(probes=probes).check()
    dialog = MissingDependencyDialog(report)
    assert dialog.install_command() == "sudo apt install libxcb-cursor0"
    command_field = dialog.findChild(QLineEdit, "installCommand")
    assert command_field is not None
    assert command_field.text() == "sudo apt install libxcb-cursor0"
    dialog.copy_command()
    clipboard = QGuiApplication.clipboard()
    assert clipboard is not None
    assert clipboard.text() == "sudo apt install libxcb-cursor0"
    dialog.close()
