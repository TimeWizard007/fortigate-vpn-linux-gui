# SPDX-License-Identifier: GPL-3.0-or-later
"""Diagnostics page placeholder with the profile configuration path."""

from __future__ import annotations

from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget

from fortigate_vpn_gui.gui.config_path_widget import ProfileConfigPathWidget
from fortigate_vpn_gui.profiles.manager import ProfileManager


class DiagnosticsPage(QWidget):
    """Diagnostic collection is not implemented; the config path is shown for support."""

    def __init__(self, manager: ProfileManager, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        title = QLabel("Diagnostics")
        title.setStyleSheet("font-size: 20px; font-weight: 600;")
        intro = QLabel(
            "Diagnostic collection will live here in a later release.\n\n"
            "No system probes, packet captures, or VPN health checks are "
            "performed. The profile file path below contains no secrets and "
            "can be shared when reporting issues."
        )
        intro.setWordWrap(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 24, 16)
        layout.setSpacing(12)
        layout.addWidget(title)
        layout.addWidget(intro)
        layout.addWidget(ProfileConfigPathWidget(manager.storage_path))
        layout.addStretch(1)
