# SPDX-License-Identifier: GPL-3.0-or-later
"""Settings page: local configuration paths and notes."""

from __future__ import annotations

from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget

from fortigate_vpn_gui.gui.config_path_widget import ProfileConfigPathWidget
from fortigate_vpn_gui.profiles.manager import ProfileManager


class SettingsPage(QWidget):
    """Application settings. Certificate verification will never be silently disabled."""

    def __init__(self, manager: ProfileManager, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        title = QLabel("Settings")
        title.setStyleSheet("font-size: 20px; font-weight: 600;")
        intro = QLabel(
            "Application preferences will expand in a later release. "
            "Certificate verification must not be silently disabled."
        )
        intro.setWordWrap(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 24, 16)
        layout.setSpacing(12)
        layout.addWidget(title)
        layout.addWidget(intro)
        layout.addWidget(ProfileConfigPathWidget(manager.storage_path))
        layout.addStretch(1)
