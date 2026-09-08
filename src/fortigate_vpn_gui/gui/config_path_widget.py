# SPDX-License-Identifier: GPL-3.0-or-later
"""Read-only display of the per-user profile configuration path."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import QLabel, QLineEdit, QVBoxLayout, QWidget

from fortigate_vpn_gui.profiles.storage import display_path


class ProfileConfigPathWidget(QWidget):
    """Show where ``profiles.json`` lives. The file contains no secrets."""

    def __init__(self, path: Path, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        heading = QLabel("Profile configuration file")
        heading.setStyleSheet("font-weight: 600;")

        self._path_field = QLineEdit(display_path(path))
        self._path_field.setReadOnly(True)
        self._path_field.setObjectName("profileConfigPath")
        self._path_field.setToolTip(str(path))

        note = QLabel(
            "Profiles are stored per-user as UTF-8 JSON. The file does not "
            "contain passwords, SAML tokens, cookies, or other secrets."
        )
        note.setWordWrap(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        layout.addWidget(heading)
        layout.addWidget(self._path_field)
        layout.addWidget(note)
