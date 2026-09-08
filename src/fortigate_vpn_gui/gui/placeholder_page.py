# SPDX-License-Identifier: GPL-3.0-or-later
"""Reusable placeholder page for features that are not implemented yet."""

from __future__ import annotations

from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget


class PlaceholderPage(QWidget):
    """Simple informational page used until a feature is implemented."""

    def __init__(self, title: str, body: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        heading = QLabel(title)
        heading.setStyleSheet("font-size: 20px; font-weight: 600;")

        description = QLabel(body)
        description.setWordWrap(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 24, 16)
        layout.setSpacing(12)
        layout.addWidget(heading)
        layout.addWidget(description)
        layout.addStretch(1)
