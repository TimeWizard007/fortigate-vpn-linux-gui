# SPDX-License-Identifier: GPL-3.0-or-later
"""Scrollable page containers for smaller window sizes."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QScrollArea, QSizePolicy, QWidget


def create_page_scroll_area(content: QWidget) -> QScrollArea:
    """Wrap *content* so it can scroll when the window is short."""
    area = QScrollArea()
    area.setObjectName("pageScrollArea")
    area.setWidgetResizable(True)
    area.setFrameShape(QFrame.Shape.NoFrame)
    area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
    area.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
    area.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
    content.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
    area.setWidget(content)
    return area
