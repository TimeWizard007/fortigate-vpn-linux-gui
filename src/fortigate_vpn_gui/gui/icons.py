# SPDX-License-Identifier: GPL-3.0-or-later
"""Application icon loading. Never uses a source-checkout absolute path."""

from __future__ import annotations

from importlib.resources import as_file, files

from PySide6.QtGui import QColor, QIcon, QPainter, QPixmap

from fortigate_vpn_gui.metadata import ICON_NAME


def application_icon() -> QIcon:
    """Return the packaged or theme icon, with a generated fallback."""
    theme = QIcon.fromTheme(ICON_NAME)
    if not theme.isNull():
        return theme
    try:
        resource = files("fortigate_vpn_gui.resources").joinpath("icons", f"{ICON_NAME}.svg")
        with as_file(resource) as path:
            if path.is_file():
                icon = QIcon(str(path))
                if not icon.isNull():
                    return icon
    except (FileNotFoundError, ModuleNotFoundError, OSError):
        pass
    return _generated_fallback_icon()


def _generated_fallback_icon() -> QIcon:
    pixmap = QPixmap(64, 64)
    pixmap.fill(QColor(0, 0, 0, 0))
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setBrush(QColor("#0f766e"))
    painter.setPen(QColor("#0f766e"))
    painter.drawRoundedRect(2, 2, 60, 60, 14, 14)
    painter.setBrush(QColor("#99f6e4"))
    painter.setPen(QColor("#ecfdf5"))
    painter.drawEllipse(26, 26, 12, 12)
    painter.end()
    return QIcon(pixmap)
