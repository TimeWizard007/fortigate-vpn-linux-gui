# SPDX-License-Identifier: GPL-3.0-or-later
"""Main application window and navigation."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from fortigate_vpn_gui import APP_NAME, __version__
from fortigate_vpn_gui.gui.connection_page import ConnectionPage
from fortigate_vpn_gui.gui.placeholder_page import PlaceholderPage

_NAV_ITEMS: tuple[str, ...] = (
    "Connection",
    "Profiles",
    "Diagnostics",
    "Logs",
    "Settings",
)


class MainWindow(QMainWindow):
    """Primary window: sidebar navigation plus stacked pages."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(APP_NAME)
        self.setMinimumSize(840, 560)
        self.resize(960, 640)

        self._connection_page = ConnectionPage()
        self._stack = QStackedWidget()
        self._stack.addWidget(self._connection_page)
        self._stack.addWidget(
            PlaceholderPage(
                "Profiles",
                "Connection profiles will be managed here in a later release.\n\n"
                "Nothing is stored or loaded yet. Profile persistence is not "
                "implemented in v0.1.x.",
            )
        )
        self._stack.addWidget(
            PlaceholderPage(
                "Diagnostics",
                "Diagnostic collection will live here in a later release.\n\n"
                "No system probes, packet captures, or VPN health checks are "
                "performed in v0.1.x.",
            )
        )
        self._stack.addWidget(
            PlaceholderPage(
                "Logs",
                "Application logs will appear here in a later release.\n\n"
                "When logging is added, credentials, SAML tokens, cookies, and "
                "other authentication material must be redacted. Nothing is "
                "written to disk in v0.1.x.",
            )
        )
        self._stack.addWidget(
            PlaceholderPage(
                "Settings",
                "Application settings will appear here in a later release.\n\n"
                "No configuration is persisted in v0.1.x. Certificate "
                "verification will never be silently disabled.",
            )
        )

        self._nav = QListWidget()
        self._nav.setObjectName("navList")
        self._nav.setFixedWidth(180)
        for label in _NAV_ITEMS:
            QListWidgetItem(label, self._nav)
        self._nav.setCurrentRow(0)
        self._nav.currentRowChanged.connect(self._stack.setCurrentIndex)

        header = QLabel(f"{APP_NAME}  ·  v{__version__}")
        header.setObjectName("appHeader")
        header.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)

        body = QWidget()
        body_layout = QHBoxLayout(body)
        body_layout.setContentsMargins(12, 8, 12, 12)
        body_layout.setSpacing(12)
        body_layout.addWidget(self._nav)
        body_layout.addWidget(self._stack, stretch=1)

        central = QWidget()
        layout = QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(header)
        layout.addWidget(body, stretch=1)
        self.setCentralWidget(central)

        self.statusBar().showMessage("Disconnected")
        self._apply_style()

    def connection_status(self) -> str:
        """Return the connection status shown in the Connection page."""
        return self._connection_page.status_text()

    def _apply_style(self) -> None:
        self.setStyleSheet(
            """
            QLabel#appHeader {
                font-size: 16px;
                font-weight: 600;
                padding: 14px 16px 8px 16px;
            }
            QListWidget#navList {
                border: none;
                outline: none;
                padding: 8px 0;
                font-size: 14px;
            }
            QListWidget#navList::item {
                padding: 10px 14px;
            }
            QPushButton#connectButton {
                font-size: 16px;
                font-weight: 600;
                min-height: 48px;
                padding: 12px 24px;
            }
            """
        )
