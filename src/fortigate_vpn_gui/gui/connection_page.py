# SPDX-License-Identifier: GPL-3.0-or-later
"""Connection page: profile selector, status, and placeholder SSO button."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QFormLayout,
    QFrame,
    QLabel,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


class ConnectionPage(QWidget):
    """Connection controls that do not start a VPN session."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)

        title = QLabel("Connection")
        title.setObjectName("pageTitle")
        title.setStyleSheet("font-size: 20px; font-weight: 600;")

        self._profile_combo = QComboBox()
        self._profile_combo.addItem("No profiles configured")
        self._profile_combo.setEnabled(False)
        self._profile_combo.setMinimumWidth(280)

        self._status_label = QLabel("Disconnected")
        self._status_label.setObjectName("connectionStatus")

        self._gateway_label = QLabel("Not configured")
        self._gateway_label.setObjectName("gatewayValue")

        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        form.setHorizontalSpacing(16)
        form.setVerticalSpacing(10)
        form.addRow("Connection profile:", self._profile_combo)
        form.addRow("Status:", self._status_label)
        form.addRow("Gateway:", self._gateway_label)

        form_frame = QFrame()
        form_frame.setLayout(form)

        self._connect_button = QPushButton("Connect with SSO")
        self._connect_button.setObjectName("connectButton")
        self._connect_button.setDefault(True)
        self._connect_button.clicked.connect(self._on_connect_clicked)

        notice = QLabel(
            "SSO authentication and VPN connectivity are planned and are not "
            "implemented yet.\n\n"
            "The intended flow uses the system browser and Microsoft Entra ID. "
            "This button does not open a browser, contact any server, or "
            "change network configuration."
        )
        notice.setWordWrap(True)
        notice.setObjectName("placeholderNotice")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 24, 16)
        layout.setSpacing(16)
        layout.addWidget(title)
        layout.addWidget(form_frame)
        layout.addWidget(self._connect_button)
        layout.addWidget(notice)
        layout.addStretch(1)

    def status_text(self) -> str:
        """Return the displayed connection status."""
        return self._status_label.text()

    def _on_connect_clicked(self) -> None:
        QMessageBox.information(
            self,
            "Not implemented",
            "Connect with SSO is a placeholder.\n\n"
            "SAML/SSO authentication, Microsoft Entra ID, and FortiGate SSL VPN "
            "connectivity are planned for a later release. No network request "
            "was made.",
        )
