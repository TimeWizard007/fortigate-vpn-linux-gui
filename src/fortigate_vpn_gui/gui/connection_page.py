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

from fortigate_vpn_gui.profiles.manager import ProfileManager
from fortigate_vpn_gui.profiles.model import ConnectionProfile


class ConnectionPage(QWidget):
    """Connection controls that do not start a VPN session."""

    def __init__(self, manager: ProfileManager, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._manager = manager
        self._manager.add_change_listener(self.refresh_profiles)

        title = QLabel("Connection")
        title.setObjectName("pageTitle")
        title.setStyleSheet("font-size: 20px; font-weight: 600;")

        self._profile_combo = QComboBox()
        self._profile_combo.setObjectName("profileSelector")
        self._profile_combo.setMinimumWidth(280)
        self._profile_combo.currentIndexChanged.connect(self._on_profile_changed)

        self._status_label = QLabel("Disconnected")
        self._status_label.setObjectName("connectionStatus")

        self._gateway_label = QLabel("Not configured")
        self._gateway_label.setObjectName("gatewayValue")

        self._port_label = QLabel("—")
        self._port_label.setObjectName("portValue")

        self._sso_label = QLabel("—")
        self._sso_label.setObjectName("ssoValue")

        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        form.setHorizontalSpacing(16)
        form.setVerticalSpacing(10)
        form.addRow("Connection profile:", self._profile_combo)
        form.addRow("Status:", self._status_label)
        form.addRow("Gateway:", self._gateway_label)
        form.addRow("Port:", self._port_label)
        form.addRow("SSO:", self._sso_label)

        form_frame = QFrame()
        form_frame.setLayout(form)

        self._connect_button = QPushButton("Connect with SSO")
        self._connect_button.setObjectName("connectButton")
        self._connect_button.setDefault(True)
        self._connect_button.clicked.connect(self._on_connect_clicked)

        self._empty_hint = QLabel(
            "No profiles configured. Open the Profiles page and add a "
            "connection profile to enable Connect with SSO."
        )
        self._empty_hint.setWordWrap(True)
        self._empty_hint.setObjectName("noProfilesHint")

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
        layout.addWidget(self._empty_hint)
        layout.addWidget(notice)
        layout.addStretch(1)
        self.refresh_profiles()

    def status_text(self) -> str:
        """Return the displayed connection status."""
        return self._status_label.text()

    def gateway_text(self) -> str:
        return self._gateway_label.text()

    def port_text(self) -> str:
        return self._port_label.text()

    def sso_text(self) -> str:
        return self._sso_label.text()

    def connect_enabled(self) -> bool:
        return self._connect_button.isEnabled()

    def empty_hint_visible(self) -> bool:
        return not self._empty_hint.isHidden()

    def selected_profile(self) -> ConnectionProfile | None:
        profile_id = self._profile_combo.currentData()
        if not profile_id:
            return None
        return self._manager.get(str(profile_id))

    def refresh_profiles(self) -> None:
        """Reload the selector from the profile manager without restarting."""
        previous = self._profile_combo.currentData()
        self._profile_combo.blockSignals(True)
        self._profile_combo.clear()
        profiles = self._manager.list_profiles()
        if not profiles:
            self._profile_combo.addItem("No profiles configured")
            self._profile_combo.setEnabled(False)
            self._connect_button.setEnabled(False)
            self._empty_hint.show()
            self._show_profile(None)
            self._profile_combo.blockSignals(False)
            return

        self._profile_combo.setEnabled(True)
        self._connect_button.setEnabled(True)
        self._empty_hint.hide()
        selected_index = 0
        for index, profile in enumerate(profiles):
            self._profile_combo.addItem(profile.name, profile.id)
            if previous and profile.id == previous:
                selected_index = index
        self._profile_combo.setCurrentIndex(selected_index)
        self._profile_combo.blockSignals(False)
        self._show_profile(profiles[selected_index])

    def _on_profile_changed(self, _index: int) -> None:
        self._show_profile(self.selected_profile())

    def _show_profile(self, profile: ConnectionProfile | None) -> None:
        self._status_label.setText("Disconnected")
        if profile is None:
            self._gateway_label.setText("Not configured")
            self._port_label.setText("—")
            self._sso_label.setText("—")
            return
        self._gateway_label.setText(profile.gateway)
        self._port_label.setText(str(profile.port))
        self._sso_label.setText("Enabled" if profile.use_sso else "Disabled")

    def _on_connect_clicked(self) -> None:
        QMessageBox.information(
            self,
            "Not implemented",
            "Connect with SSO is a placeholder.\n\n"
            "SAML/SSO authentication, Microsoft Entra ID, and FortiGate SSL VPN "
            "connectivity are planned for a later release. No network request "
            "was made.",
        )
