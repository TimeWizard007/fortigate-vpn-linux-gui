# SPDX-License-Identifier: GPL-3.0-or-later
"""Connection page: profile selector and Connect/Disconnect controls."""

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
from fortigate_vpn_gui.system.dependencies import ubuntu_install_command
from fortigate_vpn_gui.vpn.backend import VpnBackend, VpnEvent
from fortigate_vpn_gui.vpn.detect import locate_openfortivpn
from fortigate_vpn_gui.vpn.models import (
    BUSY_STATES,
    ConnectionState,
    VpnErrorCode,
    state_label,
)


class ConnectionPage(QWidget):
    """Connection controls backed by ``VpnBackend``."""

    def __init__(
        self,
        manager: ProfileManager,
        vpn: VpnBackend,
        parent: QWidget | None = None,
        *,
        locator=locate_openfortivpn,
    ) -> None:
        super().__init__(parent)
        self._manager = manager
        self._vpn = vpn
        self._manager.add_change_listener(self.refresh_profiles)
        self._openfortivpn_path = locator()

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

        self._action_button = QPushButton("Connect")
        self._action_button.setObjectName("connectButton")
        self._action_button.setDefault(True)
        self._action_button.clicked.connect(self._on_action_clicked)

        self._empty_hint = QLabel(
            "No profiles configured. Open the Profiles page and add a "
            "connection profile to enable Connect."
        )
        self._empty_hint.setWordWrap(True)
        self._empty_hint.setObjectName("noProfilesHint")

        install = ubuntu_install_command(("openfortivpn",))
        self._missing_hint = QLabel(
            "VPN connectivity is unavailable because openfortivpn is not "
            "installed.\n\n"
            f"Recommended Ubuntu command:\n{install}\n\n"
            "The application does not install packages automatically. The GUI "
            "can still manage profiles."
        )
        self._missing_hint.setWordWrap(True)
        self._missing_hint.setObjectName("missingOpenfortivpnHint")

        self._notice = QLabel(
            "SAML/SSO profiles do not start a VPN in v0.3.0. Use a profile with "
            "Use SSO disabled to exercise the openfortivpn process lifecycle. "
            "Passwords are not stored; authentication may fail, which is expected. "
            "A privileged helper is not implemented yet."
        )
        self._notice.setWordWrap(True)
        self._notice.setObjectName("placeholderNotice")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 24, 16)
        layout.setSpacing(16)
        layout.addWidget(title)
        layout.addWidget(form_frame)
        layout.addWidget(self._action_button)
        layout.addWidget(self._empty_hint)
        layout.addWidget(self._missing_hint)
        layout.addWidget(self._notice)
        layout.addStretch(1)
        self.refresh_profiles()
        self.apply_snapshot(self._vpn.snapshot())

    def status_text(self) -> str:
        return self._status_label.text()

    def gateway_text(self) -> str:
        return self._gateway_label.text()

    def port_text(self) -> str:
        return self._port_label.text()

    def sso_text(self) -> str:
        return self._sso_label.text()

    def connect_enabled(self) -> bool:
        return self._action_button.isEnabled()

    def action_text(self) -> str:
        return self._action_button.text()

    def empty_hint_visible(self) -> bool:
        return not self._empty_hint.isHidden()

    def missing_openfortivpn_visible(self) -> bool:
        return not self._missing_hint.isHidden()

    def selected_profile(self) -> ConnectionProfile | None:
        profile_id = self._profile_combo.currentData()
        if not profile_id:
            return None
        return self._manager.get(str(profile_id))

    def refresh_profiles(self) -> None:
        previous = self._profile_combo.currentData()
        self._profile_combo.blockSignals(True)
        self._profile_combo.clear()
        profiles = self._manager.list_profiles()
        if not profiles:
            self._profile_combo.addItem("No profiles configured")
            self._show_profile(None)
            self._profile_combo.blockSignals(False)
            self.apply_snapshot(self._vpn.snapshot())
            return

        selected_index = 0
        for index, profile in enumerate(profiles):
            self._profile_combo.addItem(profile.name, profile.id)
            if previous and profile.id == previous:
                selected_index = index
        self._profile_combo.setCurrentIndex(selected_index)
        self._profile_combo.blockSignals(False)
        self._show_profile(profiles[selected_index])
        self.apply_snapshot(self._vpn.snapshot())

    def apply_snapshot(self, snapshot) -> None:
        """Update status and buttons from a backend snapshot."""
        self._status_label.setText(state_label(snapshot.state))
        busy = snapshot.state in BUSY_STATES
        has_profile = self.selected_profile() is not None
        missing = self._openfortivpn_path is None
        self._missing_hint.setVisible(missing)
        self._empty_hint.setVisible(not has_profile)
        self._profile_combo.setEnabled(has_profile and not busy)
        self._sync_button(snapshot.state, has_profile)

    def show_user_error(self, event: VpnEvent) -> None:
        message = event.error_message or "The VPN operation could not continue."
        QMessageBox.warning(self, _error_title(event.error_code), message)

    def _sync_button(self, state: ConnectionState, has_profile: bool) -> None:
        profile = self.selected_profile()
        if state in {
            ConnectionState.STARTING,
            ConnectionState.CONNECTING,
            ConnectionState.WAITING_FOR_AUTH,
        }:
            self._action_button.setText("Connecting...")
            self._action_button.setEnabled(False)
            return
        if state is ConnectionState.DISCONNECTING:
            self._action_button.setText("Disconnecting...")
            self._action_button.setEnabled(False)
            return
        if state is ConnectionState.CONNECTED:
            self._action_button.setText("Disconnect")
            self._action_button.setEnabled(True)
            return
        if profile is not None and profile.use_sso:
            self._action_button.setText("Connect with SSO")
        else:
            self._action_button.setText("Connect")
        self._action_button.setEnabled(has_profile)

    def _on_profile_changed(self, _index: int) -> None:
        self._show_profile(self.selected_profile())
        self.apply_snapshot(self._vpn.snapshot())

    def _show_profile(self, profile: ConnectionProfile | None) -> None:
        if profile is None:
            self._gateway_label.setText("Not configured")
            self._port_label.setText("—")
            self._sso_label.setText("—")
            return
        self._gateway_label.setText(profile.gateway)
        self._port_label.setText(str(profile.port))
        self._sso_label.setText("Enabled" if profile.use_sso else "Disabled")

    def _on_action_clicked(self) -> None:
        state = self._vpn.current_state()
        if state is ConnectionState.CONNECTED:
            self._vpn.disconnect()
            return
        self._vpn.connect(self.selected_profile())


def _error_title(code: VpnErrorCode | None) -> str:
    mapping = {
        VpnErrorCode.SSO_NOT_SUPPORTED: "SAML/SSO not available",
        VpnErrorCode.OPENFORTIVPN_MISSING: "openfortivpn is missing",
        VpnErrorCode.PERMISSION_DENIED: "Insufficient privileges",
        VpnErrorCode.AUTH_FAILURE: "Authentication failed",
        VpnErrorCode.FAILED_TO_START: "Failed to start VPN",
        VpnErrorCode.UNEXPECTED_EXIT: "VPN process ended",
        VpnErrorCode.INVALID_PROFILE: "Invalid profile",
        VpnErrorCode.ALREADY_BUSY: "VPN busy",
    }
    if code is None:
        return "VPN"
    return mapping.get(code, "VPN")
