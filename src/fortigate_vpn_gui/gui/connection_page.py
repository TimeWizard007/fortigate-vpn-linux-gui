# SPDX-License-Identifier: GPL-3.0-or-later
"""Connection page: profile selector and Connect/Disconnect/SSO controls."""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QFormLayout,
    QFrame,
    QLabel,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from fortigate_vpn_gui.gui.certificate_dialog import CertificateTrustDialog
from fortigate_vpn_gui.gui.page_container import create_page_scroll_area
from fortigate_vpn_gui.gui.windowing import dialog_parent_for
from fortigate_vpn_gui.helper.protocol import CertificateInfo
from fortigate_vpn_gui.metadata import CONNECTION_SSO_NOTICE
from fortigate_vpn_gui.profiles.manager import ProfileManager
from fortigate_vpn_gui.profiles.model import ConnectionProfile, auth_mode_label
from fortigate_vpn_gui.system.dependencies import ubuntu_install_command
from fortigate_vpn_gui.vpn.backend import VpnBackend, VpnEvent
from fortigate_vpn_gui.vpn.detect import locate_openfortivpn
from fortigate_vpn_gui.vpn.models import (
    BUSY_STATES,
    CANCELABLE_STATES,
    ConnectionState,
    VpnErrorCode,
    VpnSnapshot,
    state_label,
)

TrustPrompt = Callable[..., bool]


class ConnectionPage(QWidget):
    """Connection controls backed by ``VpnBackend``."""

    def __init__(
        self,
        manager: ProfileManager,
        vpn: VpnBackend,
        parent: QWidget | None = None,
        *,
        locator=locate_openfortivpn,
        trust_prompt: TrustPrompt | None = None,
    ) -> None:
        super().__init__(parent)
        self._manager = manager
        self._vpn = vpn
        self._trust_prompt = trust_prompt
        self._manager.add_change_listener(self.refresh_profiles)
        self._openfortivpn_path = locator()
        self._safe_auth_url: str | None = None
        self._last_trust_decision: bool | None = None
        self._shown_cert_sha: str | None = None

        title = QLabel("Connection")
        title.setObjectName("pageTitle")

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
        form.addRow("Authentication:", self._sso_label)

        form_frame = QFrame()
        form_frame.setLayout(form)

        self._action_button = QPushButton("Connect")
        self._action_button.setObjectName("connectButton")
        self._action_button.setDefault(True)
        self._action_button.clicked.connect(self._on_action_clicked)

        self._reconnect_button = QPushButton("Reconnect")
        self._reconnect_button.setObjectName("reconnectButton")
        self._reconnect_button.setVisible(False)
        self._reconnect_button.setAutoDefault(False)
        self._reconnect_button.setDefault(False)
        self._reconnect_button.clicked.connect(self._on_reconnect_clicked)

        self._copy_url_button = QPushButton("Copy sign-in address")
        self._copy_url_button.setObjectName("copySignInUrlButton")
        self._copy_url_button.setVisible(False)
        self._copy_url_button.clicked.connect(self._copy_safe_auth_url)

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

        self._sso_hint = QLabel("Complete sign-in in your web browser.")
        self._sso_hint.setWordWrap(True)
        self._sso_hint.setObjectName("ssoBrowserHint")
        self._sso_hint.setVisible(False)

        self._cert_hint = QLabel("Waiting for certificate trust")
        self._cert_hint.setWordWrap(True)
        self._cert_hint.setObjectName("certificateTrustHint")
        self._cert_hint.setVisible(False)

        self._closing_hint = QLabel(
            "Closing...\nCleaning up VPN connection and background processes."
        )
        self._closing_hint.setWordWrap(True)
        self._closing_hint.setObjectName("closingHint")
        self._closing_hint.setVisible(False)

        self._reconnect_hint = QLabel("")
        self._reconnect_hint.setWordWrap(True)
        self._reconnect_hint.setObjectName("reconnectHint")
        self._reconnect_hint.setVisible(False)

        self._helper_hint = QLabel(
            "The privileged VPN helper is not installed, so the VPN cannot start. "
            "See the About page for how the helper works."
        )
        self._helper_hint.setWordWrap(True)
        self._helper_hint.setObjectName("missingHelperHint")
        self._helper_hint.setVisible(False)

        self._failure_hint = QLabel("")
        self._failure_hint.setWordWrap(True)
        self._failure_hint.setObjectName("connectionFailureHint")
        self._failure_hint.setVisible(False)

        self._notice = QLabel(CONNECTION_SSO_NOTICE)
        self._notice.setWordWrap(True)
        self._notice.setObjectName("placeholderNotice")

        inner = QWidget()
        layout = QVBoxLayout(inner)
        layout.setContentsMargins(16, 12, 24, 16)
        layout.setSpacing(12)
        layout.addWidget(title)
        layout.addWidget(form_frame)
        layout.addWidget(self._action_button)
        layout.addWidget(self._reconnect_button)
        layout.addWidget(self._copy_url_button)
        layout.addWidget(self._empty_hint)
        layout.addWidget(self._missing_hint)
        layout.addWidget(self._helper_hint)
        layout.addWidget(self._failure_hint)
        layout.addWidget(self._sso_hint)
        layout.addWidget(self._cert_hint)
        layout.addWidget(self._closing_hint)
        layout.addWidget(self._reconnect_hint)
        layout.addWidget(self._notice)
        layout.addStretch(1)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(create_page_scroll_area(inner))
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

    def sso_hint_visible(self) -> bool:
        return not self._sso_hint.isHidden()

    def cert_hint_visible(self) -> bool:
        return not self._cert_hint.isHidden()

    def copy_url_visible(self) -> bool:
        return not self._copy_url_button.isHidden()

    def missing_helper_visible(self) -> bool:
        return not self._helper_hint.isHidden()

    def closing_hint_visible(self) -> bool:
        return not self._closing_hint.isHidden()

    def reconnect_hint_visible(self) -> bool:
        return not self._reconnect_hint.isHidden()

    def reconnect_button_visible(self) -> bool:
        return not self._reconnect_button.isHidden()

    def failure_hint_visible(self) -> bool:
        return not self._failure_hint.isHidden()

    def failure_hint_text(self) -> str:
        return self._failure_hint.text()

    def notice_text(self) -> str:
        return self._notice.text()

    def last_trust_decision(self) -> bool | None:
        return self._last_trust_decision

    def selected_profile(self) -> ConnectionProfile | None:
        profile_id = self._profile_combo.currentData()
        if not profile_id:
            return None
        return self._manager.get(str(profile_id))

    def select_profile(self, profile_id: str) -> bool:
        """Select *profile_id* in the combo. Returns False if it is not listed."""
        for index in range(self._profile_combo.count()):
            if self._profile_combo.itemData(index) == profile_id:
                self._profile_combo.setCurrentIndex(index)
                return True
        return False

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

        default_id = self._manager.default_profile_id()
        selected_index = 0
        previous_index: int | None = None
        default_index: int | None = None
        for index, profile in enumerate(profiles):
            label = profile.name
            if profile.id == default_id:
                label = f"{profile.name} (default)"
                default_index = index
            self._profile_combo.addItem(label, profile.id)
            if previous and profile.id == previous:
                previous_index = index
        if previous_index is not None:
            selected_index = previous_index
        elif default_index is not None:
            selected_index = default_index
        self._profile_combo.setCurrentIndex(selected_index)
        self._profile_combo.blockSignals(False)
        self._show_profile(profiles[selected_index])
        self.apply_snapshot(self._vpn.snapshot())

    def apply_snapshot(self, snapshot: VpnSnapshot) -> None:
        """Update status and buttons from a backend snapshot."""
        self._safe_auth_url = snapshot.safe_auth_url
        busy = snapshot.state in BUSY_STATES or snapshot.manual_reconnect
        has_profile = self.selected_profile() is not None
        missing = self._openfortivpn_path is None
        waiting = snapshot.state is ConnectionState.WAITING_FOR_AUTH
        waiting_cert = snapshot.state is ConnectionState.WAITING_FOR_CERTIFICATE_TRUST
        closing = snapshot.shutdown_in_progress or snapshot.state is ConnectionState.CLOSING
        if snapshot.manual_reconnect and not closing:
            self._status_label.setText("Reconnecting...")
        else:
            self._status_label.setText(state_label(snapshot.state))
        helper_missing = snapshot.helper_installed is False or snapshot.helper_status == "missing"
        self._missing_hint.setVisible(missing and not closing)
        self._helper_hint.setVisible(helper_missing and not closing)
        self._empty_hint.setVisible(not has_profile and not closing)
        self._sso_hint.setVisible(waiting and not closing)
        self._cert_hint.setVisible(waiting_cert and not closing)
        self._closing_hint.setVisible(closing)
        failed = snapshot.state is ConnectionState.FAILED and not closing
        if failed and snapshot.error_message:
            self._failure_hint.setText(snapshot.error_message)
            self._failure_hint.setVisible(True)
        else:
            self._failure_hint.setVisible(False)
        if snapshot.reconnect_pending and not closing:
            delay = snapshot.reconnect_delay_seconds
            delay_display = int(delay) if delay == int(delay) else delay
            self._reconnect_hint.setText(
                f"Reconnecting in {delay_display} seconds... "
                f"(attempt {snapshot.reconnect_attempt} of {snapshot.reconnect_limit})"
            )
            self._reconnect_hint.setVisible(True)
        elif snapshot.manual_reconnect and not closing:
            self._reconnect_hint.setText("Reconnecting...")
            self._reconnect_hint.setVisible(True)
        else:
            self._reconnect_hint.setVisible(False)
        self._copy_url_button.setVisible(waiting and bool(snapshot.safe_auth_url) and not closing)
        self._profile_combo.setEnabled(has_profile and not busy)
        self._sync_button(snapshot, has_profile)
        if snapshot.state in {ConnectionState.DISCONNECTED, ConnectionState.STARTING}:
            self._shown_cert_sha = None

    def show_user_error(self, event: VpnEvent) -> None:
        if event.error_code in {
            VpnErrorCode.CERTIFICATE_UNTRUSTED,
            VpnErrorCode.CERTIFICATE_CHANGED,
        }:
            self._handle_certificate_error(event)
            return
        message = event.error_message or "The VPN operation could not continue."
        QMessageBox.warning(dialog_parent_for(self), _error_title(event.error_code), message)

    def _handle_certificate_error(self, event: VpnEvent) -> None:
        profile = self.selected_profile()
        info = event.certificate or event.snapshot.presented_certificate
        if profile is None or info is None:
            QMessageBox.warning(
                dialog_parent_for(self),
                _error_title(event.error_code),
                event.error_message or "",
            )
            return
        if self._shown_cert_sha == info.sha256:
            return
        self._shown_cert_sha = info.sha256
        changed = event.error_code is VpnErrorCode.CERTIFICATE_CHANGED
        accepted = self._ask_certificate_trust(
            gateway=profile.gateway,
            certificate=info,
            previous_fingerprint=profile.trusted_cert_sha256,
            changed=changed,
        )
        self._last_trust_decision = accepted
        if not accepted:
            self._vpn.disconnect()
            return
        self._manager.set_trusted_certificate(profile.id, info.sha256)
        updated = self._manager.get(profile.id)
        self._vpn.connect(updated, after_trust=True)

    def _sync_button(self, snapshot: VpnSnapshot, has_profile: bool) -> None:
        profile = self.selected_profile()
        state = snapshot.state
        closing = snapshot.shutdown_in_progress or state is ConnectionState.CLOSING
        self._reconnect_button.setVisible(state is ConnectionState.CONNECTED and not closing)
        self._reconnect_button.setEnabled(state is ConnectionState.CONNECTED and not closing)
        if closing:
            self._action_button.setText("Closing...")
            self._action_button.setEnabled(False)
            return
        if snapshot.manual_reconnect:
            self._reconnect_button.setVisible(False)
            self._reconnect_button.setEnabled(False)
            self._action_button.setText("Reconnecting...")
            self._action_button.setEnabled(False)
            return
        if snapshot.reconnect_pending:
            self._action_button.setText("Cancel reconnect")
            self._action_button.setEnabled(True)
            return
        if state is ConnectionState.STARTING:
            self._action_button.setText("Starting...")
            self._action_button.setEnabled(False)
            return
        if state is ConnectionState.WAITING_FOR_AUTH:
            self._action_button.setText("Cancel")
            self._action_button.setEnabled(True)
            return
        if state is ConnectionState.WAITING_FOR_CERTIFICATE_TRUST:
            self._action_button.setText("Cancel")
            self._action_button.setEnabled(True)
            return
        if state is ConnectionState.CONNECTING:
            self._action_button.setText("Cancel")
            self._action_button.setEnabled(True)
            return
        if state is ConnectionState.DISCONNECTING:
            self._action_button.setText("Disconnecting...")
            self._action_button.setEnabled(False)
            return
        if state is ConnectionState.CONNECTED:
            self._action_button.setText("Disconnect")
            self._action_button.setEnabled(True)
            return
        if state is ConnectionState.FAILED:
            self._action_button.setText("Connect again")
            self._action_button.setEnabled(has_profile)
            return
        if profile is not None and profile.use_sso:
            self._action_button.setText("Connect with SSO")
        else:
            self._action_button.setText("Connect")
        self._action_button.setEnabled(has_profile)

    def _on_reconnect_clicked(self) -> None:
        if self._vpn.snapshot().shutdown_in_progress:
            return
        self._vpn.reconnect(self.selected_profile())

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
        self._sso_label.setText(auth_mode_label(profile.use_sso))

    def _on_action_clicked(self) -> None:
        snapshot = self._vpn.snapshot()
        if snapshot.shutdown_in_progress or snapshot.state is ConnectionState.CLOSING:
            return
        if snapshot.manual_reconnect:
            return
        if snapshot.reconnect_pending:
            self._vpn.disconnect()
            return
        state = snapshot.state
        if state in CANCELABLE_STATES:
            self._vpn.disconnect()
            return
        self._vpn.connect(self.selected_profile())

    def _copy_safe_auth_url(self) -> None:
        """Copy origin+path only. Query values are never placed on the clipboard."""
        if not self._safe_auth_url:
            return
        clipboard = QApplication.clipboard()
        clipboard.setText(self._safe_auth_url)

    def _ask_certificate_trust(
        self,
        *,
        gateway: str,
        certificate: CertificateInfo,
        previous_fingerprint: str | None,
        changed: bool,
    ) -> bool:
        if self._trust_prompt is not None:
            return bool(
                self._trust_prompt(
                    gateway=gateway,
                    certificate=certificate,
                    previous_fingerprint=previous_fingerprint,
                    changed=changed,
                )
            )
        dialog = CertificateTrustDialog(
            gateway=gateway,
            certificate=certificate,
            previous_fingerprint=previous_fingerprint,
            changed=changed,
            parent=dialog_parent_for(self),
        )
        return dialog.exec() == QDialog.DialogCode.Accepted


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
        VpnErrorCode.BROWSER_FAILED: "Browser launch failed",
        VpnErrorCode.SAML_TIMEOUT: "SAML sign-in timed out",
        VpnErrorCode.INVALID_AUTH_URL: "Unsafe sign-in URL",
        VpnErrorCode.PRIVILEGE_DENIED: "Authorization denied",
        VpnErrorCode.HELPER_NOT_AVAILABLE: "Privileged helper missing",
        VpnErrorCode.HELPER_VERSION_MISMATCH: "Helper version mismatch",
        VpnErrorCode.HELPER_STARTUP_FAILED: "Privileged helper failed to start",
        VpnErrorCode.POLKIT_UNAVAILABLE: "polkit unavailable",
        VpnErrorCode.CERTIFICATE_UNTRUSTED: "Gateway certificate",
        VpnErrorCode.CERTIFICATE_CHANGED: "Gateway certificate changed",
        VpnErrorCode.SAML_FAILED: "SAML sign-in failed",
        VpnErrorCode.VPN_PROCESS_FAILED: "VPN process ended",
        VpnErrorCode.CONNECTION_LOST: "VPN connection lost",
        VpnErrorCode.PPP_FAILED: "PPP setup failed",
        VpnErrorCode.ROUTE_FAILED: "Route setup failed",
        VpnErrorCode.DNS_FAILED: "DNS setup failed",
    }
    if code is None:
        return "VPN"
    return mapping.get(code, "VPN")
