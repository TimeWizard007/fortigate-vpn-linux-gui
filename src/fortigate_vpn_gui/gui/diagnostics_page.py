# SPDX-License-Identifier: GPL-3.0-or-later
"""Diagnostics page: helper, openfortivpn, certificate, and VPN status."""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFormLayout, QLabel, QSizePolicy, QVBoxLayout, QWidget

from fortigate_vpn_gui.diagnostics.collector import build_diagnostics_snapshot
from fortigate_vpn_gui.gui.config_path_widget import ProfileConfigPathWidget
from fortigate_vpn_gui.gui.page_container import create_page_scroll_area
from fortigate_vpn_gui.profiles.manager import ProfileManager
from fortigate_vpn_gui.profiles.model import ConnectionProfile
from fortigate_vpn_gui.vpn.backend import VpnBackend
from fortigate_vpn_gui.vpn.detect import detect_openfortivpn


class DiagnosticsPage(QWidget):
    """Safe-to-share runtime details. No secrets are shown."""

    def __init__(
        self,
        manager: ProfileManager,
        vpn: VpnBackend,
        selected_profile: Callable[[], ConnectionProfile | None],
        parent: QWidget | None = None,
        *,
        detect=detect_openfortivpn,
        desktop_info: Callable[[], dict[str, str]] | None = None,
    ) -> None:
        super().__init__(parent)
        self._manager = manager
        self._vpn = vpn
        self._selected_profile = selected_profile
        self._detect = detect
        self._desktop_info = desktop_info

        title = QLabel("Diagnostics")
        title.setObjectName("pageTitle")
        intro = QLabel(
            "Read-only runtime information for troubleshooting. Passwords, "
            "SAML tokens, cookies, and sign-in URL query values are never shown. "
            "Certificate fingerprints are not secrets and may be displayed."
        )
        intro.setWordWrap(True)

        self._helper_installed = QLabel("—")
        self._helper_installed.setObjectName("diagHelperInstalled")
        self._helper_version = QLabel("—")
        self._helper_version.setObjectName("diagHelperVersion")
        self._helper_auth = QLabel("—")
        self._helper_auth.setObjectName("diagHelperAuth")
        self._helper_status = QLabel("—")
        self._helper_status.setObjectName("diagHelperStatus")
        self._helper_startup = QLabel("—")
        self._helper_startup.setObjectName("diagHelperStartupDetail")
        self._helper_pid = QLabel("—")
        self._helper_pid.setObjectName("diagHelperPid")
        self._detected = QLabel("—")
        self._detected.setObjectName("diagOpenfortivpnDetected")
        self._path = QLabel("—")
        self._path.setObjectName("diagOpenfortivpnPath")
        self._version = QLabel("—")
        self._version.setObjectName("diagOpenfortivpnVersion")
        self._saml = QLabel("—")
        self._saml.setObjectName("diagOpenfortivpnSaml")
        self._cookie_stdin = QLabel("—")
        self._cookie_stdin.setObjectName("diagOpenfortivpnCookieStdin")
        self._cert_pinned = QLabel("—")
        self._cert_pinned.setObjectName("diagCertPinned")
        self._cert_fingerprint = QLabel("—")
        self._cert_fingerprint.setObjectName("diagCertFingerprint")
        self._cert_subject = QLabel("—")
        self._cert_subject.setObjectName("diagCertSubject")
        self._cert_issuer = QLabel("—")
        self._cert_issuer.setObjectName("diagCertIssuer")
        self._state = QLabel("—")
        self._state.setObjectName("diagVpnState")
        self._wait_reason = QLabel("—")
        self._wait_reason.setObjectName("diagWaitReason")
        self._failure = QLabel("—")
        self._failure.setObjectName("diagFailureReason")
        self._last_failure = QLabel("—")
        self._last_failure.setObjectName("diagLastFailureReason")
        self._last_disconnect = QLabel("—")
        self._last_disconnect.setObjectName("diagLastDisconnectReason")
        self._attempt = QLabel("—")
        self._attempt.setObjectName("diagAttemptId")
        self._retry = QLabel("—")
        self._retry.setObjectName("diagRetryCount")
        self._pid = QLabel("—")
        self._pid.setObjectName("diagVpnPid")
        self._profile = QLabel("—")
        self._profile.setObjectName("diagSelectedProfile")
        self._auth_mode = QLabel("—")
        self._auth_mode.setObjectName("diagAuthMode")
        self._browser = QLabel("—")
        self._browser.setObjectName("diagBrowserStatus")
        self._waiting = QLabel("—")
        self._waiting.setObjectName("diagWaitingForAuth")
        self._tray_available = QLabel("—")
        self._tray_available.setObjectName("diagTrayAvailable")
        self._tray_active = QLabel("—")
        self._tray_active.setObjectName("diagTrayActive")
        self._close_behavior = QLabel("—")
        self._close_behavior.setObjectName("diagCloseBehavior")
        self._autostart = QLabel("—")
        self._autostart.setObjectName("diagAutostart")
        self._auto_reconnect = QLabel("—")
        self._auto_reconnect.setObjectName("diagAutoReconnect")
        self._reconnect_attempt = QLabel("—")
        self._reconnect_attempt.setObjectName("diagReconnectAttempt")
        self._reconnect_pending = QLabel("—")
        self._reconnect_pending.setObjectName("diagReconnectPending")
        self._shutdown = QLabel("—")
        self._shutdown.setObjectName("diagShutdownInProgress")

        value_labels = (
            self._helper_installed,
            self._helper_version,
            self._helper_auth,
            self._helper_status,
            self._helper_startup,
            self._helper_pid,
            self._detected,
            self._path,
            self._version,
            self._saml,
            self._cookie_stdin,
            self._cert_pinned,
            self._cert_fingerprint,
            self._cert_subject,
            self._cert_issuer,
            self._state,
            self._wait_reason,
            self._failure,
            self._last_failure,
            self._last_disconnect,
            self._attempt,
            self._retry,
            self._pid,
            self._profile,
            self._auth_mode,
            self._browser,
            self._waiting,
            self._tray_available,
            self._tray_active,
            self._close_behavior,
            self._autostart,
            self._auto_reconnect,
            self._reconnect_attempt,
            self._reconnect_pending,
            self._shutdown,
        )
        for label in value_labels:
            label.setWordWrap(True)
            label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)

        form = QFormLayout()
        form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapLongRows)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)
        form.setHorizontalSpacing(12)
        form.setVerticalSpacing(8)
        form.addRow("Privileged helper installed:", self._helper_installed)
        form.addRow("Helper version:", self._helper_version)
        form.addRow("Authorization mechanism:", self._helper_auth)
        form.addRow("Helper status:", self._helper_status)
        form.addRow("Helper startup detail:", self._helper_startup)
        form.addRow("Privileged process PID:", self._helper_pid)
        form.addRow("openfortivpn detected:", self._detected)
        form.addRow("Selected executable:", self._path)
        form.addRow("Version:", self._version)
        form.addRow("SAML support:", self._saml)
        form.addRow("Cookie-on-stdin support:", self._cookie_stdin)
        form.addRow("Certificate pinned:", self._cert_pinned)
        form.addRow("Certificate fingerprint:", self._cert_fingerprint)
        form.addRow("Certificate subject:", self._cert_subject)
        form.addRow("Certificate issuer:", self._cert_issuer)
        form.addRow("VPN state:", self._state)
        form.addRow("Wait reason:", self._wait_reason)
        form.addRow("Failure reason:", self._failure)
        form.addRow("Last failure reason:", self._last_failure)
        form.addRow("Last disconnect reason:", self._last_disconnect)
        form.addRow("Connection attempt:", self._attempt)
        form.addRow("Retry count:", self._retry)
        form.addRow("Process PID:", self._pid)
        form.addRow("Selected profile:", self._profile)
        form.addRow("Authentication mode:", self._auth_mode)
        form.addRow("Browser launch status:", self._browser)
        form.addRow("Waiting for authentication:", self._waiting)
        form.addRow("Tray available:", self._tray_available)
        form.addRow("Tray active:", self._tray_active)
        form.addRow("Close behavior:", self._close_behavior)
        form.addRow("Autostart enabled:", self._autostart)
        form.addRow("Auto-reconnect enabled:", self._auto_reconnect)
        form.addRow("Reconnect attempt / limit:", self._reconnect_attempt)
        form.addRow("Reconnect pending:", self._reconnect_pending)
        form.addRow("Shutdown in progress:", self._shutdown)

        inner = QWidget()
        inner_layout = QVBoxLayout(inner)
        inner_layout.setContentsMargins(16, 12, 24, 16)
        inner_layout.setSpacing(12)
        inner_layout.addWidget(title)
        inner_layout.addWidget(intro)
        inner_layout.addLayout(form)
        inner_layout.addWidget(ProfileConfigPathWidget(manager.storage_path))
        inner_layout.addStretch(1)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(create_page_scroll_area(inner))
        self.refresh(include_version=False)

    def showEvent(self, event) -> None:  # noqa: N802 — Qt API
        super().showEvent(event)
        if getattr(self, "_vpn", None) is None:
            return
        self.refresh(include_version=True)

    def refresh(self, *, include_version: bool = True) -> None:
        data = build_diagnostics_snapshot(
            self._vpn,
            self._selected_profile(),
            str(self._manager.storage_path),
            detect=lambda **kwargs: self._detect(
                include_version=include_version,
                include_capabilities=include_version,
            ),
            desktop=self._desktop_info() if self._desktop_info is not None else None,
        )
        self._helper_installed.setText(data["helper_installed"])
        self._helper_version.setText(data["helper_version"])
        self._helper_auth.setText(data["authorization_mechanism"])
        self._helper_status.setText(data["helper_status"])
        self._helper_startup.setText(data["helper_startup_detail"])
        self._helper_pid.setText(data["privileged_pid"])
        self._detected.setText(data["openfortivpn_detected"])
        self._path.setText(data["selected_executable"])
        self._version.setText(data["version"])
        self._saml.setText(data["supports_saml"])
        self._cookie_stdin.setText(data["supports_cookie_stdin"])
        self._cert_pinned.setText(data["certificate_pinned"])
        self._cert_fingerprint.setText(data["certificate_fingerprint"])
        self._cert_subject.setText(data["certificate_subject"])
        self._cert_issuer.setText(data["certificate_issuer"])
        self._state.setText(data["vpn_state"])
        self._wait_reason.setText(data["wait_reason"])
        self._failure.setText(data["failure_reason"])
        self._last_failure.setText(data["last_failure_reason"])
        self._last_disconnect.setText(data["last_disconnect_reason"])
        self._attempt.setText(data["attempt_id"])
        self._retry.setText(data["retry_count"])
        self._pid.setText(data["process_pid"])
        self._profile.setText(data["selected_profile"])
        self._auth_mode.setText(data["auth_mode"])
        self._browser.setText(data["browser_status"])
        self._waiting.setText(data["waiting_for_auth"])
        self._tray_available.setText(data.get("tray_available", "—"))
        self._tray_active.setText(data.get("tray_active", "—"))
        self._close_behavior.setText(data.get("close_behavior", "—"))
        self._autostart.setText(data.get("autostart_enabled", "—"))
        self._auto_reconnect.setText(data["auto_reconnect_enabled"])
        self._reconnect_attempt.setText(
            f"{data['reconnect_attempt']} / {data['reconnect_limit']}"
        )
        self._reconnect_pending.setText(data["reconnect_pending"])
        self._shutdown.setText(data["shutdown_in_progress"])
