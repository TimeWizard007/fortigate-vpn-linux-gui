# SPDX-License-Identifier: GPL-3.0-or-later
"""Diagnostics page: openfortivpn detection and VPN process status."""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtWidgets import QFormLayout, QLabel, QVBoxLayout, QWidget

from fortigate_vpn_gui.gui.config_path_widget import ProfileConfigPathWidget
from fortigate_vpn_gui.profiles.manager import ProfileManager
from fortigate_vpn_gui.profiles.model import ConnectionProfile
from fortigate_vpn_gui.vpn.backend import VpnBackend
from fortigate_vpn_gui.vpn.detect import detect_openfortivpn
from fortigate_vpn_gui.vpn.models import state_label


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
    ) -> None:
        super().__init__(parent)
        self._manager = manager
        self._vpn = vpn
        self._selected_profile = selected_profile
        self._detect = detect

        title = QLabel("Diagnostics")
        title.setStyleSheet("font-size: 20px; font-weight: 600;")
        intro = QLabel(
            "Read-only runtime information for troubleshooting. Passwords, "
            "SAML tokens, and cookies are never shown."
        )
        intro.setWordWrap(True)

        self._detected = QLabel("—")
        self._detected.setObjectName("diagOpenfortivpnDetected")
        self._path = QLabel("—")
        self._path.setObjectName("diagOpenfortivpnPath")
        self._version = QLabel("—")
        self._version.setObjectName("diagOpenfortivpnVersion")
        self._state = QLabel("—")
        self._state.setObjectName("diagVpnState")
        self._pid = QLabel("—")
        self._pid.setObjectName("diagVpnPid")
        self._profile = QLabel("—")
        self._profile.setObjectName("diagSelectedProfile")

        form = QFormLayout()
        form.addRow("openfortivpn detected:", self._detected)
        form.addRow("Executable path:", self._path)
        form.addRow("Version:", self._version)
        form.addRow("VPN state:", self._state)
        form.addRow("Process PID:", self._pid)
        form.addRow("Selected profile:", self._profile)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 24, 16)
        layout.setSpacing(12)
        layout.addWidget(title)
        layout.addWidget(intro)
        layout.addLayout(form)
        layout.addWidget(ProfileConfigPathWidget(manager.storage_path))
        layout.addStretch(1)
        self.refresh(include_version=False)

    def showEvent(self, event) -> None:  # noqa: N802 — Qt API
        super().showEvent(event)
        self.refresh(include_version=True)

    def refresh(self, *, include_version: bool = True) -> None:
        detection = self._detect(include_version=include_version)
        self._detected.setText("Yes" if detection.available else "No")
        self._path.setText(detection.path or "—")
        self._version.setText(detection.version or "—")
        snapshot = self._vpn.snapshot()
        self._state.setText(state_label(snapshot.state))
        if snapshot.process is not None and snapshot.process.pid is not None:
            self._pid.setText(str(snapshot.process.pid))
        else:
            self._pid.setText("—")
        profile = self._selected_profile()
        if profile is None:
            self._profile.setText("—")
        else:
            self._profile.setText(f"{profile.name} ({profile.gateway}:{profile.port})")
