# SPDX-License-Identifier: GPL-3.0-or-later
"""Add/Edit dialog for a connection profile."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from fortigate_vpn_gui.helper.validation import format_sha256_fingerprint
from fortigate_vpn_gui.profiles.manager import ProfileManager
from fortigate_vpn_gui.profiles.model import ConnectionProfile, ProfileValidationError


class ProfileEditorDialog(QDialog):
    """Collect profile fields and persist them through ``ProfileManager``."""

    def __init__(
        self,
        manager: ProfileManager,
        profile: ConnectionProfile | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._manager = manager
        self._existing = profile
        self.setWindowTitle("Edit profile" if profile else "Add profile")
        self.setModal(True)
        self.setWindowModality(Qt.WindowModality.WindowModal)
        self.setMinimumWidth(420)

        self._error_label = QLabel()
        self._error_label.setObjectName("profileEditorError")
        self._error_label.setWordWrap(True)
        self._error_label.setStyleSheet("color: #c4564c;")
        self._error_label.hide()

        self._name = QLineEdit()
        self._name.setObjectName("profileName")
        self._gateway = QLineEdit()
        self._gateway.setObjectName("profileGateway")
        self._port = QSpinBox()
        self._port.setObjectName("profilePort")
        self._port.setRange(1, 65535)
        self._port.setValue(443)
        self._description = QLineEdit()
        self._description.setObjectName("profileDescription")
        self._username_hint = QLineEdit()
        self._username_hint.setObjectName("profileUsernameHint")
        self._use_sso = QCheckBox("Use SSO")
        self._use_sso.setObjectName("profileUseSso")
        self._use_sso.setChecked(True)
        self._clear_trust = False

        self._cert_status = QLabel("No certificate pinned")
        self._cert_status.setObjectName("profileCertStatus")
        self._cert_status.setWordWrap(True)
        self._reset_cert = QPushButton("Remove certificate trust")
        self._reset_cert.setObjectName("profileResetCert")
        self._reset_cert.clicked.connect(self._on_reset_cert)

        if profile is not None:
            self._name.setText(profile.name)
            self._gateway.setText(profile.gateway)
            self._port.setValue(profile.port)
            self._description.setText(profile.description)
            self._username_hint.setText(profile.username_hint)
            self._use_sso.setChecked(profile.use_sso)
            self._refresh_cert_status(profile.trusted_cert_sha256)
        else:
            self._refresh_cert_status(None)
            self._reset_cert.setEnabled(False)

        form = QFormLayout()
        form.addRow("Profile name:", self._name)
        form.addRow("Gateway:", self._gateway)
        form.addRow("Port:", self._port)
        form.addRow("Description:", self._description)
        form.addRow("Username hint:", self._username_hint)
        form.addRow("", self._use_sso)
        form.addRow("Certificate pin:", self._cert_status)
        form.addRow("", self._reset_cert)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.submit)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addWidget(self._error_label)
        layout.addLayout(form)
        layout.addWidget(buttons)

    def error_text(self) -> str:
        """Return the validation message shown in the dialog."""
        return self._error_label.text()

    def submit(self) -> bool:
        """Validate and save. Returns True when the dialog is accepted."""
        values = {
            "name": self._name.text(),
            "gateway": self._gateway.text(),
            "port": self._port.value(),
            "description": self._description.text(),
            "username_hint": self._username_hint.text(),
            "use_sso": self._use_sso.isChecked(),
        }
        if self._existing is not None:
            values["trusted_cert_sha256"] = (
                None if self._clear_trust else self._existing.trusted_cert_sha256
            )
        try:
            if self._existing is None:
                self._manager.add(**values)
            else:
                self._manager.update(self._existing.id, **values)
        except ProfileValidationError as exc:
            self._error_label.setText("\n".join(exc.errors))
            self._error_label.show()
            return False
        self.accept()
        return True

    def _on_reset_cert(self) -> None:
        self._clear_trust = True
        self._refresh_cert_status(None)
        self._reset_cert.setEnabled(False)

    def _refresh_cert_status(self, fingerprint: str | None) -> None:
        if fingerprint:
            shown = format_sha256_fingerprint(fingerprint)
            self._cert_status.setText(f"Pinned SHA-256:\n{shown}")
            self._reset_cert.setEnabled(True)
        else:
            self._cert_status.setText("No certificate pinned")
            self._reset_cert.setEnabled(False)
