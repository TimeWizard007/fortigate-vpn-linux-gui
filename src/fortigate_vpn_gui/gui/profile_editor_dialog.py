# SPDX-License-Identifier: GPL-3.0-or-later
"""Add/Edit dialog for a connection profile."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QButtonGroup,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QRadioButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from fortigate_vpn_gui.helper.validation import format_sha256_fingerprint
from fortigate_vpn_gui.profiles.manager import ProfileManager
from fortigate_vpn_gui.profiles.model import ConnectionProfile, ProfileValidationError

_ERROR_STYLE = "color: #c4564c;"


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
        self._error_label.setStyleSheet(_ERROR_STYLE)
        self._error_label.hide()

        self._name = QLineEdit()
        self._name.setObjectName("profileName")
        self._name.setPlaceholderText("Customer - ABC")
        self._name_error = self._field_error("profileNameError")

        self._gateway = QLineEdit()
        self._gateway.setObjectName("profileGateway")
        self._gateway.setPlaceholderText("vpn.example.com")
        self._gateway_error = self._field_error("profileGatewayError")

        self._port = QSpinBox()
        self._port.setObjectName("profilePort")
        self._port.setRange(1, 65535)
        self._port.setValue(443)
        self._port_error = self._field_error("profilePortError")

        self._description = QLineEdit()
        self._description.setObjectName("profileDescription")

        self._saml_radio = QRadioButton("SAML / SSO")
        self._saml_radio.setObjectName("profileAuthSaml")
        self._password_radio = QRadioButton("Username / Password")
        self._password_radio.setObjectName("profileAuthPassword")
        self._auth_group = QButtonGroup(self)
        self._auth_group.addButton(self._saml_radio)
        self._auth_group.addButton(self._password_radio)
        self._saml_radio.setChecked(True)
        self._saml_radio.toggled.connect(self._sync_auth_fields)

        auth_box = QWidget()
        auth_layout = QVBoxLayout(auth_box)
        auth_layout.setContentsMargins(0, 0, 0, 0)
        auth_layout.setSpacing(4)
        auth_layout.addWidget(self._saml_radio)
        auth_layout.addWidget(self._password_radio)

        self._username_hint = QLineEdit()
        self._username_hint.setObjectName("profileUsernameHint")
        self._username_hint.setPlaceholderText("Optional reminder; passwords are not stored")
        self._username_row = QWidget()
        username_form = QFormLayout(self._username_row)
        username_form.setContentsMargins(0, 0, 0, 0)
        username_form.addRow("Username hint:", self._username_hint)

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
            self._saml_radio.setChecked(profile.use_sso)
            self._password_radio.setChecked(not profile.use_sso)
            self._refresh_cert_status(profile.trusted_cert_sha256)
        else:
            self._refresh_cert_status(None)
            self._reset_cert.setEnabled(False)

        form = QFormLayout()
        form.addRow("Profile name:", self._stack_field(self._name, self._name_error))
        form.addRow("Gateway / Host:", self._stack_field(self._gateway, self._gateway_error))
        form.addRow("Port:", self._stack_field(self._port, self._port_error))
        form.addRow("Description:", self._description)
        form.addRow("Authentication:", auth_box)
        form.addRow(self._username_row)
        form.addRow("Certificate pin:", self._cert_status)
        form.addRow("", self._reset_cert)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.submit)
        buttons.rejected.connect(self.reject)
        ok_button = buttons.button(QDialogButtonBox.StandardButton.Ok)
        if ok_button is not None:
            ok_button.setDefault(True)
            ok_button.setAutoDefault(True)

        layout = QVBoxLayout(self)
        layout.addWidget(self._error_label)
        layout.addLayout(form)
        layout.addWidget(buttons)
        self._sync_auth_fields()

    def error_text(self) -> str:
        """Return the validation message shown in the dialog."""
        return self._error_label.text()

    def field_error_text(self, field: str) -> str:
        """Return the per-field validation message, if any."""
        label = {
            "name": self._name_error,
            "gateway": self._gateway_error,
            "port": self._port_error,
        }.get(field)
        if label is None or label.isHidden():
            return ""
        return label.text()

    def submit(self) -> bool:
        """Validate and save. Returns True when the dialog is accepted."""
        self._clear_errors()
        values = {
            "name": self._name.text(),
            "gateway": self._gateway.text(),
            "port": self._port.value(),
            "description": self._description.text(),
            "username_hint": self._username_hint.text(),
            "use_sso": self._saml_radio.isChecked(),
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
            self._show_errors(exc)
            return False
        self.accept()
        return True

    def _show_errors(self, exc: ProfileValidationError) -> None:
        self._error_label.setText("\n".join(exc.errors))
        self._error_label.show()
        mapping = {
            "name": self._name_error,
            "gateway": self._gateway_error,
            "port": self._port_error,
        }
        for field, message in exc.field_errors.items():
            label = mapping.get(field)
            if label is None:
                continue
            label.setText(message)
            label.show()

    def _clear_errors(self) -> None:
        self._error_label.hide()
        self._error_label.clear()
        for label in (self._name_error, self._gateway_error, self._port_error):
            label.hide()
            label.clear()

    def _sync_auth_fields(self) -> None:
        self._username_row.setVisible(self._password_radio.isChecked())

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

    @staticmethod
    def _field_error(object_name: str) -> QLabel:
        label = QLabel()
        label.setObjectName(object_name)
        label.setWordWrap(True)
        label.setStyleSheet(_ERROR_STYLE)
        label.hide()
        return label

    @staticmethod
    def _stack_field(widget: QWidget, error: QLabel) -> QWidget:
        wrap = QWidget()
        layout = QVBoxLayout(wrap)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)
        layout.addWidget(widget)
        layout.addWidget(error)
        return wrap
