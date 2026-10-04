# SPDX-License-Identifier: GPL-3.0-or-later
"""Password and confirmation dialogs for encrypted Backup/Restore."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QVBoxLayout,
    QWidget,
)

from fortigate_vpn_gui.backup.format import MIN_PASSWORD_LENGTH
from fortigate_vpn_gui.backup.service import validate_backup_password


class BackupPasswordDialog(QDialog):
    """Ask for a new backup password and confirmation."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("backupPasswordDialog")
        self.setWindowTitle("Backup profiles")
        intro = QLabel(
            "Choose a password for this encrypted backup. "
            f"Use at least {MIN_PASSWORD_LENGTH} characters. "
            "The password is not stored and is not your VPN or account password. "
            "Export is not a backup of secrets."
        )
        intro.setWordWrap(True)
        intro.setObjectName("backupPasswordIntro")
        self._error = QLabel("")
        self._error.setObjectName("backupPasswordError")
        self._error.setWordWrap(True)
        self._error.hide()
        self._password = QLineEdit()
        self._password.setObjectName("backupPassword")
        self._password.setEchoMode(QLineEdit.EchoMode.Password)
        self._confirm = QLineEdit()
        self._confirm.setObjectName("backupPasswordConfirm")
        self._confirm.setEchoMode(QLineEdit.EchoMode.Password)
        form = QFormLayout()
        form.addRow("Password:", self._password)
        form.addRow("Confirm password:", self._confirm)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._try_accept)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addWidget(intro)
        layout.addLayout(form)
        layout.addWidget(self._error)
        layout.addWidget(buttons)

    def password(self) -> str:
        return self._password.text()

    def confirmation(self) -> str:
        return self._confirm.text()

    def _try_accept(self) -> None:
        try:
            validate_backup_password(self.password(), self.confirmation())
        except Exception as exc:
            self._error.setText(str(exc))
            self._error.show()
            return
        self.accept()


class RestorePasswordDialog(QDialog):
    """Ask for the backup password. Does not enforce the create-time minimum."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("restorePasswordDialog")
        self.setWindowTitle("Restore backup")
        intro = QLabel(
            "Enter the password that was used when this encrypted backup was "
            "created. This is not your sudo password, VPN password, or current "
            "account password."
        )
        intro.setWordWrap(True)
        intro.setObjectName("restorePasswordIntro")
        self._password = QLineEdit()
        self._password.setObjectName("restorePassword")
        self._password.setEchoMode(QLineEdit.EchoMode.Password)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addWidget(intro)
        layout.addWidget(self._password)
        layout.addWidget(buttons)

    def password(self) -> str:
        return self._password.text()
