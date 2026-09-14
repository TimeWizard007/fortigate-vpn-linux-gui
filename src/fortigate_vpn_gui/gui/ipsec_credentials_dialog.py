# SPDX-License-Identifier: GPL-3.0-or-later
"""Connect-time IPsec secrets. Never stored in profiles.json."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from fortigate_vpn_gui.profiles.manager import ProfileManager
from fortigate_vpn_gui.profiles.model import ConnectionProfile
from fortigate_vpn_gui.system.psk_store import (
    PASSWORD_UNAVAILABLE_MESSAGE,
    PskStore,
    PskStoreError,
)
from fortigate_vpn_gui.vpn.ipsec.secrets import IpsecCredentials

_INTRO = (
    "The pre-shared key authenticates the IPsec tunnel. It is not your user "
    "account password.\n\n"
    "Username and Password are the XAuth user credentials (for example your "
    "directory / FortiGate login)."
)
_PSK_NEEDED = "This pre-shared key was not saved. Enter it to connect."
_PSK_SAVED = "Using the saved pre-shared key."
_PASSWORD_SAVED = "Using the saved XAuth password."


class IpsecCredentialsDialog(QDialog):
    """Ask only for missing IPsec PSK / XAuth credentials."""

    def __init__(
        self,
        profile_name: str,
        username_hint: str = "",
        stored_psk: str | None = None,
        stored_password: str | None = None,
        *,
        remember_username: bool = True,
        can_save_password: bool = False,
        password_unavailable_message: str = PASSWORD_UNAVAILABLE_MESSAGE,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._stored_psk = stored_psk or ""
        self._stored_password = stored_password or ""
        self.setWindowTitle("IPsec credentials")
        self.setModal(True)
        self.setWindowModality(Qt.WindowModality.WindowModal)
        self.setMinimumWidth(420)
        intro = QLabel(_INTRO)
        intro.setObjectName("ipsecCredentialsIntro")
        intro.setWordWrap(True)
        heading = QLabel(f'Connect "{profile_name}"')
        heading.setObjectName("ipsecCredentialsHeading")
        heading.setWordWrap(True)

        self._psk = QLineEdit()
        self._psk.setObjectName("ipsecPsk")
        self._psk.setEchoMode(QLineEdit.EchoMode.Password)
        self._psk_toggle = QPushButton("Show")
        self._psk_toggle.setObjectName("ipsecPskToggle")
        self._psk_toggle.setCheckable(True)
        self._psk_toggle.setFixedWidth(72)
        self._psk_toggle.toggled.connect(self._on_psk_reveal)
        psk_field = QWidget()
        psk_field.setObjectName("ipsecPskRow")
        psk_layout = QHBoxLayout(psk_field)
        psk_layout.setContentsMargins(0, 0, 0, 0)
        psk_layout.setSpacing(8)
        psk_layout.addWidget(self._psk, 1)
        psk_layout.addWidget(self._psk_toggle)

        self._psk_saved = QLabel(_PSK_SAVED)
        self._psk_saved.setObjectName("ipsecPskSavedHint")
        self._psk_saved.setWordWrap(True)
        self._psk_needed = QLabel(_PSK_NEEDED)
        self._psk_needed.setObjectName("ipsecPskNeededHint")
        self._psk_needed.setWordWrap(True)

        self._username = QLineEdit()
        self._username.setObjectName("ipsecUsername")
        self._username.setText(username_hint)
        self._remember_username = QCheckBox("Remember username")
        self._remember_username.setObjectName("ipsecRememberUsername")
        self._remember_username.setChecked(remember_username)

        self._password = QLineEdit()
        self._password.setObjectName("ipsecPassword")
        self._password.setEchoMode(QLineEdit.EchoMode.Password)
        self._save_password = QCheckBox("Save password securely")
        self._save_password.setObjectName("ipsecSavePassword")
        self._password_status = QLabel()
        self._password_status.setObjectName("ipsecPasswordStatus")
        self._password_status.setWordWrap(True)
        self._password_saved = QLabel(_PASSWORD_SAVED)
        self._password_saved.setObjectName("ipsecPasswordSavedHint")
        self._password_saved.setWordWrap(True)

        self._psk_label = QLabel("Pre-shared key")
        self._psk_label.setObjectName("ipsecPskLabel")
        self._username_label = QLabel("Username")
        self._username_label.setObjectName("ipsecUsernameLabel")
        self._password_label = QLabel("Password")
        self._password_label.setObjectName("ipsecPasswordLabel")

        form = QFormLayout()
        form.setObjectName("ipsecCredentialsForm")
        form.addRow(self._psk_label, psk_field)
        form.addRow(self._username_label, self._username)
        form.addRow(self._password_label, self._password)

        if self._stored_psk:
            self._psk.hide()
            self._psk_toggle.hide()
            self._psk_label.hide()
            psk_field.hide()
            self._psk_needed.hide()
        else:
            self._psk_saved.hide()

        if can_save_password:
            self._save_password.setEnabled(True)
            self._save_password.setChecked(bool(self._stored_password))
            self._password_status.hide()
        else:
            self._save_password.setChecked(False)
            self._save_password.setEnabled(False)
            self._password_status.setText(password_unavailable_message)
            self._password_status.show()

        if self._stored_password:
            self._password.hide()
            self._password_label.hide()
            self._password_status.hide()
        else:
            self._password_saved.hide()

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addWidget(heading)
        layout.addWidget(intro)
        layout.addWidget(self._psk_saved)
        layout.addWidget(self._psk_needed)
        layout.addLayout(form)
        layout.addWidget(self._remember_username)
        layout.addWidget(self._password_saved)
        layout.addWidget(self._save_password)
        layout.addWidget(self._password_status)
        layout.addWidget(buttons)

    def remember_username(self) -> bool:
        return self._remember_username.isChecked()

    def save_password(self) -> bool:
        return self._save_password.isEnabled() and self._save_password.isChecked()

    def credentials(self) -> IpsecCredentials | None:
        psk = self._stored_psk or self._psk.text()
        username = self._username.text().strip()
        password = self._stored_password or self._password.text()
        if not psk or not username or not password:
            return None
        return IpsecCredentials(psk=psk, username=username, password=password)

    def _on_psk_reveal(self, checked: bool) -> None:
        if checked:
            self._psk.setEchoMode(QLineEdit.EchoMode.Normal)
            self._psk_toggle.setText("Hide")
            return
        self._psk.setEchoMode(QLineEdit.EchoMode.Password)
        self._psk_toggle.setText("Show")


def lookup_stored_psk(psk_store: PskStore | None, profile_id: str) -> str | None:
    """Return a stored PSK without raising or logging the secret."""
    return _lookup(psk_store, profile_id, "psk")


def lookup_stored_password(psk_store: PskStore | None, profile_id: str) -> str | None:
    """Return a stored XAuth password without raising or logging the secret."""
    return _lookup(psk_store, profile_id, "password")


def _lookup(psk_store: PskStore | None, profile_id: str, kind: str) -> str | None:
    if psk_store is None:
        return None
    try:
        if not psk_store.is_available():
            return None
        if kind == "password":
            secret = psk_store.get_xauth_password(profile_id)
        else:
            secret = psk_store.get(profile_id)
        if not secret:
            return None
        return secret
    except Exception:
        return None


def prompt_ipsec_credentials(
    profile: ConnectionProfile | str,
    username_hint: str = "",
    parent: QWidget | None = None,
    *,
    psk_store: PskStore | None = None,
    stored_psk: str | None = None,
    manager: ProfileManager | None = None,
) -> IpsecCredentials | None:
    """Return connect-time credentials, or None when cancelled/incomplete.

    Reuses securely stored PSK/password when present and only asks for missing
    fields. Username may be remembered in the non-secret profile.
    """
    profile_obj: ConnectionProfile | None = None
    if isinstance(profile, ConnectionProfile):
        profile_obj = profile
        profile_name = profile.name
        hint = username_hint or profile.username_hint
        resolved_psk = stored_psk
        if resolved_psk is None:
            resolved_psk = lookup_stored_psk(psk_store, profile.id)
        resolved_password = lookup_stored_password(psk_store, profile.id)
    else:
        profile_name = profile
        hint = username_hint
        resolved_psk = stored_psk
        resolved_password = None
    if profile_obj is not None and resolved_psk and hint.strip() and resolved_password:
        return IpsecCredentials(psk=resolved_psk, username=hint.strip(), password=resolved_password)
    can_save = bool(psk_store is not None and psk_store.is_available())
    unavailable = (
        psk_store.password_unavailable_message()
        if psk_store is not None
        else PASSWORD_UNAVAILABLE_MESSAGE
    )
    dialog = IpsecCredentialsDialog(
        profile_name,
        username_hint=hint,
        stored_psk=resolved_psk,
        stored_password=resolved_password,
        remember_username=True,
        can_save_password=can_save,
        password_unavailable_message=unavailable,
        parent=parent,
    )
    if dialog.exec() != QDialog.DialogCode.Accepted:
        return None
    credentials = dialog.credentials()
    if credentials is None:
        return None
    if profile_obj is not None and manager is not None:
        new_hint = credentials.username if dialog.remember_username() else ""
        if new_hint != profile_obj.username_hint:
            manager.set_username_hint(profile_obj.id, new_hint)
    if profile_obj is not None and psk_store is not None and psk_store.is_available():
        if dialog.save_password() and not resolved_password:
            try:
                psk_store.set_xauth_password(profile_obj.id, credentials.password)
            except PskStoreError:
                pass
        elif not dialog.save_password():
            psk_store.delete_xauth_password(profile_obj.id)
    return credentials
