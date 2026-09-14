# SPDX-License-Identifier: GPL-3.0-or-later
"""IPsec connect-time PSK vs XAuth fields. No Secret Service plaintext fallback."""

from __future__ import annotations

import json
from pathlib import Path

from PySide6.QtWidgets import QCheckBox, QComboBox, QGroupBox, QLabel, QLineEdit

from fortigate_vpn_gui.gui.connection_page import ConnectionPage
from fortigate_vpn_gui.gui.ipsec_credentials_dialog import (
    IpsecCredentialsDialog,
    lookup_stored_psk,
)
from fortigate_vpn_gui.gui.profile_editor_dialog import ProfileEditorDialog
from fortigate_vpn_gui.gui.profiles_page import ProfilesPage
from fortigate_vpn_gui.profiles.ipsec import default_ipsec_settings
from fortigate_vpn_gui.profiles.manager import ProfileManager
from fortigate_vpn_gui.system.psk_store import SecretServicePskStore, UnavailablePskStore
from fortigate_vpn_gui.vpn.models import ConnectionState
from tests.vpn_fakes import VpnHarness

_PSK = "tunnel-psk-secret"
_XAUTH_PASSWORD = "ad-directory-password"


def test_connect_dialog_labels_distinguish_psk_username_password(qapp) -> None:
    dialog = IpsecCredentialsDialog("Office IPsec", username_hint="mwi")
    assert dialog.findChild(QLabel, "ipsecPskLabel").text() == "Pre-shared key"
    assert dialog.findChild(QLabel, "ipsecUsernameLabel").text() == "Username"
    assert dialog.findChild(QLabel, "ipsecPasswordLabel").text() == "Password"
    intro = dialog.findChild(QLabel, "ipsecCredentialsIntro").text()
    assert "not your user account password" in intro.lower()
    assert "xauth" in intro.lower()
    username = dialog.findChild(QLineEdit, "ipsecUsername")
    password = dialog.findChild(QLineEdit, "ipsecPassword")
    psk = dialog.findChild(QLineEdit, "ipsecPsk")
    assert username is not None and username.text() == "mwi"
    assert password is not None and password.echoMode() == QLineEdit.EchoMode.Password
    assert psk is not None and not psk.isHidden()
    psk.setText(_PSK)
    password.setText(_XAUTH_PASSWORD)
    credentials = dialog.credentials()
    assert credentials is not None
    assert credentials.psk == _PSK
    assert credentials.username == "mwi"
    assert credentials.password == _XAUTH_PASSWORD
    assert credentials.psk != credentials.password
    assert credentials.username != credentials.psk


def test_connect_dialog_reuses_stored_psk_and_asks_xauth(qapp) -> None:
    dialog = IpsecCredentialsDialog(
        "Office IPsec",
        username_hint="mwi",
        stored_psk=_PSK,
    )
    assert dialog.findChild(QLineEdit, "ipsecPsk").isHidden()
    assert dialog.findChild(QLabel, "ipsecPskLabel").isHidden()
    hint = dialog.findChild(QLabel, "ipsecPskSavedHint")
    assert hint is not None and not hint.isHidden()
    assert "saved pre-shared key" in hint.text().lower()
    dialog.findChild(QLineEdit, "ipsecUsername").setText("mwi")
    dialog.findChild(QLineEdit, "ipsecPassword").setText(_XAUTH_PASSWORD)
    credentials = dialog.credentials()
    assert credentials is not None
    assert credentials.psk == _PSK
    assert credentials.username == "mwi"
    assert credentials.password == _XAUTH_PASSWORD
    assert "psk" not in dialog.findChild(QLabel, "ipsecPasswordLabel").text().lower()


def test_connect_dialog_incomplete_without_xauth_password(qapp) -> None:
    dialog = IpsecCredentialsDialog("Office IPsec", username_hint="mwi", stored_psk=_PSK)
    assert dialog.credentials() is None
    dialog.findChild(QLineEdit, "ipsecPassword").setText(_XAUTH_PASSWORD)
    assert dialog.credentials() is not None


def test_editor_save_psk_never_writes_profiles_json(
    qapp, profile_manager: ProfileManager, psk_store
) -> None:
    dialog = ProfileEditorDialog(profile_manager)
    vpn_type = dialog.findChild(QComboBox, "profileVpnType")
    vpn_type.setCurrentIndex(1)
    dialog.findChild(QLineEdit, "profileName").setText("IPsec office")
    dialog.findChild(QLineEdit, "profileGateway").setText("vpn.example.com")
    dialog.findChild(QLineEdit, "profileUsernameHint").setText("mwi")
    dialog.findChild(QLineEdit, "profileIpsecPsk").setText(_PSK)
    save = dialog.findChild(QCheckBox, "profileSavePsk")
    assert save is not None and save.isEnabled()
    save.setChecked(True)
    assert dialog.findChild(QLabel, "profileXauthNote").text() == (
        "User authentication: XAuth username/password"
    )
    assert dialog.findChild(QLabel, "profileUsernameLabel").text() == "Username:"
    assert dialog.submit() is True
    profile = profile_manager.list_profiles()[0]
    raw = profile_manager.storage_path.read_text(encoding="utf-8")
    assert _PSK not in raw
    assert json.loads(raw)["profiles"][0]["username_hint"] == "mwi"
    assert psk_store.get(profile.id) == _PSK
    assert profile.username_hint != _PSK


def test_editor_unavailable_secret_service_shows_message(qapp, tmp_path: Path, monkeypatch) -> None:
    manager = ProfileManager(
        config_dir=tmp_path / "cfg",
        psk_store=UnavailablePskStore(),
    )
    dialog = ProfileEditorDialog(manager)
    vpn_type = dialog.findChild(QComboBox, "profileVpnType")
    vpn_type.setCurrentIndex(1)
    save = dialog.findChild(QCheckBox, "profileSavePsk")
    status = dialog.findChild(QLabel, "profilePskStatus")
    assert save is not None and not save.isEnabled()
    assert status is not None and not status.isHidden()
    assert "Secure keyring unavailable" in status.text()
    assert "PSK will be requested again" in status.text()
    dialog.findChild(QLineEdit, "profileName").setText("IPsec office")
    dialog.findChild(QLineEdit, "profileGateway").setText("vpn.example.com")
    dialog.findChild(QLineEdit, "profileUsernameHint").setText("mwi")
    dialog.findChild(QLineEdit, "profileIpsecPsk").setText(_PSK)
    notices: list[str] = []

    def _info(parent, title, text):
        del parent, title
        notices.append(text)
        return 1

    monkeypatch.setattr(
        "fortigate_vpn_gui.gui.profile_editor_dialog.QMessageBox.information",
        _info,
    )
    assert dialog.submit() is True
    assert notices
    assert "not stored" in notices[0].lower()
    profile = manager.list_profiles()[0]
    raw = manager.storage_path.read_text(encoding="utf-8")
    assert _PSK not in raw
    assert manager.psk_store.get(profile.id) is None
    assert profile.username_hint == "mwi"


def test_editor_save_psk_enabled_when_secret_service_backend_is_available(
    qapp, tmp_path: Path
) -> None:
    from tests.test_psk_store import SecretServiceKeyringApi

    manager = ProfileManager(
        config_dir=tmp_path / "cfg",
        psk_store=SecretServicePskStore(SecretServiceKeyringApi()),
    )
    dialog = ProfileEditorDialog(manager)
    vpn_type = dialog.findChild(QComboBox, "profileVpnType")
    vpn_type.setCurrentIndex(1)
    save = dialog.findChild(QCheckBox, "profileSavePsk")
    status = dialog.findChild(QLabel, "profilePskStatus")
    assert save is not None and save.isEnabled()
    assert status is not None and status.isHidden()


def test_connection_page_looks_up_stored_psk(
    qapp, profile_manager: ProfileManager, psk_store, monkeypatch
) -> None:
    profile = profile_manager.add(
        name="IPsec office",
        gateway="vpn.example.com",
        port=500,
        vpn_type="ipsec",
        username_hint="mwi",
        ipsec=default_ipsec_settings().to_json(),
    )
    psk_store.set(profile.id, _PSK)
    seen: dict[str, object] = {}

    def fake_prompt(selected, username_hint="", parent=None, **kwargs):
        seen["id"] = selected.id
        seen["hint"] = selected.username_hint
        seen["lookup"] = lookup_stored_psk(kwargs.get("psk_store"), selected.id)
        return None

    monkeypatch.setattr(
        "fortigate_vpn_gui.gui.connection_page.prompt_ipsec_credentials",
        fake_prompt,
    )
    harness = VpnHarness()
    page = ConnectionPage(profile_manager, harness.backend, locator=lambda: "/usr/bin/openfortivpn")
    page.select_profile(profile.id)
    page._on_action_clicked()
    assert seen["id"] == profile.id
    assert seen["hint"] == "mwi"
    assert seen["lookup"] == _PSK
    assert harness.backend.snapshot().state is ConnectionState.DISCONNECTED


def test_profiles_page_ipsec_connect_uses_same_prompt(
    qapp, profile_manager: ProfileManager, psk_store, monkeypatch
) -> None:
    profile = profile_manager.add(
        name="IPsec office",
        gateway="vpn.example.com",
        port=500,
        vpn_type="ipsec",
        username_hint="mwi",
        ipsec=default_ipsec_settings().to_json(),
    )
    seen: dict[str, object] = {}

    def fake_prompt(selected, username_hint="", parent=None, **kwargs):
        seen["lookup"] = lookup_stored_psk(kwargs.get("psk_store"), selected.id)
        return None

    monkeypatch.setattr(
        "fortigate_vpn_gui.gui.profiles_page.prompt_ipsec_credentials",
        fake_prompt,
    )
    harness = VpnHarness()
    page = ProfilesPage(profile_manager, harness.backend)
    assert page.connect_profile(profile.id) is False
    assert seen["lookup"] is None
    psk_store.set(profile.id, _PSK)
    assert page.connect_profile(profile.id) is False
    assert seen["lookup"] == _PSK


def test_ssl_editor_hides_ipsec_psk_fields(qapp, profile_manager: ProfileManager) -> None:
    dialog = ProfileEditorDialog(profile_manager)
    ipsec_box = dialog.findChild(QGroupBox, "profileIpsecBox")
    psk = dialog.findChild(QLineEdit, "profileIpsecPsk")
    save = dialog.findChild(QCheckBox, "profileSavePsk")
    assert ipsec_box is not None and ipsec_box.isHidden()
    dialog.show()
    qapp.processEvents()
    assert psk is not None and not psk.isVisible()
    assert save is not None and not save.isVisible()
    name = dialog.findChild(QLineEdit, "profileName")
    gateway = dialog.findChild(QLineEdit, "profileGateway")
    name.setText("Office SSL")
    gateway.setText("vpn.example.com")
    assert dialog.submit() is True
    created = profile_manager.list_profiles()[0]
    assert created.is_ssl()
    assert created.use_sso is True
    raw = profile_manager.storage_path.read_text(encoding="utf-8")
    assert _PSK not in raw
    dialog.close()


def test_connect_dialog_asks_for_unstored_psk(qapp) -> None:
    dialog = IpsecCredentialsDialog("Office IPsec", username_hint="mwi")
    needed = dialog.findChild(QLabel, "ipsecPskNeededHint")
    saved = dialog.findChild(QLabel, "ipsecPskSavedHint")
    assert needed is not None and not needed.isHidden()
    assert saved is not None and saved.isHidden()
    assert not dialog.findChild(QLineEdit, "ipsecPsk").isHidden()


def test_connect_skips_dialog_when_psk_username_and_password_stored(
    qapp, profile_manager: ProfileManager, psk_store
) -> None:
    profile = profile_manager.add(
        name="IPsec office",
        gateway="vpn.example.com",
        port=500,
        vpn_type="ipsec",
        username_hint="mwi",
        ipsec=default_ipsec_settings().to_json(),
    )
    psk_store.set(profile.id, _PSK)
    psk_store.set_xauth_password(profile.id, _XAUTH_PASSWORD)
    from fortigate_vpn_gui.gui.ipsec_credentials_dialog import prompt_ipsec_credentials

    credentials = prompt_ipsec_credentials(profile, psk_store=psk_store, manager=profile_manager)
    assert credentials is not None
    assert credentials.psk == _PSK
    assert credentials.username == "mwi"
    assert credentials.password == _XAUTH_PASSWORD


def test_remember_username_updates_profile(qapp, profile_manager: ProfileManager) -> None:
    profile = profile_manager.add(
        name="IPsec office",
        gateway="vpn.example.com",
        port=500,
        vpn_type="ipsec",
        ipsec=default_ipsec_settings().to_json(),
    )
    dialog = IpsecCredentialsDialog(
        profile.name,
        username_hint="",
        stored_psk=_PSK,
        remember_username=True,
    )
    dialog.findChild(QLineEdit, "ipsecUsername").setText("mwi")
    dialog.findChild(QLineEdit, "ipsecPassword").setText(_XAUTH_PASSWORD)
    dialog.findChild(QCheckBox, "ipsecRememberUsername").setChecked(True)
    credentials = dialog.credentials()
    assert credentials is not None
    profile_manager.set_username_hint(profile.id, credentials.username)
    updated = profile_manager.get(profile.id)
    assert updated is not None
    assert updated.username_hint == "mwi"
    raw = profile_manager.storage_path.read_text(encoding="utf-8")
    assert _XAUTH_PASSWORD not in raw
    assert _PSK not in raw


def test_save_password_securely_stays_out_of_profiles_json(
    qapp, profile_manager: ProfileManager, psk_store
) -> None:
    profile = profile_manager.add(
        name="IPsec office",
        gateway="vpn.example.com",
        port=500,
        vpn_type="ipsec",
        username_hint="mwi",
        ipsec=default_ipsec_settings().to_json(),
    )
    dialog = IpsecCredentialsDialog(
        profile.name,
        username_hint="mwi",
        stored_psk=_PSK,
        can_save_password=True,
    )
    dialog.findChild(QLineEdit, "ipsecPassword").setText(_XAUTH_PASSWORD)
    dialog.findChild(QCheckBox, "ipsecSavePassword").setChecked(True)
    credentials = dialog.credentials()
    assert credentials is not None
    psk_store.set_xauth_password(profile.id, credentials.password)
    raw = json.loads(profile_manager.storage_path.read_text(encoding="utf-8"))
    dumped = json.dumps(raw)
    assert _XAUTH_PASSWORD not in dumped
    assert psk_store.get_xauth_password(profile.id) == _XAUTH_PASSWORD
    assert raw["profiles"][0]["username_hint"] == "mwi"


def test_connect_reuses_stored_xauth_password_without_asking(qapp) -> None:
    dialog = IpsecCredentialsDialog(
        "Office IPsec",
        username_hint="mwi",
        stored_psk=_PSK,
        stored_password=_XAUTH_PASSWORD,
    )
    assert dialog.findChild(QLineEdit, "ipsecPassword").isHidden()
    hint = dialog.findChild(QLabel, "ipsecPasswordSavedHint")
    assert hint is not None and not hint.isHidden()
    credentials = dialog.credentials()
    assert credentials is not None
    assert credentials.password == _XAUTH_PASSWORD
    assert credentials.psk == _PSK
    assert credentials.username == "mwi"


def test_connect_password_save_unavailable_explains_keyring(qapp) -> None:
    dialog = IpsecCredentialsDialog(
        "Office IPsec",
        username_hint="mwi",
        stored_psk=_PSK,
        can_save_password=False,
    )
    save = dialog.findChild(QCheckBox, "ipsecSavePassword")
    status = dialog.findChild(QLabel, "ipsecPasswordStatus")
    assert save is not None and not save.isEnabled()
    assert status is not None and not status.isHidden()
    assert "Secure keyring unavailable" in status.text()
    assert "XAuth password will be requested again" in status.text()


def test_connect_password_save_enabled_when_secret_service_is_available(qapp) -> None:
    dialog = IpsecCredentialsDialog(
        "Office IPsec",
        username_hint="mwi",
        stored_psk=_PSK,
        can_save_password=True,
    )
    save = dialog.findChild(QCheckBox, "ipsecSavePassword")
    status = dialog.findChild(QLabel, "ipsecPasswordStatus")
    assert save is not None and save.isEnabled()
    assert status is None or status.isHidden()
