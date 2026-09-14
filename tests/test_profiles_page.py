# SPDX-License-Identifier: GPL-3.0-or-later
"""Profiles page GUI tests. No network, sudo, or VPN tools."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialogButtonBox,
    QGroupBox,
    QLabel,
    QLineEdit,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QSpinBox,
    QToolButton,
    QWidget,
)

from fortigate_vpn_gui.gui.connection_page import ConnectionPage
from fortigate_vpn_gui.gui.profile_editor_dialog import ProfileEditorDialog
from fortigate_vpn_gui.gui.profiles_page import ProfilesPage
from fortigate_vpn_gui.profiles.ipsec import default_ipsec_settings
from fortigate_vpn_gui.profiles.manager import ProfileManager
from tests.vpn_fakes import VpnHarness


def test_profiles_page_empty_state(qapp, profile_manager: ProfileManager) -> None:
    page = ProfilesPage(profile_manager)
    assert page.empty_state_visible() is True
    assert page.card_count() == 0
    hint = page.findChild(QLabel, "emptyProfilesHint")
    assert hint is not None
    assert "No VPN profiles yet" in hint.text()
    add = page.findChild(QPushButton, "emptyAddProfileButton")
    assert add is not None
    assert add.text() == "Add profile"


def test_profiles_page_add_via_dialog(qapp, profile_manager: ProfileManager) -> None:
    page = ProfilesPage(profile_manager)
    dialog = ProfileEditorDialog(profile_manager, parent=page)
    name_field = dialog.findChild(QLineEdit, "profileName")
    gateway_field = dialog.findChild(QLineEdit, "profileGateway")
    assert name_field is not None
    assert gateway_field is not None
    name_field.setText("Office")
    gateway_field.setText("vpn.example.com")
    assert dialog.submit() is True
    assert len(profile_manager.list_profiles()) == 1
    assert page.card_count() == 1
    assert page.empty_state_visible() is False


def test_profiles_page_edit_save_and_cancel(qapp, profile_manager: ProfileManager) -> None:
    profile = profile_manager.add(name="Office", gateway="vpn.example.com")
    page = ProfilesPage(profile_manager)
    dialog = ProfileEditorDialog(profile_manager, profile, parent=page)
    name_field = dialog.findChild(QLineEdit, "profileName")
    gateway_field = dialog.findChild(QLineEdit, "profileGateway")
    assert name_field is not None
    assert gateway_field is not None
    name_field.setText("Changed")
    gateway_field.setText("changed.example")
    dialog.reject()
    unchanged = profile_manager.get(profile.id)
    assert unchanged is not None
    assert unchanged.name == "Office"
    assert unchanged.gateway == "vpn.example.com"

    dialog = ProfileEditorDialog(profile_manager, profile, parent=page)
    name_field = dialog.findChild(QLineEdit, "profileName")
    gateway_field = dialog.findChild(QLineEdit, "profileGateway")
    assert name_field is not None
    assert gateway_field is not None
    name_field.setText("Home")
    gateway_field.setText("home.example")
    assert dialog.submit() is True
    updated = profile_manager.get(profile.id)
    assert updated is not None
    assert updated.name == "Home"
    assert updated.gateway == "home.example"


def test_profiles_page_delete_requires_confirmation(qapp, profile_manager: ProfileManager) -> None:
    profile = profile_manager.add(name="Office", gateway="vpn.example.com")
    page = ProfilesPage(profile_manager)
    page.delete_profile(profile.id, confirmed=False)
    assert len(profile_manager.list_profiles()) == 1
    page.delete_profile(profile.id, confirmed=True)
    assert profile_manager.list_profiles() == ()
    assert page.card_count() == 0
    assert page.empty_state_visible() is True


def test_profiles_page_set_default(qapp, profile_manager: ProfileManager) -> None:
    first = profile_manager.add(name="Office", gateway="vpn.example.com")
    second = profile_manager.add(name="Home", gateway="home.example")
    page = ProfilesPage(profile_manager)
    page.set_default_profile(second.id)
    assert profile_manager.default_profile_id() == second.id
    badges = [
        badge for badge in page.findChildren(QLabel, "profileDefaultBadge") if not badge.isHidden()
    ]
    assert len(badges) == 1
    page.set_default_profile(first.id)
    assert profile_manager.default_profile_id() == first.id


def test_profiles_page_duplicate_action(qapp, profile_manager: ProfileManager) -> None:
    profile = profile_manager.add(name="Customer ABC", gateway="vpn.example.com")
    page = ProfilesPage(profile_manager)
    copy = page.duplicate_profile(profile.id, open_editor=False)
    assert copy is not None
    assert copy.name == "Customer ABC (copy)"
    assert page.card_count() == 2


def test_profile_editor_shows_validation_error(qapp, profile_manager: ProfileManager) -> None:
    dialog = ProfileEditorDialog(profile_manager)
    name_field = dialog.findChild(QLineEdit, "profileName")
    gateway_field = dialog.findChild(QLineEdit, "profileGateway")
    assert name_field is not None
    assert gateway_field is not None
    name_field.setText(" ")
    gateway_field.setText("vpn.example.com")
    assert dialog.submit() is False
    assert "profile name is required" in dialog.error_text().lower()
    assert dialog.field_error_text("name") == "Profile name is required."
    assert profile_manager.list_profiles() == ()


def test_profile_editor_duplicate_name_and_invalid_host(
    qapp, profile_manager: ProfileManager
) -> None:
    profile_manager.add(name="Office", gateway="vpn.example.com")
    dialog = ProfileEditorDialog(profile_manager)
    name_field = dialog.findChild(QLineEdit, "profileName")
    gateway_field = dialog.findChild(QLineEdit, "profileGateway")
    assert name_field is not None
    assert gateway_field is not None
    name_field.setText("office")
    gateway_field.setText("https://vpn.example.com")
    assert dialog.submit() is False
    assert "already exists" in dialog.field_error_text("name").lower()
    assert dialog.field_error_text("gateway") == "Enter a valid gateway."


def test_profile_editor_auth_fields_react(qapp, profile_manager: ProfileManager) -> None:
    dialog = ProfileEditorDialog(profile_manager)
    saml = dialog.findChild(QRadioButton, "profileAuthSaml")
    password = dialog.findChild(QRadioButton, "profileAuthPassword")
    hint = dialog.findChild(QLineEdit, "profileUsernameHint")
    assert saml is not None
    assert password is not None
    assert hint is not None
    assert saml.isChecked()
    username_row = hint.parentWidget()
    assert username_row is not None
    assert username_row.isHidden()
    password.setChecked(True)
    assert hint.parentWidget() is not None
    assert not hint.parentWidget().isHidden()


def test_profile_editor_shows_and_clears_certificate_pin(
    qapp, profile_manager: ProfileManager
) -> None:
    digest = "ab" * 32
    profile = profile_manager.add(
        name="Office", gateway="vpn.example.com", trusted_cert_sha256=digest
    )
    page = ProfilesPage(profile_manager)
    dialog = ProfileEditorDialog(profile_manager, profile, parent=page)
    assert "Pinned SHA-256" in dialog._cert_status.text()
    dialog._on_reset_cert()
    assert dialog.submit() is True
    updated = profile_manager.get(profile.id)
    assert updated is not None
    assert updated.trusted_cert_sha256 is None


def test_connection_selector_refreshes_after_crud(qapp, profile_manager: ProfileManager) -> None:
    harness = VpnHarness()
    connection = ConnectionPage(
        profile_manager, harness.backend, locator=lambda: "/usr/bin/openfortivpn"
    )
    page = ProfilesPage(profile_manager)
    dialog = ProfileEditorDialog(profile_manager, parent=page)
    name_field = dialog.findChild(QLineEdit, "profileName")
    gateway_field = dialog.findChild(QLineEdit, "profileGateway")
    assert name_field is not None
    assert gateway_field is not None
    name_field.setText("Office")
    gateway_field.setText("vpn.example.com")
    assert dialog.submit() is True
    assert connection._profile_combo.count() == 1
    created = profile_manager.list_profiles()[0]
    copy = page.duplicate_profile(created.id, open_editor=False)
    assert copy is not None
    assert connection._profile_combo.count() == 2
    page.delete_profile(copy.id, confirmed=True)
    assert connection._profile_combo.count() == 1


def test_connection_selector_selects_default(qapp, profile_manager: ProfileManager) -> None:
    first = profile_manager.add(name="Office", gateway="vpn.example.com")
    second = profile_manager.add(name="Home", gateway="home.example")
    profile_manager.set_default(second.id)
    harness = VpnHarness()
    connection = ConnectionPage(
        profile_manager, harness.backend, locator=lambda: "/usr/bin/openfortivpn"
    )
    selected = connection.selected_profile()
    assert selected is not None
    assert selected.id == second.id
    assert "default" in connection._profile_combo.currentText()
    assert first.id != second.id


def test_profile_editor_ipsec_type_shows_advanced_and_saves(
    qapp, profile_manager: ProfileManager
) -> None:
    dialog = ProfileEditorDialog(profile_manager)
    vpn_type = dialog.findChild(QComboBox, "profileVpnType")
    name_field = dialog.findChild(QLineEdit, "profileName")
    gateway_field = dialog.findChild(QLineEdit, "profileGateway")
    local_id = dialog.findChild(QLineEdit, "profileLocalId")
    ipsec_box = dialog.findChild(QGroupBox, "profileIpsecBox")
    advanced = dialog.findChild(QGroupBox, "profileIpsecAdvancedBox")
    assert vpn_type is not None
    assert name_field is not None
    assert gateway_field is not None
    assert local_id is not None
    assert ipsec_box is not None
    assert advanced is not None
    assert ipsec_box.isHidden()
    vpn_type.setCurrentIndex(1)
    assert not ipsec_box.isHidden()
    assert not advanced.isHidden()
    name_field.setText("IPsec office")
    gateway_field.setText("vpn.example.com")
    local_id.setText("client@example")
    assert dialog.submit() is True
    created = profile_manager.list_profiles()[0]
    assert created.is_ipsec()
    assert created.port == 500
    assert created.ipsec is not None
    assert created.ipsec.local_id == "client@example"
    assert created.ipsec.is_supported()
    assert advanced.isCheckable()
    assert advanced.isChecked() is False
    cert_box = dialog.findChild(QGroupBox, "profileCertBox")
    ssl_auth = dialog.findChild(QGroupBox, "profileSslAuthBox")
    assert cert_box is not None and cert_box.isHidden()
    assert ssl_auth is not None and ssl_auth.isHidden()


def test_profile_editor_ssl_hides_ipsec_and_shows_certificate_pin(
    qapp, profile_manager: ProfileManager
) -> None:
    dialog = ProfileEditorDialog(profile_manager)
    ssl_auth = dialog.findChild(QGroupBox, "profileSslAuthBox")
    ipsec_box = dialog.findChild(QGroupBox, "profileIpsecBox")
    advanced = dialog.findChild(QGroupBox, "profileIpsecAdvancedBox")
    cert_box = dialog.findChild(QGroupBox, "profileCertBox")
    saml = dialog.findChild(QRadioButton, "profileAuthSaml")
    assert ssl_auth is not None and not ssl_auth.isHidden()
    assert ipsec_box is not None and ipsec_box.isHidden()
    assert advanced is not None and advanced.isHidden()
    assert cert_box is not None and not cert_box.isHidden()
    assert saml is not None and not saml.isHidden()
    assert "No certificate pinned" in dialog._cert_status.text()


def test_profile_editor_ipsec_hides_certificate_pin_and_saml(
    qapp, profile_manager: ProfileManager
) -> None:
    dialog = ProfileEditorDialog(profile_manager)
    vpn_type = dialog.findChild(QComboBox, "profileVpnType")
    assert vpn_type is not None
    vpn_type.setCurrentIndex(1)
    cert_box = dialog.findChild(QGroupBox, "profileCertBox")
    cert_status = dialog.findChild(QLabel, "profileCertStatus")
    reset = dialog.findChild(QPushButton, "profileResetCert")
    ssl_auth = dialog.findChild(QGroupBox, "profileSslAuthBox")
    ipsec_box = dialog.findChild(QGroupBox, "profileIpsecBox")
    assert cert_box is not None and cert_box.isHidden()
    assert cert_status is not None and cert_status.isHidden()
    assert reset is not None and reset.isHidden()
    assert ssl_auth is not None and ssl_auth.isHidden()
    assert ipsec_box is not None and not ipsec_box.isHidden()
    vpn_type.setCurrentIndex(0)
    assert not cert_box.isHidden()
    assert not ssl_auth.isHidden()
    assert ipsec_box.isHidden()


def test_profile_editor_advanced_collapsed_for_new_expanded_for_existing(
    qapp, profile_manager: ProfileManager
) -> None:
    dialog = ProfileEditorDialog(profile_manager)
    vpn_type = dialog.findChild(QComboBox, "profileVpnType")
    advanced = dialog.findChild(QGroupBox, "profileIpsecAdvancedBox")
    assert vpn_type is not None
    assert advanced is not None
    vpn_type.setCurrentIndex(1)
    assert advanced.isCheckable()
    assert advanced.isChecked() is False
    advanced.setChecked(True)
    assert advanced.isChecked() is True
    advanced.setChecked(False)
    assert advanced.isChecked() is False

    created = profile_manager.add(
        name="IPsec office",
        gateway="vpn.example.com",
        port=500,
        vpn_type="ipsec",
        ipsec={**default_ipsec_settings().to_json(), "local_id": "client@example"},
    )
    edit = ProfileEditorDialog(profile_manager, created)
    edit_advanced = edit.findChild(QGroupBox, "profileIpsecAdvancedBox")
    local_id = edit.findChild(QLineEdit, "profileLocalId")
    ike_version = edit.findChild(QComboBox, "profileIkeVersion")
    ike_mode = edit.findChild(QComboBox, "profileIkeMode")
    assert edit_advanced is not None
    assert local_id is not None
    assert ike_version is not None
    assert ike_mode is not None
    assert edit_advanced.isChecked() is True
    assert local_id.text() == "client@example"
    edit_advanced.setChecked(False)
    edit_advanced.setChecked(True)
    assert ike_version.currentData() == "ikev1"
    assert ike_mode.currentData() == "aggressive"


def test_profile_editor_ipsec_controls_reachable_in_scroll_area(
    qapp, profile_manager: ProfileManager
) -> None:
    dialog = ProfileEditorDialog(profile_manager)
    vpn_type = dialog.findChild(QComboBox, "profileVpnType")
    scroll = dialog.findChild(QScrollArea, "profileEditorScroll")
    advanced = dialog.findChild(QGroupBox, "profileIpsecAdvancedBox")
    buttons = dialog.findChild(QDialogButtonBox, "profileEditorButtons")
    assert vpn_type is not None
    assert scroll is not None
    assert advanced is not None
    assert buttons is not None
    vpn_type.setCurrentIndex(1)
    advanced.setChecked(True)
    dialog.resize(480, 360)
    dialog.show()
    qapp.processEvents()
    assert dialog.minimumHeight() <= 360
    assert scroll.widgetResizable()
    assert buttons.isVisible()
    names = (
        "profileLocalId",
        "profilePeerId",
        "profileIpsecAuth",
        "profileIpsecPsk",
        "profileSavePsk",
        "profileRememberUsername",
        "profileXauthNote",
        "profileIpsecSso",
        "profileIkeVersion",
        "profileIkeMode",
        "profileIpsecAddress",
        "profilePhase1Enc",
        "profilePhase1Int",
        "profileDhGroup",
        "profilePhase1Lifetime",
        "profilePhase2Enc",
        "profilePhase2Int",
        "profilePfs",
        "profilePfsDh",
        "profilePhase2Lifetime",
        "profileReplay",
        "profileNatT",
        "profileDpd",
        "profileDpdInterval",
        "profileLocalLan",
    )
    for object_name in names:
        widget = dialog.findChild(QWidget, object_name)
        assert widget is not None, object_name
        scroll.ensureWidgetVisible(widget)
        qapp.processEvents()
        assert widget.isVisible(), object_name
    assert dialog.findChild(QGroupBox, "profileIpsecPhase1Box") is not None
    assert dialog.findChild(QGroupBox, "profileIpsecPhase2Box") is not None
    assert dialog.findChild(QGroupBox, "profileIpsecTransportBox") is not None
    dialog.close()


def test_profile_editor_ssl_add_still_defaults_to_saml(
    qapp, profile_manager: ProfileManager
) -> None:
    dialog = ProfileEditorDialog(profile_manager)
    name_field = dialog.findChild(QLineEdit, "profileName")
    gateway_field = dialog.findChild(QLineEdit, "profileGateway")
    saml = dialog.findChild(QRadioButton, "profileAuthSaml")
    assert name_field is not None
    assert gateway_field is not None
    assert saml is not None and saml.isChecked()
    name_field.setText("Office SSL")
    gateway_field.setText("vpn.example.com")
    assert dialog.submit() is True
    created = profile_manager.list_profiles()[0]
    assert created.is_ssl()
    assert created.use_sso is True
    assert created.port == 443


def test_more_menu_lists_edit_duplicate_delete(qapp, profile_manager: ProfileManager) -> None:
    profile = profile_manager.add(name="Office", gateway="vpn.example.com")
    page = ProfilesPage(profile_manager)
    more = page.findChild(QToolButton, f"profileMoreButton_{profile.id}")
    assert more is not None
    menu = more.menu()
    assert menu is not None
    labels = [action.text() for action in menu.actions() if action.text()]
    assert "Edit" in labels
    assert "Duplicate" in labels
    assert "Delete" in labels
    edit = next(action for action in menu.actions() if action.text() == "Edit")
    assert edit.objectName() == f"profileEditAction_{profile.id}"


def test_more_edit_opens_populated_ipsec_editor(
    qapp, profile_manager: ProfileManager, monkeypatch
) -> None:
    settings = {
        **default_ipsec_settings().to_json(),
        "local_id": "client@example",
        "peer_id": "vpn.example.com",
        "phase1_lifetime": 11111,
        "dpd": False,
        "nat_traversal": False,
        "pfs": False,
    }
    profile = profile_manager.add(
        name="IPsec office",
        gateway="vpn.example.com",
        port=500,
        vpn_type="ipsec",
        username_hint="mwi",
        ipsec=settings,
    )
    seen: dict[str, object] = {}

    def fake_exec(dialog) -> int:
        seen["name"] = dialog.findChild(QLineEdit, "profileName").text()
        seen["vpn"] = dialog.findChild(QComboBox, "profileVpnType").currentData()
        seen["gateway"] = dialog.findChild(QLineEdit, "profileGateway").text()
        seen["port"] = dialog.findChild(QSpinBox, "profilePort").value()
        seen["user"] = dialog.findChild(QLineEdit, "profileUsernameHint").text()
        seen["local"] = dialog.findChild(QLineEdit, "profileLocalId").text()
        seen["peer"] = dialog.findChild(QLineEdit, "profilePeerId").text()
        seen["life"] = dialog.findChild(QSpinBox, "profilePhase1Lifetime").value()
        seen["dpd"] = dialog.findChild(QCheckBox, "profileDpd").isChecked()
        seen["natt"] = dialog.findChild(QCheckBox, "profileNatT").isChecked()
        seen["pfs"] = dialog.findChild(QCheckBox, "profilePfs").isChecked()
        seen["psk"] = dialog.findChild(QLineEdit, "profileIpsecPsk").text()
        return 0

    monkeypatch.setattr(
        "fortigate_vpn_gui.gui.profiles_page.ProfileEditorDialog.exec",
        fake_exec,
    )
    page = ProfilesPage(profile_manager)
    page.edit_profile(profile.id)
    assert seen["name"] == "IPsec office"
    assert seen["vpn"] == "ipsec"
    assert seen["gateway"] == "vpn.example.com"
    assert seen["port"] == 500
    assert seen["user"] == "mwi"
    assert seen["local"] == "client@example"
    assert seen["peer"] == "vpn.example.com"
    assert seen["life"] == 11111
    assert seen["dpd"] is False
    assert seen["natt"] is False
    assert seen["pfs"] is False
    assert seen["psk"] == ""


def test_ipsec_editor_round_trip_preserves_settings(qapp, profile_manager: ProfileManager) -> None:
    profile = profile_manager.add(
        name="IPsec office",
        gateway="vpn.example.com",
        port=500,
        vpn_type="ipsec",
        username_hint="mwi",
        ipsec={
            **default_ipsec_settings().to_json(),
            "local_id": "client@example",
            "peer_id": "peer.example",
            "phase2_lifetime": 22222,
        },
    )
    dialog = ProfileEditorDialog(profile_manager, profile)
    assert dialog.findChild(QLineEdit, "profileLocalId").text() == "client@example"
    assert dialog.findChild(QLineEdit, "profilePeerId").text() == "peer.example"
    assert dialog.findChild(QSpinBox, "profilePhase2Lifetime").value() == 22222
    remember = dialog.findChild(QCheckBox, "profileRememberUsername")
    assert remember is not None and remember.isChecked()
    dialog.findChild(QLineEdit, "profilePeerId").setText("peer.updated")
    assert dialog.submit() is True
    updated = profile_manager.get(profile.id)
    assert updated is not None
    assert updated.ipsec is not None
    assert updated.ipsec.local_id == "client@example"
    assert updated.ipsec.peer_id == "peer.updated"
    assert updated.ipsec.phase2_lifetime == 22222
    assert updated.username_hint == "mwi"
    assert updated.vpn_type == "ipsec"


def test_editor_uncheck_remember_username_clears_hint(
    qapp, profile_manager: ProfileManager
) -> None:
    profile = profile_manager.add(
        name="IPsec office",
        gateway="vpn.example.com",
        port=500,
        vpn_type="ipsec",
        username_hint="mwi",
        ipsec=default_ipsec_settings().to_json(),
    )
    dialog = ProfileEditorDialog(profile_manager, profile)
    remember = dialog.findChild(QCheckBox, "profileRememberUsername")
    assert remember is not None
    remember.setChecked(False)
    assert dialog.submit() is True
    updated = profile_manager.get(profile.id)
    assert updated is not None
    assert updated.username_hint == ""


def test_ipsec_sso_checkbox_is_disabled_ssl_saml_unchanged(
    qapp, profile_manager: ProfileManager
) -> None:
    ipsec = ProfileEditorDialog(profile_manager)
    vpn_type = ipsec.findChild(QComboBox, "profileVpnType")
    assert vpn_type is not None
    vpn_type.setCurrentIndex(1)
    sso = ipsec.findChild(QCheckBox, "profileIpsecSso")
    assert sso is not None
    assert sso.isEnabled() is False
    assert "not implemented" in sso.text().lower()
    ssl = ProfileEditorDialog(profile_manager)
    saml = ssl.findChild(QRadioButton, "profileAuthSaml")
    password = ssl.findChild(QRadioButton, "profileAuthPassword")
    assert saml is not None and saml.isEnabled()
    assert password is not None and password.isEnabled()
    assert saml.isChecked()


def test_more_duplicate_and_delete_secret_lifecycle(
    qapp, profile_manager: ProfileManager, psk_store, monkeypatch
) -> None:
    settings = {
        **default_ipsec_settings().to_json(),
        "local_id": "client@example",
        "peer_id": "peer.example",
    }
    profile = profile_manager.add(
        name="IPsec office",
        gateway="vpn.example.com",
        port=500,
        vpn_type="ipsec",
        username_hint="mwi",
        ipsec=settings,
    )
    psk_store.set(profile.id, "tunnel-psk-secret")
    psk_store.set_xauth_password(profile.id, "ad-directory-password")
    monkeypatch.setattr(
        "fortigate_vpn_gui.gui.profiles_page.ProfileEditorDialog.exec",
        lambda dialog: 0,
    )
    page = ProfilesPage(profile_manager)
    more = page.findChild(QToolButton, f"profileMoreButton_{profile.id}")
    assert more is not None
    menu = more.menu()
    assert menu is not None
    duplicate = next(action for action in menu.actions() if action.text() == "Duplicate")
    delete = next(action for action in menu.actions() if action.text() == "Delete")
    assert delete.objectName() == f"profileDeleteAction_{profile.id}"
    duplicate.trigger()
    copy = next(item for item in profile_manager.list_profiles() if item.id != profile.id)
    assert copy.username_hint == "mwi"
    assert copy.vpn_type == "ipsec"
    assert copy.ipsec is not None
    assert copy.ipsec.local_id == "client@example"
    assert copy.ipsec.peer_id == "peer.example"
    assert psk_store.get(copy.id) is None
    assert psk_store.get_xauth_password(copy.id) is None
    assert psk_store.get(profile.id) == "tunnel-psk-secret"
    page.delete_profile(profile.id, confirmed=True)
    assert profile_manager.get(profile.id) is None
    assert psk_store.get(profile.id) is None
    assert psk_store.get_xauth_password(profile.id) is None
    raw = profile_manager.storage_path.read_text(encoding="utf-8")
    assert "tunnel-psk-secret" not in raw
    assert "ad-directory-password" not in raw
