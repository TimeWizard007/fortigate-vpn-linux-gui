# SPDX-License-Identifier: GPL-3.0-or-later
"""Profiles page GUI tests. No network, sudo, or VPN tools."""

from __future__ import annotations

from PySide6.QtWidgets import QLabel, QLineEdit, QPushButton, QRadioButton

from fortigate_vpn_gui.gui.connection_page import ConnectionPage
from fortigate_vpn_gui.gui.profile_editor_dialog import ProfileEditorDialog
from fortigate_vpn_gui.gui.profiles_page import ProfilesPage
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


def test_profiles_page_delete_requires_confirmation(
    qapp, profile_manager: ProfileManager
) -> None:
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
        badge
        for badge in page.findChildren(QLabel, "profileDefaultBadge")
        if not badge.isHidden()
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


def test_connection_selector_refreshes_after_crud(
    qapp, profile_manager: ProfileManager
) -> None:
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
