# SPDX-License-Identifier: GPL-3.0-or-later
"""Profiles page GUI tests. No network, sudo, or VPN tools."""

from __future__ import annotations

from PySide6.QtWidgets import QLineEdit

from fortigate_vpn_gui.gui.profile_editor_dialog import ProfileEditorDialog
from fortigate_vpn_gui.gui.profiles_page import ProfilesPage
from fortigate_vpn_gui.profiles.manager import ProfileManager


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
    assert page._table.rowCount() == 1


def test_profiles_page_edit_via_dialog(qapp, profile_manager: ProfileManager) -> None:
    profile = profile_manager.add(name="Office", gateway="vpn.example.com")
    page = ProfilesPage(profile_manager)
    page._table.selectRow(0)
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
    profile_manager.add(name="Office", gateway="vpn.example.com")
    page = ProfilesPage(profile_manager)
    page._table.selectRow(0)
    page.delete_profile(confirmed=False)
    assert len(profile_manager.list_profiles()) == 1
    page.delete_profile(confirmed=True)
    assert profile_manager.list_profiles() == ()
    assert page._table.rowCount() == 0


def test_profile_editor_shows_validation_error(qapp, profile_manager: ProfileManager) -> None:
    dialog = ProfileEditorDialog(profile_manager)
    name_field = dialog.findChild(QLineEdit, "profileName")
    gateway_field = dialog.findChild(QLineEdit, "profileGateway")
    assert name_field is not None
    assert gateway_field is not None
    name_field.setText(" ")
    gateway_field.setText("vpn.example.com")
    assert dialog.submit() is False
    assert "name cannot be empty" in dialog.error_text().lower()
    assert profile_manager.list_profiles() == ()
