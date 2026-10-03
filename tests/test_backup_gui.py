# SPDX-License-Identifier: GPL-3.0-or-later
"""Profiles page Backup/Restore GUI tests. No network."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import QLabel, QPushButton

from fortigate_vpn_gui.backup.service import create_backup
from fortigate_vpn_gui.gui.backup_dialog import BackupPasswordDialog
from fortigate_vpn_gui.gui.profiles_page import ProfilesPage
from fortigate_vpn_gui.profiles.ipsec import default_ipsec_settings
from fortigate_vpn_gui.profiles.manager import ProfileManager
from fortigate_vpn_gui.system.psk_store import MemoryPskStore

_FAST = {"memory_kib": 8, "time_cost": 1, "parallelism": 1}
_PASSWORD = "backup-password-ok"
_PSK = "TEST_ONLY_BACKUP_PSK_DO_NOT_USE"


def test_profiles_page_has_backup_restore_and_export_warning(
    qapp, profile_manager: ProfileManager
) -> None:
    page = ProfilesPage(profile_manager)
    assert any(
        "Export does not include passwords" in label.text() for label in page.findChildren(QLabel)
    )
    restore = page.findChild(QPushButton, "emptyRestoreProfilesButton")
    backup = page.findChild(QPushButton, "emptyBackupProfilesButton")
    assert restore is not None
    assert backup is not None
    assert "Backup" not in [
        child.text()
        for child in page.findChildren(QPushButton)
        if "tray" in (child.objectName() or "")
    ]


def test_profiles_page_backup_restore_round_trip(qapp, tmp_path: Path) -> None:
    store = MemoryPskStore()
    manager = ProfileManager(config_dir=tmp_path / "a", psk_store=store)
    profile = manager.add(
        name="Tunnel",
        gateway="ike.example.com",
        port=500,
        vpn_type="ipsec",
        ipsec=default_ipsec_settings().to_json(),
    )
    store.set(profile.id, _PSK)
    page = ProfilesPage(manager)
    path = tmp_path / "gui.fvbackup"
    written = page.backup_profiles(
        path,
        password=_PASSWORD,
        confirmation=_PASSWORD,
        memory_kib=8,
        time_cost=1,
    )
    assert written is not None
    assert _PSK.encode() not in written.read_bytes()
    dest_store = MemoryPskStore()
    dest = ProfileManager(config_dir=tmp_path / "b", psk_store=dest_store)
    dest_page = ProfilesPage(dest)
    plan = dest_page.restore_profiles(path, password=_PASSWORD, confirmed=True)
    assert plan is not None
    restored = dest.get(profile.id)
    assert restored is not None
    assert restored.name == "Tunnel"
    assert dest_store.get(profile.id) == _PSK


def test_export_still_excludes_secrets_on_profiles_page(
    qapp, tmp_path: Path, psk_store: MemoryPskStore
) -> None:
    manager = ProfileManager(config_dir=tmp_path / "cfg", psk_store=psk_store)
    profile = manager.add(
        name="Tunnel",
        gateway="ike.example.com",
        port=500,
        vpn_type="ipsec",
        ipsec=default_ipsec_settings().to_json(),
    )
    psk_store.set(profile.id, _PSK)
    page = ProfilesPage(manager)
    export_path = tmp_path / "profile.json"
    page.export_profile(profile.id, export_path)
    text = export_path.read_text(encoding="utf-8")
    assert _PSK not in text
    assert '"psk"' not in text
    assert "xauth_password" not in text
    assert "secrets" not in text


def test_backup_password_dialog_rejects_short(qapp) -> None:
    dialog = BackupPasswordDialog()
    dialog._password.setText("short")
    dialog._confirm.setText("short")
    dialog._try_accept()
    assert dialog._error.isHidden() is False
    assert "12" in dialog._error.text()


def test_create_backup_helper_used_by_empty_backup(tmp_path: Path) -> None:
    manager = ProfileManager(config_dir=tmp_path / "cfg", psk_store=MemoryPskStore())
    path = tmp_path / "empty.fvbackup"
    create_backup(manager, path, _PASSWORD, confirmation=_PASSWORD, **_FAST)
    assert path.is_file()
