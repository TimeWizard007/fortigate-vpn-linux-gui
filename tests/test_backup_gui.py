# SPDX-License-Identifier: GPL-3.0-or-later
"""Profiles page Backup/Restore GUI tests. No network."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import QLabel, QMessageBox, QPushButton, QToolButton

from fortigate_vpn_gui.backup.format import AUTH_FAILURE_MESSAGE
from fortigate_vpn_gui.backup.service import create_backup
from fortigate_vpn_gui.gui.backup_dialog import BackupPasswordDialog, RestorePasswordDialog
from fortigate_vpn_gui.gui.profiles_page import (
    BACKUP_FILE_FILTER,
    BACKUP_TOOLTIP,
    EXPORT_TOOLTIP,
    IMPORT_TOOLTIP,
    RESTORE_TOOLTIP,
    ProfilesPage,
)
from fortigate_vpn_gui.profiles.ipsec import default_ipsec_settings
from fortigate_vpn_gui.profiles.manager import ProfileManager
from fortigate_vpn_gui.system.psk_store import MemoryPskStore

_FAST = {"memory_kib": 8, "time_cost": 1, "parallelism": 1}
_PASSWORD = "backup-password-ok"
_PSK = "TEST_ONLY_BACKUP_PSK_DO_NOT_USE"


def _page_with_profile(tmp_path: Path) -> tuple[ProfilesPage, ProfileManager, MemoryPskStore]:
    store = MemoryPskStore()
    manager = ProfileManager(config_dir=tmp_path / "cfg", psk_store=store)
    profile = manager.add(
        name="Tunnel",
        gateway="ike.example.com",
        port=500,
        vpn_type="ipsec",
        ipsec=default_ipsec_settings().to_json(),
    )
    store.set(profile.id, _PSK)
    return ProfilesPage(manager), manager, store


def _silence_boxes(monkeypatch, *, question_result=QMessageBox.StandardButton.Yes):
    infos: list[str] = []
    warnings: list[str] = []
    questions: list[dict[str, object]] = []

    def information(_parent, _title, text):
        infos.append(text)
        return QMessageBox.StandardButton.Ok

    def warning(_parent, _title, text):
        warnings.append(text)
        return QMessageBox.StandardButton.Ok

    def question(_parent, _title, text, buttons=None, default=None):
        questions.append({"text": text, "default": default})
        return question_result

    monkeypatch.setattr("fortigate_vpn_gui.gui.profiles_page.QMessageBox.information", information)
    monkeypatch.setattr("fortigate_vpn_gui.gui.profiles_page.QMessageBox.warning", warning)
    monkeypatch.setattr("fortigate_vpn_gui.gui.profiles_page.QMessageBox.question", question)
    return infos, warnings, questions


def _track_password_dialogs(monkeypatch, order: list[str]) -> None:
    orig_backup_init = BackupPasswordDialog.__init__
    orig_restore_init = RestorePasswordDialog.__init__

    def backup_init(self, *args, **kwargs):
        order.append("backup-password")
        orig_backup_init(self, *args, **kwargs)

    def restore_init(self, *args, **kwargs):
        order.append("restore-password")
        orig_restore_init(self, *args, **kwargs)

    monkeypatch.setattr(BackupPasswordDialog, "__init__", backup_init)
    monkeypatch.setattr(RestorePasswordDialog, "__init__", restore_init)


def _choose_save(monkeypatch, chosen: str, order: list[str] | None = None) -> None:
    def get_save(*_args, **_kwargs):
        if order is not None:
            order.append("save")
        return chosen, BACKUP_FILE_FILTER

    monkeypatch.setattr(
        "fortigate_vpn_gui.gui.profiles_page.QFileDialog.getSaveFileName",
        get_save,
    )


def _choose_open(monkeypatch, chosen: str, order: list[str] | None = None) -> None:
    def get_open(*_args, **_kwargs):
        if order is not None:
            order.append("open")
        return chosen, BACKUP_FILE_FILTER

    monkeypatch.setattr(
        "fortigate_vpn_gui.gui.profiles_page.QFileDialog.getOpenFileName",
        get_open,
    )


def _accept_backup_password(monkeypatch, password: str, confirmation: str) -> None:
    def exec_dialog(self):
        self._password.setText(password)
        self._confirm.setText(confirmation)
        self._try_accept()
        return self.result()

    monkeypatch.setattr(BackupPasswordDialog, "exec", exec_dialog)


def _accept_restore_password(monkeypatch, password: str) -> None:
    def exec_dialog(self):
        self._password.setText(password)
        self.accept()
        return self.result()

    monkeypatch.setattr(RestorePasswordDialog, "exec", exec_dialog)


def _spy_create_backup(monkeypatch, seen: list[object], *, write: bool = True):
    real = create_backup

    def wrapped(manager, path, password, **kwargs):
        seen.append(path)
        if not write:
            return path
        kwargs.setdefault("memory_kib", 8)
        kwargs.setdefault("time_cost", 1)
        kwargs.setdefault("parallelism", 1)
        return real(manager, path, password, **kwargs)

    monkeypatch.setattr("fortigate_vpn_gui.gui.profiles_page.create_backup", wrapped)


def _spy_preflight(monkeypatch, seen: list[object]):
    from fortigate_vpn_gui.backup.service import preflight_restore as real

    def wrapped(manager, path, password, **kwargs):
        seen.append(path)
        return real(manager, path, password, **kwargs)

    monkeypatch.setattr("fortigate_vpn_gui.gui.profiles_page.preflight_restore", wrapped)


def test_profiles_page_has_backup_restore_and_export_warning(
    qapp, profile_manager: ProfileManager
) -> None:
    page = ProfilesPage(profile_manager)
    intro = page.findChild(QLabel, "profilesIntro")
    assert intro is not None
    text = intro.text()
    assert "Saved IPsec PSKs and XAuth passwords are stored securely" in text
    assert "SSL passwords, SAML tokens, cookies, and session secrets" in text
    assert "never stored" in text
    assert "Import and Export transfer profiles without saved credentials" in text
    assert "including saved IPsec PSKs and XAuth passwords" in text
    assert "Restore recovers them from an encrypted backup" in text
    restore = page.findChild(QPushButton, "emptyRestoreProfilesButton")
    backup = page.findChild(QPushButton, "emptyBackupProfilesButton")
    imported = page.findChild(QPushButton, "emptyImportProfileButton")
    assert restore is not None
    assert backup is not None
    assert imported is not None
    assert backup.toolTip() == BACKUP_TOOLTIP
    assert restore.toolTip() == RESTORE_TOOLTIP
    assert imported.toolTip() == IMPORT_TOOLTIP
    assert EXPORT_TOOLTIP.startswith("Export profiles")
    assert "Backup" not in [
        child.text()
        for child in page.findChildren(QPushButton)
        if "tray" in (child.objectName() or "")
    ]


def test_profiles_page_backup_restore_round_trip(qapp, tmp_path: Path) -> None:
    page, manager, store = _page_with_profile(tmp_path / "a")
    path = tmp_path / "gui.fvbackup"
    written = page.backup_profiles(
        destination=path,
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
    plan = dest_page.restore_profiles(source=path, password=_PASSWORD, confirmed=True)
    assert plan is not None
    restored = dest.get(manager.list_profiles()[0].id)
    assert restored is not None
    assert restored.name == "Tunnel"
    assert dest_store.get(restored.id) == _PSK


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
    more = page.findChild(QToolButton, f"profileMoreButton_{profile.id}")
    assert more is not None
    export_action = next(
        action
        for action in more.menu().actions()
        if action.objectName() == f"profileExportAction_{profile.id}"
    )
    assert export_action.toolTip() == EXPORT_TOOLTIP


def test_backup_password_dialog_rejects_short(qapp) -> None:
    dialog = BackupPasswordDialog()
    dialog._password.setText("short")
    dialog._confirm.setText("short")
    dialog._try_accept()
    assert dialog._error.isHidden() is False
    assert "12" in dialog._error.text()


def test_backup_password_dialog_rejects_mismatch(qapp) -> None:
    dialog = BackupPasswordDialog()
    dialog._password.setText(_PASSWORD)
    dialog._confirm.setText("backup-password-no")
    dialog._try_accept()
    assert dialog._error.isHidden() is False
    assert "match" in dialog._error.text().lower()


def test_restore_password_dialog_explains_backup_password(qapp) -> None:
    dialog = RestorePasswordDialog()
    intro = dialog.findChild(QLabel, "restorePasswordIntro")
    assert intro is not None
    text = intro.text()
    assert "used when this encrypted backup was created" in text
    assert "sudo" in text
    assert "VPN password" in text


def test_create_backup_helper_used_by_empty_backup(tmp_path: Path) -> None:
    manager = ProfileManager(config_dir=tmp_path / "cfg", psk_store=MemoryPskStore())
    path = tmp_path / "empty.fvbackup"
    create_backup(manager, path, _PASSWORD, confirmation=_PASSWORD, **_FAST)
    assert path.is_file()


def test_backup_button_click_does_not_pass_clicked_bool(qapp, tmp_path: Path, monkeypatch) -> None:
    page, _manager, _store = _page_with_profile(tmp_path)
    order: list[str] = []
    seen: list[object] = []
    infos, _warnings, _questions = _silence_boxes(monkeypatch)
    _track_password_dialogs(monkeypatch, order)
    _choose_save(monkeypatch, str(tmp_path / "clicked.fvbackup"), order)
    _accept_backup_password(monkeypatch, _PASSWORD, _PASSWORD)
    _spy_create_backup(monkeypatch, seen)
    button = page.findChild(QPushButton, "backupProfilesButton")
    assert button is not None
    button.click()
    assert order[:2] == ["save", "backup-password"]
    assert seen
    assert all(isinstance(path, Path) for path in seen)
    assert all(path is not False and path is not True for path in seen)
    assert (tmp_path / "clicked.fvbackup").is_file()
    assert str(tmp_path / "clicked.fvbackup") in infos[0]
    assert _PSK not in infos[0]


def test_backup_button_click_save_dialog_before_password(qapp, tmp_path: Path, monkeypatch) -> None:
    page, _manager, _store = _page_with_profile(tmp_path)
    order: list[str] = []
    _silence_boxes(monkeypatch)
    _track_password_dialogs(monkeypatch, order)
    _choose_save(monkeypatch, str(tmp_path / "order.fvbackup"), order)
    _accept_backup_password(monkeypatch, _PASSWORD, _PASSWORD)
    _spy_create_backup(monkeypatch, [])
    page.findChild(QPushButton, "backupProfilesButton").click()
    assert order.index("save") < order.index("backup-password")
    assert "restore-password" not in order


def test_backup_cancel_save_skips_password(qapp, tmp_path: Path, monkeypatch) -> None:
    page, manager, _store = _page_with_profile(tmp_path)
    order: list[str] = []
    seen: list[object] = []
    _silence_boxes(monkeypatch)
    _track_password_dialogs(monkeypatch, order)
    _choose_save(monkeypatch, "", order)
    _accept_backup_password(monkeypatch, _PASSWORD, _PASSWORD)
    _spy_create_backup(monkeypatch, seen)
    page.findChild(QPushButton, "backupProfilesButton").click()
    assert order == ["save"]
    assert "backup-password" not in order
    assert seen == []
    assert list(tmp_path.glob("*.fvbackup")) == []
    assert manager.list_profiles()


def test_backup_click_short_password_rejected(qapp, tmp_path: Path, monkeypatch) -> None:
    page, _manager, _store = _page_with_profile(tmp_path)
    seen: list[object] = []
    _silence_boxes(monkeypatch)
    _choose_save(monkeypatch, str(tmp_path / "short.fvbackup"))
    _accept_backup_password(monkeypatch, "short", "short")
    _spy_create_backup(monkeypatch, seen)
    page.findChild(QPushButton, "backupProfilesButton").click()
    assert seen == []
    assert not (tmp_path / "short.fvbackup").exists()


def test_backup_click_mismatch_rejected(qapp, tmp_path: Path, monkeypatch) -> None:
    page, _manager, _store = _page_with_profile(tmp_path)
    seen: list[object] = []
    _silence_boxes(monkeypatch)
    _choose_save(monkeypatch, str(tmp_path / "mismatch.fvbackup"))
    _accept_backup_password(monkeypatch, _PASSWORD, "backup-password-no")
    _spy_create_backup(monkeypatch, seen)
    page.findChild(QPushButton, "backupProfilesButton").click()
    assert seen == []
    assert not (tmp_path / "mismatch.fvbackup").exists()


def test_backup_click_appends_fvbackup_extension(qapp, tmp_path: Path, monkeypatch) -> None:
    page, _manager, _store = _page_with_profile(tmp_path)
    seen: list[object] = []
    infos, _warnings, _questions = _silence_boxes(monkeypatch)
    _choose_save(monkeypatch, str(tmp_path / "noext"))
    _accept_backup_password(monkeypatch, _PASSWORD, _PASSWORD)
    _spy_create_backup(monkeypatch, seen)
    page.findChild(QPushButton, "backupProfilesButton").click()
    assert seen == [tmp_path / "noext.fvbackup"]
    assert (tmp_path / "noext.fvbackup").is_file()
    assert (tmp_path / "noext.fvbackup").stat().st_mode & 0o777 == 0o600
    assert "noext.fvbackup" in infos[0]


def test_empty_backup_button_click_does_not_pass_bool(
    qapp, tmp_path: Path, monkeypatch, profile_manager: ProfileManager
) -> None:
    page = ProfilesPage(profile_manager)
    seen: list[object] = []
    _silence_boxes(monkeypatch)
    _choose_save(monkeypatch, str(tmp_path / "empty.fvbackup"))
    _accept_backup_password(monkeypatch, _PASSWORD, _PASSWORD)
    _spy_create_backup(monkeypatch, seen)
    button = page.findChild(QPushButton, "emptyBackupProfilesButton")
    assert button is not None
    button.click()
    assert seen == [tmp_path / "empty.fvbackup"]
    assert isinstance(seen[0], Path)


def test_restore_button_click_does_not_pass_clicked_bool(qapp, tmp_path: Path, monkeypatch) -> None:
    _source_page, source, _store = _page_with_profile(tmp_path / "src")
    backup = tmp_path / "restore.fvbackup"
    create_backup(source, backup, _PASSWORD, confirmation=_PASSWORD, **_FAST)
    dest_store = MemoryPskStore()
    dest = ProfileManager(config_dir=tmp_path / "dst", psk_store=dest_store)
    page = ProfilesPage(dest)
    order: list[str] = []
    seen: list[object] = []
    infos, _warnings, questions = _silence_boxes(monkeypatch)
    _track_password_dialogs(monkeypatch, order)
    _choose_open(monkeypatch, str(backup), order)
    _accept_restore_password(monkeypatch, _PASSWORD)
    _spy_preflight(monkeypatch, seen)
    button = page.findChild(QPushButton, "emptyRestoreProfilesButton")
    assert button is not None
    button.click()
    assert order[:2] == ["open", "restore-password"]
    assert order.index("open") < order.index("restore-password")
    assert seen == [backup]
    assert all(isinstance(path, Path) for path in seen)
    assert questions
    summary = str(questions[0]["text"])
    assert str(backup) in summary
    assert "Will add" in summary
    assert "Will replace" in summary
    assert "Will rename" in summary
    assert _PSK not in summary
    assert dest.get(source.list_profiles()[0].id) is not None
    assert dest_store.get(source.list_profiles()[0].id) == _PSK
    assert page.card_count() == 1
    assert page.empty_state_visible() is False
    assert _PSK not in infos[0]


def test_restore_cancel_open_skips_password(qapp, tmp_path: Path, monkeypatch) -> None:
    page, manager, _store = _page_with_profile(tmp_path)
    order: list[str] = []
    seen: list[object] = []
    _silence_boxes(monkeypatch)
    _track_password_dialogs(monkeypatch, order)
    _choose_open(monkeypatch, "", order)
    _accept_restore_password(monkeypatch, _PASSWORD)
    _spy_preflight(monkeypatch, seen)
    page.findChild(QPushButton, "restoreProfilesButton").click()
    assert order == ["open"]
    assert "restore-password" not in order
    assert seen == []
    assert len(manager.list_profiles()) == 1


def test_restore_wrong_password_no_traceback(qapp, tmp_path: Path, monkeypatch) -> None:
    _source_page, source, _store = _page_with_profile(tmp_path / "src")
    backup = tmp_path / "badpass.fvbackup"
    create_backup(source, backup, _PASSWORD, confirmation=_PASSWORD, **_FAST)
    dest = ProfileManager(config_dir=tmp_path / "dst", psk_store=MemoryPskStore())
    page = ProfilesPage(dest)
    _infos, warnings, questions = _silence_boxes(monkeypatch)
    _choose_open(monkeypatch, str(backup))
    _accept_restore_password(monkeypatch, "wrong-password-xx")
    page.findChild(QPushButton, "emptyRestoreProfilesButton").click()
    assert warnings == [AUTH_FAILURE_MESSAGE]
    assert questions == []
    assert dest.list_profiles() == ()
    assert page.empty_state_visible() is True


def test_restore_requires_explicit_confirmation(qapp, tmp_path: Path, monkeypatch) -> None:
    _source_page, source, _store = _page_with_profile(tmp_path / "src")
    backup = tmp_path / "confirm.fvbackup"
    create_backup(source, backup, _PASSWORD, confirmation=_PASSWORD, **_FAST)
    dest = ProfileManager(config_dir=tmp_path / "dst", psk_store=MemoryPskStore())
    page = ProfilesPage(dest)
    _infos, _warnings, questions = _silence_boxes(
        monkeypatch, question_result=QMessageBox.StandardButton.No
    )
    _choose_open(monkeypatch, str(backup))
    _accept_restore_password(monkeypatch, _PASSWORD)
    page.findChild(QPushButton, "emptyRestoreProfilesButton").click()
    assert questions
    assert questions[0]["default"] == QMessageBox.StandardButton.No
    assert dest.list_profiles() == ()
    assert page.empty_state_visible() is True
