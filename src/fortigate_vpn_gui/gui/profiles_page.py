# SPDX-License-Identifier: GPL-3.0-or-later
"""Profiles page: manage many FortiGate connection profiles."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

from PySide6.QtCore import Qt, Slot
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMenu,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from fortigate_vpn_gui.backup.payload import format_restore_summary
from fortigate_vpn_gui.backup.service import (
    BackupError,
    RestorePlan,
    create_backup,
    ensure_backup_suffix,
    preflight_restore,
    restore_backup,
)
from fortigate_vpn_gui.gui.backup_dialog import BackupPasswordDialog, RestorePasswordDialog
from fortigate_vpn_gui.gui.ipsec_connect import collect_ipsec_connect_credentials
from fortigate_vpn_gui.gui.page_container import create_page_scroll_area
from fortigate_vpn_gui.gui.profile_editor_dialog import ProfileEditorDialog
from fortigate_vpn_gui.gui.windowing import dialog_parent_for
from fortigate_vpn_gui.profiles.manager import ProfileManager
from fortigate_vpn_gui.profiles.model import ConnectionProfile, ProfileNotFoundError
from fortigate_vpn_gui.profiles.transfer import (
    ProfileTransferError,
    write_exported_profile,
)
from fortigate_vpn_gui.vpn.backend import VpnBackend
from fortigate_vpn_gui.vpn.models import CONNECTABLE_STATES, ConnectionState, VpnSnapshot

SelectProfile = Callable[[str], None]
OnConnect = Callable[[], None]
BACKUP_FILE_FILTER = "FortiGate VPN encrypted backup (*.fvbackup)"
IMPORT_TOOLTIP = "Import profiles exported without credentials."
EXPORT_TOOLTIP = "Export profiles without saved credentials."
BACKUP_TOOLTIP = "Create an encrypted backup of all profiles and saved credentials."
RESTORE_TOOLTIP = "Restore profiles and saved credentials from an encrypted backup."


class ProfilesPage(QWidget):
    """Manage persisted FortiGate connection profiles."""

    def __init__(
        self,
        manager: ProfileManager,
        vpn: VpnBackend | None = None,
        parent: QWidget | None = None,
        *,
        on_connect: OnConnect | None = None,
        select_profile: SelectProfile | None = None,
    ) -> None:
        super().__init__(parent)
        self._manager = manager
        self._vpn = vpn
        self._on_connect = on_connect
        self._select_profile = select_profile
        self._snapshot: VpnSnapshot | None = None
        self._manager.add_change_listener(self.refresh)

        title = QLabel("Profiles")
        title.setObjectName("pageTitle")

        intro = QLabel(
            "Profiles are stored on this computer only. SSL passwords, SAML "
            "tokens, cookies, and other session secrets are never saved here.\n\n"
            "Import brings in profiles exported without credentials. "
            "Export writes profiles without saved credentials. "
            "Backup creates an encrypted copy of all profiles and saved "
            "credentials. Restore restores profiles and saved credentials "
            "from an encrypted backup."
        )
        intro.setWordWrap(True)
        intro.setObjectName("profilesIntro")

        self._feedback = QLabel("")
        self._feedback.setObjectName("profileConnectFeedback")
        self._feedback.setWordWrap(True)
        self._feedback.hide()

        self._add_button = QPushButton("New profile")
        self._add_button.setObjectName("addProfileButton")
        self._add_button.clicked.connect(self.add_profile)
        self._import_button = QPushButton("Import")
        self._import_button.setObjectName("importProfileButton")
        self._import_button.setToolTip(IMPORT_TOOLTIP)
        self._import_button.clicked.connect(self._on_import_clicked)
        self._backup_button = QPushButton("Backup…")
        self._backup_button.setObjectName("backupProfilesButton")
        self._backup_button.setToolTip(BACKUP_TOOLTIP)
        self._backup_button.clicked.connect(self._on_backup_clicked)
        self._restore_button = QPushButton("Restore…")
        self._restore_button.setObjectName("restoreProfilesButton")
        self._restore_button.setToolTip(RESTORE_TOOLTIP)
        self._restore_button.clicked.connect(self._on_restore_clicked)

        header_buttons = QVBoxLayout()
        header_buttons.setContentsMargins(0, 0, 0, 0)
        header_buttons.setSpacing(6)
        header_buttons.addWidget(self._add_button)
        header_buttons.addWidget(self._import_button)
        header_buttons.addWidget(self._backup_button)
        header_buttons.addWidget(self._restore_button)

        header_row = QHBoxLayout()
        header_row.addWidget(intro, stretch=1)
        header_row.addLayout(header_buttons)

        self._empty = QWidget()
        self._empty.setObjectName("emptyProfilesState")
        empty_layout = QVBoxLayout(self._empty)
        empty_layout.setContentsMargins(0, 24, 0, 0)
        empty_layout.setSpacing(12)
        empty_hint = QLabel(
            "No VPN profiles yet.\nCreate a profile or import one to connect to a FortiGate VPN."
        )
        empty_hint.setObjectName("emptyProfilesHint")
        empty_hint.setWordWrap(True)
        self._empty_add = QPushButton("New profile")
        self._empty_add.setObjectName("emptyAddProfileButton")
        self._empty_add.clicked.connect(self.add_profile)
        self._empty_import = QPushButton("Import")
        self._empty_import.setObjectName("emptyImportProfileButton")
        self._empty_import.setToolTip(IMPORT_TOOLTIP)
        self._empty_import.clicked.connect(self._on_import_clicked)
        self._empty_backup = QPushButton("Backup…")
        self._empty_backup.setObjectName("emptyBackupProfilesButton")
        self._empty_backup.setToolTip(BACKUP_TOOLTIP)
        self._empty_backup.clicked.connect(self._on_backup_clicked)
        self._empty_restore = QPushButton("Restore…")
        self._empty_restore.setObjectName("emptyRestoreProfilesButton")
        self._empty_restore.setToolTip(RESTORE_TOOLTIP)
        self._empty_restore.clicked.connect(self._on_restore_clicked)
        empty_layout.addWidget(empty_hint)
        empty_layout.addWidget(self._empty_add, alignment=Qt.AlignmentFlag.AlignLeft)
        empty_layout.addWidget(self._empty_import, alignment=Qt.AlignmentFlag.AlignLeft)
        empty_layout.addWidget(self._empty_backup, alignment=Qt.AlignmentFlag.AlignLeft)
        empty_layout.addWidget(self._empty_restore, alignment=Qt.AlignmentFlag.AlignLeft)
        empty_layout.addStretch(1)

        self._list = QWidget()
        self._list.setObjectName("profilesList")
        self._list_layout = QVBoxLayout(self._list)
        self._list_layout.setContentsMargins(0, 0, 0, 0)
        self._list_layout.setSpacing(8)

        inner = QWidget()
        layout = QVBoxLayout(inner)
        layout.setContentsMargins(16, 12, 24, 16)
        layout.setSpacing(12)
        layout.addWidget(title)
        layout.addLayout(header_row)
        layout.addWidget(self._feedback)
        layout.addWidget(self._empty)
        layout.addWidget(self._list, stretch=1)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(create_page_scroll_area(inner))
        if vpn is not None:
            self._snapshot = vpn.snapshot()
        self.refresh()

    def refresh(self) -> None:
        """Reload the list from the profile manager."""
        while self._list_layout.count():
            item = self._list_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.hide()
                widget.setParent(None)
                widget.deleteLater()
        profiles = self._manager.list_profiles()
        empty = not profiles
        self._empty.setVisible(empty)
        self._list.setVisible(not empty)
        self._add_button.setVisible(not empty)
        self._import_button.setVisible(not empty)
        self._backup_button.setVisible(not empty)
        self._restore_button.setVisible(not empty)
        for profile in profiles:
            self._list_layout.addWidget(self._build_card(profile))
        if profiles:
            self._list_layout.addStretch(1)
        self._sync_connect_buttons()

    def apply_snapshot(self, snapshot: VpnSnapshot) -> None:
        """Update Connect availability from the shared VPN backend."""
        self._snapshot = snapshot
        if snapshot.state in CONNECTABLE_STATES and not snapshot.reconnect_pending:
            self._feedback.hide()
            self._feedback.clear()
        self._sync_connect_buttons()

    def empty_state_visible(self) -> bool:
        return not self._empty.isHidden()

    def card_count(self) -> int:
        return len(self.findChildren(QFrame, "profileCard"))

    def add_profile(self) -> None:
        dialog = ProfileEditorDialog(self._manager, parent=dialog_parent_for(self))
        dialog.exec()

    @Slot()
    def _on_import_clicked(self) -> None:
        self.import_profile()

    @Slot()
    def _on_backup_clicked(self) -> None:
        self.backup_profiles()

    @Slot()
    def _on_restore_clicked(self) -> None:
        self.restore_profiles()

    def import_profile(self, *, source: Path | None = None) -> ConnectionProfile | None:
        """Import a secret-free profile export. *source* is for tests."""
        path = source
        if path is None:
            chosen, _filter = QFileDialog.getOpenFileName(
                dialog_parent_for(self),
                "Import profile",
                "",
                "Profile export (*.json);;All files (*)",
            )
            if not chosen:
                return None
            path = Path(chosen)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            profile = self._manager.import_profile(payload)
        except (OSError, UnicodeError, json.JSONDecodeError):
            QMessageBox.warning(
                dialog_parent_for(self),
                "Import failed",
                "The profile file is not valid JSON.",
            )
            return None
        except ProfileTransferError as exc:
            QMessageBox.warning(
                dialog_parent_for(self),
                "Import failed",
                str(exc),
            )
            return None
        self._feedback.setText(
            f'Imported "{profile.name}". Enter any required secrets before connecting.'
        )
        self._feedback.show()
        return profile

    def export_profile(self, profile_id: str, destination: Path | None = None) -> Path | None:
        """Export non-secret profile configuration. Never includes secrets."""
        profile = self._manager.get(profile_id)
        if profile is None:
            return None
        path = destination
        if path is None:
            suggested = f"{profile.name}.json"
            chosen, _filter = QFileDialog.getSaveFileName(
                dialog_parent_for(self),
                "Export profile",
                suggested,
                "Profile export (*.json)",
            )
            if not chosen:
                return None
            path = Path(chosen)
            if path.suffix.lower() != ".json":
                path = path.with_suffix(".json")
        try:
            written = write_exported_profile(profile, path)
        except OSError:
            QMessageBox.warning(
                dialog_parent_for(self),
                "Export failed",
                "The profile could not be written.",
            )
            return None
        self._feedback.setText(
            f'Exported "{profile.name}" without passwords or the IPsec pre-shared key.'
        )
        self._feedback.show()
        return written

    def backup_profiles(
        self,
        *,
        destination: Path | None = None,
        password: str | None = None,
        confirmation: str | None = None,
        memory_kib: int | None = None,
        time_cost: int | None = None,
    ) -> Path | None:
        """Create an encrypted backup of all profiles and saved IPsec secrets."""
        interactive = destination is None or password is None
        path = destination
        if path is None:
            chosen, _filter = QFileDialog.getSaveFileName(
                dialog_parent_for(self),
                "Backup profiles",
                "fortigate-vpn-linux-gui.fvbackup",
                BACKUP_FILE_FILTER,
            )
            if not chosen:
                return None
            path = ensure_backup_suffix(Path(chosen))
        if password is None:
            dialog = BackupPasswordDialog(dialog_parent_for(self))
            if dialog.exec() != dialog.DialogCode.Accepted:
                return None
            password = dialog.password()
            confirmation = dialog.confirmation()
        kwargs: dict[str, int] = {}
        if memory_kib is not None:
            kwargs["memory_kib"] = memory_kib
        if time_cost is not None:
            kwargs["time_cost"] = time_cost
        try:
            written = create_backup(
                self._manager,
                path,
                password,
                confirmation=confirmation,
                **kwargs,
            )
        except BackupError as exc:
            QMessageBox.warning(dialog_parent_for(self), "Backup failed", str(exc))
            return None
        except OSError:
            QMessageBox.warning(
                dialog_parent_for(self),
                "Backup failed",
                "The backup file could not be written.",
            )
            return None
        self._feedback.setText(
            f"Encrypted backup saved to {written}. Store the file and password "
            "separately. Export is not a backup of secrets."
        )
        self._feedback.show()
        if interactive:
            QMessageBox.information(
                dialog_parent_for(self),
                "Backup saved",
                (f"Backup saved to:\n{written}\n\nStore this file and password separately."),
            )
        return written

    def restore_profiles(
        self,
        *,
        source: Path | None = None,
        password: str | None = None,
        confirmed: bool | None = None,
    ) -> RestorePlan | None:
        """Restore profiles and saved IPsec secrets from an encrypted backup."""
        interactive = source is None or password is None or confirmed is None
        path = source
        if path is None:
            chosen, _filter = QFileDialog.getOpenFileName(
                dialog_parent_for(self),
                "Restore backup",
                "",
                f"{BACKUP_FILE_FILTER};;All files (*)",
            )
            if not chosen:
                return None
            path = Path(chosen)
        if password is None:
            dialog = RestorePasswordDialog(dialog_parent_for(self))
            if dialog.exec() != dialog.DialogCode.Accepted:
                return None
            password = dialog.password()
        snapshot = self._current_snapshot()
        try:
            plan = preflight_restore(
                self._manager,
                path,
                password,
                snapshot=snapshot,
            )
        except BackupError as exc:
            QMessageBox.warning(dialog_parent_for(self), "Restore failed", str(exc))
            return None
        summary = format_restore_summary(plan, source=path)
        if confirmed is None:
            answer = QMessageBox.question(
                dialog_parent_for(self),
                "Restore backup",
                summary,
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            confirmed = answer == QMessageBox.StandardButton.Yes
        if not confirmed:
            plan.wipe()
            return None
        try:
            restore_backup(
                self._manager,
                path,
                password,
                snapshot=snapshot,
                plan=plan,
            )
        except BackupError as exc:
            QMessageBox.warning(dialog_parent_for(self), "Restore failed", str(exc))
            return None
        plan.wipe()
        self._feedback.setText(
            f"Restored {len(plan.rows)} profile(s) from {path}. IPsec secrets "
            "were written to the desktop keyring when present."
        )
        self._feedback.show()
        if interactive:
            QMessageBox.information(
                dialog_parent_for(self),
                "Restore complete",
                self._feedback.text(),
            )
        return plan

    def edit_profile(self, profile_id: str) -> None:
        profile = self._manager.get(profile_id)
        if profile is None:
            return
        dialog = ProfileEditorDialog(self._manager, profile, parent=dialog_parent_for(self))
        dialog.exec()

    def duplicate_profile(
        self, profile_id: str, *, open_editor: bool = True
    ) -> ConnectionProfile | None:
        """Duplicate safe metadata. Optionally open the editor for the copy."""
        try:
            copy = self._manager.duplicate(profile_id)
        except ProfileNotFoundError:
            return None
        if open_editor:
            self.edit_profile(copy.id)
        return copy

    def set_default_profile(self, profile_id: str) -> None:
        self._manager.set_default(profile_id)

    def delete_profile(self, profile_id: str, *, confirmed: bool | None = None) -> None:
        """Delete a profile after confirmation.

        *confirmed* is for tests. When omitted, a confirmation dialog is shown.
        Deleting a profile does not disconnect an active VPN session.
        """
        profile = self._manager.get(profile_id)
        if profile is None:
            return
        if confirmed is None:
            answer = QMessageBox.question(
                dialog_parent_for(self),
                "Delete profile",
                (
                    f'Delete profile "{profile.name}"?\n\n'
                    "Saved passwords and the IPsec pre-shared key for this "
                    "profile will also be removed. This cannot be undone."
                ),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            confirmed = answer == QMessageBox.StandardButton.Yes
        if not confirmed:
            return
        self._manager.delete(profile.id)

    def connect_profile(self, profile_id: str) -> bool:
        """Start the existing VPN flow for *profile_id*.

        Uses ``VpnBackend.connect`` — the same controller as the Connection page.
        Returns False when a session is already active or the profile is missing.
        """
        profile = self._manager.get(profile_id)
        if profile is None or self._vpn is None:
            return False
        snapshot = self._vpn.snapshot()
        if not self._can_start_connection(snapshot):
            return False
        if not profile.is_connectable():
            reason = profile.connect_block_reason() or "This profile cannot be connected."
            self._feedback.setText(reason)
            self._feedback.show()
            return False
        if self._select_profile is not None:
            self._select_profile(profile.id)
        proceed, credentials = collect_ipsec_connect_credentials(
            profile,
            parent=dialog_parent_for(self),
            psk_store=self._manager.psk_store,
            manager=self._manager,
        )
        if not proceed:
            return False
        self._feedback.setText(f"Connecting… {profile.name}")
        self._feedback.show()
        self._vpn.connect(profile, credentials=credentials)
        self.apply_snapshot(self._vpn.snapshot())
        if self._on_connect is not None:
            self._on_connect()
        return True

    def connect_enabled_for(self, profile_id: str) -> bool:
        button = self.findChild(QPushButton, f"connectProfileButton_{profile_id}")
        return button is not None and button.isEnabled()

    def _build_card(self, profile: ConnectionProfile) -> QFrame:
        card = QFrame()
        card.setObjectName("profileCard")
        card.setProperty("profileId", profile.id)
        card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        name = QLabel(profile.name)
        name.setObjectName("profileCardName")
        name.setWordWrap(True)

        default_badge = QLabel("Default")
        default_badge.setObjectName("profileDefaultBadge")
        default_badge.setVisible(self._manager.is_default(profile.id))

        host = QLabel(f"{profile.vpn_type_label()} · {profile.gateway}:{profile.port}")
        host.setObjectName("profileCardHost")
        host.setWordWrap(True)

        auth = QLabel(profile.auth_label())
        auth.setObjectName("profileCardAuth")

        connect = QPushButton("Connect")
        connect.setObjectName(f"connectProfileButton_{profile.id}")
        connect.clicked.connect(lambda checked=False, pid=profile.id: self.connect_profile(pid))

        more = QToolButton()
        more.setObjectName(f"profileMoreButton_{profile.id}")
        more.setText("More")
        more.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextOnly)
        more.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        more.setMenu(self._card_menu(profile, more))
        more.clicked.connect(more.showMenu)

        title_row = QHBoxLayout()
        title_row.setContentsMargins(0, 0, 0, 0)
        title_row.addWidget(name, stretch=1)
        title_row.addWidget(default_badge)

        meta_row = QHBoxLayout()
        meta_row.setContentsMargins(0, 0, 0, 0)
        meta_row.addWidget(auth)
        meta_row.addStretch(1)
        meta_row.addWidget(connect)
        meta_row.addWidget(more)

        layout = QVBoxLayout(card)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(6)
        layout.addLayout(title_row)
        layout.addWidget(host)
        layout.addLayout(meta_row)
        return card

    def _card_menu(self, profile: ConnectionProfile, parent: QWidget) -> QMenu:
        menu = QMenu(parent)
        menu.setObjectName(f"profileMoreMenu_{profile.id}")
        edit = menu.addAction("Edit")
        edit.setObjectName(f"profileEditAction_{profile.id}")
        edit.triggered.connect(lambda checked=False, pid=profile.id: self.edit_profile(pid))
        duplicate = menu.addAction("Duplicate")
        duplicate.setObjectName(f"profileDuplicateAction_{profile.id}")
        duplicate.triggered.connect(
            lambda checked=False, pid=profile.id: self.duplicate_profile(pid)
        )
        export_action = menu.addAction("Export")
        export_action.setObjectName(f"profileExportAction_{profile.id}")
        export_action.setToolTip(EXPORT_TOOLTIP)
        export_action.triggered.connect(
            lambda checked=False, pid=profile.id: self.export_profile(pid)
        )
        set_default = menu.addAction("Set as default")
        set_default.setObjectName(f"profileDefaultAction_{profile.id}")
        set_default.triggered.connect(
            lambda checked=False, pid=profile.id: self.set_default_profile(pid)
        )
        set_default.setEnabled(not self._manager.is_default(profile.id))
        menu.addSeparator()
        delete_action = menu.addAction("Delete")
        delete_action.setObjectName(f"profileDeleteAction_{profile.id}")
        delete_action.triggered.connect(
            lambda checked=False, pid=profile.id: self.delete_profile(pid)
        )
        return menu

    def _sync_connect_buttons(self) -> None:
        allowed = self._can_start_connection(self._current_snapshot())
        snapshot = self._current_snapshot()
        connecting_id = None
        if snapshot is not None and snapshot.state not in CONNECTABLE_STATES:
            connecting_id = snapshot.profile_id
        for profile in self._manager.list_profiles():
            button = self.findChild(QPushButton, f"connectProfileButton_{profile.id}")
            if button is None:
                continue
            button.setEnabled(allowed and profile.is_connectable())
            if not profile.is_connectable():
                reason = profile.connect_block_reason() or "This profile cannot be connected."
                button.setToolTip(reason)
            else:
                button.setToolTip("")
            if connecting_id == profile.id and snapshot is not None:
                if snapshot.state is ConnectionState.CONNECTED:
                    button.setText("Connected")
                elif snapshot.state is ConnectionState.DISCONNECTING:
                    button.setText("Disconnecting…")
                else:
                    button.setText("Connecting…")
            else:
                button.setText("Connect")

    def _current_snapshot(self) -> VpnSnapshot | None:
        if self._snapshot is not None:
            return self._snapshot
        if self._vpn is not None:
            return self._vpn.snapshot()
        return None

    @staticmethod
    def _can_start_connection(snapshot: VpnSnapshot | None) -> bool:
        if snapshot is None:
            return False
        if snapshot.shutdown_in_progress or snapshot.state is ConnectionState.CLOSING:
            return False
        if snapshot.manual_reconnect or snapshot.reconnect_pending:
            return False
        return snapshot.state in CONNECTABLE_STATES
