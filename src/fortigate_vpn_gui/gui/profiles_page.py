# SPDX-License-Identifier: GPL-3.0-or-later
"""Profiles page: list, add, edit, and delete saved connection profiles."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from fortigate_vpn_gui.gui.profile_editor_dialog import ProfileEditorDialog
from fortigate_vpn_gui.gui.windowing import dialog_parent_for
from fortigate_vpn_gui.profiles.manager import ProfileManager
from fortigate_vpn_gui.profiles.model import ConnectionProfile

_COLUMNS = ("Name", "Gateway", "Port", "SSO", "Description")


class ProfilesPage(QWidget):
    """Manage persisted FortiGate connection profiles."""

    def __init__(self, manager: ProfileManager, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._manager = manager
        self._manager.add_change_listener(self.refresh)

        title = QLabel("Profiles")
        title.setStyleSheet("font-size: 20px; font-weight: 600;")

        intro = QLabel(
            "Profiles are stored on this computer only. They do not contain "
            "passwords, SAML tokens, cookies, or other secrets."
        )
        intro.setWordWrap(True)

        self._table = QTableWidget(0, len(_COLUMNS))
        self._table.setObjectName("profilesTable")
        self._table.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self._table.setHorizontalHeaderLabels(_COLUMNS)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.verticalHeader().setVisible(False)
        header = self._table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self._table.itemSelectionChanged.connect(self._sync_buttons)

        self._add_button = QPushButton("Add profile")
        self._add_button.setObjectName("addProfileButton")
        self._add_button.clicked.connect(self.add_profile)
        self._edit_button = QPushButton("Edit profile")
        self._edit_button.setObjectName("editProfileButton")
        self._edit_button.clicked.connect(self.edit_profile)
        self._delete_button = QPushButton("Delete profile")
        self._delete_button.setObjectName("deleteProfileButton")
        self._delete_button.clicked.connect(self.delete_profile)

        buttons = QHBoxLayout()
        buttons.addWidget(self._add_button)
        buttons.addWidget(self._edit_button)
        buttons.addWidget(self._delete_button)
        buttons.addStretch(1)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 24, 16)
        layout.setSpacing(12)
        layout.addWidget(title)
        layout.addWidget(intro)
        layout.addWidget(self._table, stretch=1)
        layout.addLayout(buttons)
        self.refresh()

    def refresh(self) -> None:
        """Reload the table from the profile manager."""
        selected = self.selected_profile_id()
        self._table.setRowCount(0)
        for profile in self._manager.list_profiles():
            row = self._table.rowCount()
            self._table.insertRow(row)
            values = (
                profile.name,
                profile.gateway,
                str(profile.port),
                "Yes" if profile.use_sso else "No",
                profile.description,
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column == 0:
                    item.setData(Qt.ItemDataRole.UserRole, profile.id)
                self._table.setItem(row, column, item)
            if profile.id == selected:
                self._table.selectRow(row)
        self._sync_buttons()

    def selected_profile_id(self) -> str | None:
        """Return the id of the selected row, if any."""
        items = self._table.selectedItems()
        if not items:
            return None
        row = items[0].row()
        name_item = self._table.item(row, 0)
        if name_item is None:
            return None
        value = name_item.data(Qt.ItemDataRole.UserRole)
        return str(value) if value else None

    def selected_profile(self) -> ConnectionProfile | None:
        profile_id = self.selected_profile_id()
        if profile_id is None:
            return None
        return self._manager.get(profile_id)

    def add_profile(self) -> None:
        dialog = ProfileEditorDialog(self._manager, parent=dialog_parent_for(self))
        dialog.exec()

    def edit_profile(self) -> None:
        profile = self.selected_profile()
        if profile is None:
            return
        dialog = ProfileEditorDialog(self._manager, profile, parent=dialog_parent_for(self))
        dialog.exec()

    def delete_profile(self, *, confirmed: bool | None = None) -> None:
        """Delete the selected profile after confirmation.

        *confirmed* is for tests. When omitted, a confirmation dialog is shown.
        """
        profile = self.selected_profile()
        if profile is None:
            return
        if confirmed is None:
            answer = QMessageBox.question(
                dialog_parent_for(self),
                "Delete profile",
                f'Delete profile "{profile.name}"?\n\nThis cannot be undone.',
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            confirmed = answer == QMessageBox.StandardButton.Yes
        if not confirmed:
            return
        self._manager.delete(profile.id)

    def _sync_buttons(self) -> None:
        has_selection = self.selected_profile_id() is not None
        self._edit_button.setEnabled(has_selection)
        self._delete_button.setEnabled(has_selection)
