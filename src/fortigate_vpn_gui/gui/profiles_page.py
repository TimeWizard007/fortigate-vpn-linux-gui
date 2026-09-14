# SPDX-License-Identifier: GPL-3.0-or-later
"""Profiles page: manage many FortiGate connection profiles."""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
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

from fortigate_vpn_gui.gui.ipsec_credentials_dialog import prompt_ipsec_credentials
from fortigate_vpn_gui.gui.page_container import create_page_scroll_area
from fortigate_vpn_gui.gui.profile_editor_dialog import ProfileEditorDialog
from fortigate_vpn_gui.gui.windowing import dialog_parent_for
from fortigate_vpn_gui.profiles.manager import ProfileManager
from fortigate_vpn_gui.profiles.model import ConnectionProfile, ProfileNotFoundError
from fortigate_vpn_gui.vpn.backend import VpnBackend
from fortigate_vpn_gui.vpn.models import CONNECTABLE_STATES, ConnectionState, VpnSnapshot

SelectProfile = Callable[[str], None]
OnConnect = Callable[[], None]


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
            "Profiles are stored on this computer only. They do not contain "
            "passwords, SAML tokens, cookies, or other secrets."
        )
        intro.setWordWrap(True)

        self._feedback = QLabel("")
        self._feedback.setObjectName("profileConnectFeedback")
        self._feedback.setWordWrap(True)
        self._feedback.hide()

        self._add_button = QPushButton("Add profile")
        self._add_button.setObjectName("addProfileButton")
        self._add_button.clicked.connect(self.add_profile)

        header_row = QHBoxLayout()
        header_row.addWidget(intro, stretch=1)
        header_row.addWidget(self._add_button, alignment=Qt.AlignmentFlag.AlignTop)

        self._empty = QWidget()
        self._empty.setObjectName("emptyProfilesState")
        empty_layout = QVBoxLayout(self._empty)
        empty_layout.setContentsMargins(0, 24, 0, 0)
        empty_layout.setSpacing(12)
        empty_hint = QLabel("No VPN profiles yet.\nAdd a profile to connect to a FortiGate VPN.")
        empty_hint.setObjectName("emptyProfilesHint")
        empty_hint.setWordWrap(True)
        self._empty_add = QPushButton("Add profile")
        self._empty_add.setObjectName("emptyAddProfileButton")
        self._empty_add.clicked.connect(self.add_profile)
        empty_layout.addWidget(empty_hint)
        empty_layout.addWidget(self._empty_add, alignment=Qt.AlignmentFlag.AlignLeft)
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
                f'Delete profile "{profile.name}"?\n\nThis cannot be undone.',
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
        if self._select_profile is not None:
            self._select_profile(profile.id)
        credentials = None
        if profile.is_ipsec():
            credentials = prompt_ipsec_credentials(
                profile,
                parent=dialog_parent_for(self),
                psk_store=self._manager.psk_store,
                manager=self._manager,
            )
            if credentials is None:
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
            button.setEnabled(allowed)
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
