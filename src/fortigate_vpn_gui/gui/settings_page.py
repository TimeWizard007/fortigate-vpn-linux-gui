# SPDX-License-Identifier: GPL-3.0-or-later
"""Settings page: window, autostart, and reconnect preferences."""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QLabel,
    QMessageBox,
    QVBoxLayout,
    QWidget,
)

from fortigate_vpn_gui.desktop.autostart import AutostartError, disable_autostart, enable_autostart
from fortigate_vpn_gui.desktop.settings import DesktopPreferences
from fortigate_vpn_gui.gui.config_path_widget import ProfileConfigPathWidget
from fortigate_vpn_gui.gui.page_container import create_page_scroll_area
from fortigate_vpn_gui.gui.windowing import dialog_parent_for
from fortigate_vpn_gui.metadata import APP_NAME
from fortigate_vpn_gui.profiles.manager import ProfileManager
from fortigate_vpn_gui.vpn.log_buffer import LogBuffer


class SettingsPage(QWidget):
    """Application settings. Certificate verification will never be silently disabled."""

    def __init__(
        self,
        manager: ProfileManager,
        parent: QWidget | None = None,
        *,
        preferences: DesktopPreferences | None = None,
        on_always_on_top: Callable[[bool], None] | None = None,
        on_close_to_tray: Callable[[bool], None] | None = None,
        on_auto_reconnect: Callable[[bool], None] | None = None,
        on_autostart: Callable[[bool], None] | None = None,
        log_buffer: LogBuffer | None = None,
        tray_available: bool = True,
    ) -> None:
        super().__init__(parent)
        prefs = preferences or DesktopPreferences()
        self._on_always_on_top = on_always_on_top
        self._on_close_to_tray = on_close_to_tray
        self._on_auto_reconnect = on_auto_reconnect
        self._on_autostart = on_autostart
        self._log = log_buffer
        self._updating = False

        title = QLabel("Settings")
        title.setObjectName("pageTitle")
        intro = QLabel(
            "Application preferences. Certificate verification must not be "
            "silently disabled. Desktop options are optional and off by default."
        )
        intro.setWordWrap(True)

        self._always_on_top = QCheckBox("Always on top")
        self._always_on_top.setObjectName("alwaysOnTopCheckbox")
        self._always_on_top.setChecked(prefs.always_on_top)
        self._always_on_top.toggled.connect(self._emit_always_on_top)

        self._close_combo = QComboBox()
        self._close_combo.setObjectName("closeBehaviorCombo")
        self._close_combo.addItem("Exit application", False)
        self._close_combo.addItem("Minimize to system tray", True)
        self._close_combo.setCurrentIndex(1 if prefs.close_to_tray else 0)
        self._close_combo.setEnabled(tray_available)
        self._close_combo.currentIndexChanged.connect(self._emit_close_to_tray)

        self._autostart = QCheckBox("Start FortiGate VPN Linux GUI automatically after login")
        self._autostart.setObjectName("autostartCheckbox")
        self._autostart.setChecked(prefs.autostart)
        self._autostart.toggled.connect(self._emit_autostart)

        self._auto_reconnect = QCheckBox("Automatically reconnect if VPN connection is lost")
        self._auto_reconnect.setObjectName("autoReconnectCheckbox")
        self._auto_reconnect.setChecked(prefs.auto_reconnect)
        self._auto_reconnect.toggled.connect(self._emit_auto_reconnect)
        reconnect_note = QLabel(
            "Auto-reconnect is off by default. It only runs after unexpected "
            "tunnel loss, never after Disconnect or Quit, and never skips "
            "SAML or certificate approval."
        )
        reconnect_note.setWordWrap(True)

        form = QFormLayout()
        form.addRow("Close button behavior:", self._close_combo)

        inner = QWidget()
        inner_layout = QVBoxLayout(inner)
        inner_layout.setContentsMargins(16, 12, 24, 16)
        inner_layout.setSpacing(12)
        inner_layout.addWidget(title)
        inner_layout.addWidget(intro)
        inner_layout.addWidget(self._always_on_top)
        inner_layout.addLayout(form)
        inner_layout.addWidget(self._autostart)
        inner_layout.addWidget(self._auto_reconnect)
        inner_layout.addWidget(reconnect_note)
        inner_layout.addWidget(ProfileConfigPathWidget(manager.storage_path))
        inner_layout.addStretch(1)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(create_page_scroll_area(inner))

    def always_on_top_checked(self) -> bool:
        return self._always_on_top.isChecked()

    def close_to_tray_selected(self) -> bool:
        return bool(self._close_combo.currentData())

    def autostart_checked(self) -> bool:
        return self._autostart.isChecked()

    def auto_reconnect_checked(self) -> bool:
        return self._auto_reconnect.isChecked()

    def apply_preferences(self, prefs: DesktopPreferences, *, tray_available: bool = True) -> None:
        self._updating = True
        self._always_on_top.setChecked(prefs.always_on_top)
        self._close_combo.setCurrentIndex(1 if prefs.close_to_tray else 0)
        self._close_combo.setEnabled(tray_available)
        self._autostart.setChecked(prefs.autostart)
        self._auto_reconnect.setChecked(prefs.auto_reconnect)
        self._updating = False

    def _emit_always_on_top(self, checked: bool) -> None:
        if self._updating:
            return
        if self._on_always_on_top is not None:
            self._on_always_on_top(checked)

    def _emit_close_to_tray(self, _index: int) -> None:
        if self._updating:
            return
        if self._on_close_to_tray is not None:
            self._on_close_to_tray(self.close_to_tray_selected())

    def _emit_auto_reconnect(self, checked: bool) -> None:
        if self._updating:
            return
        if self._on_auto_reconnect is not None:
            self._on_auto_reconnect(checked)

    def _emit_autostart(self, checked: bool) -> None:
        if self._updating:
            return
        try:
            if checked:
                enable_autostart()
                if self._log is not None:
                    self._log.append("vpn", "Autostart enabled.")
            else:
                disable_autostart()
                if self._log is not None:
                    self._log.append("vpn", "Autostart disabled.")
        except AutostartError as exc:
            self._updating = True
            self._autostart.setChecked(not checked)
            self._updating = False
            QMessageBox.warning(dialog_parent_for(self), APP_NAME, str(exc))
            return
        if self._on_autostart is not None:
            self._on_autostart(checked)
