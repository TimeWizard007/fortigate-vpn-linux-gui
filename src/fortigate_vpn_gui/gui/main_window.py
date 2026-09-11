# SPDX-License-Identifier: GPL-3.0-or-later
"""Main application window and navigation."""

from __future__ import annotations

from PySide6.QtCore import QSettings, Qt, Signal
from PySide6.QtGui import QCloseEvent, QShowEvent
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from fortigate_vpn_gui import APP_NAME, __version__
from fortigate_vpn_gui.desktop.settings import (
    DesktopPreferences,
    load_desktop_preferences,
    save_desktop_preferences,
)
from fortigate_vpn_gui.gui.about_page import AboutPage
from fortigate_vpn_gui.gui.connection_page import ConnectionPage
from fortigate_vpn_gui.gui.diagnostics_page import DiagnosticsPage
from fortigate_vpn_gui.gui.event_pump import BackendEventPump
from fortigate_vpn_gui.gui.icons import application_icon
from fortigate_vpn_gui.gui.logs_page import LogsPage
from fortigate_vpn_gui.gui.profiles_page import ProfilesPage
from fortigate_vpn_gui.gui.settings_page import SettingsPage
from fortigate_vpn_gui.gui.tray import TrayController
from fortigate_vpn_gui.gui.windowing import (
    apply_always_on_top,
    clear_transient_parent,
    configure_independent_main_window,
)
from fortigate_vpn_gui.profiles.manager import ProfileManager
from fortigate_vpn_gui.vpn.backend import VpnBackend, VpnEvent
from fortigate_vpn_gui.vpn.detect import detect_openfortivpn
from fortigate_vpn_gui.vpn.log_buffer import LogBuffer
from fortigate_vpn_gui.vpn.models import ConnectionState, VpnErrorCode, VpnSnapshot, state_label

_NAV_ITEMS: tuple[str, ...] = (
    "Connection",
    "Profiles",
    "Diagnostics",
    "Logs",
    "Settings",
    "About",
)


class MainWindow(QMainWindow):
    """Primary window: sidebar navigation plus stacked pages."""

    # Queued so helper/timeout worker threads cannot nest inside closeEvent and
    # cannot create a QTimer on a thread that has no Qt event loop.
    _shutdown_complete = Signal()

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        profile_manager: ProfileManager | None = None,
        vpn_backend: VpnBackend | None = None,
        log_buffer: LogBuffer | None = None,
        detect=detect_openfortivpn,
        settings: QSettings | None = None,
        tray_available: bool | None = None,
    ) -> None:
        super().__init__(None)
        _ = parent
        self.setWindowTitle(APP_NAME)
        self.setWindowIcon(application_icon())
        self.setMinimumSize(640, 420)
        self.resize(960, 640)
        self._settings = settings or QSettings(
            "fortigate-vpn-linux-gui",
            "fortigate-vpn-linux-gui",
        )
        self._prefs = load_desktop_preferences(self._settings)
        self._always_on_top = self._prefs.always_on_top
        configure_independent_main_window(self, always_on_top=self._always_on_top)

        self._profile_manager = profile_manager or ProfileManager()
        self._log_buffer = log_buffer if log_buffer is not None else LogBuffer()
        self._vpn = vpn_backend or VpnBackend(log_buffer=self._log_buffer)
        if vpn_backend is not None and log_buffer is None:
            self._log_buffer = vpn_backend.log_buffer
        self._vpn.set_auto_reconnect(self._prefs.auto_reconnect)

        self._quit_started = False
        self._can_finish_close = False
        self._close_finalized = False
        self._force_quit = False
        self._last_notified_state: ConnectionState | None = None
        self._tray: TrayController | None = None
        self._shutdown_complete.connect(self._finish_close, Qt.ConnectionType.QueuedConnection)

        self._connection_page = ConnectionPage(self._profile_manager, self._vpn)
        self._profiles_page = ProfilesPage(
            self._profile_manager,
            self._vpn,
            on_connect=lambda: self.show_page("Connection"),
            select_profile=self._connection_page.select_profile,
        )
        self._diagnostics_page = DiagnosticsPage(
            self._profile_manager,
            self._vpn,
            self._connection_page.selected_profile,
            detect=detect,
            desktop_info=self._desktop_diagnostics,
        )
        self._logs_page = LogsPage(self._log_buffer)
        self._settings_page = SettingsPage(
            self._profile_manager,
            preferences=self._prefs,
            on_always_on_top=self.set_always_on_top,
            on_close_to_tray=self.set_close_to_tray,
            on_auto_reconnect=self.set_auto_reconnect,
            on_autostart=self.set_autostart,
            log_buffer=self._log_buffer,
            tray_available=True,
        )
        self._about_page = AboutPage()

        self._stack = QStackedWidget()
        self._stack.addWidget(self._connection_page)
        self._stack.addWidget(self._profiles_page)
        self._stack.addWidget(self._diagnostics_page)
        self._stack.addWidget(self._logs_page)
        self._stack.addWidget(self._settings_page)
        self._stack.addWidget(self._about_page)

        self._nav = QListWidget()
        self._nav.setObjectName("navList")
        self._nav.setFixedWidth(160)
        for label in _NAV_ITEMS:
            QListWidgetItem(label, self._nav)
        self._nav.setCurrentRow(0)
        self._nav.currentRowChanged.connect(self._on_nav_changed)

        header = QLabel(f"{APP_NAME}  ·  v{__version__}")
        header.setObjectName("appHeader")
        header.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)

        body = QWidget()
        body_layout = QHBoxLayout(body)
        body_layout.setContentsMargins(12, 8, 12, 12)
        body_layout.setSpacing(12)
        body_layout.addWidget(self._nav)
        body_layout.addWidget(self._stack, stretch=1)

        central = QWidget()
        layout = QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(header)
        layout.addWidget(body, stretch=1)
        self.setCentralWidget(central)

        self.statusBar().showMessage("Disconnected")
        self._pump = BackendEventPump(self._vpn, self._log_buffer, parent=self)
        self._pump.state_changed.connect(self._on_vpn_snapshot)
        self._pump.user_error.connect(self._on_vpn_error)
        self._pump.log_record.connect(self._logs_page.append_record)

        self._tray = TrayController(
            self,
            available=tray_available,
            on_show=self.restore_from_tray,
            on_hide=self.hide,
            on_connect=self._tray_connect,
            on_disconnect=self._vpn.disconnect,
            on_reconnect=self._tray_reconnect,
            on_settings=lambda: self.show_page("Settings"),
            on_about=lambda: self.show_page("About"),
            on_quit=self.request_quit,
        )
        self._settings_page.apply_preferences(self._prefs, tray_available=self._tray.available)
        if self._tray.available:
            app = QApplication.instance()
            if isinstance(app, QApplication):
                app.setQuitOnLastWindowClosed(False)
            self._tray.apply_snapshot(self._vpn.snapshot())
            self._tray.show()
        self._diagnostics_page.refresh(include_version=False)

        self._apply_style()

    def _desktop_diagnostics(self) -> dict[str, str]:
        tray = self._tray
        available = bool(tray is not None and tray.available)
        active = bool(tray is not None and tray.active)
        return {
            "tray_available": "Yes" if available else "No",
            "tray_active": "Yes" if active else "No",
            "close_behavior": (
                "Minimize to system tray" if self._prefs.close_to_tray else "Exit application"
            ),
            "autostart_enabled": "Yes" if self._prefs.autostart else "No",
        }

    @property
    def profile_manager(self) -> ProfileManager:
        return self._profile_manager

    @property
    def vpn_backend(self) -> VpnBackend:
        return self._vpn

    @property
    def connection_page(self) -> ConnectionPage:
        return self._connection_page

    @property
    def profiles_page(self) -> ProfilesPage:
        return self._profiles_page

    @property
    def logs_page(self) -> LogsPage:
        return self._logs_page

    @property
    def diagnostics_page(self) -> DiagnosticsPage:
        return self._diagnostics_page

    @property
    def settings_page(self) -> SettingsPage:
        return self._settings_page

    @property
    def about_page(self) -> AboutPage:
        return self._about_page

    @property
    def tray(self) -> TrayController:
        assert self._tray is not None
        return self._tray

    def always_on_top(self) -> bool:
        return self._always_on_top

    def set_always_on_top(self, enabled: bool) -> None:
        self._always_on_top = bool(enabled)
        self._prefs = DesktopPreferences(
            always_on_top=self._always_on_top,
            close_to_tray=self._prefs.close_to_tray,
            autostart=self._prefs.autostart,
            auto_reconnect=self._prefs.auto_reconnect,
            tray_hint_shown=self._prefs.tray_hint_shown,
        )
        save_desktop_preferences(self._settings, self._prefs)
        apply_always_on_top(self, self._always_on_top)

    def set_close_to_tray(self, enabled: bool) -> None:
        self._prefs = DesktopPreferences(
            always_on_top=self._prefs.always_on_top,
            close_to_tray=bool(enabled) and self.tray.available,
            autostart=self._prefs.autostart,
            auto_reconnect=self._prefs.auto_reconnect,
            tray_hint_shown=self._prefs.tray_hint_shown,
        )
        save_desktop_preferences(self._settings, self._prefs)

    def set_auto_reconnect(self, enabled: bool) -> None:
        self._prefs = DesktopPreferences(
            always_on_top=self._prefs.always_on_top,
            close_to_tray=self._prefs.close_to_tray,
            autostart=self._prefs.autostart,
            auto_reconnect=bool(enabled),
            tray_hint_shown=self._prefs.tray_hint_shown,
        )
        save_desktop_preferences(self._settings, self._prefs)
        self._vpn.set_auto_reconnect(enabled)

    def set_autostart(self, enabled: bool) -> None:
        self._prefs = DesktopPreferences(
            always_on_top=self._prefs.always_on_top,
            close_to_tray=self._prefs.close_to_tray,
            autostart=bool(enabled),
            auto_reconnect=self._prefs.auto_reconnect,
            tray_hint_shown=self._prefs.tray_hint_shown,
        )
        save_desktop_preferences(self._settings, self._prefs)

    def showEvent(self, event: QShowEvent) -> None:  # noqa: N802 — Qt API
        super().showEvent(event)
        clear_transient_parent(self)

    def connection_status(self) -> str:
        return self._connection_page.status_text()

    def show_page(self, name: str) -> None:
        try:
            index = _NAV_ITEMS.index(name)
        except ValueError:
            return
        self._nav.setCurrentRow(index)
        self.restore_from_tray()

    def restore_from_tray(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def request_quit(self) -> None:
        self._force_quit = True
        self.close()

    def closeEvent(self, event: QCloseEvent) -> None:
        if (
            not self._force_quit
            and self._prefs.close_to_tray
            and self.tray.available
            and not self._quit_started
        ):
            event.ignore()
            self.hide()
            self._log_buffer.append("vpn", "Application minimized to system tray.")
            if not self._prefs.tray_hint_shown:
                self.tray.notify(
                    APP_NAME,
                    "FortiGate VPN Linux GUI is still running in the system tray.",
                )
                self._prefs = DesktopPreferences(
                    always_on_top=self._prefs.always_on_top,
                    close_to_tray=self._prefs.close_to_tray,
                    autostart=self._prefs.autostart,
                    auto_reconnect=self._prefs.auto_reconnect,
                    tray_hint_shown=True,
                )
                save_desktop_preferences(self._settings, self._prefs)
            return
        if self._can_finish_close:
            event.accept()
            super().closeEvent(event)
            return
        event.ignore()
        if self._quit_started:
            return
        self._quit_started = True
        self.statusBar().showMessage("Closing...")
        self._vpn.begin_shutdown(on_complete=self._shutdown_complete.emit)
        self._connection_page.apply_snapshot(self._vpn.snapshot())
        self.tray.apply_snapshot(self._vpn.snapshot())

    def close_finalized(self) -> bool:
        return self._close_finalized

    def _finish_close(self) -> None:
        if self._close_finalized:
            return
        self._close_finalized = True
        self._can_finish_close = True
        if self._tray is not None:
            self._tray.hide()
        app = QApplication.instance()
        if isinstance(app, QApplication):
            app.setQuitOnLastWindowClosed(True)
        self.close()

    def _tray_connect(self) -> None:
        self._vpn.connect(self._connection_page.selected_profile())

    def _tray_reconnect(self) -> None:
        self._vpn.reconnect(self._connection_page.selected_profile())

    def _on_nav_changed(self, index: int) -> None:
        self._stack.setCurrentIndex(index)
        if index == 2:
            self._diagnostics_page.refresh()

    def _on_vpn_snapshot(self, snapshot: VpnSnapshot) -> None:
        self._connection_page.apply_snapshot(snapshot)
        self._profiles_page.apply_snapshot(snapshot)
        if snapshot.manual_reconnect:
            self.statusBar().showMessage("Reconnecting...")
        else:
            self.statusBar().showMessage(state_label(snapshot.state))
        self.tray.apply_snapshot(snapshot)
        self._notify_state(snapshot)

    def _notify_state(self, snapshot: VpnSnapshot) -> None:
        if snapshot.state is self._last_notified_state and not snapshot.reconnect_pending:
            return
        previous = self._last_notified_state
        self._last_notified_state = snapshot.state
        if snapshot.reconnect_pending and previous is ConnectionState.FAILED:
            self.tray.notify(APP_NAME, "Reconnecting in 5 seconds...")
            return
        connected = snapshot.state is ConnectionState.CONNECTED
        if connected and previous is not ConnectionState.CONNECTED:
            if previous is ConnectionState.FAILED:
                self.tray.notify(APP_NAME, "VPN reconnected successfully.")
            else:
                self.tray.notify(APP_NAME, "VPN connected.")
        elif (
            snapshot.state is ConnectionState.FAILED
            and snapshot.error_code is VpnErrorCode.CONNECTION_LOST
            and not snapshot.shutdown_in_progress
        ):
            self.tray.notify(APP_NAME, "VPN connection was lost.")

    def _on_vpn_error(self, event: VpnEvent) -> None:
        if self._quit_started:
            return
        self._connection_page.show_user_error(event)

    def _apply_style(self) -> None:
        self.setStyleSheet(
            """
            QLabel#appHeader {
                font-size: 16px;
                font-weight: 600;
                padding: 14px 16px 8px 16px;
            }
            QListWidget#navList {
                border: none;
                outline: none;
                padding: 8px 0;
                font-size: 14px;
            }
            QListWidget#navList::item {
                padding: 10px 14px;
            }
            QLabel#pageTitle {
                font-size: 20px;
                font-weight: 600;
            }
            QPushButton#connectButton {
                font-size: 16px;
                font-weight: 600;
                min-height: 48px;
                padding: 12px 24px;
            }
            QPushButton#reconnectButton {
                font-size: 14px;
                min-height: 36px;
                padding: 8px 16px;
            }
            QFrame#profileCard {
                border: 1px solid palette(mid);
                border-radius: 6px;
            }
            QLabel#profileCardName {
                font-size: 16px;
                font-weight: 600;
            }
            QLabel#profileDefaultBadge {
                font-weight: 600;
            }
            QLabel#profileConnectFeedback {
                font-weight: 600;
            }
            """
        )
