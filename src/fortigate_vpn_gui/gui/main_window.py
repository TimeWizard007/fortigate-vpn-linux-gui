# SPDX-License-Identifier: GPL-3.0-or-later
"""Main application window and navigation."""

from __future__ import annotations

from PySide6.QtCore import QSettings, Qt
from PySide6.QtGui import QCloseEvent, QShowEvent
from PySide6.QtWidgets import (
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
from fortigate_vpn_gui.gui.connection_page import ConnectionPage
from fortigate_vpn_gui.gui.diagnostics_page import DiagnosticsPage
from fortigate_vpn_gui.gui.event_pump import BackendEventPump
from fortigate_vpn_gui.gui.logs_page import LogsPage
from fortigate_vpn_gui.gui.profiles_page import ProfilesPage
from fortigate_vpn_gui.gui.settings_page import SettingsPage
from fortigate_vpn_gui.gui.windowing import (
    apply_always_on_top,
    clear_transient_parent,
    configure_independent_main_window,
)
from fortigate_vpn_gui.profiles.manager import ProfileManager
from fortigate_vpn_gui.vpn.backend import VpnBackend, VpnEvent
from fortigate_vpn_gui.vpn.detect import detect_openfortivpn
from fortigate_vpn_gui.vpn.log_buffer import LogBuffer
from fortigate_vpn_gui.vpn.models import state_label

_NAV_ITEMS: tuple[str, ...] = (
    "Connection",
    "Profiles",
    "Diagnostics",
    "Logs",
    "Settings",
)
_ALWAYS_ON_TOP_KEY = "ui/always_on_top"


class MainWindow(QMainWindow):
    """Primary window: sidebar navigation plus stacked pages."""

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        profile_manager: ProfileManager | None = None,
        vpn_backend: VpnBackend | None = None,
        log_buffer: LogBuffer | None = None,
        detect=detect_openfortivpn,
        settings: QSettings | None = None,
    ) -> None:
        super().__init__(None)
        _ = parent
        self.setWindowTitle(APP_NAME)
        self.setMinimumSize(640, 420)
        self.resize(960, 640)
        self._settings = settings or QSettings(
            "fortigate-vpn-linux-gui",
            "fortigate-vpn-linux-gui",
        )
        self._always_on_top = self._read_always_on_top()
        configure_independent_main_window(self, always_on_top=self._always_on_top)

        self._profile_manager = profile_manager or ProfileManager()
        self._log_buffer = log_buffer if log_buffer is not None else LogBuffer()
        self._vpn = vpn_backend or VpnBackend(log_buffer=self._log_buffer)
        if vpn_backend is not None and log_buffer is None:
            self._log_buffer = vpn_backend.log_buffer

        self._connection_page = ConnectionPage(self._profile_manager, self._vpn)
        self._profiles_page = ProfilesPage(self._profile_manager)
        self._diagnostics_page = DiagnosticsPage(
            self._profile_manager,
            self._vpn,
            self._connection_page.selected_profile,
            detect=detect,
        )
        self._logs_page = LogsPage(self._log_buffer)
        self._settings_page = SettingsPage(
            self._profile_manager,
            always_on_top=self._always_on_top,
            on_always_on_top=self.set_always_on_top,
        )

        self._stack = QStackedWidget()
        self._stack.addWidget(self._connection_page)
        self._stack.addWidget(self._profiles_page)
        self._stack.addWidget(self._diagnostics_page)
        self._stack.addWidget(self._logs_page)
        self._stack.addWidget(self._settings_page)

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
        self._apply_style()

    def _read_always_on_top(self) -> bool:
        value = self._settings.value(_ALWAYS_ON_TOP_KEY, False)
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in {"1", "true", "yes"}
        return bool(value)

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

    def always_on_top(self) -> bool:
        return self._always_on_top

    def set_always_on_top(self, enabled: bool) -> None:
        self._always_on_top = bool(enabled)
        self._settings.setValue(_ALWAYS_ON_TOP_KEY, self._always_on_top)
        apply_always_on_top(self, self._always_on_top)

    def showEvent(self, event: QShowEvent) -> None:  # noqa: N802 — Qt API
        super().showEvent(event)
        clear_transient_parent(self)

    def connection_status(self) -> str:
        return self._connection_page.status_text()

    def closeEvent(self, event: QCloseEvent) -> None:
        self._vpn.shutdown(timeout=5.0)
        super().closeEvent(event)

    def _on_nav_changed(self, index: int) -> None:
        self._stack.setCurrentIndex(index)
        if index == 2:
            self._diagnostics_page.refresh()

    def _on_vpn_snapshot(self, snapshot) -> None:
        self._connection_page.apply_snapshot(snapshot)
        self.statusBar().showMessage(state_label(snapshot.state))

    def _on_vpn_error(self, event: VpnEvent) -> None:
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
            QPushButton#connectButton {
                font-size: 16px;
                font-weight: 600;
                min-height: 48px;
                padding: 12px 24px;
            }
            """
        )
