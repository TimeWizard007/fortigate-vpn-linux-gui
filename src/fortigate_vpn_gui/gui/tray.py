# SPDX-License-Identifier: GPL-3.0-or-later
"""System tray integration. Falls back to window-only when tray is missing."""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtGui import QAction, QColor, QIcon, QPainter, QPixmap
from PySide6.QtWidgets import QMenu, QSystemTrayIcon, QWidget

from fortigate_vpn_gui.metadata import APP_NAME
from fortigate_vpn_gui.vpn.models import ConnectionState, VpnSnapshot, state_label

TRAY_STILL_RUNNING_MESSAGE = "FortiGate VPN Linux GUI is still running in the system tray."


def tray_tooltip(snapshot: VpnSnapshot) -> str:
    """Short tooltip from the backend snapshot. No secrets."""
    name = APP_NAME
    state = snapshot.state
    profile = snapshot.profile_name
    if snapshot.shutdown_in_progress or state is ConnectionState.CLOSING:
        return f"{name} — Closing..."
    if snapshot.manual_reconnect:
        return f"{name} — Reconnecting..."
    if snapshot.reconnect_pending:
        return f"{name} — Reconnecting ({snapshot.reconnect_attempt} of {snapshot.reconnect_limit})"
    if state is ConnectionState.DISCONNECTED:
        return f"{name} — Disconnected"
    if state is ConnectionState.FAILED:
        return f"{name} — Connection failed"
    if state is ConnectionState.WAITING_FOR_CERTIFICATE_TRUST:
        return f"{name} — Waiting for certificate trust"
    if state in {
        ConnectionState.STARTING,
        ConnectionState.WAITING_FOR_AUTH,
        ConnectionState.CONNECTING,
        ConnectionState.DISCONNECTING,
    }:
        return f"{name} — Connecting..."
    if state is ConnectionState.CONNECTED:
        if profile:
            return f"{name} — Connected — {profile}"
        return f"{name} — Connected"
    return f"{name} — {state_label(state)}"


def tray_action_enabled(snapshot: VpnSnapshot) -> dict[str, bool]:
    """Enable/disable tray actions from the same backend snapshot."""
    closing = snapshot.shutdown_in_progress or snapshot.state is ConnectionState.CLOSING
    reconnecting = snapshot.manual_reconnect or snapshot.reconnect_pending
    connected = snapshot.state is ConnectionState.CONNECTED
    connecting = snapshot.state in {
        ConnectionState.STARTING,
        ConnectionState.CONNECTING,
        ConnectionState.WAITING_FOR_AUTH,
        ConnectionState.WAITING_FOR_CERTIFICATE_TRUST,
        ConnectionState.DISCONNECTING,
    }
    idle = snapshot.state in {ConnectionState.DISCONNECTED, ConnectionState.FAILED}
    return {
        "connect": (not closing) and idle and not reconnecting,
        "disconnect": (not closing) and (connected or connecting or snapshot.reconnect_pending),
        "reconnect": (
            (not closing)
            and (not snapshot.manual_reconnect)
            and (connected or idle)
            and bool(snapshot.profile_id)
        ),
        "quit": True,
    }


def _state_icon(snapshot: VpnSnapshot) -> QIcon:
    color = QColor("#6b7280")
    if snapshot.shutdown_in_progress or snapshot.state is ConnectionState.CLOSING:
        color = QColor("#9ca3af")
    elif snapshot.state is ConnectionState.CONNECTED:
        color = QColor("#16a34a")
    elif snapshot.state is ConnectionState.FAILED:
        color = QColor("#dc2626")
    elif (
        snapshot.state
        in {
            ConnectionState.STARTING,
            ConnectionState.CONNECTING,
            ConnectionState.WAITING_FOR_AUTH,
            ConnectionState.WAITING_FOR_CERTIFICATE_TRUST,
            ConnectionState.DISCONNECTING,
        }
        or snapshot.reconnect_pending
    ):
        color = QColor("#d97706")
    pixmap = QPixmap(16, 16)
    pixmap.fill(QColor(0, 0, 0, 0))
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setBrush(color)
    painter.setPen(color)
    painter.drawEllipse(1, 1, 14, 14)
    painter.end()
    return QIcon(pixmap)


def _disconnected_icon() -> QIcon:
    return _state_icon(
        VpnSnapshot(
            state=ConnectionState.DISCONNECTED,
            profile_id=None,
            profile_name=None,
            error_code=None,
            error_message=None,
            process=None,
        )
    )


class TrayController:
    """One QSystemTrayIcon bound to VpnBackend snapshots."""

    def __init__(
        self,
        parent: QWidget,
        *,
        available: bool | None = None,
        on_show: Callable[[], None] | None = None,
        on_hide: Callable[[], None] | None = None,
        on_connect: Callable[[], None] | None = None,
        on_disconnect: Callable[[], None] | None = None,
        on_reconnect: Callable[[], None] | None = None,
        on_settings: Callable[[], None] | None = None,
        on_about: Callable[[], None] | None = None,
        on_quit: Callable[[], None] | None = None,
        icon: QSystemTrayIcon | None = None,
    ) -> None:
        self._available = (
            QSystemTrayIcon.isSystemTrayAvailable() if available is None else bool(available)
        )
        self._on_show = on_show
        self._on_hide = on_hide
        self._messages: list[tuple[str, str]] = []
        self._visible = False
        self._icon: QSystemTrayIcon | None = None
        self._icon_assigned = False
        self._shown = False
        self._show_without_icon = False
        if not self._available:
            return
        tray = icon if icon is not None else QSystemTrayIcon(parent)
        self._icon = tray
        if tray.icon().isNull():
            tray.setIcon(_disconnected_icon())
        self._icon_assigned = not tray.icon().isNull()
        self._shown = False
        menu = QMenu(parent)
        self._show_action = QAction("Show window", menu)
        self._hide_action = QAction("Hide window", menu)
        self._connect_action = QAction("Connect", menu)
        self._disconnect_action = QAction("Disconnect", menu)
        self._reconnect_action = QAction("Reconnect", menu)
        self._settings_action = QAction("Settings", menu)
        self._about_action = QAction("About", menu)
        self._quit_action = QAction("Quit", menu)
        self._show_action.triggered.connect(lambda: self._on_show and self._on_show())
        self._hide_action.triggered.connect(lambda: self._on_hide and self._on_hide())
        self._connect_action.triggered.connect(lambda: self._on_connect(on_connect))
        self._disconnect_action.triggered.connect(lambda: self._on_disconnect(on_disconnect))
        self._reconnect_action.triggered.connect(lambda: self._on_reconnect(on_reconnect))
        self._settings_action.triggered.connect(lambda: on_settings and on_settings())
        self._about_action.triggered.connect(lambda: on_about and on_about())
        self._quit_action.triggered.connect(lambda: on_quit and on_quit())
        menu.addAction(self._show_action)
        menu.addAction(self._hide_action)
        menu.addSeparator()
        menu.addAction(self._connect_action)
        menu.addAction(self._disconnect_action)
        menu.addAction(self._reconnect_action)
        menu.addSeparator()
        menu.addAction(self._settings_action)
        menu.addAction(self._about_action)
        menu.addSeparator()
        menu.addAction(self._quit_action)
        tray.setContextMenu(menu)
        tray.activated.connect(self._on_activated)
        self._connect_cb = on_connect
        self._disconnect_cb = on_disconnect
        self._reconnect_cb = on_reconnect

    @property
    def available(self) -> bool:
        return self._available

    @property
    def active(self) -> bool:
        return self._available and self._icon is not None and self._visible

    @property
    def messages(self) -> list[tuple[str, str]]:
        return list(self._messages)

    @property
    def icon_assigned(self) -> bool:
        if self._icon is None:
            return False
        return not self._icon.icon().isNull()

    @property
    def shown_before_icon(self) -> bool:
        return self._show_without_icon

    def show(self) -> None:
        if self._icon is None:
            return
        self._show_without_icon = self._icon.icon().isNull()
        if self._show_without_icon:
            self._icon.setIcon(_disconnected_icon())
        self._icon_assigned = not self._icon.icon().isNull()
        self._icon.show()
        self._visible = True
        self._shown = True

    def hide(self) -> None:
        if self._icon is None:
            return
        self._icon.hide()
        self._visible = False

    def dispose(self) -> None:
        """Hide and release the tray icon so it cannot keep Qt's event loop alive."""
        if self._icon is None:
            self._visible = False
            return
        self._icon.hide()
        self._visible = False
        menu = self._icon.contextMenu()
        self._icon.setContextMenu(None)
        if menu is not None:
            menu.deleteLater()
        self._icon.deleteLater()
        self._icon = None

    def apply_snapshot(self, snapshot: VpnSnapshot) -> None:
        if self._icon is None:
            return
        self._icon.setIcon(_state_icon(snapshot))
        self._icon_assigned = not self._icon.icon().isNull()
        self._icon.setToolTip(tray_tooltip(snapshot))
        enabled = tray_action_enabled(snapshot)
        self._connect_action.setEnabled(enabled["connect"])
        self._disconnect_action.setEnabled(enabled["disconnect"])
        self._reconnect_action.setEnabled(enabled["reconnect"])

    def notify(self, title: str, message: str) -> None:
        self._messages.append((title, message))
        if self._icon is None:
            return
        if not QSystemTrayIcon.supportsMessages():
            return
        try:
            self._icon.showMessage(title, message, QSystemTrayIcon.MessageIcon.Information, 4000)
        except Exception:
            return

    def _on_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason == QSystemTrayIcon.ActivationReason.Trigger and self._on_show:
            self._on_show()

    def _on_connect(self, callback: Callable[[], None] | None) -> None:
        if callback is not None:
            callback()

    def _on_disconnect(self, callback: Callable[[], None] | None) -> None:
        if callback is not None:
            callback()

    def _on_reconnect(self, callback: Callable[[], None] | None) -> None:
        if callback is not None:
            callback()
