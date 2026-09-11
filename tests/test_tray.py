# SPDX-License-Identifier: GPL-3.0-or-later
"""System tray controller tests. No real desktop session required."""

from __future__ import annotations

from PySide6.QtWidgets import QSystemTrayIcon, QWidget

from fortigate_vpn_gui.gui.tray import TrayController, tray_action_enabled, tray_tooltip
from fortigate_vpn_gui.metadata import APP_NAME
from fortigate_vpn_gui.vpn.models import ConnectionState, VpnSnapshot


def _snapshot(**kwargs) -> VpnSnapshot:
    values: dict[str, object] = {
        "state": ConnectionState.DISCONNECTED,
        "profile_id": None,
        "profile_name": None,
        "error_code": None,
        "error_message": None,
        "process": None,
    }
    values.update(kwargs)
    return VpnSnapshot(**values)  # type: ignore[arg-type]


def test_tray_unavailable_fallback(qapp) -> None:
    parent = QWidget()
    tray = TrayController(parent, available=False)
    assert tray.available is False
    assert tray.active is False
    tray.show()
    tray.apply_snapshot(_snapshot())
    tray.notify(APP_NAME, "VPN connected.")
    assert tray.messages == [(APP_NAME, "VPN connected.")]
    assert parent.findChildren(QSystemTrayIcon) == []


def test_tray_created_once_with_icon_before_show(qapp) -> None:
    parent = QWidget()
    tray = TrayController(parent, available=True)
    assert tray.icon_assigned is True
    assert tray.shown_before_icon is False
    tray.show()
    icons = parent.findChildren(QSystemTrayIcon)
    assert len(icons) == 1
    assert icons[0].icon().isNull() is False
    assert tray.shown_before_icon is False
    tray.show()
    assert parent.findChildren(QSystemTrayIcon) == icons
    assert tray.active is True


def test_tray_tooltip_follows_backend_snapshot() -> None:
    assert tray_tooltip(_snapshot()).endswith("Disconnected")
    assert "Connecting..." in tray_tooltip(_snapshot(state=ConnectionState.STARTING))
    assert "Connecting..." in tray_tooltip(_snapshot(state=ConnectionState.WAITING_FOR_AUTH))
    assert "Connecting..." in tray_tooltip(_snapshot(state=ConnectionState.CONNECTING))
    assert "Waiting for certificate trust" in tray_tooltip(
        _snapshot(state=ConnectionState.WAITING_FOR_CERTIFICATE_TRUST)
    )
    assert "Connected — Office" in tray_tooltip(
        _snapshot(state=ConnectionState.CONNECTED, profile_name="Office")
    )
    assert "Connection failed" in tray_tooltip(_snapshot(state=ConnectionState.FAILED))
    assert "Closing..." in tray_tooltip(_snapshot(shutdown_in_progress=True))
    assert tray_tooltip(_snapshot(manual_reconnect=True)).endswith("Reconnecting...")


def test_tray_actions_are_state_aware() -> None:
    idle = tray_action_enabled(_snapshot(profile_id="p1"))
    assert idle["connect"] is True
    assert idle["disconnect"] is False
    assert idle["reconnect"] is True
    connected = tray_action_enabled(
        _snapshot(state=ConnectionState.CONNECTED, profile_id="p1")
    )
    assert connected["connect"] is False
    assert connected["disconnect"] is True
    assert connected["reconnect"] is True
    connecting = tray_action_enabled(_snapshot(state=ConnectionState.CONNECTING))
    assert connecting["connect"] is False
    assert connecting["disconnect"] is True
    closing = tray_action_enabled(_snapshot(state=ConnectionState.CLOSING))
    assert closing["connect"] is False
    assert closing["disconnect"] is False
    reconnecting = tray_action_enabled(
        _snapshot(state=ConnectionState.DISCONNECTING, profile_id="p1", manual_reconnect=True)
    )
    assert reconnecting["connect"] is False
    assert reconnecting["reconnect"] is False


def test_tray_show_hide_and_connect_callbacks(qapp) -> None:
    parent = QWidget()
    calls: list[str] = []
    tray = TrayController(
        parent,
        available=True,
        on_show=lambda: calls.append("show"),
        on_hide=lambda: calls.append("hide"),
        on_connect=lambda: calls.append("connect"),
        on_disconnect=lambda: calls.append("disconnect"),
        on_quit=lambda: calls.append("quit"),
    )
    tray.show()
    tray.hide()
    assert tray.active is False
    tray._show_action.trigger()
    tray._hide_action.trigger()
    tray._connect_action.trigger()
    tray._disconnect_action.trigger()
    tray._quit_action.trigger()
    assert calls == ["show", "hide", "connect", "disconnect", "quit"]


def test_iconless_injected_tray_gets_default_icon_before_show(qapp) -> None:
    parent = QWidget()
    raw = QSystemTrayIcon(parent)
    assert raw.icon().isNull() is True
    tray = TrayController(parent, available=True, icon=raw)
    assert tray.icon_assigned is True
    assert raw.icon().isNull() is False
    tray.show()
    assert tray.shown_before_icon is False
    assert parent.findChildren(QSystemTrayIcon) == [raw]


def test_tray_show_does_not_warn_about_missing_icon(qapp) -> None:
    from PySide6.QtCore import qInstallMessageHandler

    warnings: list[str] = []

    def _capture(_mode, _context, message: str) -> None:
        warnings.append(message)

    parent = QWidget()
    qInstallMessageHandler(_capture)
    try:
        tray = TrayController(parent, available=True)
        tray.show()
        tray.show()
    finally:
        qInstallMessageHandler(None)
    assert tray.icon_assigned is True
    assert not any("No Icon set" in message for message in warnings)
