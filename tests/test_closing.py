# SPDX-License-Identifier: GPL-3.0-or-later
"""Application shutdown / Closing state tests. No real VPN or pkexec."""

from __future__ import annotations

import threading

from PySide6.QtCore import QSettings, Qt, QThread
from PySide6.QtWidgets import QApplication

from fortigate_vpn_gui.gui.main_window import MainWindow
from fortigate_vpn_gui.profiles.manager import ProfileManager
from fortigate_vpn_gui.profiles.model import build_profile
from fortigate_vpn_gui.vpn.detect import OpenfortivpnDetection
from fortigate_vpn_gui.vpn.models import ConnectionState
from tests.vpn_fakes import VpnHarness

_TUNNEL_READY = "INFO:   Tunnel is up and running."
_AUTH_URL = "https://vpn.example.com:443/remote/saml/start?id=should-not-leak"
_DIGEST = "aa" * 32
_CERT_LINES = (
    "ERROR: Gateway certificate validation failed",
    "ERROR:  Gateway certificate:",
    "ERROR:      subject:",
    "ERROR:          /CN=vpn.example.com",
    "ERROR:      issuer:",
    "ERROR:          /C=US/O=Example CA",
    f"ERROR:      sha256 digest: {_DIGEST}",
)


def _profile(**kwargs):
    values = {"name": "Office", "gateway": "vpn.example.com", "port": 443, "use_sso": False}
    values.update(kwargs)
    return build_profile(**values)


def _vpn_messages(harness: VpnHarness) -> list[str]:
    return [record.message for record in harness.log.records() if record.source == "vpn"]


def _no_openfortivpn(**kwargs) -> OpenfortivpnDetection:
    return OpenfortivpnDetection(available=False, path=None, version=None)


def _window(profile_manager, tmp_path, harness, *, tray_available: bool = False) -> MainWindow:
    settings = QSettings(str(tmp_path / "ui.ini"), QSettings.Format.IniFormat)
    return MainWindow(
        profile_manager=profile_manager,
        vpn_backend=harness.backend,
        detect=_no_openfortivpn,
        settings=settings,
        tray_available=tray_available,
    )


def _wait_finalized(qapp, window: MainWindow, *, rounds: int = 40) -> None:
    for _ in range(rounds):
        qapp.processEvents()
        if window.close_finalized():
            return
    raise AssertionError("shutdown completion did not finalize the window")


def test_closing_while_disconnected() -> None:
    harness = VpnHarness()
    completed = []
    harness.backend.begin_shutdown(on_complete=lambda: completed.append(True))
    snapshot = harness.backend.snapshot()
    assert snapshot.state is ConnectionState.CLOSING
    assert snapshot.shutdown_in_progress is True
    assert completed == [True]
    assert "Application closing." in _vpn_messages(harness)
    harness.backend.connect(_profile())
    assert harness.process is None
    assert harness.backend.current_state() is ConnectionState.CLOSING


def test_closing_while_connected() -> None:
    harness = VpnHarness()
    harness.backend.connect(_profile())
    harness.process.emit(_TUNNEL_READY)
    completed = []
    harness.backend.begin_shutdown(on_complete=lambda: completed.append(True))
    assert harness.process.terminate_called
    assert completed == [True]
    assert "Waiting for VPN cleanup before exit." in _vpn_messages(harness)
    assert harness.backend.snapshot().reconnect_pending is False
    assert harness.scheduler.callback is None


def test_closing_while_waiting_for_saml() -> None:
    harness = VpnHarness()
    harness.backend.connect(_profile(use_sso=True))
    harness.process.emit(f"INFO:   Authenticate at '{_AUTH_URL}'")
    assert harness.backend.current_state() is ConnectionState.WAITING_FOR_AUTH
    harness.backend.begin_shutdown()
    assert harness.process.terminate_called
    assert harness.backend.snapshot().state is ConnectionState.CLOSING


def test_closing_while_connecting() -> None:
    harness = VpnHarness()
    harness.backend.connect(_profile())
    assert harness.backend.current_state() is ConnectionState.CONNECTING
    harness.backend.begin_shutdown()
    assert harness.process.terminate_called
    assert harness.backend.snapshot().shutdown_in_progress is True


def test_closing_while_waiting_for_certificate() -> None:
    harness = VpnHarness()
    harness.backend.connect(_profile())
    for line in _CERT_LINES:
        harness.process.emit(line)
    harness.process.finish(1)
    assert harness.backend.current_state() is ConnectionState.WAITING_FOR_CERTIFICATE_TRUST
    harness.backend.begin_shutdown()
    assert harness.backend.snapshot().state is ConnectionState.CLOSING


def test_repeated_begin_shutdown_is_idempotent() -> None:
    harness = VpnHarness()
    harness.backend.connect(_profile())
    harness.process.emit(_TUNNEL_READY)
    first = []
    second = []
    harness.backend.begin_shutdown(on_complete=lambda: first.append(True))
    harness.backend.begin_shutdown(on_complete=lambda: second.append(True))
    assert first == [True]
    assert second == []
    assert _vpn_messages(harness).count("Application closing.") == 1
    assert harness.scheduler.callback is None


def test_shutdown_timeout_fallback() -> None:
    harness = VpnHarness()
    harness.backend.connect(_profile())
    harness.process.emit(_TUNNEL_READY)
    harness.process.exit_on_terminate = False
    completed = []
    harness.backend.begin_shutdown(timeout=0.05, on_complete=lambda: completed.append(True))
    assert harness.process.terminate_called
    assert completed == []
    harness.scheduler.fire()
    assert harness.process.kill_called or harness.process.poll() is not None
    assert completed == [True]
    harness.scheduler.fire()
    assert completed == [True]


def test_exit_after_shutdown_timeout_does_not_complete_twice() -> None:
    harness = VpnHarness()
    harness.backend.connect(_profile())
    harness.process.emit(_TUNNEL_READY)
    harness.process.exit_on_terminate = False
    completed = []
    harness.backend.begin_shutdown(timeout=0.05, on_complete=lambda: completed.append(True))
    harness.scheduler.fire()
    assert completed == [True]
    harness.process.finish(0)
    assert completed == [True]


def test_gui_disconnected_close_reaches_finish_close(
    qapp, profile_manager: ProfileManager, tmp_path
) -> None:
    harness = VpnHarness()
    window = _window(profile_manager, tmp_path, harness)
    window.show()
    qapp.processEvents()
    assert window.close_finalized() is False
    window.close()
    assert window.connection_page.status_text() == "Closing"
    assert window.connection_page.action_text() == "Closing..."
    assert window.close_finalized() is False
    window.close()
    assert window.close_finalized() is False
    _wait_finalized(qapp, window)
    assert window.close_finalized() is True
    assert harness.backend.snapshot().shutdown_in_progress is True


def test_gui_connected_close_follows_exit_to_finish_close(
    qapp, profile_manager: ProfileManager, tmp_path
) -> None:
    harness = VpnHarness()
    profile_manager.add(name="Office", gateway="vpn.example.com", use_sso=False)
    window = _window(profile_manager, tmp_path, harness)
    window.connection_page._on_action_clicked()
    harness.process.emit(_TUNNEL_READY)
    window.connection_page.apply_snapshot(harness.backend.snapshot())
    window.close()
    assert window.connection_page.status_text() == "Closing"
    assert window.connection_page.closing_hint_visible() is True
    assert harness.process.terminate_called
    _wait_finalized(qapp, window)


def test_gui_shutdown_timeout_finalizes_window(
    qapp, profile_manager: ProfileManager, tmp_path
) -> None:
    harness = VpnHarness()
    profile_manager.add(name="Office", gateway="vpn.example.com", use_sso=False)
    window = _window(profile_manager, tmp_path, harness)
    window.connection_page._on_action_clicked()
    harness.process.emit(_TUNNEL_READY)
    harness.process.exit_on_terminate = False
    window.close()
    qapp.processEvents()
    assert window.close_finalized() is False
    assert harness.process.terminate_called
    harness.scheduler.fire()
    _wait_finalized(qapp, window)
    assert harness.process.kill_called or harness.process.poll() is not None


def test_gui_shutdown_completion_from_worker_thread(
    qapp, profile_manager: ProfileManager, tmp_path
) -> None:
    harness = VpnHarness()
    profile_manager.add(name="Office", gateway="vpn.example.com", use_sso=False)
    window = _window(profile_manager, tmp_path, harness)
    slots: list[QThread] = []
    window._shutdown_complete.connect(
        lambda: slots.append(QThread.currentThread()),
        Qt.ConnectionType.QueuedConnection,
    )
    window.connection_page._on_action_clicked()
    harness.process.emit(_TUNNEL_READY)
    harness.process.exit_on_terminate = False
    window.close()
    qapp.processEvents()
    assert window.close_finalized() is False

    worker = threading.Thread(target=harness.process.finish, args=(0,), name="helper-ipc")
    worker.start()
    worker.join()
    assert window.close_finalized() is False
    _wait_finalized(qapp, window)
    assert slots
    assert all(thread is window.thread() for thread in slots)
    assert window.thread() is QApplication.instance().thread()


def test_gui_timeout_from_worker_thread_finalizes_window(
    qapp, profile_manager: ProfileManager, tmp_path
) -> None:
    harness = VpnHarness()
    profile_manager.add(name="Office", gateway="vpn.example.com", use_sso=False)
    window = _window(profile_manager, tmp_path, harness)
    window.connection_page._on_action_clicked()
    harness.process.emit(_TUNNEL_READY)
    harness.process.exit_on_terminate = False
    window.close()
    qapp.processEvents()
    assert window.close_finalized() is False

    worker = threading.Thread(target=harness.scheduler.fire, name="shutdown-timeout")
    worker.start()
    worker.join()
    assert window.close_finalized() is False
    _wait_finalized(qapp, window)


def test_gui_repeated_close_is_one_shutdown(
    qapp, profile_manager: ProfileManager, tmp_path
) -> None:
    harness = VpnHarness()
    profile_manager.add(name="Office", gateway="vpn.example.com", use_sso=False)
    window = _window(profile_manager, tmp_path, harness)
    finishes = []
    window._shutdown_complete.connect(lambda: finishes.append("done"))
    window.connection_page._on_action_clicked()
    harness.process.emit(_TUNNEL_READY)
    window.close()
    window.close()
    window.close()
    _wait_finalized(qapp, window)
    assert _vpn_messages(harness).count("Application closing.") == 1
    assert finishes == ["done"]


def test_gui_tray_quit_uses_same_shutdown_path(
    qapp, profile_manager: ProfileManager, tmp_path
) -> None:
    harness = VpnHarness()
    profile_manager.add(name="Office", gateway="vpn.example.com", use_sso=False)
    window = _window(profile_manager, tmp_path, harness, tray_available=True)
    window.show()
    qapp.processEvents()
    window.connection_page._on_action_clicked()
    harness.process.emit(_TUNNEL_READY)
    window.tray._quit_action.trigger()
    assert window.connection_page.status_text() == "Closing"
    _wait_finalized(qapp, window)
    assert harness.process.terminate_called
    assert window.tray.active is False


def test_close_to_tray_hides_window(
    qapp, profile_manager: ProfileManager, tmp_path
) -> None:
    harness = VpnHarness()
    profile_manager.add(name="Office", gateway="vpn.example.com", use_sso=False)
    settings = QSettings(str(tmp_path / "ui.ini"), QSettings.Format.IniFormat)
    window = MainWindow(
        profile_manager=profile_manager,
        vpn_backend=harness.backend,
        detect=lambda **kwargs: OpenfortivpnDetection(available=False, path=None, version=None),
        settings=settings,
        tray_available=True,
    )
    window.set_close_to_tray(True)
    window.show()
    qapp.processEvents()
    window.connection_page._on_action_clicked()
    harness.process.emit(_TUNNEL_READY)
    window.close()
    qapp.processEvents()
    assert window.isHidden()
    assert harness.backend.current_state() is ConnectionState.CONNECTED
    assert any("still running in the system tray" in message for _, message in window.tray.messages)
    window.request_quit()
    _wait_finalized(qapp, window)
    assert harness.process.terminate_called
