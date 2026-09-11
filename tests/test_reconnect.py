# SPDX-License-Identifier: GPL-3.0-or-later
"""Manual and automatic reconnect tests. No real VPN, pkexec, or browser."""

from __future__ import annotations

from fortigate_vpn_gui.profiles.model import build_profile
from fortigate_vpn_gui.vpn.models import ConnectionState, VpnErrorCode
from tests.vpn_fakes import VpnHarness

_TUNNEL_READY = "INFO:   Tunnel is up and running."
_DIGEST = "aa" * 32
_FAIL = "ERROR: Gateway certificate validation failed"
_CERT_LINES = (
    _FAIL,
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


def test_auto_reconnect_disabled_by_default() -> None:
    harness = VpnHarness()
    snapshot = harness.backend.snapshot()
    assert snapshot.auto_reconnect_enabled is False
    harness.backend.connect(_profile())
    harness.process.emit(_TUNNEL_READY)
    harness.process.finish(1)
    assert harness.backend.snapshot().reconnect_pending is False
    assert "Automatic reconnect scheduled in 5 seconds." not in _vpn_messages(harness)


def test_unexpected_loss_schedules_auto_reconnect() -> None:
    harness = VpnHarness()
    harness.backend.set_auto_reconnect(True)
    harness.backend.connect(_profile())
    harness.process.emit(_TUNNEL_READY)
    first = harness.process
    harness.process.finish(1)
    snapshot = harness.backend.snapshot()
    assert snapshot.state is ConnectionState.FAILED
    assert snapshot.error_code is VpnErrorCode.CONNECTION_LOST
    assert snapshot.reconnect_pending is True
    assert snapshot.reconnect_attempt == 1
    assert snapshot.reconnect_limit == 3
    assert harness.scheduler.delay == 5.0
    messages = _vpn_messages(harness)
    assert "VPN connection lost." in messages
    assert "Automatic reconnect scheduled in 5 seconds." in messages
    assert "Reconnect attempt 1 of 3." in messages
    harness.scheduler.fire()
    assert harness.process is not first
    harness.process.emit(_TUNNEL_READY)
    assert harness.backend.current_state() is ConnectionState.CONNECTED
    assert harness.backend.snapshot().reconnect_attempt == 0
    assert "VPN reconnected successfully." in _vpn_messages(harness)


def test_explicit_disconnect_does_not_reconnect() -> None:
    harness = VpnHarness()
    harness.backend.set_auto_reconnect(True)
    harness.backend.connect(_profile())
    harness.process.emit(_TUNNEL_READY)
    harness.backend.disconnect(wait=True)
    assert harness.backend.current_state() is ConnectionState.DISCONNECTED
    assert harness.backend.snapshot().reconnect_pending is False
    assert "Automatic reconnect scheduled in 5 seconds." not in _vpn_messages(harness)


def test_shutdown_does_not_reconnect() -> None:
    harness = VpnHarness()
    harness.backend.set_auto_reconnect(True)
    harness.backend.connect(_profile())
    harness.process.emit(_TUNNEL_READY)
    harness.backend.begin_shutdown()
    assert harness.backend.snapshot().shutdown_in_progress is True
    assert harness.backend.snapshot().reconnect_pending is False
    assert "Automatic reconnect scheduled in 5 seconds." not in _vpn_messages(harness)


def test_certificate_rejection_does_not_reconnect() -> None:
    harness = VpnHarness()
    harness.backend.set_auto_reconnect(True)
    harness.backend.connect(_profile())
    for line in _CERT_LINES:
        harness.process.emit(line)
    harness.process.finish(1)
    assert harness.backend.current_state() is ConnectionState.WAITING_FOR_CERTIFICATE_TRUST
    harness.backend.disconnect(wait=True)
    assert harness.backend.snapshot().reconnect_pending is False
    assert "Automatic reconnect scheduled in 5 seconds." not in _vpn_messages(harness)


def test_retry_limit_stops_after_three_schedules() -> None:
    harness = VpnHarness()
    harness.backend.set_auto_reconnect(True)
    harness.backend.connect(_profile())
    harness.process.emit(_TUNNEL_READY)
    harness.process.finish(1)
    assert harness.backend.snapshot().reconnect_attempt == 1
    harness.backend._cancel_reconnect(user_cancel=False)
    harness.backend._maybe_schedule_reconnect()
    assert harness.backend.snapshot().reconnect_attempt == 2
    harness.backend._cancel_reconnect(user_cancel=False)
    harness.backend._maybe_schedule_reconnect()
    assert harness.backend.snapshot().reconnect_attempt == 3
    harness.backend._cancel_reconnect(user_cancel=False)
    harness.backend._maybe_schedule_reconnect()
    assert "Automatic reconnect stopped after 3 attempts." in _vpn_messages(harness)
    assert harness.backend.snapshot().reconnect_pending is False


def test_retry_counter_resets_after_successful_reconnect() -> None:
    harness = VpnHarness()
    harness.backend.set_auto_reconnect(True)
    harness.backend.connect(_profile())
    harness.process.emit(_TUNNEL_READY)
    harness.process.finish(1)
    assert harness.backend.snapshot().reconnect_attempt == 1
    harness.scheduler.fire()
    harness.process.emit(_TUNNEL_READY)
    assert harness.backend.snapshot().reconnect_attempt == 0
    harness.process.finish(1)
    assert harness.backend.snapshot().reconnect_attempt == 1


def test_user_can_cancel_pending_reconnect() -> None:
    harness = VpnHarness()
    harness.backend.set_auto_reconnect(True)
    harness.backend.connect(_profile())
    harness.process.emit(_TUNNEL_READY)
    harness.process.finish(1)
    assert harness.backend.snapshot().reconnect_pending is True
    harness.backend.disconnect()
    assert harness.backend.snapshot().reconnect_pending is False
    assert "Automatic reconnect cancelled." in _vpn_messages(harness)
    harness.scheduler.fire()
    assert harness.backend.current_state() is not ConnectionState.STARTING


def test_manual_reconnect_uses_same_profile_without_overlap() -> None:
    harness = VpnHarness()
    profile = _profile(trusted_cert_sha256=_DIGEST)
    harness.backend.connect(profile)
    harness.process.emit(_TUNNEL_READY)
    first = harness.process
    harness.backend.reconnect(profile)
    assert first.terminate_called
    assert first.poll() is not None
    second = harness.process
    assert second is not first
    assert second.poll() is None
    assert "--trusted-cert" in second.argv
    assert _DIGEST in second.argv
    harness.process.emit(_TUNNEL_READY)
    assert harness.backend.current_state() is ConnectionState.CONNECTED
    assert "Reconnect requested." in _vpn_messages(harness)
    assert "Disconnecting current VPN session for reconnect." in _vpn_messages(harness)
    assert "Previous VPN session stopped." in _vpn_messages(harness)
    assert _vpn_messages(harness).count("Starting VPN reconnection.") == 1
    assert _vpn_messages(harness).count("Starting VPN connection.") == 1
    assert "Disconnect requested." not in _vpn_messages(harness)
    assert "VPN disconnected." not in _vpn_messages(harness)
    assert "VPN reconnected successfully." in _vpn_messages(harness)


def test_manual_reconnect_waits_for_previous_process_exit() -> None:
    harness = VpnHarness()
    profile = _profile()
    harness.backend.connect(profile)
    harness.process.emit(_TUNNEL_READY)
    first = harness.process
    first.exit_on_terminate = False
    harness.backend.reconnect(profile)
    assert first.terminate_called
    assert harness.process is first
    assert first.poll() is None
    assert harness.backend.snapshot().manual_reconnect is True
    assert harness.backend.current_state() is ConnectionState.DISCONNECTING
    first.finish(0)
    second = harness.process
    assert second is not first
    assert second.poll() is None
    assert harness.backend.current_state() is ConnectionState.CONNECTING
    assert "Previous VPN session stopped." in _vpn_messages(harness)
    assert "Starting VPN reconnection." in _vpn_messages(harness)


def test_manual_reconnect_ignores_duplicate_requests() -> None:
    harness = VpnHarness()
    profile = _profile()
    harness.backend.connect(profile)
    harness.process.emit(_TUNNEL_READY)
    first = harness.process
    first.exit_on_terminate = False
    harness.backend.reconnect(profile)
    harness.backend.reconnect(profile)
    harness.backend.reconnect(profile)
    assert _vpn_messages(harness).count("Reconnect requested.") == 1
    assert harness.process is first
    first.finish(0)
    assert harness.process is not first
    assert _vpn_messages(harness).count("Starting VPN reconnection.") == 1


def test_manual_reconnect_saml_reuses_connect_workflow() -> None:
    harness = VpnHarness()
    profile = _profile(use_sso=True)
    harness.backend.connect(profile)
    harness.process.emit("INFO:   Authenticate at 'https://vpn.example.com:443/remote/saml/start'")
    harness.process.emit("DEBUG:  Incoming HTTP connection")
    harness.process.emit(_TUNNEL_READY)
    assert harness.backend.current_state() is ConnectionState.CONNECTED
    first = harness.process
    first.exit_on_terminate = False
    harness.backend.reconnect(profile)
    first.finish(0)
    assert harness.process is not first
    harness.process.emit("INFO:   Authenticate at 'https://vpn.example.com:443/remote/saml/start'")
    assert harness.backend.current_state() is ConnectionState.WAITING_FOR_AUTH
    assert harness.browser.opened
    harness.process.emit("DEBUG:  Incoming HTTP connection")
    harness.process.emit(_TUNNEL_READY)
    assert harness.backend.current_state() is ConnectionState.CONNECTED
    assert "VPN reconnected successfully." in _vpn_messages(harness)


def test_manual_reconnect_logs_error_when_new_session_fails() -> None:
    harness = VpnHarness()
    profile = _profile()
    harness.backend.connect(profile)
    harness.process.emit(_TUNNEL_READY)
    first = harness.process
    first.exit_on_terminate = False
    harness.helper._denied = True
    harness.backend.reconnect(profile)
    first.finish(0)
    assert harness.backend.current_state() is ConnectionState.DISCONNECTED
    assert "Reconnect failed to start a new VPN session." in _vpn_messages(harness)
    assert harness.backend.snapshot().manual_reconnect is False
    assert harness.backend.snapshot().error_code is VpnErrorCode.PRIVILEGE_DENIED


def test_certificate_trust_still_required_on_reconnect() -> None:
    harness = VpnHarness()
    harness.backend.set_auto_reconnect(True)
    harness.backend.connect(_profile())
    harness.process.emit(_TUNNEL_READY)
    harness.process.finish(1)
    harness.scheduler.fire()
    for line in _CERT_LINES:
        harness.process.emit(line)
    harness.process.finish(1)
    assert harness.backend.current_state() is ConnectionState.WAITING_FOR_CERTIFICATE_TRUST
    assert harness.backend.snapshot().reconnect_pending is False
