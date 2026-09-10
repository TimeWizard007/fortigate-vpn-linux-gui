# SPDX-License-Identifier: GPL-3.0-or-later
"""Connection lifecycle, timeout, and logging tests. No real VPN or pkexec."""

from __future__ import annotations

from fortigate_vpn_gui.diagnostics.collector import build_diagnostics_snapshot
from fortigate_vpn_gui.profiles.model import build_profile
from fortigate_vpn_gui.vpn.detect import OpenfortivpnDetection
from fortigate_vpn_gui.vpn.models import ConnectionState, VpnErrorCode
from tests.vpn_fakes import VpnHarness

_AUTH_URL = "https://vpn.example.com:443/remote/saml/start?id=should-not-leak"
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


def _sso_profile(**kwargs):
    values = {"name": "Office", "gateway": "vpn.example.com", "port": 443, "use_sso": True}
    values.update(kwargs)
    return build_profile(**values)


def _vpn_messages(harness: VpnHarness) -> list[str]:
    return [record.message for record in harness.log.records() if record.source == "vpn"]


def _emit_cert(harness: VpnHarness, *, finish: bool = True) -> None:
    assert harness.process is not None
    for line in _CERT_LINES:
        harness.process.emit(line)
    if finish:
        harness.process.finish(1)


def _idle_detect(**kwargs):
    return OpenfortivpnDetection(
        available=True,
        path="/usr/local/bin/openfortivpn",
        version="1.24.1",
        supports_saml=True,
        supports_cookie_stdin=True,
    )


def test_sso_state_machine_path() -> None:
    harness = VpnHarness()
    harness.backend.connect(_sso_profile())
    assert harness.backend.current_state() is ConnectionState.STARTING
    harness.process.emit("INFO:   Listening for SAML login on port 8020")
    harness.process.emit(f"INFO:   Authenticate at '{_AUTH_URL}'")
    assert harness.backend.current_state() is ConnectionState.WAITING_FOR_AUTH
    harness.process.emit("DEBUG:  Incoming HTTP connection")
    assert harness.backend.current_state() is ConnectionState.CONNECTING
    harness.process.emit("INFO:   Connected to gateway.")
    assert harness.backend.current_state() is ConnectionState.CONNECTING
    assert _vpn_messages(harness).count("Connected to gateway.") == 1
    assert "VPN tunnel established." not in _vpn_messages(harness)
    harness.process.emit("INFO:   Authenticated.")
    assert harness.backend.current_state() is ConnectionState.CONNECTING
    harness.process.emit("INFO:   Interface ppp0 is UP.")
    assert harness.backend.current_state() is ConnectionState.CONNECTING
    harness.process.emit(_TUNNEL_READY)
    assert harness.backend.current_state() is ConnectionState.CONNECTED
    assert _vpn_messages(harness).count("VPN tunnel established.") == 1


def test_certificate_retry_state_machine_path() -> None:
    harness = VpnHarness()
    profile = _sso_profile()
    harness.backend.connect(profile)
    _emit_cert(harness, finish=False)
    assert harness.backend.current_state() is ConnectionState.WAITING_FOR_CERTIFICATE_TRUST
    pinned = _sso_profile(trusted_cert_sha256=_DIGEST)
    harness.backend.connect(pinned, after_trust=True)
    assert harness.backend.current_state() is ConnectionState.STARTING
    harness.process.emit(f"INFO:   Authenticate at '{_AUTH_URL}'")
    assert harness.backend.current_state() is ConnectionState.WAITING_FOR_AUTH
    harness.process.emit("DEBUG:  Incoming HTTP connection")
    assert harness.backend.current_state() is ConnectionState.CONNECTING
    harness.process.emit("INFO:   Connected to gateway.")
    assert harness.backend.current_state() is ConnectionState.CONNECTING
    harness.process.emit(_TUNNEL_READY)
    assert harness.backend.current_state() is ConnectionState.CONNECTED


def test_clean_disconnect_path() -> None:
    harness = VpnHarness()
    harness.backend.connect(_sso_profile(use_sso=False))
    harness.process.emit(_TUNNEL_READY)
    assert harness.backend.current_state() is ConnectionState.CONNECTED
    harness.backend.disconnect(wait=True)
    assert harness.backend.current_state() is ConnectionState.DISCONNECTED
    assert _vpn_messages(harness).count("Disconnect requested.") == 1
    assert _vpn_messages(harness).count("VPN disconnected.") == 1


def test_unexpected_loss_path() -> None:
    harness = VpnHarness()
    harness.backend.connect(_sso_profile(use_sso=False))
    harness.process.emit(_TUNNEL_READY)
    harness.process.finish(1)
    snapshot = harness.backend.snapshot()
    assert snapshot.state is ConnectionState.FAILED
    assert snapshot.error_code is VpnErrorCode.CONNECTION_LOST
    assert snapshot.error_message == "VPN connection was lost."
    assert snapshot.privileged_pid is None
    assert "VPN connection lost unexpectedly." in _vpn_messages(harness)
    assert _vpn_messages(harness).count("VPN connection lost unexpectedly.") == 1


def test_repeated_connect_clicks_do_not_start_second_process() -> None:
    harness = VpnHarness()
    harness.backend.connect(_sso_profile())
    first = harness.process
    harness.backend.connect(_sso_profile(name="Other"))
    harness.backend.connect(_sso_profile())
    assert harness.process is first
    assert first is not None
    assert first.poll() is None


def test_connect_during_starting_is_ignored() -> None:
    harness = VpnHarness()
    harness.backend.connect(_sso_profile())
    assert harness.backend.current_state() is ConnectionState.STARTING
    first = harness.process
    harness.backend.connect(_sso_profile())
    assert harness.process is first


def test_connect_during_waiting_for_auth_is_ignored() -> None:
    harness = VpnHarness()
    harness.backend.connect(_sso_profile())
    harness.process.emit(f"INFO:   Authenticate at '{_AUTH_URL}'")
    assert harness.backend.current_state() is ConnectionState.WAITING_FOR_AUTH
    first = harness.process
    harness.backend.connect(_sso_profile())
    assert harness.process is first
    assert first.poll() is None


def test_disconnect_during_starting() -> None:
    harness = VpnHarness()
    harness.backend.connect(_sso_profile())
    assert harness.backend.current_state() is ConnectionState.STARTING
    harness.backend.disconnect(wait=True)
    assert harness.process.terminate_called
    assert harness.backend.current_state() is ConnectionState.DISCONNECTED
    assert harness.backend.is_running() is False


def test_disconnect_during_waiting_for_auth() -> None:
    harness = VpnHarness()
    harness.backend.connect(_sso_profile())
    harness.process.emit(f"INFO:   Authenticate at '{_AUTH_URL}'")
    harness.backend.disconnect(wait=True)
    assert harness.process.terminate_called
    assert harness.backend.current_state() is ConnectionState.DISCONNECTED
    assert harness.scheduler.cancelled is True


def test_disconnect_during_certificate_trust() -> None:
    harness = VpnHarness()
    harness.backend.connect(_sso_profile())
    _emit_cert(harness)
    assert harness.backend.current_state() is ConnectionState.WAITING_FOR_CERTIFICATE_TRUST
    harness.backend.disconnect(wait=True)
    assert harness.backend.current_state() is ConnectionState.FAILED
    assert harness.backend.is_running() is False


def test_disconnect_during_connecting() -> None:
    harness = VpnHarness()
    harness.backend.connect(_sso_profile())
    harness.process.emit(f"INFO:   Authenticate at '{_AUTH_URL}'")
    harness.process.emit("DEBUG:  Incoming HTTP connection")
    assert harness.backend.current_state() is ConnectionState.CONNECTING
    harness.backend.disconnect(wait=True)
    assert harness.process.terminate_called
    assert harness.backend.current_state() is ConnectionState.DISCONNECTED


def test_disconnect_while_connected() -> None:
    harness = VpnHarness()
    harness.backend.connect(_sso_profile(use_sso=False))
    harness.process.emit(_TUNNEL_READY)
    harness.backend.disconnect(wait=True)
    assert harness.backend.current_state() is ConnectionState.DISCONNECTED
    assert harness.backend.is_running() is False


def test_timeout_cancelled_after_auth() -> None:
    harness = VpnHarness()
    harness.backend.connect(_sso_profile())
    harness.process.emit(f"INFO:   Authenticate at '{_AUTH_URL}'")
    assert harness.scheduler.callback is not None
    harness.process.emit("DEBUG:  Incoming HTTP connection")
    assert harness.backend.current_state() is ConnectionState.CONNECTING
    harness.scheduler.fire()
    assert harness.backend.current_state() is ConnectionState.CONNECTING
    assert harness.backend.snapshot().error_code is not VpnErrorCode.SAML_TIMEOUT


def test_timeout_cancelled_on_disconnect() -> None:
    harness = VpnHarness()
    harness.backend.connect(_sso_profile())
    harness.process.emit(f"INFO:   Authenticate at '{_AUTH_URL}'")
    harness.backend.disconnect(wait=True)
    harness.scheduler.fire()
    assert harness.backend.current_state() is ConnectionState.DISCONNECTED
    assert harness.backend.snapshot().error_code is not VpnErrorCode.SAML_TIMEOUT


def test_timeout_cancelled_when_certificate_dialog_is_shown() -> None:
    harness = VpnHarness()
    harness.backend.connect(_sso_profile())
    harness.process.emit(f"INFO:   Authenticate at '{_AUTH_URL}'")
    _emit_cert(harness, finish=False)
    assert harness.backend.current_state() is ConnectionState.WAITING_FOR_CERTIFICATE_TRUST
    harness.scheduler.fire()
    assert harness.backend.current_state() is ConnectionState.WAITING_FOR_CERTIFICATE_TRUST
    assert harness.backend.snapshot().error_code is VpnErrorCode.CERTIFICATE_UNTRUSTED


def test_browser_failure_is_one_error() -> None:
    harness = VpnHarness()
    harness.browser.fail = True
    codes: list[VpnErrorCode] = []
    harness.backend.subscribe(
        lambda event: codes.append(event.error_code) if event.error_code else None
    )
    harness.backend.connect(_sso_profile())
    harness.process.emit(f"INFO:   Authenticate at '{_AUTH_URL}'")
    harness.process.emit(f"INFO:   Authenticate at '{_AUTH_URL}'")
    assert codes.count(VpnErrorCode.BROWSER_FAILED) == 1
    assert harness.browser.opened == []
    assert harness.backend.current_state() is ConnectionState.FAILED


def test_browser_opens_only_once() -> None:
    harness = VpnHarness()
    harness.backend.connect(_sso_profile())
    harness.process.emit(f"INFO:   Authenticate at '{_AUTH_URL}'")
    harness.process.emit(f"INFO:   Authenticate at '{_AUTH_URL}'")
    assert harness.browser.opened == [_AUTH_URL]


def test_raw_openfortivpn_saml_url_is_redacted_in_logs() -> None:
    harness = VpnHarness()
    harness.backend.connect(_sso_profile())
    harness.process.emit(f"INFO:   Authenticate at '{_AUTH_URL}'")
    assert harness.browser.opened == [_AUTH_URL]
    joined = " ".join(record.message for record in harness.log.records())
    assert "should-not-leak" not in joined
    assert "id=" not in joined
    assert "https://vpn.example.com:443/remote/saml/start" in joined


def test_no_duplicate_tunnel_or_disconnect_logs() -> None:
    harness = VpnHarness()
    harness.backend.connect(_sso_profile(use_sso=False))
    harness.process.emit("INFO: Connected to gateway.")
    harness.process.emit("INFO:   Interface ppp0 is UP.")
    assert harness.backend.current_state() is ConnectionState.CONNECTING
    harness.process.emit(_TUNNEL_READY)
    harness.process.emit(_TUNNEL_READY)
    messages = _vpn_messages(harness)
    assert messages.count("VPN tunnel established.") == 1
    assert messages.count("Connected to gateway.") == 1
    assert harness.backend.current_state() is ConnectionState.CONNECTED
    harness.backend.disconnect(wait=True)
    messages = _vpn_messages(harness)
    assert messages.count("Disconnect requested.") == 1
    assert messages.count("VPN disconnected.") == 1


def test_certificate_dedup_resets_on_new_attempt() -> None:
    harness = VpnHarness()
    profile = _sso_profile()
    harness.backend.connect(profile)
    _emit_cert(harness)
    assert _vpn_messages(harness).count("Gateway certificate requires explicit trust.") == 1
    harness.backend.disconnect(wait=True)
    harness.backend.connect(profile)
    _emit_cert(harness)
    assert _vpn_messages(harness).count("Gateway certificate requires explicit trust.") == 2


def test_ppp_route_dns_exit_classification() -> None:
    harness = VpnHarness()
    harness.backend.connect(_sso_profile(use_sso=False))
    harness.process.emit("ERROR: PPP negotiation failed")
    harness.process.finish(1)
    assert harness.backend.snapshot().error_code is VpnErrorCode.PPP_FAILED

    harness = VpnHarness()
    harness.backend.connect(_sso_profile(use_sso=False))
    harness.process.emit("ERROR: Failed to set routes")
    harness.process.finish(1)
    assert harness.backend.snapshot().error_code is VpnErrorCode.ROUTE_FAILED

    harness = VpnHarness()
    harness.backend.connect(_sso_profile(use_sso=False))
    harness.process.emit("ERROR: DNS nameserver update failed")
    harness.process.finish(1)
    assert harness.backend.snapshot().error_code is VpnErrorCode.DNS_FAILED


def test_diagnostics_lifecycle_fields_do_not_leak_secrets() -> None:
    harness = VpnHarness()
    profile = _sso_profile()
    harness.backend.connect(profile)
    harness.process.emit(f"INFO:   Authenticate at '{_AUTH_URL}'")
    data = build_diagnostics_snapshot(
        harness.backend,
        profile,
        "/tmp/profiles.json",
        detect=_idle_detect,
    )
    assert data["connection_state"] == "waiting_for_auth"
    assert data["wait_reason"] == "saml_browser"
    assert data["browser_waiting"] == "Yes"
    assert data["attempt_id"] == "1"
    assert data["retry_count"] == "0"
    assert "should-not-leak" not in str(data.values())
    assert "id=" not in str(data.values())
    _emit_cert(harness)
    data = build_diagnostics_snapshot(
        harness.backend,
        profile,
        "/tmp/profiles.json",
        detect=_idle_detect,
    )
    assert data["connection_state"] == "waiting_for_certificate_trust"
    assert data["wait_reason"] == "certificate_trust"
    assert data["failure_reason"] == "certificate_untrusted"
    assert data["last_failure_reason"] == "certificate_untrusted"
    assert data["browser_waiting"] == "No"
    assert "should-not-leak" not in str(data.values())
