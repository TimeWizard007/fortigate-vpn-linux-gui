# SPDX-License-Identifier: GPL-3.0-or-later
"""VpnBackend lifecycle tests. The real openfortivpn binary is never started."""

from __future__ import annotations

from fortigate_vpn_gui.profiles.model import build_profile
from fortigate_vpn_gui.vpn.backend import VpnBackend
from fortigate_vpn_gui.vpn.models import ConnectionState, VpnErrorCode
from tests.vpn_fakes import FakeVpnProcess, VpnHarness


def _profile(*, use_sso: bool = False, name: str = "Office"):
    return build_profile(
        name=name,
        gateway="vpn.example.com",
        port=443,
        use_sso=use_sso,
    )


def test_valid_state_transitions_to_connected() -> None:
    harness = VpnHarness()
    harness.backend.connect(_profile())
    assert harness.backend.current_state() is ConnectionState.CONNECTING
    assert harness.process is not None
    assert harness.process.started
    harness.process.emit("INFO: Connected to gateway.")
    assert harness.backend.current_state() is ConnectionState.CONNECTING
    harness.process.emit("INFO:   Tunnel is up and running.")
    assert harness.backend.current_state() is ConnectionState.CONNECTED
    assert harness.backend.is_running() is True
    assert harness.backend.process_info() is not None
    assert harness.backend.process_info().pid == 4242


def test_repeated_connect_is_ignored() -> None:
    harness = VpnHarness()
    harness.backend.connect(_profile())
    first = harness.process
    harness.backend.connect(_profile(name="Other"))
    assert harness.process is first
    assert first is not None
    assert first.argv[1] == "vpn.example.com:443"


def test_disconnect_lifecycle() -> None:
    harness = VpnHarness()
    harness.backend.connect(_profile())
    harness.process.emit("INFO:   Tunnel is up and running.")
    assert harness.backend.current_state() is ConnectionState.CONNECTED
    harness.backend.disconnect(wait=True)
    assert harness.process.terminate_called
    assert harness.backend.current_state() is ConnectionState.DISCONNECTED
    assert harness.backend.is_running() is False


def test_disconnect_when_not_connected() -> None:
    harness = VpnHarness()
    harness.backend.disconnect(wait=True)
    assert harness.backend.current_state() is ConnectionState.DISCONNECTED
    assert harness.process is None


def test_failed_process_startup() -> None:
    harness = VpnHarness()

    def factory(argv, on_output, on_exit):
        proc = FakeVpnProcess(argv, on_output, on_exit)
        proc.raise_on_start = OSError("No such file")
        harness.process = proc
        return proc

    harness.backend = VpnBackend(
        log_buffer=harness.log,
        process_factory=factory,
        locator=lambda: "/usr/bin/openfortivpn",
        selector=harness.selector,
    )
    errors: list[VpnErrorCode] = []
    harness.backend.subscribe(
        lambda event: errors.append(event.error_code) if event.error_code else None
    )
    harness.backend.connect(_profile())
    assert VpnErrorCode.FAILED_TO_START in errors
    assert harness.backend.current_state() is ConnectionState.DISCONNECTED


def test_non_zero_exit() -> None:
    harness = VpnHarness()
    harness.backend.connect(_profile())
    harness.process.finish(1)
    assert harness.backend.current_state() is ConnectionState.FAILED
    assert harness.backend.snapshot().error_code is VpnErrorCode.VPN_PROCESS_FAILED


def test_permission_denied_message() -> None:
    harness = VpnHarness()
    events = []
    harness.backend.subscribe(lambda event: events.append(event))
    harness.backend.connect(_profile())
    harness.process.emit("ERROR: Permission denied")
    harness.process.finish(1)
    assert harness.backend.snapshot().error_code is VpnErrorCode.PERMISSION_DENIED
    assert any(event.error_code is VpnErrorCode.PERMISSION_DENIED for event in events)
    assert "polkit" in (harness.backend.snapshot().error_message or "").lower()


def test_graceful_shutdown() -> None:
    harness = VpnHarness()
    harness.backend.connect(_profile())
    harness.process.emit("INFO:   Tunnel is up and running.")
    harness.backend.shutdown(timeout=0.05)
    assert harness.process.terminate_called
    assert harness.backend.current_state() is ConnectionState.DISCONNECTED


def test_forced_kill_fallback() -> None:
    harness = VpnHarness()
    harness.backend.connect(_profile())
    assert harness.process is not None
    harness.process.exit_on_terminate = False
    harness.backend.disconnect(wait=True, grace_seconds=0.01)
    assert harness.process.terminate_called
    assert harness.process.kill_called
    assert harness.backend.current_state() is ConnectionState.DISCONNECTED


def test_sso_profile_refused_without_saml_binary() -> None:
    harness = VpnHarness(executable="/usr/bin/openfortivpn", version="1.21.0", supports_saml=False)
    codes: list[VpnErrorCode] = []
    harness.backend.subscribe(
        lambda event: codes.append(event.error_code) if event.error_code else None
    )
    harness.backend.connect(_profile(use_sso=True))
    assert harness.process is None
    assert harness.backend.current_state() is ConnectionState.DISCONNECTED
    assert VpnErrorCode.SSO_NOT_SUPPORTED in codes
    assert "does not support SAML/SSO" in (harness.backend.snapshot().error_message or "")


def test_non_sso_profile_not_blocked_without_saml() -> None:
    harness = VpnHarness(executable="/usr/bin/openfortivpn", version="1.21.0", supports_saml=False)
    harness.backend.connect(_profile(use_sso=False))
    assert harness.process is not None
    assert harness.process.argv == [
        "/usr/bin/openfortivpn",
        "vpn.example.com:443",
    ]
    assert "--saml-login" not in harness.process.argv


def test_missing_openfortivpn_does_not_start_process() -> None:
    backend = VpnBackend(
        process_factory=lambda *args: (_ for _ in ()).throw(AssertionError("factory")),
        locator=lambda: None,
        selector=lambda _require_saml: None,
    )
    codes: list[VpnErrorCode] = []
    backend.subscribe(lambda event: codes.append(event.error_code) if event.error_code else None)
    backend.connect(_profile())
    assert VpnErrorCode.OPENFORTIVPN_MISSING in codes
    assert backend.current_state() is ConnectionState.DISCONNECTED


def test_authentication_failure() -> None:
    harness = VpnHarness()
    harness.backend.connect(_profile())
    harness.process.emit("ERROR: Authentication failed")
    harness.process.finish(1)
    assert harness.backend.current_state() is ConnectionState.FAILED
    assert harness.backend.snapshot().error_code is VpnErrorCode.AUTH_FAILURE


def test_failed_disconnect_returns_to_disconnected() -> None:
    harness = VpnHarness()
    harness.backend.connect(_profile())
    harness.process.finish(1)
    assert harness.backend.current_state() is ConnectionState.FAILED
    harness.backend.disconnect(wait=True)
    assert harness.backend.current_state() is ConnectionState.DISCONNECTED


def test_command_recorded_without_secrets() -> None:
    harness = VpnHarness()
    harness.backend.connect(_profile())
    assert harness.process is not None
    assert harness.process.argv[0].endswith("openfortivpn")
    assert "password" not in " ".join(harness.process.argv).lower()
    assert "--trusted-cert" not in harness.process.argv
