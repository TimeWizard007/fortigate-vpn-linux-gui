# SPDX-License-Identifier: GPL-3.0-or-later
"""SAML/SSO backend tests. No real VPN, browser, or network."""

from __future__ import annotations

from fortigate_vpn_gui.profiles.model import build_profile
from fortigate_vpn_gui.vpn.models import ConnectionState, VpnErrorCode
from tests.vpn_fakes import VpnHarness

_AUTH_URL = "https://vpn.example.com:443/remote/saml/start?redirect=1"


def _sso_profile(**kwargs):
    values = {"name": "Office", "gateway": "vpn.example.com", "port": 443, "use_sso": True}
    values.update(kwargs)
    return build_profile(**values)


def test_sso_argv_includes_saml_login_without_secrets() -> None:
    harness = VpnHarness()
    harness.backend.connect(_sso_profile())
    assert harness.process is not None
    assert harness.process.argv == [
        "/usr/local/bin/openfortivpn",
        "vpn.example.com:443",
        "--saml-login",
    ]
    joined = " ".join(harness.process.argv).lower()
    assert "password" not in joined
    assert "cookie" not in joined
    assert "token" not in joined
    assert "--trusted-cert" not in harness.process.argv


def test_sso_state_flow_to_connected() -> None:
    harness = VpnHarness()
    harness.backend.connect(_sso_profile())
    assert harness.backend.current_state() is ConnectionState.STARTING
    harness.process.emit("INFO:   Listening for SAML login on port 8020")
    harness.process.emit(f"INFO:   Authenticate at '{_AUTH_URL}'")
    assert harness.backend.current_state() is ConnectionState.WAITING_FOR_AUTH
    assert harness.browser.opened == [_AUTH_URL]
    harness.process.emit(f"INFO:   Authenticate at '{_AUTH_URL}'")
    assert harness.browser.opened == [_AUTH_URL]
    harness.process.emit("DEBUG:  Incoming HTTP connection")
    assert harness.backend.current_state() is ConnectionState.CONNECTING
    harness.process.emit("INFO:   Connected to gateway.")
    assert harness.backend.current_state() is ConnectionState.CONNECTED


def test_cancel_during_auth() -> None:
    harness = VpnHarness()
    harness.backend.connect(_sso_profile())
    harness.process.emit(f"INFO:   Authenticate at '{_AUTH_URL}'")
    assert harness.backend.current_state() is ConnectionState.WAITING_FOR_AUTH
    harness.backend.disconnect(wait=True)
    assert harness.process.terminate_called
    assert harness.backend.current_state() is ConnectionState.DISCONNECTED


def test_saml_auth_failure() -> None:
    harness = VpnHarness()
    harness.backend.connect(_sso_profile())
    harness.process.emit(f"INFO:   Authenticate at '{_AUTH_URL}'")
    harness.process.emit("ERROR:  Finally failed to retrieve SAML authentication token")
    assert harness.backend.current_state() is ConnectionState.FAILED
    assert harness.backend.snapshot().error_code is VpnErrorCode.SAML_FAILED


def test_saml_timeout_does_not_wait_in_real_time() -> None:
    harness = VpnHarness()
    harness.backend.connect(_sso_profile())
    harness.process.emit(f"INFO:   Authenticate at '{_AUTH_URL}'")
    assert harness.scheduler.delay == 120.0
    harness.process.exit_on_terminate = False
    harness.scheduler.fire()
    assert harness.backend.current_state() is ConnectionState.FAILED
    assert harness.backend.snapshot().error_code is VpnErrorCode.SAML_TIMEOUT
    assert harness.process.terminate_called


def test_browser_failure() -> None:
    harness = VpnHarness()
    harness.browser.fail = True
    harness.backend.connect(_sso_profile())
    harness.process.emit(f"INFO:   Authenticate at '{_AUTH_URL}'")
    assert harness.backend.current_state() is ConnectionState.FAILED
    assert harness.backend.snapshot().error_code is VpnErrorCode.BROWSER_FAILED


def test_sso_without_saml_binary() -> None:
    harness = VpnHarness(executable="/usr/bin/openfortivpn", version="1.21.0", supports_saml=False)
    codes: list[VpnErrorCode] = []
    harness.backend.subscribe(
        lambda event: codes.append(event.error_code) if event.error_code else None
    )
    harness.backend.connect(_sso_profile())
    assert harness.process is None
    assert VpnErrorCode.SSO_NOT_SUPPORTED in codes
    assert "SAML/SSO requires openfortivpn with --saml-login support." in (
        harness.backend.snapshot().error_message or ""
    )
