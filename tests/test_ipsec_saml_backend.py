# SPDX-License-Identifier: GPL-3.0-or-later
"""IPsec SAML pre-auth and IKEv2 handoff tests. Synthetic secrets only."""

from __future__ import annotations

import threading
import time
from pathlib import Path

from fortigate_vpn_gui.profiles.ipsec import AUTH_EAP, IKE_V2, default_ipsec_settings
from fortigate_vpn_gui.profiles.model import build_profile
from fortigate_vpn_gui.vpn.ipsec.forticlient_vid import EAP_LOCAL_PLAN_LOG
from fortigate_vpn_gui.vpn.ipsec.saml_bootstrap import (
    IPSEC_SAML_CONNECT_MESSAGE,
    IPSEC_SAML_HTTP_UNKNOWN_MESSAGE,
    IPSEC_SAML_START_URL_MESSAGE,
    BlockedIpsecSamlHtmlFetcher,
    IpsecSamlConnectError,
    IpsecSamlHttpRejectedError,
    IpsecSamlPreauthSession,
    IpsecSamlStartUrlError,
)
from fortigate_vpn_gui.vpn.ipsec.saml_credentials import IpsecSamlCredentials
from fortigate_vpn_gui.vpn.ipsec.saml_listener import IpsecSamlListenerError
from fortigate_vpn_gui.vpn.ipsec.secrets import IpsecCredentials
from fortigate_vpn_gui.vpn.models import ConnectionState, VpnErrorCode
from tests.test_ipsec_saml_bootstrap import (
    _PROVEN_HTML,
    _ImmediateListener,
    _StaticHtmlFetcher,
)
from tests.vpn_fakes import VpnHarness

_TOKEN = "TEST_ONLY_TOKEN_DO_NOT_USE"
_UID = "0123456789abcdef0123456789abcdef"
_USER = "test-user"
_PSK = "TEST_ONLY_PSK_DO_NOT_USE"


def _sso_psk() -> IpsecCredentials:
    return IpsecCredentials(psk=_PSK, username="", password="")


def _saml_profile():
    return build_profile(
        name="IPsec SAML",
        gateway="vpn.example.com",
        port=500,
        vpn_type="ipsec",
        use_sso=True,
        ipsec={
            **default_ipsec_settings().to_json(),
            "ike_version": IKE_V2,
            "ike_mode": "main",
            "auth_method": AUTH_EAP,
        },
    )


def _wait_state(backend, *states: ConnectionState, timeout: float = 2.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        current = backend.current_state()
        if current in states:
            return backend.snapshot()
        time.sleep(0.02)
    raise AssertionError(f"timed out in {backend.current_state().value}")


def _wait_runtime_secrets(runtime: Path, harness: VpnHarness, timeout: float = 2.0) -> Path:
    secrets = runtime / "secrets.conf"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if secrets.is_file() and harness.helper.is_running():
            return secrets
        time.sleep(0.02)
    snap = harness.backend.snapshot()
    raise AssertionError(f"IKE runtime did not start ({snap.state.value}, {snap.error_code})")


def _joined_logs(harness: VpnHarness) -> str:
    return "\n".join(item.message for item in harness.log.records())


def _assert_secrets_absent(text: str) -> None:
    assert _TOKEN not in text
    assert _UID not in text
    assert _PSK not in text
    assert _USER not in text
    assert "tokenid=" not in text


class _BlockingSession:
    def run(self, profile, *, browser, cancel_event, on_waiting):
        on_waiting("https://vpn.example.com:1001/saml")
        if cancel_event.wait(timeout=5):
            raise IpsecSamlListenerError("IPsec SAML listener was cancelled.")
        raise AssertionError("expected cancellation")


class _SuccessSession:
    def __init__(self) -> None:
        self.credentials = IpsecSamlCredentials(
            username=_USER,
            tokenid=_TOKEN,
            eap_identity=_UID,
        )

    def run(self, profile, *, browser, cancel_event, on_waiting):
        browser.open("https://vpn.example.com:1001/saml?0123456789abcdef")
        on_waiting("https://vpn.example.com:1001/saml")
        return self.credentials


class _MintingSuccessSession:
    """Fresh credentials and a distinct cancel event per Connect attempt."""

    def __init__(self) -> None:
        self.runs = 0
        self.cancel_events: list[threading.Event] = []
        self.credentials: list[IpsecSamlCredentials] = []

    def run(self, profile, *, browser, cancel_event, on_waiting):
        self.runs += 1
        self.cancel_events.append(cancel_event)
        if cancel_event is not None and cancel_event.is_set():
            raise IpsecSamlListenerError("IPsec SAML listener was cancelled.")
        browser.open("https://vpn.example.com:1001/saml?0123456789abcdef")
        on_waiting("https://vpn.example.com:1001/saml")
        credentials = IpsecSamlCredentials(
            username=_USER,
            tokenid=_TOKEN,
            eap_identity=_UID,
        )
        self.credentials.append(credentials)
        return credentials


class _ScriptedSession:
    """Drive Connect → Disconnect → Connect failure modes in one backend."""

    def __init__(self, actions: list[str]) -> None:
        self.actions = list(actions)
        self.runs = 0
        self.cancel_events: list[threading.Event] = []

    def run(self, profile, *, browser, cancel_event, on_waiting):
        self.runs += 1
        self.cancel_events.append(cancel_event)
        action = self.actions.pop(0) if self.actions else "success"
        if action != "block" and cancel_event is not None and cancel_event.is_set():
            raise AssertionError("second Connect reused a cancelled SAML event")
        if action == "block":
            on_waiting("https://vpn.example.com:1001/saml")
            if cancel_event.wait(timeout=5):
                raise IpsecSamlListenerError("IPsec SAML listener was cancelled.")
            raise AssertionError("expected cancellation")
        if action == "connect-error":
            raise IpsecSamlConnectError(IPSEC_SAML_CONNECT_MESSAGE)
        if action == "timeout":
            raise IpsecSamlListenerError("IPsec SAML sign-in timed out.")
        browser.open("https://vpn.example.com:1001/saml?0123456789abcdef")
        on_waiting("https://vpn.example.com:1001/saml")
        return IpsecSamlCredentials(
            username=_USER,
            tokenid=_TOKEN,
            eap_identity=_UID,
        )


def _ike_harness(tmp_path: Path, session) -> tuple[VpnHarness, Path]:
    runtime = tmp_path / "run"
    runtime.mkdir()
    harness = VpnHarness(
        ipsec_available=True,
        runtime_dir_factory=lambda: runtime,
        vici_wait=lambda path, timeout: True,
        ipsec_saml_session=session,
    )
    return harness, runtime


def _start_ike(harness: VpnHarness, runtime: Path) -> None:
    harness.backend.connect(_saml_profile(), credentials=_sso_psk())
    _wait_runtime_secrets(runtime, harness)
    proc = harness.process
    assert proc is not None
    proc.emit("13[IKE] CHILD_SA fortigate{1} established with SPIs c1-c2")
    connected = _wait_state(harness.backend, ConnectionState.CONNECTED)
    assert connected.state is ConnectionState.CONNECTED


def test_sso_without_psk_does_not_start_saml() -> None:
    harness = VpnHarness(ipsec_saml_session=_BlockingSession())
    harness.backend.connect(_saml_profile())
    snapshot = harness.backend.snapshot()
    assert snapshot.error_code is VpnErrorCode.IPSEC_CREDENTIALS_REQUIRED
    assert snapshot.state is not ConnectionState.WAITING_FOR_AUTH
    assert snapshot.state is not ConnectionState.CONNECTED
    assert harness.helper.is_running() is False


def test_http_unknown_does_not_start_helper(tmp_path: Path) -> None:
    session = IpsecSamlPreauthSession(
        fetcher=BlockedIpsecSamlHtmlFetcher(),
        uid_path=tmp_path / "ipsec-saml-uid",
        timeout_seconds=0.4,
    )
    harness = VpnHarness(ipsec_saml_session=session)
    harness.backend.connect(_saml_profile(), credentials=_sso_psk())
    snapshot = _wait_state(harness.backend, ConnectionState.DISCONNECTED)
    assert snapshot.error_code is VpnErrorCode.IPSEC_SAML_HTTP_UNKNOWN
    assert "IMPLEMENTATION BLOCKED AT HTTP BOOTSTRAP DETAIL" in IPSEC_SAML_HTTP_UNKNOWN_MESSAGE
    assert harness.helper.is_running() is False
    assert snapshot.state is not ConnectionState.CONNECTED
    _assert_secrets_absent(_joined_logs(harness))


def test_waiting_for_auth_then_cancel() -> None:
    harness = VpnHarness(ipsec_saml_session=_BlockingSession())
    harness.backend.connect(_saml_profile(), credentials=_sso_psk())
    snapshot = _wait_state(harness.backend, ConnectionState.WAITING_FOR_AUTH)
    assert snapshot.state is ConnectionState.WAITING_FOR_AUTH
    assert harness.helper.is_running() is False
    harness.backend.disconnect()
    idle = _wait_state(harness.backend, ConnectionState.DISCONNECTED)
    assert idle.state is ConnectionState.DISCONNECTED
    assert idle.state is not ConnectionState.CONNECTED
    assert harness.helper.is_running() is False
    _assert_secrets_absent(_joined_logs(harness))


def test_successful_callback_does_not_report_connected_without_child_sa(tmp_path: Path) -> None:
    session = _SuccessSession()
    runtime = tmp_path / "run"
    runtime.mkdir()
    harness = VpnHarness(
        ipsec_available=True,
        runtime_dir_factory=lambda: runtime,
        vici_wait=lambda path, timeout: True,
        ipsec_saml_session=session,
    )
    harness.backend.connect(_saml_profile(), credentials=_sso_psk())
    early = _wait_state(
        harness.backend,
        ConnectionState.WAITING_FOR_AUTH,
        ConnectionState.CONNECTING,
        ConnectionState.CONNECTED,
    )
    if early.state is ConnectionState.WAITING_FOR_AUTH:
        assert early.state is not ConnectionState.CONNECTED
        assert harness.helper.is_running() is False
    _wait_runtime_secrets(runtime, harness)
    joined = _joined_logs(harness)
    assert "IPsec SAML pre-authentication completed." in joined
    assert "Starting private IKEv2 runtime." in joined
    assert "The VPN tunnel is not started in this slice." not in joined
    _assert_secrets_absent(joined)
    assert session.credentials.tokenid == ""
    assert session.credentials.eap_identity == ""
    assert harness.helper.is_running() is True
    harness.backend.disconnect(wait=True)
    _wait_state(harness.backend, ConnectionState.DISCONNECTED)
    assert not runtime.exists()


def test_saml_credentials_are_handed_to_ikev2_runtime(tmp_path: Path) -> None:
    session = _SuccessSession()
    runtime = tmp_path / "run"
    runtime.mkdir()
    harness = VpnHarness(
        ipsec_available=True,
        runtime_dir_factory=lambda: runtime,
        vici_wait=lambda path, timeout: True,
        ipsec_saml_session=session,
    )
    harness.backend.connect(_saml_profile(), credentials=_sso_psk())
    secrets_path = _wait_runtime_secrets(runtime, harness)
    secrets = secrets_path.read_text(encoding="utf-8")
    conf = (runtime / "swanctl.conf").read_text(encoding="utf-8")
    strongswan = (runtime / "strongswan.conf").read_text(encoding="utf-8")
    assert "eap {" in secrets
    assert "ike-psk" in secrets
    assert "xauth-user" not in secrets
    assert f'id = "{_UID}"' in secrets
    assert f'secret = "{_TOKEN}"' in secrets
    assert f'secret = "{_PSK}"' in secrets
    assert _USER not in secrets
    assert "eap-mschapv2" in conf
    assert "local-eap" in conf
    assert "local-psk" not in conf
    assert "remote-psk" in conf
    assert "auth = psk" in conf
    assert conf.count("auth = psk") == 1
    assert f'eap_id = "{_UID}"' in conf
    assert "auth = xauth" not in conf
    assert _USER not in conf
    assert _TOKEN not in conf
    assert _PSK not in conf
    assert "cisco_unity = no" in strongswan
    assert "fvl-forticlient-vid {" in strongswan
    assert "load = yes" in strongswan
    joined = _joined_logs(harness)
    assert "FortiClient compatibility Vendor IDs enabled for private IKEv2 SSO runtime" in joined
    assert "3 Vendor IDs configured for IKE_SA_INIT" in joined
    assert "FortiClient compatibility: first IKE_AUTH will omit EAP_ONLY" in joined
    assert "FortiClient compatibility: first IKE_AUTH will omit MSG_ID_SYN_SUP" in joined
    assert "FortiClient compatibility: first IKE_AUTH will add INITIAL_CONTACT" in joined
    assert "FortiClient compatibility: first IKE_AUTH will omit initiator AUTH" in joined
    assert EAP_LOCAL_PLAN_LOG in joined
    assert "unix:///run/charon.vici" not in strongswan
    assert _TOKEN not in repr(session.credentials)
    assert _UID not in repr(session.credentials)
    proc = harness.process
    assert proc is not None
    assert proc.env is not None
    assert all(_TOKEN not in value for value in proc.env.values())
    assert all(_PSK not in value for value in proc.env.values())
    assert all(_UID not in value for value in proc.env.values())
    proc.emit("13[IKE] initiating IKE_SA fortigate[1] to 1.2.3.4")
    proc.emit("13[IKE] FortiClient compatibility: removed EAP_ONLY from first IKE_AUTH")
    proc.emit("13[IKE] FortiClient compatibility: removed MSG_ID_SYN_SUP from first IKE_AUTH")
    proc.emit("13[IKE] FortiClient compatibility: added INITIAL_CONTACT to first IKE_AUTH")
    proc.emit("13[IKE] FortiClient compatibility: omitted initiator AUTH from first IKE_AUTH")
    proc.emit("13[IKE] EAP method EAP_MSCHAPV2 selected")
    proc.emit("13[IKE] CHILD_SA fortigate{1} established with SPIs c1-c2")
    connected = _wait_state(harness.backend, ConnectionState.CONNECTED)
    assert connected.state is ConnectionState.CONNECTED
    joined = _joined_logs(harness)
    assert "IKE_SA_INIT started." in joined
    assert "FortiClient compatibility: removed EAP_ONLY from first IKE_AUTH" in joined
    assert "FortiClient compatibility: removed MSG_ID_SYN_SUP from first IKE_AUTH" in joined
    assert "FortiClient compatibility: added INITIAL_CONTACT to first IKE_AUTH" in joined
    assert "FortiClient compatibility: omitted initiator AUTH from first IKE_AUTH" in joined
    assert "EAP authentication in progress." in joined
    assert "CHILD_SA established." in joined
    _assert_secrets_absent(joined)
    harness.backend.disconnect(wait=True)
    _wait_state(harness.backend, ConnectionState.DISCONNECTED)
    assert not runtime.exists()


def test_human_username_is_not_eap_identity(tmp_path: Path) -> None:
    session = _SuccessSession()
    runtime = tmp_path / "run"
    runtime.mkdir()
    harness = VpnHarness(
        ipsec_available=True,
        runtime_dir_factory=lambda: runtime,
        vici_wait=lambda path, timeout: True,
        ipsec_saml_session=session,
    )
    harness.backend.connect(_saml_profile(), credentials=_sso_psk())
    secrets_path = _wait_runtime_secrets(runtime, harness)
    secrets = secrets_path.read_text(encoding="utf-8")
    conf = (runtime / "swanctl.conf").read_text(encoding="utf-8")
    assert _USER not in secrets
    assert _USER not in conf
    assert _UID in secrets
    harness.backend.disconnect(wait=True)


def test_cancel_after_saml_during_ike_cleans_runtime(tmp_path: Path) -> None:
    runtime = tmp_path / "run"
    runtime.mkdir()
    harness = VpnHarness(
        ipsec_available=True,
        runtime_dir_factory=lambda: runtime,
        vici_wait=lambda path, timeout: True,
        ipsec_saml_session=_SuccessSession(),
    )
    harness.backend.connect(_saml_profile(), credentials=_sso_psk())
    _wait_runtime_secrets(runtime, harness)
    assert harness.helper.is_running() is True
    harness.backend.disconnect(wait=True)
    idle = _wait_state(harness.backend, ConnectionState.DISCONNECTED)
    assert idle.state is ConnectionState.DISCONNECTED
    assert idle.state is not ConnectionState.CONNECTED
    assert harness.helper.is_running() is False
    assert not runtime.exists()
    _assert_secrets_absent(_joined_logs(harness))


def test_ikev1_path_still_requires_credentials() -> None:
    harness = VpnHarness()
    profile = build_profile(
        name="IPsec",
        gateway="vpn.example.com",
        port=500,
        vpn_type="ipsec",
        ipsec=default_ipsec_settings().to_json(),
    )
    harness.backend.connect(profile)
    snapshot = harness.backend.snapshot()
    assert snapshot.error_code is VpnErrorCode.IPSEC_CREDENTIALS_REQUIRED
    assert snapshot.state is not ConnectionState.WAITING_FOR_AUTH


def test_ikev1_does_not_use_sso() -> None:
    profile = build_profile(
        name="IPsec",
        gateway="vpn.example.com",
        port=500,
        vpn_type="ipsec",
        use_sso=True,
        ipsec=default_ipsec_settings().to_json(),
    )
    assert profile.use_sso is False
    assert profile.is_ipsec_saml_preauth() is False


class _RaiseSession:
    def __init__(self, error: BaseException) -> None:
        self.error = error

    def run(self, profile, *, browser, cancel_event, on_waiting):
        raise self.error


def test_connect_failure_is_distinguishable() -> None:
    harness = VpnHarness(
        ipsec_saml_session=_RaiseSession(IpsecSamlConnectError(IPSEC_SAML_CONNECT_MESSAGE)),
    )
    harness.backend.connect(_saml_profile(), credentials=_sso_psk())
    snapshot = _wait_state(harness.backend, ConnectionState.DISCONNECTED)
    assert snapshot.error_code is VpnErrorCode.IPSEC_SAML_CONNECT_FAILED
    assert snapshot.error_message == IPSEC_SAML_CONNECT_MESSAGE
    assert snapshot.state is not ConnectionState.CONNECTED
    assert harness.helper.is_running() is False


def test_http_reject_reports_status_without_body() -> None:
    error = IpsecSamlHttpRejectedError(403)
    harness = VpnHarness(ipsec_saml_session=_RaiseSession(error))
    harness.backend.connect(_saml_profile(), credentials=_sso_psk())
    snapshot = _wait_state(harness.backend, ConnectionState.DISCONNECTED)
    assert snapshot.error_code is VpnErrorCode.IPSEC_SAML_HTTP_REJECTED
    assert "HTTP 403" in (snapshot.error_message or "")
    _assert_secrets_absent(_joined_logs(harness))
    assert snapshot.state is not ConnectionState.CONNECTED


def test_missing_start_url_is_distinguishable() -> None:
    harness = VpnHarness(
        ipsec_saml_session=_RaiseSession(IpsecSamlStartUrlError(IPSEC_SAML_START_URL_MESSAGE)),
    )
    harness.backend.connect(_saml_profile(), credentials=_sso_psk())
    snapshot = _wait_state(harness.backend, ConnectionState.DISCONNECTED)
    assert snapshot.error_code is VpnErrorCode.SAML_FAILED
    assert snapshot.error_message == IPSEC_SAML_START_URL_MESSAGE
    assert snapshot.state is not ConnectionState.CONNECTED


def test_malformed_callback_does_not_leak_query() -> None:
    harness = VpnHarness(
        ipsec_saml_session=_RaiseSession(
            IpsecSamlListenerError("IPsec SAML callback is missing tokenid.")
        ),
    )
    harness.backend.connect(_saml_profile(), credentials=_sso_psk())
    snapshot = _wait_state(harness.backend, ConnectionState.DISCONNECTED)
    assert snapshot.error_code is VpnErrorCode.SAML_FAILED
    assert snapshot.error_message == "The IPsec SAML callback was incomplete or malformed."
    joined = _joined_logs(harness)
    _assert_secrets_absent(joined)
    assert "tokenid=" not in joined


def test_callback_timeout_uses_ipsec_message() -> None:
    harness = VpnHarness(
        ipsec_saml_session=_RaiseSession(IpsecSamlListenerError("IPsec SAML sign-in timed out.")),
    )
    harness.backend.connect(_saml_profile(), credentials=_sso_psk())
    snapshot = _wait_state(harness.backend, ConnectionState.DISCONNECTED)
    assert snapshot.error_code is VpnErrorCode.SAML_TIMEOUT
    assert "five minutes" in (snapshot.error_message or "")
    assert snapshot.state is not ConnectionState.CONNECTED
    assert harness.helper.is_running() is False


def test_connect_disconnect_connect_creates_fresh_saml_preauth(tmp_path: Path) -> None:
    session = _MintingSuccessSession()
    harness, runtime = _ike_harness(tmp_path, session)
    _start_ike(harness, runtime)
    harness.backend.disconnect(wait=True)
    idle = _wait_state(harness.backend, ConnectionState.DISCONNECTED)
    assert idle.state is ConnectionState.DISCONNECTED
    assert harness.helper.is_running() is False
    _start_ike(harness, runtime)
    assert session.runs == 2
    assert session.cancel_events[0] is not session.cancel_events[1]
    assert session.cancel_events[1].is_set() is False
    assert len(harness.browser.opened) == 2
    _assert_secrets_absent(_joined_logs(harness))
    harness.backend.disconnect(wait=True)


def test_cancelled_saml_then_reconnect_starts_ike(tmp_path: Path) -> None:
    session = _ScriptedSession(["block", "success"])
    harness, runtime = _ike_harness(tmp_path, session)
    harness.backend.connect(_saml_profile(), credentials=_sso_psk())
    _wait_state(harness.backend, ConnectionState.WAITING_FOR_AUTH)
    harness.backend.disconnect(wait=True)
    idle = _wait_state(harness.backend, ConnectionState.DISCONNECTED)
    assert idle.state is ConnectionState.DISCONNECTED
    assert harness.helper.is_running() is False
    _start_ike(harness, runtime)
    assert session.runs == 2
    assert session.cancel_events[0] is not session.cancel_events[1]
    harness.backend.disconnect(wait=True)


def test_failed_saml_bootstrap_then_reconnect_starts_ike(tmp_path: Path) -> None:
    session = _ScriptedSession(["connect-error", "success"])
    harness, runtime = _ike_harness(tmp_path, session)
    harness.backend.connect(_saml_profile(), credentials=_sso_psk())
    failed = _wait_state(harness.backend, ConnectionState.DISCONNECTED)
    assert failed.error_code is VpnErrorCode.IPSEC_SAML_CONNECT_FAILED
    assert harness.helper.is_running() is False
    _start_ike(harness, runtime)
    assert session.runs == 2
    assert session.cancel_events[0] is not session.cancel_events[1]
    harness.backend.disconnect(wait=True)


def test_callback_timeout_then_reconnect_starts_ike(tmp_path: Path) -> None:
    session = _ScriptedSession(["timeout", "success"])
    harness, runtime = _ike_harness(tmp_path, session)
    harness.backend.connect(_saml_profile(), credentials=_sso_psk())
    failed = _wait_state(harness.backend, ConnectionState.DISCONNECTED)
    assert failed.error_code is VpnErrorCode.SAML_TIMEOUT
    assert harness.helper.is_running() is False
    _start_ike(harness, runtime)
    assert session.runs == 2
    assert session.cancel_events[0] is not session.cancel_events[1]
    harness.backend.disconnect(wait=True)


def test_reconnect_real_session_binds_fresh_listener_and_bootstraps(tmp_path: Path) -> None:
    fetcher = _StaticHtmlFetcher(_PROVEN_HTML)
    ports: list[int] = []

    def factory() -> _ImmediateListener:
        listener = _ImmediateListener(timeout_seconds=0.4)
        inner_start = listener.start

        def start() -> str:
            url = inner_start()
            ports.append(listener.port)
            return url

        listener.start = start  # type: ignore[method-assign]
        return listener

    session = IpsecSamlPreauthSession(
        fetcher=fetcher,
        uid_path=tmp_path / "ipsec-saml-uid",
        timeout_seconds=0.4,
        listener_factory=factory,
    )
    harness, runtime = _ike_harness(tmp_path, session)
    _start_ike(harness, runtime)
    harness.backend.disconnect(wait=True)
    _wait_state(harness.backend, ConnectionState.DISCONNECTED)
    _start_ike(harness, runtime)
    assert len(fetcher.calls) == 2
    assert len(ports) == 2
    assert all(port > 0 for port in ports)
    _assert_secrets_absent(_joined_logs(harness))
    harness.backend.disconnect(wait=True)
