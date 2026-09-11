# SPDX-License-Identifier: GPL-3.0-or-later
"""Connection page VPN wiring tests. No real VPN or network."""

from __future__ import annotations

from fortigate_vpn_gui.gui.connection_page import ConnectionPage
from fortigate_vpn_gui.profiles.manager import ProfileManager
from fortigate_vpn_gui.vpn.backend import VpnEvent
from fortigate_vpn_gui.vpn.models import VpnErrorCode
from tests.vpn_fakes import VpnHarness

_AUTH_URL = "https://vpn.example.com:443/remote/saml/start?redirect=1"
_FAIL = "ERROR: Gateway certificate validation failed"


def test_connection_page_without_profiles(qapp, profile_manager: ProfileManager) -> None:
    harness = VpnHarness()
    page = ConnectionPage(profile_manager, harness.backend, locator=lambda: "/usr/bin/openfortivpn")
    assert page.status_text() == "Disconnected"
    assert page.gateway_text() == "Not configured"
    assert page.connect_enabled() is False
    assert page.empty_hint_visible() is True
    assert page.selected_profile() is None


def test_connection_page_with_sso_profile(qapp, profile_manager: ProfileManager) -> None:
    profile_manager.add(name="Office", gateway="vpn.example.com", port=8443, use_sso=True)
    harness = VpnHarness()
    page = ConnectionPage(
        profile_manager, harness.backend, locator=lambda: "/usr/local/bin/openfortivpn"
    )
    assert page.connect_enabled() is True
    assert page.action_text() == "Connect with SSO"
    assert page.sso_text() == "SAML / SSO"
    page._on_action_clicked()
    page.apply_snapshot(harness.backend.snapshot())
    assert harness.process is not None
    assert page.action_text() == "Starting..."
    harness.process.emit(f"INFO:   Authenticate at '{_AUTH_URL}'")
    page.apply_snapshot(harness.backend.snapshot())
    assert page.action_text() == "Cancel"
    assert page.sso_hint_visible() is True
    assert "Complete sign-in" in page._sso_hint.text()
    harness.process.emit("DEBUG:  Incoming HTTP connection")
    harness.process.emit("INFO:   Connected to gateway.")
    page.apply_snapshot(harness.backend.snapshot())
    assert page.action_text() == "Cancel"
    assert page.status_text() == "Connecting"
    harness.process.emit("INFO:   Tunnel is up and running.")
    page.apply_snapshot(harness.backend.snapshot())
    assert page.action_text() == "Disconnect"
    assert page.status_text() == "Connected"
    assert page.reconnect_button_visible() is True


def test_connection_page_sso_notice_is_short(qapp, profile_manager: ProfileManager) -> None:
    profile_manager.add(name="Office", gateway="vpn.example.com", use_sso=True)
    harness = VpnHarness()
    page = ConnectionPage(
        profile_manager, harness.backend, locator=lambda: "/usr/local/bin/openfortivpn"
    )
    assert "web browser" in page.notice_text()
    assert "About" in page.notice_text()
    assert "--saml-login" not in page.notice_text()
    assert "polkit" not in page.notice_text()


def test_connection_page_failed_state_is_usable(qapp, profile_manager: ProfileManager) -> None:
    profile_manager.add(name="Office", gateway="vpn.example.com", use_sso=False)
    harness = VpnHarness()
    page = ConnectionPage(profile_manager, harness.backend, locator=lambda: "/usr/bin/openfortivpn")
    page._on_action_clicked()
    harness.process.emit("INFO:   Tunnel is up and running.")
    harness.process.finish(1)
    page.apply_snapshot(harness.backend.snapshot())
    assert page.status_text() == "Failed"
    assert page.action_text() == "Connect again"
    assert page.connect_enabled() is True
    assert page.reconnect_button_visible() is False
    assert page.failure_hint_visible() is True
    assert "lost" in page.failure_hint_text().lower()


def test_connection_page_saml_unsupported_message(qapp, profile_manager: ProfileManager) -> None:
    profile_manager.add(name="Office", gateway="vpn.example.com", use_sso=True)
    harness = VpnHarness(executable="/usr/bin/openfortivpn", version="1.21.0", supports_saml=False)
    page = ConnectionPage(profile_manager, harness.backend, locator=lambda: "/usr/bin/openfortivpn")
    page._on_action_clicked()
    assert harness.process is None
    event = VpnEvent(
        "error",
        harness.backend.snapshot(),
        error_code=VpnErrorCode.SSO_NOT_SUPPORTED,
        error_message=harness.backend.snapshot().error_message,
    )
    assert event.error_message is not None
    assert "does not support SAML/SSO" in event.error_message
    assert "1.21.0" in event.error_message
    assert "SAML-capable openfortivpn" in event.error_message


def test_connection_page_connect_disconnect_states(qapp, profile_manager: ProfileManager) -> None:
    profile_manager.add(name="Office", gateway="vpn.example.com", use_sso=False)
    harness = VpnHarness()
    page = ConnectionPage(profile_manager, harness.backend, locator=lambda: "/usr/bin/openfortivpn")
    assert page.action_text() == "Connect"
    page._on_action_clicked()
    page.apply_snapshot(harness.backend.snapshot())
    assert page.action_text() == "Cancel"
    assert page.connect_enabled() is True
    assert page.status_text() == "Connecting"
    harness.process.emit("INFO:   Tunnel is up and running.")
    page.apply_snapshot(harness.backend.snapshot())
    assert page.status_text() == "Connected"
    assert page.action_text() == "Disconnect"
    harness.process.exit_on_terminate = False
    page._on_action_clicked()
    page.apply_snapshot(harness.backend.snapshot())
    assert page.action_text() == "Disconnecting..."
    assert page.connect_enabled() is False
    assert harness.process.terminate_called


def test_connection_page_missing_openfortivpn(qapp, profile_manager: ProfileManager) -> None:
    profile_manager.add(name="Office", gateway="vpn.example.com", use_sso=False)
    harness = VpnHarness()
    page = ConnectionPage(profile_manager, harness.backend, locator=lambda: None)
    assert page.missing_openfortivpn_visible() is True
    assert "openfortivpn" in page._missing_hint.text()


def test_connection_page_refreshes_when_profile_added(
    qapp, profile_manager: ProfileManager
) -> None:
    harness = VpnHarness()
    page = ConnectionPage(profile_manager, harness.backend, locator=lambda: "/usr/bin/openfortivpn")
    assert page.connect_enabled() is False
    profile_manager.add(name="Office", gateway="vpn.example.com", use_sso=False)
    assert page.connect_enabled() is True
    assert page.gateway_text() == "vpn.example.com"
    assert page.status_text() == "Disconnected"
    assert page.action_text() == "Connect"


def test_connection_page_authorization_denied(qapp, profile_manager: ProfileManager) -> None:
    profile_manager.add(name="Office", gateway="vpn.example.com", use_sso=True)
    harness = VpnHarness(privilege_denied=True)
    page = ConnectionPage(
        profile_manager, harness.backend, locator=lambda: "/usr/local/bin/openfortivpn"
    )
    page._on_action_clicked()
    assert harness.process is None
    snapshot = harness.backend.snapshot()
    assert snapshot.error_code is VpnErrorCode.PRIVILEGE_DENIED
    assert "denied" in (snapshot.error_message or "").lower()


def test_connection_page_trust_saves_and_retries(qapp, profile_manager: ProfileManager) -> None:
    digest = "aa" * 32
    profile = profile_manager.add(name="Office", gateway="vpn.example.com", use_sso=True)
    harness = VpnHarness()
    prompts: list[dict] = []

    def prompt(**kwargs) -> bool:
        prompts.append(kwargs)
        return True

    page = ConnectionPage(
        profile_manager,
        harness.backend,
        locator=lambda: "/usr/local/bin/openfortivpn",
        trust_prompt=prompt,
    )
    page._on_action_clicked()
    assert harness.process is not None
    harness.process.emit(_FAIL)
    harness.process.emit("ERROR:      subject: /CN=vpn.example.com")
    harness.process.emit("ERROR:      issuer: /C=US/O=Example")
    harness.process.emit(f"ERROR:      sha256 digest: {digest}")
    harness.process.finish(1)
    event = VpnEvent(
        "error",
        harness.backend.snapshot(),
        error_code=harness.backend.snapshot().error_code,
        error_message=harness.backend.snapshot().error_message,
        certificate=harness.backend.snapshot().presented_certificate,
    )
    page.show_user_error(event)
    assert prompts and prompts[0]["changed"] is False
    updated = profile_manager.get(profile.id)
    assert updated is not None
    assert updated.trusted_cert_sha256 == digest
    assert harness.process is not None
    assert "--trusted-cert" in harness.process.argv
    assert digest in harness.process.argv


def test_connection_page_trust_cancel_does_not_save(
    qapp, profile_manager: ProfileManager
) -> None:
    digest = "aa" * 32
    profile = profile_manager.add(name="Office", gateway="vpn.example.com", use_sso=True)
    harness = VpnHarness()
    page = ConnectionPage(
        profile_manager,
        harness.backend,
        locator=lambda: "/usr/local/bin/openfortivpn",
        trust_prompt=lambda **kwargs: False,
    )
    page._on_action_clicked()
    harness.process.emit(_FAIL)
    harness.process.emit("ERROR:      subject: /CN=vpn.example.com")
    harness.process.emit("ERROR:      issuer: /C=US/O=Example")
    harness.process.emit(f"ERROR:      sha256 digest: {digest}")
    harness.process.finish(1)
    page.show_user_error(
        VpnEvent(
            "error",
            harness.backend.snapshot(),
            error_code=VpnErrorCode.CERTIFICATE_UNTRUSTED,
            error_message=harness.backend.snapshot().error_message,
            certificate=harness.backend.snapshot().presented_certificate,
        )
    )
    assert profile_manager.get(profile.id).trusted_cert_sha256 is None
    assert page.last_trust_decision() is False


def test_connection_page_changed_cert_dialog(qapp, profile_manager: ProfileManager) -> None:
    old = "aa" * 32
    new = "bb" * 32
    profile_manager.add(
        name="Office",
        gateway="vpn.example.com",
        use_sso=True,
        trusted_cert_sha256=old,
    )
    seen: list[bool] = []
    harness = VpnHarness()
    page = ConnectionPage(
        profile_manager,
        harness.backend,
        locator=lambda: "/usr/local/bin/openfortivpn",
        trust_prompt=lambda **kwargs: seen.append(kwargs["changed"]) or False,
    )
    page._on_action_clicked()
    harness.process.emit(_FAIL)
    harness.process.emit("ERROR:      subject: /CN=vpn.example.com")
    harness.process.emit("ERROR:      issuer: /C=US/O=Example")
    harness.process.emit(f"ERROR:      sha256 digest: {new}")
    harness.process.finish(1)
    snapshot = harness.backend.snapshot()
    assert snapshot.error_code is VpnErrorCode.CERTIFICATE_CHANGED
    page.show_user_error(
        VpnEvent(
            "error",
            snapshot,
            error_code=snapshot.error_code,
            error_message=snapshot.error_message,
            certificate=snapshot.presented_certificate,
        )
    )
    assert seen == [True]
    assert profile_manager.list_profiles()[0].trusted_cert_sha256 == old


def test_connection_page_certificate_wait_and_failed_retry(
    qapp, profile_manager: ProfileManager
) -> None:
    digest = "aa" * 32
    profile_manager.add(name="Office", gateway="vpn.example.com", use_sso=True)
    harness = VpnHarness()
    page = ConnectionPage(
        profile_manager,
        harness.backend,
        locator=lambda: "/usr/local/bin/openfortivpn",
        trust_prompt=lambda **kwargs: False,
    )
    page._on_action_clicked()
    harness.process.emit(_FAIL)
    harness.process.emit("ERROR:      subject: /CN=vpn.example.com")
    harness.process.emit("ERROR:      issuer: /C=US/O=Example")
    harness.process.emit(f"ERROR:      sha256 digest: {digest}")
    harness.process.finish(1)
    page.apply_snapshot(harness.backend.snapshot())
    assert page.action_text() == "Cancel"
    assert page.cert_hint_visible() is True
    assert page._cert_hint.text() == "Waiting for certificate trust"
    page._on_action_clicked()
    page.apply_snapshot(harness.backend.snapshot())
    assert page.action_text() == "Connect again"
    assert page.cert_hint_visible() is False


def test_connection_page_same_fingerprint_opens_one_dialog(
    qapp, profile_manager: ProfileManager
) -> None:
    digest = "aa" * 32
    profile_manager.add(name="Office", gateway="vpn.example.com", use_sso=True)
    harness = VpnHarness()
    prompts: list[dict] = []
    page = ConnectionPage(
        profile_manager,
        harness.backend,
        locator=lambda: "/usr/local/bin/openfortivpn",
        trust_prompt=lambda **kwargs: prompts.append(kwargs) or False,
    )
    page._on_action_clicked()
    harness.process.emit(_FAIL)
    harness.process.emit("ERROR:      subject: /CN=vpn.example.com")
    harness.process.emit("ERROR:      issuer: /C=US/O=Example")
    harness.process.emit(f"ERROR:      sha256 digest: {digest}")
    harness.process.finish(1)
    event = VpnEvent(
        "error",
        harness.backend.snapshot(),
        error_code=VpnErrorCode.CERTIFICATE_UNTRUSTED,
        error_message=harness.backend.snapshot().error_message,
        certificate=harness.backend.snapshot().presented_certificate,
    )
    page.show_user_error(event)
    page.show_user_error(event)
    assert len(prompts) == 1


def test_reconnect_button_is_wired_and_starts_reconnect(
    qapp, profile_manager: ProfileManager
) -> None:
    profile_manager.add(name="Office", gateway="vpn.example.com", use_sso=False)
    harness = VpnHarness()
    page = ConnectionPage(profile_manager, harness.backend, locator=lambda: "/usr/bin/openfortivpn")
    page._on_action_clicked()
    harness.process.emit("INFO:   Tunnel is up and running.")
    page.apply_snapshot(harness.backend.snapshot())
    assert page.reconnect_button_visible() is True
    assert page._reconnect_button.isEnabled() is True
    harness.process.exit_on_terminate = False
    page._reconnect_button.click()
    page.apply_snapshot(harness.backend.snapshot())
    assert "Reconnect requested." in [
        record.message for record in harness.log.records() if record.source == "vpn"
    ]
    assert page.status_text() == "Reconnecting..."
    assert page.action_text() == "Reconnecting..."
    assert page.reconnect_button_visible() is False
    assert page.connect_enabled() is False
    harness.process.finish(0)
    page.apply_snapshot(harness.backend.snapshot())
    assert page.status_text() == "Connecting"

