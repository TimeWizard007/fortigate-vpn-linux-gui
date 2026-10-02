# SPDX-License-Identifier: GPL-3.0-or-later
"""IPsec Connect routing: SSO skips PSK/XAuth; IKEv1 still prompts."""

from __future__ import annotations

import time

from fortigate_vpn_gui.gui.connection_page import ConnectionPage
from fortigate_vpn_gui.gui.profiles_page import ProfilesPage
from fortigate_vpn_gui.profiles.ipsec import (
    AUTH_EAP,
    IKE_V2,
    default_ikev2_saml_settings,
    default_ipsec_settings,
)
from fortigate_vpn_gui.profiles.manager import ProfileManager
from fortigate_vpn_gui.vpn.ipsec.saml_listener import IpsecSamlListenerError
from fortigate_vpn_gui.vpn.ipsec.secrets import IpsecCredentials
from fortigate_vpn_gui.vpn.models import ConnectionState
from tests.vpn_fakes import VpnHarness


class _BlockingSamlSession:
    def run(self, profile, *, browser, cancel_event, on_waiting):
        del profile, browser
        on_waiting("https://vpn.example.com:1001/saml")
        if cancel_event.wait(timeout=5):
            raise IpsecSamlListenerError("IPsec SAML listener was cancelled.")
        raise AssertionError("expected cancellation")


def _wait_state(backend, *states: ConnectionState, timeout: float = 2.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        current = backend.current_state()
        if current in states:
            return backend.snapshot()
        time.sleep(0.02)
    raise AssertionError(f"timed out in {backend.current_state().value}")


def _saml_profile(manager: ProfileManager):
    return manager.add(
        name="IPsec SAML",
        gateway="vpn.example.com",
        port=500,
        vpn_type="ipsec",
        use_sso=True,
        ipsec={
            **default_ikev2_saml_settings().to_json(),
            "ike_version": IKE_V2,
            "auth_method": AUTH_EAP,
        },
    )


_PSK = "TEST_ONLY_PSK_DO_NOT_USE"


def test_ikev1_psk_xauth_still_opens_legacy_dialog(
    qapp, profile_manager: ProfileManager, monkeypatch
) -> None:
    profile = profile_manager.add(
        name="IPsec office",
        gateway="vpn.example.com",
        port=500,
        vpn_type="ipsec",
        ipsec=default_ipsec_settings().to_json(),
    )
    seen: list[str] = []

    def fake_prompt(selected, **kwargs):
        del kwargs
        seen.append(selected.id)
        return None

    monkeypatch.setattr(
        "fortigate_vpn_gui.gui.ipsec_connect.prompt_ipsec_credentials",
        fake_prompt,
    )
    harness = VpnHarness(helper_installed=False)
    page = ConnectionPage(profile_manager, harness.backend, locator=lambda: "/usr/bin/openfortivpn")
    page.select_profile(profile.id)
    page._on_action_clicked()
    assert seen == [profile.id]
    assert harness.backend.snapshot().state is ConnectionState.DISCONNECTED
    profiles = ProfilesPage(profile_manager, harness.backend)
    assert profiles.connect_profile(profile.id) is False
    assert seen == [profile.id, profile.id]


def test_ikev2_sso_skips_legacy_dialog_on_connection_and_profiles(
    qapp, profile_manager: ProfileManager, monkeypatch
) -> None:
    profile = _saml_profile(profile_manager)
    assert profile.requires_ipsec_connect_credentials() is False
    assert profile.is_ipsec_saml_preauth() is True

    def boom(*args, **kwargs):
        del args, kwargs
        raise AssertionError("legacy PSK/XAuth dialog must not open for IKEv2 SSO")

    def fake_psk(*args, **kwargs):
        del args, kwargs
        return IpsecCredentials(psk=_PSK, username="", password="")

    monkeypatch.setattr(
        "fortigate_vpn_gui.gui.ipsec_connect.prompt_ipsec_credentials",
        boom,
    )
    monkeypatch.setattr(
        "fortigate_vpn_gui.gui.ipsec_connect.prompt_ipsec_tunnel_psk",
        fake_psk,
    )
    harness = VpnHarness(ipsec_saml_session=_BlockingSamlSession())
    page = ConnectionPage(profile_manager, harness.backend, locator=lambda: "/usr/bin/openfortivpn")
    page.select_profile(profile.id)
    assert page.action_text() == "Connect with SSO"
    page._on_action_clicked()
    snapshot = _wait_state(
        harness.backend,
        ConnectionState.STARTING,
        ConnectionState.WAITING_FOR_AUTH,
    )
    assert snapshot.state is not ConnectionState.CONNECTED
    assert harness.helper.is_running() is False
    harness.backend.disconnect(wait=True)
    _wait_state(harness.backend, ConnectionState.DISCONNECTED)

    harness = VpnHarness(ipsec_saml_session=_BlockingSamlSession())
    profiles = ProfilesPage(profile_manager, harness.backend)
    assert profiles.connect_profile(profile.id) is True
    snapshot = _wait_state(
        harness.backend,
        ConnectionState.STARTING,
        ConnectionState.WAITING_FOR_AUTH,
    )
    assert snapshot.state is not ConnectionState.CONNECTED
    assert harness.helper.is_running() is False
    harness.backend.disconnect(wait=True)
