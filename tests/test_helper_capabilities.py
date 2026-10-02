# SPDX-License-Identifier: GPL-3.0-or-later
"""Helper capability handshake tests. No pkexec, root, or live VPN."""

from __future__ import annotations

import json

import pytest

from fortigate_vpn_gui.helper.handshake import encode_hello_line, parse_helper_hello_output
from fortigate_vpn_gui.helper.protocol import (
    CAPABILITY_IPSEC_IKEV1_PSK_XAUTH,
    CAPABILITY_IPSEC_IKEV2_EAP,
    FORBIDDEN_REQUEST_KEYS,
    HELPER_CAPABILITIES,
    HELPER_VERSION,
    INSTALLED_HELPER_PATH,
    PROTOCOL_VERSION,
    HelperError,
    helper_has_capabilities,
)
from fortigate_vpn_gui.helper.validation import (
    connect_request_from_fields,
    parse_request_payload,
    required_helper_capabilities_for_request,
)
from fortigate_vpn_gui.profiles.ipsec import default_ikev2_saml_settings, default_ipsec_settings
from fortigate_vpn_gui.profiles.model import build_profile
from fortigate_vpn_gui.system.helper_client import PolkitHelperClient, resolve_helper_path
from fortigate_vpn_gui.vpn.ipsec.secrets import IpsecCredentials
from fortigate_vpn_gui.vpn.models import VpnErrorCode
from tests.vpn_fakes import VpnHarness

# Exact packaged v1.2 helper --version line from the first live Slice 2 failure.
_LIVE_OLD_HELLO = '{"type":"hello","helper_version":"0.8.0","protocol_version":1}\n'


def _completed(stdout: str = "", stderr: str = "", returncode: int = 0):
    return type("R", (), {"stdout": stdout, "stderr": stderr, "returncode": returncode})()


def _ikev2_request():
    return connect_request_from_fields(
        gateway="vpn.example.com",
        port=500,
        auth_mode="standard",
        backend="ipsec",
        ipsec=default_ikev2_saml_settings().to_json(),
    )


def _ikev1_request():
    return connect_request_from_fields(
        gateway="vpn.example.com",
        port=500,
        auth_mode="standard",
        backend="ipsec",
        ipsec=default_ipsec_settings().to_json(),
    )


def _sso_profile():
    settings = default_ikev2_saml_settings()
    return build_profile(
        name="HomeVPN",
        gateway="vpn.example.com",
        port=500,
        vpn_type="ipsec",
        use_sso=True,
        ipsec=settings.to_json(),
    )


def test_current_hello_advertises_ikev2_eap_and_keeps_protocol_1() -> None:
    line = encode_hello_line()
    payload = json.loads(line)
    assert payload["type"] == "hello"
    assert payload["helper_version"] == HELPER_VERSION == "0.9.0"
    assert payload["protocol_version"] == PROTOCOL_VERSION == 1
    assert CAPABILITY_IPSEC_IKEV1_PSK_XAUTH in payload["capabilities"]
    assert CAPABILITY_IPSEC_IKEV2_EAP in payload["capabilities"]
    for secret in ("password", "tokenid", "username", "cookie"):
        assert secret not in payload
        assert secret not in line
    assert "psk" not in payload


def test_old_v1_2_hello_has_no_capabilities() -> None:
    result = parse_helper_hello_output(stdout=_LIVE_OLD_HELLO, returncode=0)
    assert result.status == "ok"
    assert result.helper_version == "0.8.0"
    assert result.protocol_version == 1
    assert result.capabilities == ()
    assert helper_has_capabilities(result.capabilities, {CAPABILITY_IPSEC_IKEV2_EAP}) is False


def test_polkit_client_detects_live_old_helper_version_mismatch() -> None:
    seen: list[list[str]] = []

    def version_runner(argv: list[str]):
        seen.append(list(argv))
        return _completed(_LIVE_OLD_HELLO)

    client = PolkitHelperClient(
        helper_path=INSTALLED_HELPER_PATH,
        which=lambda name: "/usr/bin/pkexec" if name == "pkexec" else None,
        path_exists=lambda path: True,
        version_runner=version_runner,
    )
    probe = client.probe()
    assert seen == [[INSTALLED_HELPER_PATH, "--version"]]
    assert probe.helper_version == "0.8.0"
    assert probe.version_mismatch is True
    assert probe.status == "version_mismatch"
    assert probe.capabilities == ()
    with pytest.raises(HelperError, match="HELPER_VERSION_MISMATCH"):
        client.connect(_ikev2_request(), lambda event: None)


def test_same_version_without_ikev2_capability_is_rejected() -> None:
    hello = encode_hello_line(capabilities=(CAPABILITY_IPSEC_IKEV1_PSK_XAUTH,))
    client = PolkitHelperClient(
        helper_path=INSTALLED_HELPER_PATH,
        which=lambda name: "/usr/bin/pkexec" if name == "pkexec" else None,
        path_exists=lambda path: True,
        version_runner=lambda argv: _completed(hello + "\n"),
    )
    probe = client.probe()
    assert probe.version_mismatch is False
    assert probe.status == "ready"
    assert CAPABILITY_IPSEC_IKEV2_EAP not in probe.capabilities
    with pytest.raises(HelperError, match="HELPER_CAPABILITY_MISMATCH"):
        client.connect(_ikev2_request(), lambda event: None)
    ssl = connect_request_from_fields(
        gateway="vpn.example.com",
        port=443,
        auth_mode="saml",
    )
    assert required_helper_capabilities_for_request(ssl) == frozenset()


def test_current_helper_accepts_ikev2_eap_and_legacy_ikev1() -> None:
    ikev2 = _ikev2_request()
    ikev1 = _ikev1_request()
    assert required_helper_capabilities_for_request(ikev2) == {CAPABILITY_IPSEC_IKEV2_EAP}
    assert required_helper_capabilities_for_request(ikev1) == {CAPABILITY_IPSEC_IKEV1_PSK_XAUTH}
    assert helper_has_capabilities(
        HELPER_CAPABILITIES, required_helper_capabilities_for_request(ikev2)
    )
    assert helper_has_capabilities(
        HELPER_CAPABILITIES, required_helper_capabilities_for_request(ikev1)
    )
    assert ikev2.ipsec is not None
    assert ikev2.ipsec["ike_version"] == "ikev2"
    assert ikev2.ipsec["auth_method"] == "eap"
    assert ikev1.ipsec is not None
    assert ikev1.ipsec["ike_version"] == "ikev1"


def test_unsupported_combinations_remain_rejected() -> None:
    with pytest.raises(HelperError, match="UNSUPPORTED_IPSEC"):
        connect_request_from_fields(
            gateway="vpn.example.com",
            port=500,
            auth_mode="standard",
            backend="ipsec",
            ipsec={**default_ipsec_settings().to_json(), "ike_version": "ikev2"},
        )
    with pytest.raises(HelperError, match="UNSUPPORTED_IPSEC"):
        connect_request_from_fields(
            gateway="vpn.example.com",
            port=500,
            auth_mode="standard",
            backend="ipsec",
            ipsec={**default_ikev2_saml_settings().to_json(), "address_assignment": "manual"},
        )
    with pytest.raises(HelperError, match="UNSUPPORTED_IPSEC"):
        connect_request_from_fields(
            gateway="vpn.example.com",
            port=500,
            auth_mode="standard",
            backend="ipsec",
            ipsec={**default_ipsec_settings().to_json(), "auth_method": "eap"},
        )


def test_tokenid_remains_forbidden_and_hello_has_no_secrets() -> None:
    with pytest.raises(HelperError, match="UNSUPPORTED_FIELD"):
        parse_request_payload(
            {
                "operation": "connect",
                "gateway": "vpn.example.com",
                "port": 500,
                "auth_mode": "standard",
                "backend": "ipsec",
                "tokenid": "TEST_ONLY_TOKEN_DO_NOT_USE",
            }
        )
    assert "tokenid" in FORBIDDEN_REQUEST_KEYS
    hello = encode_hello_line()
    assert "TEST_ONLY_TOKEN_DO_NOT_USE" not in hello
    assert "tokenid" not in hello


def test_ikev2_sso_fails_before_saml_when_helper_lacks_capability() -> None:
    harness = VpnHarness(
        helper_capabilities=(CAPABILITY_IPSEC_IKEV1_PSK_XAUTH,),
    )
    codes: list[VpnErrorCode] = []
    harness.backend.subscribe(
        lambda event: codes.append(event.error_code) if event.error_code else None
    )
    harness.backend.connect(
        _sso_profile(),
        credentials=IpsecCredentials(psk="TEST_ONLY_PSK_DO_NOT_USE", username="", password=""),
    )
    assert VpnErrorCode.HELPER_CAPABILITY_MISMATCH in codes
    assert harness.browser.opened == []
    joined = "\n".join(item.message for item in harness.log.records())
    assert "Waiting for browser authentication." not in joined
    assert "TEST_ONLY_PSK_DO_NOT_USE" not in joined
    assert "install-dev-helper.sh" in (harness.backend.snapshot().error_message or "")


def test_ikev2_sso_fails_before_saml_on_old_helper_version() -> None:
    harness = VpnHarness(helper_version="0.8.0", version_mismatch=True, helper_capabilities=())
    codes: list[VpnErrorCode] = []
    harness.backend.subscribe(
        lambda event: codes.append(event.error_code) if event.error_code else None
    )
    harness.backend.connect(
        _sso_profile(),
        credentials=IpsecCredentials(psk="TEST_ONLY_PSK_DO_NOT_USE", username="", password=""),
    )
    assert VpnErrorCode.HELPER_VERSION_MISMATCH in codes
    assert VpnErrorCode.IPSEC_UNSUPPORTED not in codes
    assert harness.browser.opened == []


def test_production_path_is_installed_helper(monkeypatch) -> None:
    monkeypatch.delenv("FORTIGATE_VPN_HELPER", raising=False)
    assert resolve_helper_path() == INSTALLED_HELPER_PATH
    assert INSTALLED_HELPER_PATH == "/usr/libexec/fortigate-vpn-linux-gui/vpn-helper"
