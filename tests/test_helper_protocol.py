# SPDX-License-Identifier: GPL-3.0-or-later
"""Helper protocol and input validation tests. No root, pkexec, or network."""

from __future__ import annotations

import pytest

from fortigate_vpn_gui.helper.argv import build_helper_argv
from fortigate_vpn_gui.helper.protocol import HelperProtocolError
from fortigate_vpn_gui.helper.validation import (
    connect_request_from_fields,
    normalize_sha256_fingerprint,
    parse_request_payload,
    validate_gateway,
    validate_port,
)

_VALID_SHA = "ab" * 32


def test_valid_hostname_and_port() -> None:
    request = connect_request_from_fields(
        gateway="vpn.example.com",
        port=17414,
        auth_mode="saml",
    )
    assert request.gateway == "vpn.example.com"
    assert request.port == 17414


def test_valid_ipv4_gateway() -> None:
    assert validate_gateway("192.0.2.10") == "192.0.2.10"


def test_invalid_gateway_control_chars() -> None:
    with pytest.raises(HelperProtocolError, match="INVALID_GATEWAY"):
        validate_gateway("vpn.example.com\n")
    with pytest.raises(HelperProtocolError, match="INVALID_GATEWAY"):
        validate_gateway("vpn.example.com;rm")
    with pytest.raises(HelperProtocolError, match="INVALID_GATEWAY"):
        validate_gateway("vpn example.com")


def test_valid_and_invalid_port() -> None:
    assert validate_port(1) == 1
    assert validate_port(65535) == 65535
    with pytest.raises(HelperProtocolError, match="INVALID_PORT"):
        validate_port(0)
    with pytest.raises(HelperProtocolError, match="INVALID_PORT"):
        validate_port(65536)
    with pytest.raises(HelperProtocolError, match="INVALID_PORT"):
        validate_port("443;1")


def test_valid_sha256_fingerprint_normalized() -> None:
    colon = ":".join("AB" for _ in range(32))
    assert normalize_sha256_fingerprint(colon) == _VALID_SHA
    assert normalize_sha256_fingerprint(_VALID_SHA.upper()) == _VALID_SHA


def test_malformed_fingerprint_rejected() -> None:
    with pytest.raises(HelperProtocolError, match="INVALID_FINGERPRINT"):
        connect_request_from_fields(
            gateway="vpn.example.com",
            port=443,
            auth_mode="saml",
            trusted_certificate_fingerprint="not-a-fingerprint",
        )
    with pytest.raises(HelperProtocolError, match="INVALID_FINGERPRINT"):
        connect_request_from_fields(
            gateway="vpn.example.com",
            port=443,
            auth_mode="saml",
            trusted_certificate_fingerprint="ab" * 31,
        )


def test_arbitrary_executable_and_command_rejected() -> None:
    with pytest.raises(HelperProtocolError, match="UNSUPPORTED_FIELD"):
        parse_request_payload(
            {
                "operation": "connect",
                "gateway": "vpn.example.com",
                "port": 443,
                "auth_mode": "saml",
                "executable": "/bin/bash",
            }
        )
    with pytest.raises(HelperProtocolError, match="UNSUPPORTED_FIELD"):
        parse_request_payload(
            {
                "operation": "connect",
                "gateway": "vpn.example.com",
                "port": 443,
                "auth_mode": "saml",
                "command": "openfortivpn vpn.example.com",
            }
        )


def test_unsupported_operation_rejected() -> None:
    with pytest.raises(HelperProtocolError, match="UNSUPPORTED_OPERATION"):
        parse_request_payload({"operation": "shell"})


def test_helper_argv_rejects_unapproved_path() -> None:
    with pytest.raises(HelperProtocolError, match="INVALID_EXECUTABLE"):
        build_helper_argv(
            executable="/tmp/openfortivpn",
            gateway="vpn.example.com",
            port=443,
            auth_mode="saml",
        )


def test_helper_argv_controlled_list() -> None:
    argv = build_helper_argv(
        executable="/usr/local/bin/openfortivpn",
        gateway="vpn.example.com",
        port=17414,
        auth_mode="saml",
        trusted_certificate_fingerprint=_VALID_SHA,
    )
    assert argv == [
        "/usr/local/bin/openfortivpn",
        "vpn.example.com:17414",
        "--saml-login",
        "--trusted-cert",
        _VALID_SHA,
    ]
    assert all(isinstance(part, str) for part in argv)


def test_helper_argv_accepts_package_owned_path() -> None:
    argv = build_helper_argv(
        executable="/usr/libexec/fortigate-vpn-linux-gui/openfortivpn",
        gateway="vpn.example.com",
        port=443,
        auth_mode="saml",
    )
    assert argv[0] == "/usr/libexec/fortigate-vpn-linux-gui/openfortivpn"
    assert argv[1] == "vpn.example.com:443"
    assert argv[2] == "--saml-login"
