# SPDX-License-Identifier: GPL-3.0-or-later
"""Gateway certificate parser tests. No network or real openfortivpn."""

from __future__ import annotations

from fortigate_vpn_gui.helper.certificate import (
    is_certificate_validation_failure,
    parse_certificate_output,
)

_DIGEST = "aa" * 32

_FAIL = "ERROR: Gateway certificate validation failed"

_SAMPLE = f"""
INFO:   Connected to gateway.
{_FAIL}
ERROR:  --trusted-cert {_DIGEST}
ERROR:  Gateway certificate:
ERROR:      subject:
ERROR:          /CN=*.example.com
ERROR:      issuer:
ERROR:          /C=US/O=Example CA/CN=Example
ERROR:      sha256 digest:
ERROR:          {_DIGEST}
SVPNCOOKIE=should-not-be-parsed-as-cert
SAMLResponse=also-ignored
"""


def test_parser_extracts_subject_issuer_sha256() -> None:
    info = parse_certificate_output(_SAMPLE)
    assert info is not None
    assert info.subject == "CN=*.example.com"
    assert "Example CA" in info.issuer
    assert info.sha256 == _DIGEST


def test_validation_failed_detection() -> None:
    assert is_certificate_validation_failure(
        _FAIL
    )
    assert not is_certificate_validation_failure("INFO: Connected to gateway.")


def test_unrelated_output_ignored() -> None:
    assert parse_certificate_output("INFO: Connected to gateway.\nUsing interface ppp0\n") is None
    assert parse_certificate_output("password=secret\nSAMLResponse=abc\n") is None
