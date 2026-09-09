# SPDX-License-Identifier: GPL-3.0-or-later
"""URL validation tests. No browser or network."""

from __future__ import annotations

import pytest

from fortigate_vpn_gui.vpn.url_safety import InvalidAuthUrl, safe_url_for_display, validate_auth_url


def test_https_accepted() -> None:
    url = "https://vpn.example.com:443/remote/saml/start?redirect=1"
    assert validate_auth_url(url) == url


def test_http_accepted() -> None:
    url = "http://vpn.example.com/remote/saml/start"
    assert validate_auth_url(url) == url


def test_javascript_rejected() -> None:
    with pytest.raises(InvalidAuthUrl):
        validate_auth_url("javascript:alert(1)")


def test_file_rejected() -> None:
    with pytest.raises(InvalidAuthUrl):
        validate_auth_url("file:///etc/passwd")


def test_data_rejected() -> None:
    with pytest.raises(InvalidAuthUrl):
        validate_auth_url("data:text/html,hi")


def test_malformed_rejected() -> None:
    with pytest.raises(InvalidAuthUrl):
        validate_auth_url("not a url")
    with pytest.raises(InvalidAuthUrl):
        validate_auth_url("https://")
    with pytest.raises(InvalidAuthUrl):
        validate_auth_url("")
    with pytest.raises(InvalidAuthUrl):
        validate_auth_url("https://127.0.0.1:8020/?id=secret")


def test_display_strips_query() -> None:
    url = "https://vpn.example.com/remote/saml/start?redirect=1&id=secret"
    assert safe_url_for_display(url) == "https://vpn.example.com/remote/saml/start"
    assert "secret" not in safe_url_for_display(url)
