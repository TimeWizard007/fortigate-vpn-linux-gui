# SPDX-License-Identifier: GPL-3.0-or-later
"""Log redaction tests. No network, sudo, or VPN processes."""

from __future__ import annotations

from fortigate_vpn_gui.vpn.log_redaction import redact_log_line


def test_redact_password() -> None:
    assert redact_log_line("password=supersecret") == "password=***"
    assert redact_log_line("PASSWORD: hunter2") == "PASSWORD: ***"


def test_redact_svpncookie() -> None:
    assert redact_log_line("SVPNCOOKIE=abc123") == "SVPNCOOKIE=***"
    assert redact_log_line("svpncookie=abc123") == "svpncookie=***"


def test_redact_authorization_bearer() -> None:
    line = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9"
    assert redact_log_line(line) == "Authorization: Bearer ***"
    assert redact_log_line("authorization: bearer abc") == "authorization: bearer ***"


def test_redact_cookie() -> None:
    assert redact_log_line("Cookie: SVPNCOOKIE=xyz") == "Cookie: ***"
    assert redact_log_line("Set-Cookie: sid=123") == "Set-Cookie: ***"
    assert redact_log_line("cookie=xyz") == "cookie=***"


def test_redact_saml_response_and_relay_state() -> None:
    assert "abc" not in redact_log_line("SAMLResponse=abc123")
    assert redact_log_line("SAMLResponse=abc123") == "SAMLResponse=***"
    assert "xyz" not in redact_log_line("RelayState=xyz")
    assert redact_log_line("RelayState=xyz") == "RelayState=***"


def test_redact_id_and_session_identifiers() -> None:
    assert "secret" not in redact_log_line("http://127.0.0.1:8020/?id=secret")
    assert "id=***" in redact_log_line("callback id=secretid")
    assert redact_log_line("session_id=sess-99") == "session_id=***"


def test_redact_token_query_parameters() -> None:
    line = "https://login.example.com/cb?access_token=aaa&refresh_token=bbb&id_token=ccc"
    redacted = redact_log_line(line)
    assert "aaa" not in redacted
    assert "bbb" not in redacted
    assert "ccc" not in redacted
    assert "access_token=***" in redacted


def test_redact_id_token_and_client_secret() -> None:
    assert redact_log_line("id_token=hunter2") == "id_token=***"
    assert redact_log_line("client_secret=shh") == "client_secret=***"


def test_redact_mixed_capitalization() -> None:
    text = "PaSsWoRd=abc SVPNCOOKIE=tok Authorization: BeArEr jwt"
    redacted = redact_log_line(text)
    assert "abc" not in redacted
    assert "tok" not in redacted
    assert "jwt" not in redacted
    assert "***" in redacted
