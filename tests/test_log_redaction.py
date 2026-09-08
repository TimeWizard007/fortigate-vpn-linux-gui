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


def test_redact_mixed_capitalization() -> None:
    text = "PaSsWoRd=abc SVPNCOOKIE=tok Authorization: BeArEr jwt"
    redacted = redact_log_line(text)
    assert "abc" not in redacted
    assert "tok" not in redacted
    assert "jwt" not in redacted
    assert "***" in redacted
