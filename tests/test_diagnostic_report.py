# SPDX-License-Identifier: GPL-3.0-or-later
"""Diagnostic report formatting and sanitization tests."""

from __future__ import annotations

from datetime import datetime, timezone

from fortigate_vpn_gui.diagnostics.model import CheckStatus, DiagnosticCheck, DiagnosticRun
from fortigate_vpn_gui.diagnostics.report import format_diagnostic_report
from fortigate_vpn_gui.diagnostics.sanitization import sanitize_diagnostic_text
from fortigate_vpn_gui.profiles.model import build_profile
from tests.vpn_fakes import VpnHarness


def _run(checks: tuple[DiagnosticCheck, ...]) -> DiagnosticRun:
    now = datetime.now(timezone.utc)
    return DiagnosticRun(started_at=now, finished_at=now, checks=checks)


def test_report_contains_summary_and_statuses() -> None:
    profile = build_profile(name="Office", gateway="vpn.example.com", port=17414, use_sso=True)
    run = _run(
        (
            DiagnosticCheck(
                id="vpn.openfortivpn",
                label="openfortivpn",
                status=CheckStatus.PASS,
                summary="openfortivpn 1.24.1 — SAML supported",
                group="VPN Components",
            ),
            DiagnosticCheck(
                id="vpn.helper",
                label="VPN helper",
                status=CheckStatus.PASS,
                summary="Helper installed and compatible.",
                group="VPN Components",
            ),
            DiagnosticCheck(
                id="network.tcp",
                label="Gateway TCP",
                status=CheckStatus.FAIL,
                summary="vpn.example.com:17414 timed out",
                group="Network",
            ),
            DiagnosticCheck(
                id="tunnel.interface",
                label="VPN interface",
                status=CheckStatus.INFO,
                summary="No VPN interface detected.",
                group="Tunnel",
            ),
        )
    )
    text = format_diagnostic_report(
        run,
        app_version="0.9.0",
        os_name="Ubuntu 24.04 LTS",
        kernel="6.8.0",
        architecture="x86_64",
        profile=profile,
        snapshot=VpnHarness().backend.snapshot(),
        helper_protocol="0.7.0",
        session_type="Wayland",
    )
    assert text.startswith("FortiGate VPN Linux GUI Diagnostic Report")
    assert "Application: 0.9.0" in text
    assert "Helper protocol: 0.7.0" in text
    assert "Name: Office" in text
    assert "Gateway: vpn.example.com" in text
    assert "Port: 17414" in text
    assert "Authentication: SAML / SSO" in text
    assert "[PASS] openfortivpn: openfortivpn 1.24.1 — SAML supported" in text
    assert "[PASS] VPN helper:" in text
    assert "[FAIL] Gateway TCP:" in text
    assert "[INFO] VPN interface:" in text
    assert "State: Disconnected" in text


def test_report_sanitizes_secrets() -> None:
    dirty = DiagnosticCheck(
        id="network.tcp",
        label="Gateway TCP",
        status=CheckStatus.FAIL,
        summary=(
            "password=hunter2 Authorization: Bearer abcdef "
            "cookie=SVPNCOOKIE=leak SAMLResponse=payload access_token=tok"
        ),
        detail='{"operation":"connect","password":"hunter2"}',
        hint="Set-Cookie: session=abc",
        group="Network",
    )
    text = format_diagnostic_report(
        _run((dirty,)),
        app_version="0.9.0",
        os_name="Linux",
        kernel="6.8",
        architecture="x86_64",
        profile=None,
        snapshot=VpnHarness().backend.snapshot(),
    )
    lowered = text.lower()
    assert "hunter2" not in text
    assert "abcdef" not in text
    assert "payload" not in lowered or "samlresponse=***" in lowered
    assert "tok" not in text.split("access_token")[-1][:10] if "access_token" in text else True
    assert "SVPNCOOKIE=leak" not in text
    assert "***" in text


def test_sanitize_password_bearer_cookie_saml_auth_header() -> None:
    samples = {
        "password=supersecret": "supersecret",
        "passwd=oldpass": "oldpass",
        "Authorization: Bearer tok_abc": "tok_abc",
        "Cookie: SVPNCOOKIE=abc123": "abc123",
        "SAMLResponse=PHNhbWw+": "PHNhbWw+",
        "access_token=aaa refresh_token=bbb": "aaa",
    }
    for raw, secret in samples.items():
        cleaned = sanitize_diagnostic_text(raw)
        assert secret not in cleaned
        assert "***" in cleaned


def test_sanitize_helper_request_payload() -> None:
    payload = '{"id":"1","operation":"connect","gateway":"vpn.example.com","password":"nope"}'
    cleaned = sanitize_diagnostic_text(payload)
    assert "nope" not in cleaned
    assert "redacted helper request" in cleaned or "***" in cleaned
