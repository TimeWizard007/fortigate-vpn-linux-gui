# SPDX-License-Identifier: GPL-3.0-or-later
"""IPsec secret redaction and diagnostic sanitization."""

from __future__ import annotations

from fortigate_vpn_gui.diagnostics.checks import check_connection_state
from fortigate_vpn_gui.diagnostics.model import CheckStatus
from fortigate_vpn_gui.diagnostics.report import format_diagnostic_report
from fortigate_vpn_gui.diagnostics.sanitization import sanitize_diagnostic_text
from fortigate_vpn_gui.diagnostics.service import DiagnosticRequest, DiagnosticService
from fortigate_vpn_gui.profiles.ipsec import default_ipsec_settings
from fortigate_vpn_gui.profiles.model import build_profile
from fortigate_vpn_gui.vpn.log_redaction import redact_log_line
from fortigate_vpn_gui.vpn.models import ConnectionState, VpnErrorCode, VpnSnapshot


def test_redact_psk_and_xauth_password() -> None:
    assert "secretpsk" not in redact_log_line("psk=secretpsk")
    assert redact_log_line("PSK: secretpsk") == "PSK: ***"
    assert "hunter2" not in redact_log_line("xauth-password=hunter2")


def test_sanitize_json_psk() -> None:
    text = '{"operation":"credentials","psk":"super-secret","password":"hunter2"}'
    sanitized = sanitize_diagnostic_text(text)
    assert "super-secret" not in sanitized
    assert "hunter2" not in sanitized


def test_ipsec_diagnostics_report_has_no_secrets() -> None:
    profile = build_profile(
        name="IPsec",
        gateway="vpn.example.com",
        port=500,
        vpn_type="ipsec",
        ipsec=default_ipsec_settings().to_json(),
    )
    snapshot = VpnSnapshot(
        state=ConnectionState.DISCONNECTED,
        profile_id=profile.id,
        profile_name=profile.name,
        error_code=None,
        error_message=None,
        process=None,
    )
    run = DiagnosticService().collect_local(
        DiagnosticRequest(snapshot=snapshot, profile=profile, include_network=False)
    )
    report = format_diagnostic_report(
        run,
        app_version="1.1.0",
        os_name="Ubuntu",
        kernel="test",
        architecture="x86_64",
        profile=profile,
        snapshot=snapshot,
    )
    assert "VPN type: IPsec" in report
    assert "super-secret" not in report
    assert "hunter2" not in report
    assert run.check("vpn.ipsec") is not None
    detail = run.check("vpn.ipsec").detail or ""
    assert "ikev1" in detail
    assert "aggressive" in detail


def test_diagnostics_do_not_include_stored_psk(psk_store) -> None:
    profile = build_profile(
        name="IPsec",
        gateway="vpn.example.com",
        port=500,
        vpn_type="ipsec",
        username_hint="mwi",
        ipsec=default_ipsec_settings().to_json(),
    )
    psk_store.set(profile.id, "tunnel-psk-secret")
    snapshot = VpnSnapshot(
        state=ConnectionState.DISCONNECTED,
        profile_id=profile.id,
        profile_name=profile.name,
        error_code=None,
        error_message=None,
        process=None,
    )
    run = DiagnosticService().collect_local(
        DiagnosticRequest(snapshot=snapshot, profile=profile, include_network=False)
    )
    report = format_diagnostic_report(
        run,
        app_version="1.1.0",
        os_name="Ubuntu",
        kernel="test",
        architecture="x86_64",
        profile=profile,
        snapshot=snapshot,
    )
    assert "tunnel-psk-secret" not in report
    assert "ad-directory-password" not in report
    leaked = sanitize_diagnostic_text(
        "psk=tunnel-psk-secret password=ad-directory-password username=mwi"
    )
    assert "tunnel-psk-secret" not in leaked
    assert "ad-directory-password" not in leaked


def test_ipsec_daemon_start_failed_is_not_backend_missing() -> None:
    snapshot = VpnSnapshot(
        state=ConnectionState.FAILED,
        profile_id="p1",
        profile_name="IPsec",
        error_code=VpnErrorCode.IPSEC_DAEMON_START_FAILED,
        error_message="The IPsec daemon exited before opening its control socket (status 1).",
        process=None,
        last_failure_reason="ipsec_daemon_start_failed",
    )
    check = check_connection_state(snapshot)
    assert check.status is CheckStatus.FAIL
    assert "ipsec_daemon_start_failed" in (check.summary or "")
    assert "ipsec_backend_missing" not in (check.summary or "")
    assert "ipsec_backend_missing" not in (check.detail or "")
