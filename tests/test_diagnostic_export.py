# SPDX-License-Identifier: GPL-3.0-or-later
"""Diagnostics export/copy redaction. No real VPN or GitHub upload."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from zipfile import ZipFile

from fortigate_vpn_gui.diagnostics.export import format_diagnostic_bundle, write_diagnostic_zip
from fortigate_vpn_gui.diagnostics.model import CheckStatus, DiagnosticCheck, DiagnosticRun
from fortigate_vpn_gui.diagnostics.sanitization import sanitize_diagnostic_text
from fortigate_vpn_gui.gui.diagnostics_page import DiagnosticsPage
from fortigate_vpn_gui.profiles.manager import ProfileManager
from fortigate_vpn_gui.profiles.model import build_profile
from fortigate_vpn_gui.vpn.log_buffer import LogBuffer
from tests.vpn_fakes import VpnHarness


def _run() -> DiagnosticRun:
    now = datetime.now(timezone.utc)
    return DiagnosticRun(
        started_at=now,
        finished_at=now,
        checks=(
            DiagnosticCheck(
                id="vpn.openfortivpn",
                label="openfortivpn",
                status=CheckStatus.PASS,
                summary="openfortivpn 1.24.1",
                group="VPN Components",
            ),
        ),
    )


def test_export_bundle_redacts_common_secrets(tmp_path: Path) -> None:
    dirty = DiagnosticCheck(
        id="network.tcp",
        label="Gateway TCP",
        status=CheckStatus.FAIL,
        summary=(
            "password=hunter2 psk=tunnel-psk Authorization: Bearer abcdef "
            "SVPNCOOKIE=leakcookie access_token=tok123 "
            "-----BEGIN PRIVATE KEY-----\nMIISECRET\n-----END PRIVATE KEY-----"
        ),
        detail='{"operation":"connect","password":"hunter2","psk":"tunnel-psk"}',
        hint="Set-Cookie: session=abc https://vpn.example.com/remote/saml/start?id=secret-id",
        group="Network",
    )
    now = datetime.now(timezone.utc)
    run = DiagnosticRun(started_at=now, finished_at=now, checks=(dirty,))
    log = LogBuffer()
    log.append("vpn", "psk=should-not-appear password=also-secret")
    profile = build_profile(name="Office", gateway="vpn.example.com", use_sso=True)
    text = format_diagnostic_bundle(
        run,
        app_version="1.2.0",
        os_name="Ubuntu 24.04 LTS",
        kernel="6.8.0",
        architecture_name="x86_64",
        profile=profile,
        snapshot=VpnHarness().backend.snapshot(),
        log_buffer=log,
    )
    lowered = text.lower()
    assert "hunter2" not in text
    assert "tunnel-psk" not in text
    assert "abcdef" not in text
    assert "leakcookie" not in text
    assert "tok123" not in text
    assert "MIISECRET" not in text
    assert "should-not-appear" not in text
    assert "also-secret" not in text
    assert "secret-id" not in lowered
    assert "1.2.0" in text
    zip_path = write_diagnostic_zip(text, tmp_path / "diag.zip")
    with ZipFile(zip_path) as archive:
        names = set(archive.namelist())
        assert "report.txt" in names
        combined = "\n".join(archive.read(name).decode("utf-8") for name in archive.namelist())
    assert "hunter2" not in combined
    assert "tunnel-psk" not in combined
    assert "MIISECRET" not in combined


def test_sanitize_private_key_and_authorization_header() -> None:
    pem = "-----BEGIN RSA PRIVATE KEY-----\nABCDEF\n-----END RSA PRIVATE KEY-----"
    cleaned = sanitize_diagnostic_text(pem)
    assert "ABCDEF" not in cleaned
    assert "private key" in cleaned.lower() or "***" in cleaned
    header = sanitize_diagnostic_text("Authorization: Basic dXNlcjpwYXNz")
    assert "dXNlcjpwYXNz" not in header


def test_diagnostics_page_copy_and_export(
    qapp, profile_manager: ProfileManager, tmp_path: Path
) -> None:
    profile_manager.add(name="Office", gateway="vpn.example.com", use_sso=True)
    harness = VpnHarness()
    page = DiagnosticsPage(
        profile_manager,
        harness.backend,
        lambda: profile_manager.list_profiles()[0],
        execute_in_thread=False,
    )
    page.start_run()
    copied = page.copy_diagnostics()
    assert "FortiGate VPN Linux GUI" in copied
    assert "Office" in copied
    assert page._copy_button.text() == "Copy diagnostics"
    assert page._export_button.text() == "Export diagnostics"
    exported = page.export_report(tmp_path / "issue.zip")
    assert exported is not None
    assert exported.exists()
    with ZipFile(exported) as archive:
        body = archive.read("report.txt").decode("utf-8")
    assert "Office" in body
    assert "password=" not in body.lower() or "***" in body
