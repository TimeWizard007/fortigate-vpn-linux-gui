# SPDX-License-Identifier: GPL-3.0-or-later
"""Diagnostics snapshot tests. No real openfortivpn execution."""

from __future__ import annotations

from PySide6.QtWidgets import QLabel

from fortigate_vpn_gui.diagnostics.checks import CommandResult, DnsResult, TcpResult
from fortigate_vpn_gui.diagnostics.collector import build_diagnostics_snapshot
from fortigate_vpn_gui.diagnostics.service import DiagnosticDeps, DiagnosticService
from fortigate_vpn_gui.gui.diagnostics_page import DiagnosticsPage
from fortigate_vpn_gui.helper.protocol import POLKIT_ACTION_ID
from fortigate_vpn_gui.profiles.manager import ProfileManager
from fortigate_vpn_gui.profiles.model import build_profile
from fortigate_vpn_gui.vpn.detect import OpenfortivpnDetection
from tests.vpn_fakes import VpnHarness

_AUTH_URL = "https://vpn.example.com:443/remote/saml/start?id=should-not-leak"


def test_diagnostics_snapshot_values() -> None:
    harness = VpnHarness()
    profile = build_profile(name="Office", gateway="vpn.example.com", port=443, use_sso=False)
    harness.backend.connect(profile)
    harness.process.emit("INFO:   Tunnel is up and running.")

    def detect(**kwargs):
        return OpenfortivpnDetection(
            available=True,
            path="/usr/bin/openfortivpn",
            version="1.21.0",
            supports_saml=False,
            supports_cookie_stdin=True,
        )

    data = build_diagnostics_snapshot(
        harness.backend,
        profile,
        "/tmp/profiles.json",
        detect=detect,
    )
    assert data["openfortivpn_detected"] == "Yes"
    assert data["executable_path"] == "/usr/local/bin/openfortivpn"
    assert data["selected_executable"] == "/usr/local/bin/openfortivpn"
    assert data["version"] == "1.24.1"
    assert data["supports_saml"] == "Yes"
    assert data["vpn_state"] == "Connected"
    assert data["process_pid"] == "4242"
    assert "Office" in data["selected_profile"]
    assert data["auth_mode"] == "non-SSO"
    assert data["waiting_for_auth"] == "No"
    assert data["browser_waiting"] == "No"
    assert data["connection_state"] == "connected"
    assert data["wait_reason"] == "—"
    assert data["attempt_id"] == "1"
    assert data["retry_count"] == "0"
    assert data["last_disconnect_reason"] == "—"
    assert data["last_failure_reason"] == "—"
    assert data["config_path"] == "/tmp/profiles.json"
    assert data["auto_reconnect_enabled"] == "No"
    assert data["reconnect_pending"] == "No"
    assert data["shutdown_in_progress"] == "No"
    assert "should-not-leak" not in str(data.values())
    assert data["helper_installed"] == "Yes"
    assert data["authorization_mechanism"] == "polkit"
    assert data["helper_startup_detail"] == "—"
    assert data["certificate_pinned"] == "No"
    assert data["failure_reason"] == "—"
    assert data["privileged_pid"] == "4242"


def test_diagnostics_saml_waiting_state() -> None:
    harness = VpnHarness()
    profile = build_profile(name="Office", gateway="vpn.example.com", use_sso=True)
    harness.backend.connect(profile)
    harness.process.emit(f"INFO:   Authenticate at '{_AUTH_URL}'")

    def detect(**kwargs):
        return OpenfortivpnDetection(
            available=True,
            path="/usr/local/bin/openfortivpn",
            version="1.24.1",
            supports_saml=True,
            supports_cookie_stdin=True,
        )

    data = build_diagnostics_snapshot(harness.backend, profile, "/tmp/profiles.json", detect=detect)
    assert data["supports_saml"] == "Yes"
    assert data["auth_mode"] == "SAML/SSO"
    assert data["waiting_for_auth"] == "Yes"
    assert data["browser_waiting"] == "Yes"
    assert data["connection_state"] == "waiting_for_auth"
    assert data["wait_reason"] == "saml_browser"
    assert data["attempt_id"] == "1"
    assert data["browser_status"] == "opened"
    assert "should-not-leak" not in str(data.values())
    assert "id=" not in str(data.values())


def test_diagnostics_page_missing_binary(qapp, profile_manager: ProfileManager) -> None:
    harness = VpnHarness(executable=None)

    def detect(**kwargs):
        return OpenfortivpnDetection(available=False, path=None, version=None)

    page = DiagnosticsPage(
        profile_manager,
        harness.backend,
        lambda: None,
        detect=detect,
        execute_in_thread=False,
        service=DiagnosticService(
            DiagnosticDeps(
                detect=detect,
                which=lambda name: None,
                path_exists=lambda path: False,
                is_executable=lambda path: False,
                read_text=lambda path: "",
                resolve_host=lambda *a, **k: DnsResult(error="unused"),
                tcp_connect=lambda *a, **k: TcpResult(kind="error"),
                list_interfaces=lambda: (),
                run_argv=lambda *a, **k: CommandResult(missing=True),
                os_name="Ubuntu 24.04 LTS",
                kernel="6.8.0",
                arch="x86_64",
                session_type="Wayland",
            )
        ),
    )
    page.refresh()
    ofvpn = page.findChild(QLabel, "diagCheckSummary_vpn_openfortivpn")
    connection = page.findChild(QLabel, "diagCheckSummary_tunnel_connection")
    assert ofvpn is not None
    assert "not found" in ofvpn.text().lower()
    assert connection is not None
    assert connection.text() == "Disconnected"
    assert page._run_button.text() == "Run diagnostics"
    assert page._run_button.isEnabled()


def test_diagnostics_page_run_copy_and_stale_profile(qapp, profile_manager: ProfileManager) -> None:
    profile = profile_manager.add(name="Office", gateway="vpn.example.com", port=443, use_sso=True)
    profile_manager.add(name="Backup", gateway="203.0.113.10", port=443, use_sso=False)
    harness = VpnHarness()

    def detect(**kwargs):
        return OpenfortivpnDetection(available=True, path="/usr/bin/openfortivpn", version="1.23.1")

    def run_argv(argv, timeout=3.0):
        if argv and argv[-1] == "--version" and "openfortivpn" in argv[0]:
            return CommandResult(returncode=0, stdout="openfortivpn 1.23.1\n")
        return CommandResult(missing=True)

    service = DiagnosticService(
        DiagnosticDeps(
            detect=detect,
            which=lambda name: None,
            path_exists=lambda path: True,
            is_executable=lambda path: True,
            read_text=lambda path: f'id="{POLKIT_ACTION_ID}"',
            resolve_host=lambda *a, **k: DnsResult(addresses=("203.0.113.10",)),
            tcp_connect=lambda *a, **k: TcpResult(ok=True, elapsed_ms=12, kind="ok"),
            list_interfaces=lambda: (),
            run_argv=run_argv,
            os_name="Ubuntu 24.04 LTS",
            kernel="6.8.0",
            arch="x86_64",
            session_type="Wayland",
        )
    )
    page = DiagnosticsPage(
        profile_manager,
        harness.backend,
        lambda: profile,
        detect=detect,
        execute_in_thread=False,
        service=service,
    )
    page.start_run()
    assert page._run_button.isEnabled()
    assert page._run_button.text() == "Run diagnostics"
    assert "Last run:" in page._last_run_label.text()
    assert page._last_run_label.text() != "Last run: not yet"
    report = page.copy_report()
    assert "FortiGate VPN Linux GUI Diagnostic Report" in report
    assert "Office" in report
    assert "[PASS]" in report or "[INFO]" in report
    page._viewmodel._running = True
    previous = page._displayed_run
    page.start_run()
    assert page._displayed_run is previous
    page._viewmodel._running = False
    page._profile_combo.setCurrentIndex(1)
    assert page._viewmodel.stale is True
    assert "Run diagnostics again" in page._stale_hint.text()


def test_diagnostics_page_isolated_check_failure(qapp, profile_manager: ProfileManager) -> None:
    profile = profile_manager.add(name="Office", gateway="vpn.example.com", use_sso=True)
    harness = VpnHarness()

    def boom(*args, **kwargs):
        raise RuntimeError("explode")

    page = DiagnosticsPage(
        profile_manager,
        harness.backend,
        lambda: profile,
        execute_in_thread=False,
        service=DiagnosticService(
            DiagnosticDeps(
                detect=lambda **kw: OpenfortivpnDetection(available=False, path=None, version=None),
                which=lambda name: None,
                path_exists=lambda path: False,
                is_executable=lambda path: False,
                read_text=lambda path: "",
                resolve_host=boom,
                tcp_connect=lambda *a, **k: TcpResult(kind="error"),
                list_interfaces=lambda: (),
                run_argv=lambda *a, **k: CommandResult(missing=True),
                os_name="Ubuntu 24.04 LTS",
                kernel="6.8.0",
                arch="x86_64",
                session_type="Wayland",
            )
        ),
    )
    page.start_run()
    assert page.findChild(QLabel, "diagCheckStatus_network_dns") is not None or page.findChild(
        QLabel, "diagCheckSummary_network_dns"
    )
    dns = page.findChild(QLabel, "diagCheckStatus_network_dns")
    assert dns is not None
    assert dns.text() == "FAIL"


def test_diagnostics_desktop_overlay() -> None:
    harness = VpnHarness()

    def detect(**kwargs):
        return OpenfortivpnDetection(available=False, path=None, version=None)

    data = build_diagnostics_snapshot(
        harness.backend,
        None,
        "/tmp/profiles.json",
        detect=detect,
        desktop={
            "tray_available": "Yes",
            "tray_active": "No",
            "close_behavior": "Exit application",
            "autostart_enabled": "No",
        },
    )
    assert data["tray_available"] == "Yes"
    assert data["tray_active"] == "No"
    assert data["close_behavior"] == "Exit application"
    assert data["autostart_enabled"] == "No"
    assert data["auto_reconnect_enabled"] == "No"
    assert data["reconnect_pending"] == "No"
    assert data["shutdown_in_progress"] == "No"
