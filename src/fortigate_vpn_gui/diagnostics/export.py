# SPDX-License-Identifier: GPL-3.0-or-later
"""Build a sanitized diagnostics bundle for GitHub issues.

Never include PSK, passwords, keyring values, SAML cookies/tokens, private
keys, or helper request bodies.
"""

from __future__ import annotations

import os
import platform
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from fortigate_vpn_gui import APP_NAME, __version__
from fortigate_vpn_gui.diagnostics.model import DiagnosticRun
from fortigate_vpn_gui.diagnostics.platform_info import (
    architecture,
    desktop_session_type,
    kernel_release,
    query_dpkg_version,
    read_os_pretty_name,
)
from fortigate_vpn_gui.diagnostics.report import format_diagnostic_report
from fortigate_vpn_gui.diagnostics.sanitization import sanitize_diagnostic_text
from fortigate_vpn_gui.helper.ike_ports import format_ike_port_lines, inspect_ike_udp_ports
from fortigate_vpn_gui.helper.ipsec_runtime import inspect_owned_ipsec_state
from fortigate_vpn_gui.helper.protocol import (
    HELPER_VERSION,
    INSTALLED_HELPER_PATH,
    PACKAGE_OPENFORTIVPN_PATH,
)
from fortigate_vpn_gui.metadata import INSTALLED_LAUNCHER_PATH
from fortigate_vpn_gui.profiles.model import ConnectionProfile
from fortigate_vpn_gui.vpn.log_buffer import LogBuffer
from fortigate_vpn_gui.vpn.models import VpnSnapshot, state_label


def installed_package_version() -> str:
    """Return the dpkg version when this application is installed."""
    return query_dpkg_version("fortigate-vpn-linux-gui")


def python_runtime_summary() -> str:
    executable = sys.executable or "unknown"
    version = platform.python_version()
    return sanitize_diagnostic_text(f"{version} ({executable})")


def _safe_ike_port_lines() -> list[str]:
    try:
        return format_ike_port_lines(inspect_ike_udp_ports())
    except OSError:
        return ["IKE port 500: unknown", "IKE NAT-T port 4500: unknown"]


def format_environment_section(
    *,
    helper_path: str = "",
    helper_detected: str = "",
    openfortivpn_version: str = "",
    strongswan_version: str = "",
) -> str:
    leftover = inspect_owned_ipsec_state()
    package = installed_package_version() or "not installed as a .deb (or dpkg unavailable)"
    strongswan = strongswan_version or query_dpkg_version("strongswan") or "—"
    swanctl = query_dpkg_version("strongswan-swanctl") or "—"
    lines = [
        "Environment:",
        f"Application: {__version__}",
        f"Package: {package}",
        f"OS: {read_os_pretty_name()}",
        f"Kernel: {kernel_release()}",
        f"Architecture: {architecture()}",
        f"Session: {desktop_session_type()}",
        f"Desktop: {sanitize_diagnostic_text(os.environ.get('XDG_CURRENT_DESKTOP', '') or '—')}",
        f"Python: {python_runtime_summary()}",
        f"Helper protocol expected: {HELPER_VERSION}",
        f"Helper protocol detected: {sanitize_diagnostic_text(helper_detected or '—')}",
        f"Helper path: {sanitize_diagnostic_text(helper_path or INSTALLED_HELPER_PATH)}",
        f"Launcher: {INSTALLED_LAUNCHER_PATH}",
        f"Packaged openfortivpn path: {PACKAGE_OPENFORTIVPN_PATH}",
        f"openfortivpn: {sanitize_diagnostic_text(openfortivpn_version or '—')}",
        f"strongSwan: {sanitize_diagnostic_text(strongswan)}",
        f"swanctl package: {sanitize_diagnostic_text(swanctl)}",
        (
            "Owned leftover IPsec: "
            f"conf={leftover.owned_conf_present} "
            f"dns={leftover.owned_dns_state_present} "
            f"swanctl_dir={leftover.owned_swanctl_dir_present} "
            f"charon_pids={leftover.owned_charon_pids or '()'}"
        ),
        f"Unrelated charon running: {leftover.other_charon_running}",
        *_safe_ike_port_lines(),
    ]
    return sanitize_diagnostic_text("\n".join(lines))


def format_connection_section(
    snapshot: VpnSnapshot | None, profile: ConnectionProfile | None
) -> str:
    lines = ["Connection:"]
    if profile is None:
        lines.append("Profile: none")
        lines.append("VPN type: —")
    else:
        lines.append(f"Profile: {sanitize_diagnostic_text(profile.name)}")
        lines.append(f"VPN type: {profile.vpn_type_label()}")
        lines.append(f"Gateway: {sanitize_diagnostic_text(profile.gateway)}")
        lines.append(f"Port: {profile.port}")
        lines.append(f"Authentication: {profile.auth_label()}")
    if snapshot is None:
        lines.append("State: unknown")
    else:
        lines.append(f"State: {state_label(snapshot.state)}")
        reason = snapshot.error_message or snapshot.last_failure_reason or snapshot.failure_reason
        lines.append(f"Failure reason: {sanitize_diagnostic_text(reason or '—')}")
        lines.append(f"Backend: {snapshot.vpn_backend or '—'}")
        lines.append(f"Privileged PID: {snapshot.privileged_pid or '—'}")
    return sanitize_diagnostic_text("\n".join(lines))


def format_log_section(log_buffer: LogBuffer | None, *, limit: int = 200) -> str:
    if log_buffer is None:
        return "Logs:\n(none)"
    records = log_buffer.records()[-limit:]
    body = "\n".join(record.format_line() for record in records)
    return sanitize_diagnostic_text("Logs:\n" + (body or "(none)"), limit=50000)


def format_diagnostic_bundle(
    run: DiagnosticRun,
    *,
    app_version: str,
    os_name: str,
    kernel: str,
    architecture_name: str,
    profile: ConnectionProfile | None,
    snapshot: VpnSnapshot | None = None,
    helper_protocol: str = HELPER_VERSION,
    detected_helper_protocol: str = "",
    helper_path: str = "",
    session_type: str = "",
    log_buffer: LogBuffer | None = None,
    openfortivpn_version: str = "",
    strongswan_version: str = "",
) -> str:
    """Return a single sanitized text bundle suitable for GitHub issues."""
    report = format_diagnostic_report(
        run,
        app_version=app_version,
        os_name=os_name,
        kernel=kernel,
        architecture=architecture_name,
        profile=profile,
        snapshot=snapshot,
        helper_protocol=helper_protocol,
        detected_helper_protocol=detected_helper_protocol,
        helper_path=helper_path,
        session_type=session_type,
    )
    parts = [
        f"{APP_NAME} diagnostics export",
        f"Generated: {datetime.now(timezone.utc).astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')}",
        "",
        format_environment_section(
            helper_path=helper_path,
            helper_detected=detected_helper_protocol,
            openfortivpn_version=openfortivpn_version,
            strongswan_version=strongswan_version,
        ),
        "",
        format_connection_section(snapshot, profile),
        "",
        report.rstrip(),
        "",
        format_log_section(log_buffer),
        "",
    ]
    text = "\n".join(parts) + "\n"
    return sanitize_diagnostic_text(text, limit=120000)


def write_diagnostic_zip(text: str, destination: Path) -> Path:
    """Write *text* into a zip with report.txt and logs split when possible."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = sanitize_diagnostic_text(text, limit=120000)
    logs = ""
    if "\nLogs:\n" in payload:
        report, logs = payload.split("\nLogs:\n", 1)
        logs = "Logs:\n" + logs
    else:
        report = payload
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("report.txt", report)
        if logs:
            archive.writestr("logs.txt", logs)
    return destination
