# SPDX-License-Identifier: GPL-3.0-or-later
"""Plain-text diagnostic report for support tickets and issues."""

from __future__ import annotations

from fortigate_vpn_gui.diagnostics.model import (
    GROUP_ORDER,
    STATUS_LABEL,
    DiagnosticCheck,
    DiagnosticRun,
)
from fortigate_vpn_gui.diagnostics.sanitization import sanitize_diagnostic_text
from fortigate_vpn_gui.helper.protocol import HELPER_VERSION
from fortigate_vpn_gui.profiles.model import ConnectionProfile
from fortigate_vpn_gui.vpn.models import VpnSnapshot, state_label


def format_diagnostic_report(
    run: DiagnosticRun,
    *,
    app_version: str,
    os_name: str,
    kernel: str,
    architecture: str,
    profile: ConnectionProfile | None,
    snapshot: VpnSnapshot | None = None,
    helper_protocol: str = HELPER_VERSION,
    detected_helper_protocol: str = "",
    helper_path: str = "",
    session_type: str = "",
) -> str:
    """Return a sanitized plain-text report."""
    generated = run.finished_at.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    helper_check = run.check("vpn.helper")
    detected = detected_helper_protocol
    path = helper_path
    if helper_check is not None and helper_check.detail:
        detail = helper_check.detail
        if not detected and "detected protocol:" in detail:
            detected = detail.split("detected protocol:", 1)[1].split(";", 1)[0].strip()
        if not path and "effective path:" in detail:
            path = detail.split("effective path:", 1)[1].strip()
    lines = [
        "FortiGate VPN Linux GUI Diagnostic Report",
        f"Generated: {generated}",
        f"Application: {app_version}",
        f"Helper protocol expected: {helper_protocol}",
        f"Helper protocol detected: {sanitize_diagnostic_text(detected or '—')}",
        f"Helper path: {sanitize_diagnostic_text(path or '—')}",
        f"OS: {sanitize_diagnostic_text(os_name)}",
        f"Kernel: {sanitize_diagnostic_text(kernel)}",
        f"Architecture: {sanitize_diagnostic_text(architecture)}",
    ]
    if session_type:
        lines.append(f"Session: {sanitize_diagnostic_text(session_type)}")
    lines.append("")
    lines.append("Profile:")
    if profile is None:
        lines.append("None selected")
    else:
        lines.append(f"Name: {sanitize_diagnostic_text(profile.name)}")
        lines.append(f"VPN type: {profile.vpn_type_label()}")
        lines.append(f"Gateway: {sanitize_diagnostic_text(profile.gateway)}")
        lines.append(f"Port: {profile.port}")
        lines.append(f"Authentication: {profile.auth_label()}")
    lines.append("")
    lines.append("Checks:")
    for group in GROUP_ORDER:
        grouped = [item for item in run.checks if item.group == group]
        if not grouped:
            continue
        for item in grouped:
            lines.append(_format_check_line(item))
    leftover = [item for item in run.checks if item.group not in GROUP_ORDER]
    for item in leftover:
        lines.append(_format_check_line(item))
    lines.append("")
    lines.append("Connection:")
    if snapshot is not None:
        lines.append(f"State: {state_label(snapshot.state)}")
        if snapshot.state.value == "failed":
            reason = snapshot.last_failure_reason or snapshot.failure_reason or ""
            if reason:
                lines.append(f"Last error: {sanitize_diagnostic_text(reason)}")
    else:
        connection = run.check("tunnel.connection")
        if connection is not None:
            lines.append(f"State: {connection.summary}")
        else:
            lines.append("State: unknown")
    text = "\n".join(lines) + "\n"
    return sanitize_diagnostic_text(text, limit=20000)


def _format_check_line(item: DiagnosticCheck) -> str:
    status = STATUS_LABEL[item.status]
    summary = item.summary or ""
    return f"[{status}] {item.label}: {summary}"
