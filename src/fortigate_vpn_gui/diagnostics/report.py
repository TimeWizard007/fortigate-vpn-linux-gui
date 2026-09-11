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
from fortigate_vpn_gui.profiles.model import ConnectionProfile, auth_mode_label
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
    session_type: str = "",
) -> str:
    """Return a sanitized plain-text report."""
    generated = run.finished_at.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "FortiGate VPN Linux GUI Diagnostic Report",
        f"Generated: {generated}",
        f"Application: {app_version}",
        f"Helper protocol: {helper_protocol}",
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
        lines.append(f"Gateway: {sanitize_diagnostic_text(profile.gateway)}")
        lines.append(f"Port: {profile.port}")
        lines.append(f"Authentication: {auth_mode_label(profile.use_sso)}")
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
