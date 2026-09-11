# SPDX-License-Identifier: GPL-3.0-or-later
"""Safe-to-share diagnostics snapshots."""

from __future__ import annotations

from collections.abc import Callable

from fortigate_vpn_gui.helper.handshake import is_valid_helper_version
from fortigate_vpn_gui.helper.validation import format_sha256_fingerprint
from fortigate_vpn_gui.profiles.model import ConnectionProfile
from fortigate_vpn_gui.vpn.backend import VpnBackend
from fortigate_vpn_gui.vpn.detect import OpenfortivpnDetection, detect_openfortivpn
from fortigate_vpn_gui.vpn.models import ConnectionState, state_label


def build_diagnostics_snapshot(
    vpn: VpnBackend,
    selected_profile: ConnectionProfile | None,
    config_path: str,
    *,
    detect: Callable[..., OpenfortivpnDetection] = detect_openfortivpn,
    desktop: dict[str, str] | None = None,
) -> dict[str, str]:
    """Return a redacted diagnostics mapping. Does not contact the network."""
    detection = detect(include_version=True, include_capabilities=True)
    snapshot = vpn.snapshot()
    probe = vpn.helper.probe() if snapshot.helper_probe is None else snapshot.helper_probe
    pid = "—"
    if snapshot.privileged_pid is not None:
        pid = str(snapshot.privileged_pid)
    elif snapshot.process is not None and snapshot.process.pid is not None:
        pid = str(snapshot.process.pid)
    if selected_profile is None:
        profile = "—"
        auth_mode = snapshot.auth_mode or "—"
        pinned = snapshot.certificate_pinned
        fingerprint = snapshot.certificate_fingerprint
    else:
        profile = f"{selected_profile.name} ({selected_profile.gateway}:{selected_profile.port})"
        auth_mode = "SAML/SSO" if selected_profile.use_sso else "non-SSO"
        pinned = bool(selected_profile.trusted_cert_sha256)
        fingerprint = selected_profile.trusted_cert_sha256
    path = snapshot.selected_executable or detection.path
    version = snapshot.openfortivpn_version or detection.version
    saml = snapshot.supports_saml if snapshot.supports_saml is not None else detection.supports_saml
    cookie = (
        snapshot.supports_cookie_stdin
        if snapshot.supports_cookie_stdin is not None
        else detection.supports_cookie_stdin
    )
    waiting = snapshot.state is ConnectionState.WAITING_FOR_AUTH
    presented = snapshot.presented_certificate
    raw_version = probe.helper_version or snapshot.helper_version
    helper_version = raw_version if is_valid_helper_version(raw_version) else "—"
    wait_reason = snapshot.wait_reason
    if not wait_reason or wait_reason == "none":
        wait_display = "—"
    else:
        wait_display = wait_reason
    attempt = "—" if snapshot.attempt_id in (None, 0) else str(snapshot.attempt_id)
    retry = "—" if snapshot.retry_count is None else str(snapshot.retry_count)
    data = {
        "helper_installed": "Yes" if probe.installed else "No",
        "helper_version": helper_version,
        "authorization_mechanism": probe.authorization_mechanism or "polkit",
        "helper_status": probe.status,
        "helper_startup_detail": probe.startup_detail or "—",
        "privileged_pid": pid,
        "openfortivpn_detected": "Yes" if detection.available or path else "No",
        "executable_path": path or "—",
        "selected_executable": path or "—",
        "version": version or "—",
        "supports_saml": _yes_no(saml),
        "supports_cookie_stdin": _yes_no(cookie),
        "certificate_pinned": _yes_no(bool(pinned) if pinned is not None else None),
        "certificate_fingerprint": (format_sha256_fingerprint(fingerprint) if fingerprint else "—"),
        "certificate_subject": (
            snapshot.certificate_subject
            or (presented.subject if presented is not None else None)
            or "—"
        ),
        "certificate_issuer": (
            snapshot.certificate_issuer
            or (presented.issuer if presented is not None else None)
            or "—"
        ),
        "vpn_state": state_label(snapshot.state),
        "connection_state": snapshot.state.value,
        "wait_reason": wait_display,
        "failure_reason": snapshot.failure_reason or "—",
        "last_failure_reason": snapshot.last_failure_reason or "—",
        "last_disconnect_reason": snapshot.last_disconnect_reason or "—",
        "attempt_id": attempt,
        "retry_count": retry,
        "process_pid": pid,
        "selected_profile": profile,
        "auth_mode": auth_mode,
        "browser_status": snapshot.browser_status or "idle",
        "waiting_for_auth": "Yes" if waiting else "No",
        "browser_waiting": "Yes" if waiting else "No",
        "config_path": config_path,
        "auto_reconnect_enabled": "Yes" if snapshot.auto_reconnect_enabled else "No",
        "reconnect_attempt": str(snapshot.reconnect_attempt),
        "reconnect_limit": str(snapshot.reconnect_limit),
        "reconnect_pending": "Yes" if snapshot.reconnect_pending else "No",
        "shutdown_in_progress": "Yes" if snapshot.shutdown_in_progress else "No",
    }
    if desktop:
        data.update(desktop)
    return data


def _yes_no(value: bool | None) -> str:
    if value is None:
        return "—"
    return "Yes" if value else "No"
