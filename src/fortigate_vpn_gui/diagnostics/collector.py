# SPDX-License-Identifier: GPL-3.0-or-later
"""Safe-to-share diagnostics snapshots."""

from __future__ import annotations

from collections.abc import Callable

from fortigate_vpn_gui.profiles.model import ConnectionProfile
from fortigate_vpn_gui.vpn.backend import VpnBackend
from fortigate_vpn_gui.vpn.detect import OpenfortivpnDetection, detect_openfortivpn
from fortigate_vpn_gui.vpn.models import state_label


def build_diagnostics_snapshot(
    vpn: VpnBackend,
    selected_profile: ConnectionProfile | None,
    config_path: str,
    *,
    detect: Callable[..., OpenfortivpnDetection] = detect_openfortivpn,
) -> dict[str, str]:
    """Return a redacted diagnostics mapping. Does not contact the network."""
    detection = detect(include_version=True)
    snapshot = vpn.snapshot()
    pid = "—"
    if snapshot.process is not None and snapshot.process.pid is not None:
        pid = str(snapshot.process.pid)
    if selected_profile is None:
        profile = "—"
    else:
        profile = f"{selected_profile.name} ({selected_profile.gateway}:{selected_profile.port})"
    return {
        "openfortivpn_detected": "Yes" if detection.available else "No",
        "executable_path": detection.path or "—",
        "version": detection.version or "—",
        "vpn_state": state_label(snapshot.state),
        "process_pid": pid,
        "selected_profile": profile,
        "config_path": config_path,
    }
