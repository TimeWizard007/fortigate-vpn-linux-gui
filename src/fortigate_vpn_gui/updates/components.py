# SPDX-License-Identifier: GPL-3.0-or-later
"""Installed-component labels for About. No secrets, no VPN identifiers."""

from __future__ import annotations

import platform
import sys
from dataclasses import dataclass
from pathlib import Path

from fortigate_vpn_gui import __version__
from fortigate_vpn_gui.diagnostics.platform_info import (
    packaged_openfortivpn_version,
    query_dpkg_version,
)
from fortigate_vpn_gui.helper.protocol import HELPER_VERSION, PACKAGE_OPENFORTIVPN_PATH


@dataclass(frozen=True)
class ComponentVersions:
    """Safe-to-display runtime versions."""

    application: str
    helper_expected: str
    helper_detected: str
    python: str
    qt: str
    pyside: str
    openfortivpn: str
    openfortivpn_path: str
    strongswan: str
    swanctl: str


def collect_component_versions(*, helper_detected: str | None = None) -> ComponentVersions:
    """Gather local versions without probing the helper (no pkexec)."""
    qt = ""
    pyside = ""
    try:
        from PySide6 import __version__ as pyside_version
        from PySide6.QtCore import qVersion

        pyside = str(pyside_version or "")
        qt = str(qVersion() or "")
    except Exception:
        qt = ""
        pyside = ""
    of_path = PACKAGE_OPENFORTIVPN_PATH if Path(PACKAGE_OPENFORTIVPN_PATH).is_file() else ""
    of_version = packaged_openfortivpn_version() if of_path else ""
    detected = (helper_detected or "").strip() or "not detected"
    return ComponentVersions(
        application=__version__,
        helper_expected=HELPER_VERSION,
        helper_detected=detected,
        python=platform.python_version() or sys.version.split()[0],
        qt=qt or "not detected",
        pyside=pyside or "not detected",
        openfortivpn=of_version or "not detected",
        openfortivpn_path=of_path or "not detected",
        strongswan=query_dpkg_version("strongswan") or "not detected",
        swanctl=query_dpkg_version("strongswan-swanctl") or "not detected",
    )
