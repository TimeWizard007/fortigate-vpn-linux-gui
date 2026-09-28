# SPDX-License-Identifier: GPL-3.0-or-later
"""Local platform facts for diagnostics. Does not dump the environment."""

from __future__ import annotations

import os
import platform
import subprocess
from collections.abc import Callable
from pathlib import Path

ReadText = Callable[[str], str]


def read_os_pretty_name(read_text: ReadText | None = None) -> str:
    """Return a short distribution label from ``/etc/os-release`` when present."""
    reader = read_text or _read_text
    try:
        text = reader("/etc/os-release")
    except OSError:
        return platform.system() or "unknown"
    for line in text.splitlines():
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip().strip('"')
    return platform.system() or "unknown"


def kernel_release() -> str:
    """Return the kernel release string."""
    return platform.release() or "unknown"


def architecture() -> str:
    """Return the hardware architecture."""
    return platform.machine() or "unknown"


def query_dpkg_version(package: str) -> str:
    """Return an installed Debian package version without running VPN binaries."""
    if not package or any(ch in package for ch in " \t\n/;|&"):
        return ""
    try:
        completed = subprocess.run(  # noqa: S603 — argv list, shell False
            ["dpkg-query", "-W", "-f=${Version}", package],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    if completed.returncode != 0:
        return ""
    return (completed.stdout or "").strip()


def ssl_backend_label(*, version: str | None = None) -> str:
    """Return a short SSL backend line for About and diagnostics."""
    detected = (version or packaged_openfortivpn_version() or "").strip()
    if detected:
        return f"SSL backend: openfortivpn {detected}"
    return "SSL backend: openfortivpn (not detected)"


def packaged_openfortivpn_version() -> str:
    """Return the known packaged openfortivpn version when the binary is present.

    Does not execute the binary.
    """
    from fortigate_vpn_gui.helper.protocol import PACKAGE_OPENFORTIVPN_PATH

    try:
        if Path(PACKAGE_OPENFORTIVPN_PATH).is_file():
            return "1.24.1"
    except OSError:
        return ""
    return ""


def ipsec_backend_label(*, version: str | None = None) -> str:
    """Return a short IPsec backend line. Uses dpkg, not swanctl --version."""
    detected = (version or query_dpkg_version("strongswan") or "").strip()
    if detected:
        return f"IPsec backend: strongSwan {detected}"
    return "IPsec backend: strongSwan (not detected)"


def desktop_session_type() -> str:
    """Return X11 / Wayland / unknown from the session type only."""
    value = (os.environ.get("XDG_SESSION_TYPE") or "").strip().lower()
    if value in {"x11", "wayland", "tty", "unspecified"}:
        if value == "x11":
            return "X11"
        if value == "wayland":
            return "Wayland"
        return value
    return "unknown"


def _read_text(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")
