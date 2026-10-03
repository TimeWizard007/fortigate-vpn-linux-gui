# SPDX-License-Identifier: GPL-3.0-or-later
"""Read-only local install/APT context. Never upgrades packages."""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from fortigate_vpn_gui import __version__
from fortigate_vpn_gui.diagnostics.platform_info import query_dpkg_version
from fortigate_vpn_gui.helper.protocol import HELPER_VERSION, PROTOCOL_VERSION
from fortigate_vpn_gui.metadata import INSTALLED_LAUNCHER_PATH
from fortigate_vpn_gui.updates.checker import UpdateCheckResult
from fortigate_vpn_gui.updates.semver import compare_semver, parse_semver

PACKAGE_NAME = "fortigate-vpn-linux-gui"
APT_SOURCE_PATH = Path("/etc/apt/sources.list.d/fortigate-vpn-linux-gui.sources")
PACKAGED_VENV_PREFIX = "/usr/lib/fortigate-vpn-linux-gui/"
APT_UPGRADE_COMMANDS = "sudo apt update\nsudo apt install --only-upgrade fortigate-vpn-linux-gui"
NO_SELF_UPDATE_NOTE = "This application does not install system updates itself."

InstallMethod = Literal["apt", "deb", "source"]


@dataclass(frozen=True)
class InstallInfo:
    """Safe-to-display installation context. No VPN identifiers."""

    application: str
    debian_version: str
    apt_candidate: str
    method: InstallMethod
    apt_source_present: bool
    helper_expected: str = HELPER_VERSION
    protocol: int = PROTOCOL_VERSION

    def method_label(self) -> str:
        if self.method == "apt":
            return "APT"
        if self.method == "deb":
            return "Debian package"
        return "source"


def detect_install_info(
    *,
    application: str | None = None,
    debian_version: str | None = None,
    apt_candidate: str | None = None,
    apt_source_present: bool | None = None,
    executable: str | None = None,
    launcher_path: str = INSTALLED_LAUNCHER_PATH,
    apt_source_path: Path = APT_SOURCE_PATH,
) -> InstallInfo:
    """Inspect local packaging without privilege or network."""
    app = application if application is not None else __version__
    dpkg = debian_version if debian_version is not None else query_dpkg_version(PACKAGE_NAME)
    source_present = (
        apt_source_present
        if apt_source_present is not None
        else _apt_source_exists(apt_source_path)
    )
    candidate = apt_candidate if apt_candidate is not None else query_apt_candidate(PACKAGE_NAME)
    packaged = _looks_packaged(executable=executable, launcher_path=launcher_path)
    if packaged and source_present:
        method: InstallMethod = "apt"
    elif packaged:
        method = "deb"
    else:
        method = "source"
    return InstallInfo(
        application=app,
        debian_version=dpkg,
        apt_candidate=candidate,
        method=method,
        apt_source_present=source_present,
    )


def query_apt_candidate(package: str) -> str:
    """Return the APT Candidate version, or empty when unknown."""
    installed, candidate = query_apt_policy(package)
    del installed
    if candidate in {"", "(none)"}:
        return ""
    return candidate


def query_apt_policy(package: str) -> tuple[str, str]:
    """Return ``(Installed, Candidate)`` from ``apt-cache policy``. Read-only."""
    if not package or any(ch in package for ch in " \t\n/;|&"):
        return "", ""
    env = os.environ.copy()
    env["LC_ALL"] = "C"
    env["LANG"] = "C"
    try:
        completed = subprocess.run(  # noqa: S603 — argv list, shell False
            ["apt-cache", "policy", package],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
            shell=False,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "", ""
    if completed.returncode != 0:
        return "", ""
    return parse_apt_policy(completed.stdout or "")


def parse_apt_policy(text: str) -> tuple[str, str]:
    """Parse ``apt-cache policy`` C-locale output."""
    installed = ""
    candidate = ""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("Installed:"):
            installed = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("Candidate:"):
            candidate = stripped.split(":", 1)[1].strip()
    if installed == "(none)":
        installed = ""
    if candidate == "(none)":
        candidate = ""
    return installed, candidate


def debian_upstream_version(value: str) -> str:
    """Return the X.Y.Z upstream from a Debian ``X.Y.Z-N`` version."""
    text = str(value or "").strip()
    if not text or text == "(none)":
        return ""
    upstream = text.split("-", 1)[0]
    if parse_semver(upstream) is None:
        return ""
    return upstream


def format_update_status(result: UpdateCheckResult, info: InstallInfo) -> str:
    """User-facing update text. Errors never become update-available."""
    lines: list[str] = []
    if result.status == "up_to_date":
        lines.append("Up to date")
    elif result.status == "update_available" and result.latest:
        lines.append("Update available")
        lines.append(f"Installed: {result.installed}")
        lines.append(f"Available: {result.latest}")
    else:
        lines.append("Unable to check for updates")
    if info.debian_version:
        lines.append(f"Debian package: {info.debian_version}")
    if info.apt_candidate:
        lines.append(f"APT candidate: {info.apt_candidate}")
    lines.append(f"Install method: {info.method_label()}")
    lines.extend(format_update_instructions(result, info).splitlines())
    return "\n".join(line for line in lines if line)


def format_update_instructions(result: UpdateCheckResult, info: InstallInfo) -> str:
    """Copyable instructions. Never executed by the application."""
    if result.status != "update_available" or not result.latest:
        return NO_SELF_UPDATE_NOTE
    parts = [NO_SELF_UPDATE_NOTE]
    github_newer_than_candidate = _github_newer_than_debian(result.latest, info.apt_candidate)
    if info.method == "apt":
        parts.append("Install with:")
        parts.append(APT_UPGRADE_COMMANDS)
        if github_newer_than_candidate and info.apt_candidate:
            parts.append(
                f"GitHub has {result.latest}; the APT candidate is still {info.apt_candidate}."
            )
    elif info.method == "deb":
        parts.append(
            "Install a newer .deb from GitHub Releases, or add the project "
            "APT repository and upgrade with apt."
        )
    else:
        parts.append(
            "You are running from source. A newer GitHub release exists; "
            "this checkout is not upgraded by apt."
        )
    return "\n".join(parts)


def _github_newer_than_debian(latest: str, debian_version: str) -> bool:
    upstream = debian_upstream_version(debian_version)
    if not upstream:
        return False
    order = compare_semver(upstream, latest)
    return order is not None and order < 0


def _looks_packaged(*, executable: str | None, launcher_path: str) -> bool:
    python = executable if executable is not None else sys.executable
    if python.startswith(PACKAGED_VENV_PREFIX):
        return True
    try:
        if (
            launcher_path
            and Path(launcher_path).is_file()
            and os.path.realpath(python) == os.path.realpath(launcher_path)
        ):
            return True
    except OSError:
        return False
    return False


def _apt_source_exists(path: Path) -> bool:
    try:
        return path.is_file()
    except OSError:
        return False
