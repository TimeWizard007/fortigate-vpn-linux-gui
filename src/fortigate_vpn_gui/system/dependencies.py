# SPDX-License-Identifier: GPL-3.0-or-later
"""Host runtime dependency preflight checks.

This module never installs packages and never invokes ``sudo``, ``pkexec``,
``apt``, or any other package manager. Commands shown to the user are built
only from a static, trusted catalog of Debian/Ubuntu package names.

GUI widgets must not reimplement these checks. Call
``check_gui_startup()`` from the application entry point before creating
the main window.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import re
import shutil
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

_OS_RELEASE_PATH = Path("/etc/os-release")

# Debian/Ubuntu package tokens only. Never interpolate untrusted strings.
_DEBIAN_PACKAGE_NAME = re.compile(r"^[a-z0-9][a-z0-9+.-]*$")
_SAFE_SONAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*\.so(\.[0-9]+)*$")
_SAFE_EXECUTABLE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")


class RequirementStage(Enum):
    """When a dependency becomes relevant.

    Only ``GUI_STARTUP`` is enforced at launch. ``VPN_BACKEND`` (openfortivpn)
    is required to connect, but missing openfortivpn does not block the GUI.
    """

    GUI_STARTUP = "gui_startup"
    VPN_BACKEND = "vpn_backend"
    SAML = "saml"
    PRIVILEGED_HELPER = "privileged_helper"


class ProbeKind(Enum):
    """How the host is probed. Package-manager queries are not used for pass/fail."""

    SHARED_LIBRARY = "shared_library"
    EXECUTABLE = "executable"


@dataclass(frozen=True)
class RuntimeDependency:
    """Static, trusted metadata for one runtime dependency."""

    dependency_id: str
    display_name: str
    reason: str
    stage: RequirementStage
    probe: ProbeKind
    probe_name: str
    ubuntu_packages: tuple[str, ...]


@dataclass(frozen=True)
class DistributionInfo:
    """Parsed ``/etc/os-release`` fields. Values are display-only, never commands."""

    os_id: str
    id_like: tuple[str, ...]
    version_id: str
    pretty_name: str

    @property
    def is_ubuntu(self) -> bool:
        return self.os_id == "ubuntu" or "ubuntu" in self.id_like


@dataclass(frozen=True)
class MissingDependency:
    """A failed check plus the trusted install command for that dependency."""

    dependency: RuntimeDependency
    install_command: str


@dataclass(frozen=True)
class PreflightReport:
    """Outcome of a preflight run. ``ok`` means the selected stages are satisfied."""

    distribution: DistributionInfo | None
    missing: tuple[MissingDependency, ...]
    install_command: str | None

    @property
    def ok(self) -> bool:
        return not self.missing


@dataclass(frozen=True)
class HostProbes:
    """Injectable host lookups so tests never touch apt, sudo, or the network."""

    library_exists: Callable[[str], bool]
    executable_exists: Callable[[str], bool]
    read_os_release: Callable[[], str | None]


DEPENDENCY_CATALOG: tuple[RuntimeDependency, ...] = (
    RuntimeDependency(
        dependency_id="libxcb-cursor",
        display_name="libxcb-cursor0",
        reason=(
            "PySide6/Qt 6 needs this XCB cursor library to create desktop windows. "
            "Without it the Qt xcb platform plugin fails to load."
        ),
        stage=RequirementStage.GUI_STARTUP,
        probe=ProbeKind.SHARED_LIBRARY,
        probe_name="libxcb-cursor.so.0",
        ubuntu_packages=("libxcb-cursor0",),
    ),
    RuntimeDependency(
        dependency_id="openfortivpn",
        display_name="openfortivpn",
        reason="FortiGate SSL VPN backend. Required to connect; the GUI still starts without it.",
        stage=RequirementStage.VPN_BACKEND,
        probe=ProbeKind.EXECUTABLE,
        probe_name="openfortivpn",
        ubuntu_packages=("openfortivpn",),
    ),
    RuntimeDependency(
        dependency_id="ppp",
        display_name="ppp",
        reason="Point-to-Point Protocol helper used by some SSL VPN setups.",
        stage=RequirementStage.VPN_BACKEND,
        probe=ProbeKind.EXECUTABLE,
        probe_name="pppd",
        ubuntu_packages=("ppp",),
    ),
    RuntimeDependency(
        dependency_id="pkexec",
        display_name="polkit (pkexec)",
        reason="Planned polkit helper runtime. The GUI must never run as root.",
        stage=RequirementStage.PRIVILEGED_HELPER,
        probe=ProbeKind.EXECUTABLE,
        probe_name="pkexec",
        ubuntu_packages=("pkexec",),
    ),
    RuntimeDependency(
        dependency_id="system-browser",
        display_name="system web browser (xdg-open)",
        reason="Planned SAML/SSO via the system browser and Microsoft Entra ID.",
        stage=RequirementStage.SAML,
        probe=ProbeKind.EXECUTABLE,
        probe_name="xdg-open",
        ubuntu_packages=("xdg-utils",),
    ),
)


def trusted_ubuntu_packages(
    catalog: Sequence[RuntimeDependency] = DEPENDENCY_CATALOG,
) -> frozenset[str]:
    """Return the allowlist of package names that may appear in install commands."""
    packages: set[str] = set()
    for dependency in catalog:
        packages.update(dependency.ubuntu_packages)
    return frozenset(packages)


def _validate_catalog(catalog: Sequence[RuntimeDependency]) -> None:
    for dependency in catalog:
        if not dependency.ubuntu_packages:
            raise RuntimeError(f"catalog entry {dependency.dependency_id!r} has no packages")
        for package in dependency.ubuntu_packages:
            if not _DEBIAN_PACKAGE_NAME.fullmatch(package):
                raise RuntimeError(
                    f"catalog entry {dependency.dependency_id!r} has an invalid package name"
                )


_validate_catalog(DEPENDENCY_CATALOG)


def ubuntu_install_command(
    packages: Sequence[str],
    *,
    catalog: Sequence[RuntimeDependency] = DEPENDENCY_CATALOG,
) -> str:
    """Build a display-only Ubuntu apt command from trusted package names.

    This function never executes the command. Unknown or malformed names raise
    ``ValueError`` so untrusted input cannot reach a shell string.
    """
    allowlist = trusted_ubuntu_packages(catalog)
    unique: list[str] = []
    for package in packages:
        if not _DEBIAN_PACKAGE_NAME.fullmatch(package):
            raise ValueError("refusing package name that is not a Debian package token")
        if package not in allowlist:
            raise ValueError("refusing package name that is not in the trusted catalog")
        if package not in unique:
            unique.append(package)
    if not unique:
        raise ValueError("no packages to install")
    return "sudo apt install " + " ".join(unique)


def parse_os_release(text: str) -> DistributionInfo | None:
    """Parse os-release(5) text. Empty input yields ``None``."""
    if not text.strip():
        return None
    fields: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        fields[key] = _unquote_os_release_value(value)
    os_id = fields.get("ID", "")
    if not os_id and not fields:
        return None
    id_like = tuple(fields.get("ID_LIKE", "").split())
    return DistributionInfo(
        os_id=os_id,
        id_like=id_like,
        version_id=fields.get("VERSION_ID", ""),
        pretty_name=fields.get("PRETTY_NAME", "") or fields.get("NAME", "") or os_id,
    )


def _unquote_os_release_value(raw: str) -> str:
    value = raw.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def read_os_release_text(path: Path = _OS_RELEASE_PATH) -> str | None:
    """Read os-release from disk. Missing files are not an error."""
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def loadable_shared_library(soname: str) -> bool:
    """Return True if the dynamic linker can resolve *soname*.

    Tries ``dlopen`` first, then ``ctypes.util.find_library`` as supporting
    evidence. Does not consult ``dpkg`` or ``apt``.
    """
    if not _SAFE_SONAME.fullmatch(soname):
        return False
    try:
        ctypes.CDLL(soname)
    except OSError:
        stem = _soname_to_find_library_name(soname)
        return bool(stem and ctypes.util.find_library(stem))
    return True


def _soname_to_find_library_name(soname: str) -> str:
    name = soname[3:] if soname.startswith("lib") else soname
    so_at = name.find(".so")
    if so_at == -1:
        return name
    return name[:so_at]


def executable_on_path(name: str, *, which: Callable[[str], str | None] = shutil.which) -> bool:
    """Return True if *name* is an executable on ``PATH``. Does not run it."""
    if not _SAFE_EXECUTABLE.fullmatch(name):
        return False
    return which(name) is not None


def default_probes() -> HostProbes:
    """Probes that inspect this process's real runtime, never the package manager."""
    return HostProbes(
        library_exists=loadable_shared_library,
        executable_exists=executable_on_path,
        read_os_release=read_os_release_text,
    )


class DependencyChecker:
    """Evaluate selected catalog stages against injectable host probes."""

    def __init__(
        self,
        *,
        probes: HostProbes | None = None,
        catalog: Sequence[RuntimeDependency] | None = None,
        stages: Sequence[RequirementStage] = (RequirementStage.GUI_STARTUP,),
    ) -> None:
        self._probes = probes or default_probes()
        self._catalog = tuple(DEPENDENCY_CATALOG if catalog is None else catalog)
        self._stages = frozenset(stages)

    def check(self) -> PreflightReport:
        distribution = parse_os_release(self._probes.read_os_release() or "")
        missing: list[MissingDependency] = []
        for dependency in self._catalog:
            if dependency.stage not in self._stages:
                continue
            if self._is_satisfied(dependency):
                continue
            missing.append(
                MissingDependency(
                    dependency=dependency,
                    install_command=ubuntu_install_command(
                        dependency.ubuntu_packages,
                        catalog=self._catalog,
                    ),
                )
            )
        combined = None
        if missing:
            packages = tuple(
                package for item in missing for package in item.dependency.ubuntu_packages
            )
            combined = ubuntu_install_command(packages, catalog=self._catalog)
        return PreflightReport(
            distribution=distribution,
            missing=tuple(missing),
            install_command=combined,
        )

    def _is_satisfied(self, dependency: RuntimeDependency) -> bool:
        if dependency.probe is ProbeKind.SHARED_LIBRARY:
            return self._probes.library_exists(dependency.probe_name)
        if dependency.probe is ProbeKind.EXECUTABLE:
            return self._probes.executable_exists(dependency.probe_name)
        return False


def check_gui_startup(checker: DependencyChecker | None = None) -> PreflightReport:
    """Run the GUI startup preflight (currently ``libxcb-cursor.so.0``)."""
    return (checker or DependencyChecker()).check()


def format_missing_dependencies_message(report: PreflightReport) -> str:
    """Human-readable explanation used by the dialog and by stderr."""
    lines = [
        "The application cannot start because required runtime dependencies are missing.",
        "",
    ]
    for item in report.missing:
        dep = item.dependency
        lines.append(f"Missing: {dep.display_name}")
        lines.append(f"Why: {dep.reason}")
        lines.append("")
    if report.install_command:
        lines.append("Recommended Ubuntu install command:")
        lines.append(report.install_command)
        lines.append("")
        lines.append("This application does not install system packages automatically.")
        lines.append(
            "It will not run sudo, pkexec, or apt for you. Copy the command and run it yourself."
        )
    if report.distribution is not None and report.distribution.pretty_name:
        lines.append("")
        lines.append(f"Detected system: {report.distribution.pretty_name}")
    return "\n".join(lines).rstrip() + "\n"


def missing_dependency_ids(report: PreflightReport) -> frozenset[str]:
    return frozenset(item.dependency.dependency_id for item in report.missing)


def qt_platform_can_start_safely(report: PreflightReport) -> bool:
    """Return False when creating QApplication would likely abort (missing xcb-cursor).

    A Qt dialog is shown only when this is True. The same text is always printed
    to stderr so X11 sessions still get an actionable message.
    """
    if "libxcb-cursor" not in missing_dependency_ids(report):
        return True
    if os.environ.get("QT_QPA_PLATFORM"):
        return True
    if os.environ.get("WAYLAND_DISPLAY"):
        return True
    return False


def prepare_qt_platform_for_missing_dependencies(report: PreflightReport) -> None:
    """Prefer Wayland when the xcb cursor library is missing and it is available.

    Does not override an existing ``QT_QPA_PLATFORM`` (tests and CI set offscreen).
    Never launches a package manager.
    """
    if os.environ.get("QT_QPA_PLATFORM"):
        return
    if "libxcb-cursor" not in missing_dependency_ids(report):
        return
    if os.environ.get("WAYLAND_DISPLAY"):
        os.environ["QT_QPA_PLATFORM"] = "wayland"
