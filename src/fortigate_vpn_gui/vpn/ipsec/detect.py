# SPDX-License-Identifier: GPL-3.0-or-later
"""Discover distro strongSwan binaries. PATH is not used for execution."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

APPROVED_CHARON_PATHS: tuple[str, ...] = (
    "/usr/lib/ipsec/charon",
    "/usr/libexec/ipsec/charon",
)
APPROVED_SWANCTL_PATHS: tuple[str, ...] = (
    "/usr/sbin/swanctl",
    "/usr/bin/swanctl",
)

PathExists = Callable[[str], bool]


@dataclass(frozen=True)
class IpsecBackendCapabilities:
    """Non-secret view of the local strongSwan installation."""

    charon_path: str | None
    swanctl_path: str | None
    available: bool
    source: str


def default_is_executable(path: str) -> bool:
    candidate = Path(path)
    try:
        return candidate.is_file() and os_access_executable(candidate)
    except OSError:
        return False


def os_access_executable(path: Path) -> bool:
    import os

    return os.access(path, os.X_OK)


def is_approved_charon_path(path: str) -> bool:
    """Return True when *path* is an allowlisted charon location."""
    return _is_approved_path(path, APPROVED_CHARON_PATHS)


def is_approved_swanctl_path(path: str) -> bool:
    """Return True when *path* is an allowlisted swanctl location."""
    return _is_approved_path(path, APPROVED_SWANCTL_PATHS)


def _is_approved_path(path: str, allowed: tuple[str, ...]) -> bool:
    if path in allowed:
        return True
    try:
        real = str(Path(path).resolve())
    except OSError:
        return False
    return real in allowed


def discover_ipsec_backend(
    *,
    is_executable: PathExists = default_is_executable,
) -> IpsecBackendCapabilities:
    """Return allowlisted charon/swanctl paths that exist."""
    charon = next((path for path in APPROVED_CHARON_PATHS if is_executable(path)), None)
    swanctl = next((path for path in APPROVED_SWANCTL_PATHS if is_executable(path)), None)
    available = charon is not None and swanctl is not None
    if available:
        source = "distro"
    elif charon is None and swanctl is None:
        source = "missing"
    else:
        source = "incomplete"
    return IpsecBackendCapabilities(
        charon_path=charon,
        swanctl_path=swanctl,
        available=available,
        source=source,
    )
