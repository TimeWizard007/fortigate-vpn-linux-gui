# SPDX-License-Identifier: GPL-3.0-or-later
"""Locate openfortivpn and parse ``openfortivpn --version``.

Version probing is for diagnostics only. Application startup must not run
the binary; ``locate_openfortivpn`` uses ``PATH`` lookup alone.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from fortigate_vpn_gui.vpn.command import OPENFORTIVPN_NAME, is_openfortivpn_executable

_VERSION_RE = re.compile(r"openfortivpn\s+([0-9][\w.+-]*)", re.IGNORECASE)

VersionRunner = Callable[[list[str]], subprocess.CompletedProcess[str]]


@dataclass(frozen=True)
class OpenfortivpnDetection:
    """Result of a PATH lookup, optionally with a version string."""

    available: bool
    path: str | None
    version: str | None


def locate_openfortivpn(which: Callable[[str], str | None] = shutil.which) -> str | None:
    """Return the openfortivpn path if it is on PATH. Does not execute it."""
    path = which(OPENFORTIVPN_NAME)
    if path and is_openfortivpn_executable(path):
        return path
    return None


def parse_openfortivpn_version(text: str) -> str | None:
    """Extract a version token from ``openfortivpn --version`` output."""
    match = _VERSION_RE.search(text)
    if match:
        return match.group(1)
    stripped = text.strip()
    if re.fullmatch(r"[0-9][\w.+-]*", stripped):
        return stripped
    return None


def default_version_runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
    """Run *argv* without a shell. Tests should inject a fake runner instead."""
    return subprocess.run(  # noqa: S603 — argv is a list, shell is False
        argv,
        check=False,
        capture_output=True,
        text=True,
        timeout=3,
        shell=False,
    )


def query_openfortivpn_version(
    executable: str,
    *,
    runner: VersionRunner = default_version_runner,
) -> str | None:
    """Run ``openfortivpn --version``. Used by Diagnostics, not GUI startup."""
    if not is_openfortivpn_executable(executable):
        return None
    argv = [executable, "--version"]
    try:
        completed = runner(argv)
    except (OSError, subprocess.TimeoutExpired):
        return None
    output = (completed.stdout or "") + (completed.stderr or "")
    return parse_openfortivpn_version(output)


def detect_openfortivpn(
    *,
    which: Callable[[str], str | None] = shutil.which,
    include_version: bool = False,
    runner: VersionRunner = default_version_runner,
) -> OpenfortivpnDetection:
    """Detect openfortivpn. Version is queried only when *include_version* is True."""
    path = locate_openfortivpn(which)
    if path is None:
        return OpenfortivpnDetection(available=False, path=None, version=None)
    version = query_openfortivpn_version(path, runner=runner) if include_version else None
    return OpenfortivpnDetection(available=True, path=path, version=version)


def argv_uses_shell(kwargs: Sequence[object] | dict[str, object]) -> bool:
    """Helper for tests: True if a subprocess kwargs mapping requested a shell."""
    if isinstance(kwargs, dict):
        return bool(kwargs.get("shell", False))
    return False
