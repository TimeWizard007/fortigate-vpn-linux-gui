# SPDX-License-Identifier: GPL-3.0-or-later
"""openfortivpn capability discovery and SAML-aware executable selection.

Application startup does not probe binaries. Connect (SSO) and Diagnostics
run version/help queries with a list argv and ``shell=False``.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from fortigate_vpn_gui.command import OPENFORTIVPN_NAME, is_openfortivpn_executable

_VERSION_RE = re.compile(r"openfortivpn\s+([0-9][\w.+-]*)", re.IGNORECASE)

VersionRunner = Callable[[list[str]], subprocess.CompletedProcess[str]]


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


WELL_KNOWN_OPENFORTIVPN_PATHS: tuple[str, ...] = (
    "/usr/local/bin/openfortivpn",
    "/usr/bin/openfortivpn",
)

PathExists = Callable[[str], bool]
Which = Callable[[str], str | None]


@dataclass(frozen=True)
class OpenfortivpnCapabilities:
    """Capabilities of one openfortivpn executable."""

    executable_path: str
    version: str | None
    supports_saml: bool
    supports_cookie_stdin: bool
    source: str


@dataclass(frozen=True)
class OpenfortivpnDetection:
    """Result of locating openfortivpn, optionally with version and capabilities."""

    available: bool
    path: str | None
    version: str | None
    supports_saml: bool | None = None
    supports_cookie_stdin: bool | None = None
    source: str | None = None
    candidates: tuple[OpenfortivpnCapabilities, ...] = ()


def default_is_executable(path: str) -> bool:
    """Return True if *path* is an executable file. Does not run it."""
    try:
        return os.path.isfile(path) and os.access(path, os.X_OK)
    except OSError:
        return False


def discover_openfortivpn_paths(
    *,
    which: Which = shutil.which,
    is_executable: PathExists = default_is_executable,
    extra_paths: Sequence[str] = WELL_KNOWN_OPENFORTIVPN_PATHS,
) -> tuple[tuple[str, str], ...]:
    """Return ``(path, source)`` pairs. PATH first, then well-known locations.

    Does not execute any binary. Duplicate real paths are dropped.
    """
    ordered: list[tuple[str, str]] = []
    seen_real: set[str] = set()

    def _add(path: str | None, source: str) -> None:
        if not path or not is_openfortivpn_executable(path):
            return
        try:
            real = str(Path(path).resolve())
        except OSError:
            real = path
        if real in seen_real:
            return
        seen_real.add(real)
        ordered.append((path, source))

    path_hit = which(OPENFORTIVPN_NAME)
    if path_hit:
        _add(path_hit, "path")
    for extra in extra_paths:
        if is_executable(extra):
            source = "usr_local" if extra.startswith("/usr/local/") else "usr_bin"
            if extra not in {"/usr/local/bin/openfortivpn", "/usr/bin/openfortivpn"}:
                source = "well_known"
            _add(extra, source)
    return tuple(ordered)


def parse_help_capabilities(text: str) -> tuple[bool, bool]:
    """Return ``(supports_saml, supports_cookie_stdin)`` from help/usage text."""
    lowered = text.lower()
    return "--saml-login" in lowered, "--cookie-on-stdin" in lowered


def query_openfortivpn_help(
    executable: str,
    *,
    runner: VersionRunner = default_version_runner,
) -> str:
    """Run ``openfortivpn --help``. Used for capability detection, not GUI startup."""
    if not is_openfortivpn_executable(executable):
        return ""
    argv = [executable, "--help"]
    try:
        completed = runner(argv)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return (completed.stdout or "") + (completed.stderr or "")


def query_openfortivpn_version(
    executable: str,
    *,
    runner: VersionRunner = default_version_runner,
) -> str | None:
    """Run ``openfortivpn --version``."""
    if not is_openfortivpn_executable(executable):
        return None
    argv = [executable, "--version"]
    try:
        completed = runner(argv)
    except (OSError, subprocess.TimeoutExpired):
        return None
    output = (completed.stdout or "") + (completed.stderr or "")
    return parse_openfortivpn_version(output)


def probe_openfortivpn(
    path: str,
    source: str,
    *,
    runner: VersionRunner = default_version_runner,
) -> OpenfortivpnCapabilities:
    """Probe version and help flags for one executable."""
    version = query_openfortivpn_version(path, runner=runner)
    help_text = query_openfortivpn_help(path, runner=runner)
    supports_saml, supports_cookie_stdin = parse_help_capabilities(help_text)
    return OpenfortivpnCapabilities(
        executable_path=path,
        version=version,
        supports_saml=supports_saml,
        supports_cookie_stdin=supports_cookie_stdin,
        source=source,
    )


def _version_key(version: str | None) -> tuple[int, ...]:
    if not version:
        return (0,)
    parts = [int(part) for part in re.split(r"[^\d]+", version) if part.isdigit()]
    return tuple(parts) if parts else (0,)


def _path_rank(path: str) -> int:
    if path.startswith("/usr/local/"):
        return 2
    if path.startswith("/usr/bin/"):
        return 0
    return 1


def select_openfortivpn(
    candidates: Sequence[OpenfortivpnCapabilities],
    *,
    require_saml: bool = False,
    prefer_saml: bool = False,
) -> OpenfortivpnCapabilities | None:
    """Choose an executable. Never falls back to an insecure auth method."""
    if not candidates:
        return None
    pool: Sequence[OpenfortivpnCapabilities] = candidates
    if require_saml:
        pool = tuple(item for item in candidates if item.supports_saml)
        if not pool:
            return None
        return max(
            pool, key=lambda item: (_version_key(item.version), _path_rank(item.executable_path))
        )
    if prefer_saml:
        saml = tuple(item for item in candidates if item.supports_saml)
        if saml:
            return max(
                saml,
                key=lambda item: (_version_key(item.version), _path_rank(item.executable_path)),
            )
    return candidates[0]


def locate_openfortivpn(which: Which = shutil.which) -> str | None:
    """Return the PATH openfortivpn if present. Does not execute it."""
    path = which(OPENFORTIVPN_NAME)
    if path and is_openfortivpn_executable(path):
        return path
    return None


def detect_openfortivpn(
    *,
    which: Which = shutil.which,
    include_version: bool = False,
    include_capabilities: bool = False,
    runner: VersionRunner = default_version_runner,
    is_executable: PathExists = default_is_executable,
    extra_paths: Sequence[str] = WELL_KNOWN_OPENFORTIVPN_PATHS,
) -> OpenfortivpnDetection:
    """Detect openfortivpn. Version/help are queried only when requested."""
    if include_capabilities:
        discovered = discover_openfortivpn_paths(
            which=which,
            is_executable=is_executable,
            extra_paths=extra_paths,
        )
        if not discovered:
            return OpenfortivpnDetection(available=False, path=None, version=None)
        candidates = tuple(
            probe_openfortivpn(path, source, runner=runner) for path, source in discovered
        )
        selected = select_openfortivpn(candidates, prefer_saml=True)
        if selected is None:
            return OpenfortivpnDetection(
                available=False,
                path=None,
                version=None,
                candidates=candidates,
            )
        return OpenfortivpnDetection(
            available=True,
            path=selected.executable_path,
            version=selected.version,
            supports_saml=selected.supports_saml,
            supports_cookie_stdin=selected.supports_cookie_stdin,
            source=selected.source,
            candidates=candidates,
        )

    path = locate_openfortivpn(which)
    if path is None:
        return OpenfortivpnDetection(available=False, path=None, version=None)
    version = query_openfortivpn_version(path, runner=runner) if include_version else None
    return OpenfortivpnDetection(available=True, path=path, version=version)


def resolve_executable(
    *,
    require_saml: bool,
    which: Which = shutil.which,
    runner: VersionRunner = default_version_runner,
    is_executable: PathExists = default_is_executable,
    extra_paths: Sequence[str] = WELL_KNOWN_OPENFORTIVPN_PATHS,
) -> OpenfortivpnCapabilities | None:
    """Resolve a binary for connect. Probes help/version; not used at GUI startup."""
    discovered = discover_openfortivpn_paths(
        which=which,
        is_executable=is_executable,
        extra_paths=extra_paths,
    )
    if not discovered:
        return None
    if not require_saml:
        path, source = discovered[0]
        return OpenfortivpnCapabilities(
            executable_path=path,
            version=None,
            supports_saml=False,
            supports_cookie_stdin=False,
            source=source,
        )
    candidates = tuple(
        probe_openfortivpn(path, source, runner=runner) for path, source in discovered
    )
    return select_openfortivpn(candidates, require_saml=True)
