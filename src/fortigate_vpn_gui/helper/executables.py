# SPDX-License-Identifier: GPL-3.0-or-later
"""Select an approved openfortivpn executable inside the helper.

PATH entries outside the allowlist are ignored. Capability is taken from
``--help`` / ``--version``, not from assuming a path. Preference order is
the package-owned binary, then ``/usr/local/bin``, then ``/usr/bin``.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

from fortigate_vpn_gui.command import is_openfortivpn_executable
from fortigate_vpn_gui.helper.argv import is_approved_openfortivpn_path
from fortigate_vpn_gui.helper.protocol import APPROVED_OPENFORTIVPN_PATHS
from fortigate_vpn_gui.vpn.capabilities import (
    OpenfortivpnCapabilities,
    VersionRunner,
    approved_path_source,
    default_is_executable,
    default_version_runner,
    probe_openfortivpn,
    select_openfortivpn,
)

PathExists = Callable[[str], bool]


def discover_approved_openfortivpn(
    *,
    is_executable: PathExists = default_is_executable,
    extra_paths: Sequence[str] = APPROVED_OPENFORTIVPN_PATHS,
) -> tuple[tuple[str, str], ...]:
    """Return allowlisted openfortivpn paths that exist. Does not search PATH."""
    ordered: list[tuple[str, str]] = []
    for path in extra_paths:
        if path not in APPROVED_OPENFORTIVPN_PATHS:
            continue
        if not is_openfortivpn_executable(path):
            continue
        if not is_executable(path):
            continue
        ordered.append((path, approved_path_source(path)))
    return tuple(ordered)


def resolve_approved_executable(
    *,
    require_saml: bool,
    runner: VersionRunner = default_version_runner,
    is_executable: PathExists = default_is_executable,
    extra_paths: Sequence[str] = APPROVED_OPENFORTIVPN_PATHS,
) -> OpenfortivpnCapabilities | None:
    """Choose an approved binary. SAML connect requires ``--saml-login`` support."""
    discovered = discover_approved_openfortivpn(
        is_executable=is_executable,
        extra_paths=extra_paths,
    )
    if not discovered:
        return None
    candidates = tuple(
        probe_openfortivpn(path, source, runner=runner) for path, source in discovered
    )
    if require_saml:
        selected = select_openfortivpn(candidates, require_saml=True)
    else:
        selected = select_openfortivpn(candidates, prefer_saml=False)
    if selected is None:
        return None
    if not is_approved_openfortivpn_path(selected.executable_path):
        return None
    return selected
