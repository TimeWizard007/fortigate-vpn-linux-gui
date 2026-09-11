# SPDX-License-Identifier: GPL-3.0-or-later
"""Approved openfortivpn discovery tests. Real binaries are never executed."""

from __future__ import annotations

import subprocess

from fortigate_vpn_gui.helper.executables import (
    discover_approved_openfortivpn,
    resolve_approved_executable,
)
from fortigate_vpn_gui.helper.protocol import (
    APPROVED_OPENFORTIVPN_PATHS,
    HELPER_VERSION,
    PACKAGE_OPENFORTIVPN_PATH,
)

_HELP_OLD = "Usage: openfortivpn [--cookie-on-stdin]\n"
_HELP_SAML = "Usage: openfortivpn [--saml-login] [--cookie-on-stdin]\n"


def _runner_for(versions: dict[str, str], helps: dict[str, str]):
    def runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
        exe = argv[0]
        flag = argv[1]
        if flag == "--version":
            return subprocess.CompletedProcess(argv, 0, stdout=versions[exe] + "\n", stderr="")
        if flag == "--help":
            return subprocess.CompletedProcess(argv, 0, stdout=helps[exe], stderr="")
        raise AssertionError(argv)

    return runner


def test_helper_protocol_remains_0_7_0() -> None:
    assert HELPER_VERSION == "0.7.0"


def test_approved_paths_prefer_package_owned_binary() -> None:
    assert APPROVED_OPENFORTIVPN_PATHS[0] == PACKAGE_OPENFORTIVPN_PATH
    assert APPROVED_OPENFORTIVPN_PATHS[1] == "/usr/local/bin/openfortivpn"
    assert APPROVED_OPENFORTIVPN_PATHS[2] == "/usr/bin/openfortivpn"


def test_discover_approved_ignores_path_and_unlisted_locations() -> None:
    present = {
        PACKAGE_OPENFORTIVPN_PATH,
        "/usr/bin/openfortivpn",
        "/tmp/openfortivpn",
    }
    discovered = discover_approved_openfortivpn(
        is_executable=lambda path: path in present,
        extra_paths=(*APPROVED_OPENFORTIVPN_PATHS, "/tmp/openfortivpn"),
    )
    assert [path for path, _source in discovered] == [
        PACKAGE_OPENFORTIVPN_PATH,
        "/usr/bin/openfortivpn",
    ]
    assert discovered[0][1] == "package"
    assert discovered[1][1] == "usr_bin"


def test_resolve_approved_uses_package_owned_saml_binary() -> None:
    runner = _runner_for(
        {
            PACKAGE_OPENFORTIVPN_PATH: "openfortivpn 1.24.1",
            "/usr/local/bin/openfortivpn": "openfortivpn 1.24.1",
            "/usr/bin/openfortivpn": "openfortivpn 1.21.0",
        },
        {
            PACKAGE_OPENFORTIVPN_PATH: _HELP_SAML,
            "/usr/local/bin/openfortivpn": _HELP_SAML,
            "/usr/bin/openfortivpn": _HELP_OLD,
        },
    )
    selected = resolve_approved_executable(
        require_saml=True,
        runner=runner,
        is_executable=lambda path: path in set(APPROVED_OPENFORTIVPN_PATHS),
    )
    assert selected is not None
    assert selected.executable_path == PACKAGE_OPENFORTIVPN_PATH
    assert selected.supports_saml is True
    assert selected.version == "1.24.1"


def test_resolve_approved_stock_binary_cannot_satisfy_saml() -> None:
    runner = _runner_for(
        {"/usr/bin/openfortivpn": "openfortivpn 1.21.0"},
        {"/usr/bin/openfortivpn": _HELP_OLD},
    )
    saml = resolve_approved_executable(
        require_saml=True,
        runner=runner,
        is_executable=lambda path: path == "/usr/bin/openfortivpn",
    )
    password = resolve_approved_executable(
        require_saml=False,
        runner=runner,
        is_executable=lambda path: path == "/usr/bin/openfortivpn",
    )
    assert saml is None
    assert password is not None
    assert password.executable_path == "/usr/bin/openfortivpn"
    assert password.supports_saml is False
