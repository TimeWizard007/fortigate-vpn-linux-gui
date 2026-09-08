# SPDX-License-Identifier: GPL-3.0-or-later
"""openfortivpn detection tests. The real binary is never executed."""

from __future__ import annotations

import subprocess

from fortigate_vpn_gui.vpn.detect import (
    detect_openfortivpn,
    locate_openfortivpn,
    parse_openfortivpn_version,
    query_openfortivpn_version,
)


def test_openfortivpn_detected() -> None:
    detection = detect_openfortivpn(which=lambda name: "/usr/sbin/openfortivpn")
    assert detection.available is True
    assert detection.path == "/usr/sbin/openfortivpn"
    assert detection.version is None


def test_openfortivpn_missing() -> None:
    detection = detect_openfortivpn(which=lambda name: None)
    assert detection.available is False
    assert detection.path is None
    assert locate_openfortivpn(which=lambda name: None) is None


def test_version_parsing() -> None:
    assert parse_openfortivpn_version("openfortivpn 1.22.1\n") == "1.22.1"
    assert parse_openfortivpn_version("OpenFortiVPN 1.23.0") == "1.23.0"


def test_version_query_uses_list_argv_not_shell() -> None:
    seen: dict[str, object] = {}

    def runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
        seen["argv"] = argv
        seen["shell"] = False
        return subprocess.CompletedProcess(argv, 0, stdout="openfortivpn 1.21.0\n", stderr="")

    version = query_openfortivpn_version("/usr/bin/openfortivpn", runner=runner)
    assert version == "1.21.0"
    assert seen["argv"] == ["/usr/bin/openfortivpn", "--version"]
    assert seen["shell"] is False
