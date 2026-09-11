# SPDX-License-Identifier: GPL-3.0-or-later
"""openfortivpn capability discovery tests. Real binaries are never executed."""

from __future__ import annotations

import subprocess

from fortigate_vpn_gui.vpn.capabilities import (
    detect_openfortivpn,
    discover_openfortivpn_paths,
    format_saml_unsupported_message,
    parse_help_capabilities,
    probe_openfortivpn,
    select_openfortivpn,
)


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


_HELP_OLD = "Usage: openfortivpn [--cookie-on-stdin] [--username]\n"
_HELP_SAML = "Usage: openfortivpn [--cookie-on-stdin] [--saml-login]\n"


def test_parse_help_old_binary_without_saml() -> None:
    saml, cookie = parse_help_capabilities(_HELP_OLD)
    assert saml is False
    assert cookie is True


def test_parse_help_new_binary_with_saml() -> None:
    saml, cookie = parse_help_capabilities(_HELP_SAML)
    assert saml is True
    assert cookie is True


def test_selects_saml_capable_1_24_over_1_21() -> None:
    runner = _runner_for(
        {
            "/usr/bin/openfortivpn": "openfortivpn 1.21.0",
            "/usr/local/bin/openfortivpn": "openfortivpn 1.24.1",
        },
        {
            "/usr/bin/openfortivpn": _HELP_OLD,
            "/usr/local/bin/openfortivpn": _HELP_SAML,
        },
    )
    old = probe_openfortivpn("/usr/bin/openfortivpn", "usr_bin", runner=runner)
    new = probe_openfortivpn("/usr/local/bin/openfortivpn", "usr_local", runner=runner)
    assert old.version == "1.21.0"
    assert old.supports_saml is False
    assert new.version == "1.24.1"
    assert new.supports_saml is True
    selected = select_openfortivpn((old, new), require_saml=True)
    assert selected is not None
    assert selected.executable_path == "/usr/local/bin/openfortivpn"


def test_only_old_binary_cannot_satisfy_saml() -> None:
    runner = _runner_for(
        {"/usr/bin/openfortivpn": "openfortivpn 1.21.0"},
        {"/usr/bin/openfortivpn": _HELP_OLD},
    )
    old = probe_openfortivpn("/usr/bin/openfortivpn", "usr_bin", runner=runner)
    assert select_openfortivpn((old,), require_saml=True) is None
    assert select_openfortivpn((old,), require_saml=False) is old


def test_no_binary_discovered() -> None:
    paths = discover_openfortivpn_paths(which=lambda _name: None, is_executable=lambda _path: False)
    assert paths == ()
    detection = detect_openfortivpn(
        which=lambda _name: None,
        is_executable=lambda _path: False,
        include_capabilities=True,
        runner=lambda argv: subprocess.CompletedProcess(argv, 1, "", ""),
    )
    assert detection.available is False
    assert detection.path is None


def test_selects_package_owned_binary_before_usr_local() -> None:
    runner = _runner_for(
        {
            "/usr/libexec/fortigate-vpn-linux-gui/openfortivpn": "openfortivpn 1.24.1",
            "/usr/local/bin/openfortivpn": "openfortivpn 1.24.1",
            "/usr/bin/openfortivpn": "openfortivpn 1.21.0",
        },
        {
            "/usr/libexec/fortigate-vpn-linux-gui/openfortivpn": _HELP_SAML,
            "/usr/local/bin/openfortivpn": _HELP_SAML,
            "/usr/bin/openfortivpn": _HELP_OLD,
        },
    )
    package = probe_openfortivpn(
        "/usr/libexec/fortigate-vpn-linux-gui/openfortivpn", "package", runner=runner
    )
    local = probe_openfortivpn("/usr/local/bin/openfortivpn", "usr_local", runner=runner)
    distro = probe_openfortivpn("/usr/bin/openfortivpn", "usr_bin", runner=runner)
    selected = select_openfortivpn((package, local, distro), require_saml=True)
    assert selected is not None
    assert selected.executable_path == "/usr/libexec/fortigate-vpn-linux-gui/openfortivpn"


def test_capability_probe_uses_list_argv() -> None:
    seen: list[list[str]] = []

    def runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
        seen.append(list(argv))
        if argv[1] == "--version":
            return subprocess.CompletedProcess(argv, 0, "openfortivpn 1.24.1\n", "")
        return subprocess.CompletedProcess(argv, 0, _HELP_SAML, "")

    probe_openfortivpn("/usr/local/bin/openfortivpn", "usr_local", runner=runner)
    assert seen[0] == ["/usr/local/bin/openfortivpn", "--version"]
    assert seen[1] == ["/usr/local/bin/openfortivpn", "--help"]


def test_saml_unsupported_message_includes_detected_version() -> None:
    text = format_saml_unsupported_message("1.21.0")
    assert "1.21.0" in text
    assert "does not support SAML/SSO" in text
    assert "SAML-capable openfortivpn" in text
