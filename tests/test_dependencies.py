# SPDX-License-Identifier: GPL-3.0-or-later
"""Preflight dependency checker tests. These tests must not call apt, sudo, or the network."""

from __future__ import annotations

import pytest

from fortigate_vpn_gui.system.dependencies import (
    DEPENDENCY_CATALOG,
    DependencyChecker,
    HostProbes,
    RequirementStage,
    check_gui_startup,
    format_missing_dependencies_message,
    missing_dependency_ids,
    parse_os_release,
    ubuntu_install_command,
)

_UBUNTU_OS_RELEASE = """
PRETTY_NAME="Ubuntu 24.04.3 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
ID=ubuntu
ID_LIKE=debian
"""


def _probes(
    *,
    libraries: dict[str, bool] | None = None,
    executables: dict[str, bool] | None = None,
    os_release: str | None = _UBUNTU_OS_RELEASE,
) -> HostProbes:
    libraries = libraries or {}
    executables = executables or {}
    return HostProbes(
        library_exists=lambda name: libraries.get(name, False),
        executable_exists=lambda name: executables.get(name, False),
        read_os_release=lambda: os_release,
    )


def test_libxcb_cursor_present() -> None:
    checker = DependencyChecker(
        probes=_probes(libraries={"libxcb-cursor.so.0": True}),
    )
    report = checker.check()
    assert report.ok
    assert report.missing == ()
    assert report.install_command is None
    assert report.distribution is not None
    assert report.distribution.is_ubuntu


def test_libxcb_cursor_missing() -> None:
    checker = DependencyChecker(
        probes=_probes(libraries={"libxcb-cursor.so.0": False}),
    )
    report = checker.check()
    assert not report.ok
    assert missing_dependency_ids(report) == frozenset({"libxcb-cursor"})
    assert report.missing[0].dependency.display_name == "libxcb-cursor0"
    assert "xcb platform plugin" in report.missing[0].dependency.reason
    assert report.install_command == "sudo apt install libxcb-cursor0"


def test_ubuntu_install_command_from_trusted_metadata() -> None:
    assert ubuntu_install_command(("libxcb-cursor0",)) == "sudo apt install libxcb-cursor0"


def test_ubuntu_install_command_rejects_untrusted_input() -> None:
    with pytest.raises(ValueError, match="trusted catalog"):
        ubuntu_install_command(("evil-package",))
    with pytest.raises(ValueError, match="Debian package token"):
        ubuntu_install_command(("libxcb-cursor0; rm -rf /",))
    with pytest.raises(ValueError, match="Debian package token"):
        ubuntu_install_command(("$(reboot)",))


def test_ubuntu_install_command_deduplicates_packages() -> None:
    assert (
        ubuntu_install_command(("libxcb-cursor0", "libxcb-cursor0"))
        == "sudo apt install libxcb-cursor0"
    )


def test_gui_startup_does_not_require_openfortivpn_or_ppp() -> None:
    checker = DependencyChecker(
        probes=_probes(libraries={"libxcb-cursor.so.0": True}),
    )
    report = checker.check()
    assert report.ok
    assert "openfortivpn" not in missing_dependency_ids(report)
    assert "ppp" not in missing_dependency_ids(report)


def test_vpn_stage_can_report_openfortivpn_without_enforcing_it_at_startup() -> None:
    probes = _probes(
        libraries={"libxcb-cursor.so.0": True},
        executables={"openfortivpn": False, "pppd": False},
    )
    gui_report = DependencyChecker(
        probes=probes,
        stages=(RequirementStage.GUI_STARTUP,),
    ).check()
    vpn_report = DependencyChecker(
        probes=probes,
        stages=(RequirementStage.VPN_BACKEND,),
    ).check()
    assert gui_report.ok
    assert not vpn_report.ok
    assert missing_dependency_ids(vpn_report) == frozenset({"openfortivpn", "ppp"})
    assert vpn_report.install_command == "sudo apt install openfortivpn ppp"


def test_parse_os_release_ubuntu() -> None:
    info = parse_os_release(_UBUNTU_OS_RELEASE)
    assert info is not None
    assert info.os_id == "ubuntu"
    assert info.version_id == "24.04"
    assert info.is_ubuntu
    assert "Ubuntu 24.04" in info.pretty_name


def test_parse_os_release_empty() -> None:
    assert parse_os_release("") is None
    assert parse_os_release("   \n") is None


def test_format_message_includes_reason_and_static_command() -> None:
    report = DependencyChecker(
        probes=_probes(libraries={"libxcb-cursor.so.0": False}),
    ).check()
    message = format_missing_dependencies_message(report)
    assert "libxcb-cursor0" in message
    assert "sudo apt install libxcb-cursor0" in message
    assert "does not install system packages automatically" in message
    assert "Detected system: Ubuntu 24.04.3 LTS" in message


def test_check_gui_startup_uses_injected_checker() -> None:
    checker = DependencyChecker(
        probes=_probes(libraries={"libxcb-cursor.so.0": True}),
    )
    assert check_gui_startup(checker).ok


def test_catalog_includes_future_stages_but_startup_only_uses_gui() -> None:
    stages = {item.stage for item in DEPENDENCY_CATALOG}
    assert RequirementStage.GUI_STARTUP in stages
    assert RequirementStage.VPN_BACKEND in stages
    assert RequirementStage.SAML in stages
    assert RequirementStage.PRIVILEGED_HELPER in stages
    startup_ids = {
        item.dependency_id
        for item in DEPENDENCY_CATALOG
        if item.stage is RequirementStage.GUI_STARTUP
    }
    assert startup_ids == {"libxcb-cursor"}
