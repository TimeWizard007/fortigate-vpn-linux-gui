# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for the application entry-point helpers."""

from __future__ import annotations

from fortigate_vpn_gui.app import main
from fortigate_vpn_gui.gui.main_window import MainWindow
from fortigate_vpn_gui.runtime import is_running_as_root
from fortigate_vpn_gui.system.dependencies import (
    DependencyChecker,
    HostProbes,
    PreflightReport,
)


def _missing_xcb_report() -> PreflightReport:
    probes = HostProbes(
        library_exists=lambda name: False,
        executable_exists=lambda name: False,
        read_os_release=lambda: 'ID=ubuntu\nPRETTY_NAME="Ubuntu 24.04.3 LTS"\n',
    )
    return DependencyChecker(probes=probes).check()


def test_is_running_as_root_is_boolean() -> None:
    assert isinstance(is_running_as_root(), bool)


def test_main_returns_1_when_running_as_root(qapp, capsys) -> None:
    presented: list[str] = []

    def boom_window() -> MainWindow:
        raise AssertionError("main window must not be created when running as root")

    exit_code = main(
        argv=["fortigate-vpn-gui"],
        running_as_root=lambda: True,
        check_dependencies=lambda: _ok_report(),
        present_root_error=lambda: presented.append("root"),
        create_window=boom_window,
    )
    assert exit_code == 1
    assert presented == ["root"]
    capsys.readouterr()


def test_main_preflight_failure_does_not_create_window(qapp, capsys) -> None:
    presented: list[PreflightReport] = []
    report = _missing_xcb_report()
    assert not report.ok

    def boom_window() -> MainWindow:
        raise AssertionError("main window must not be created when preflight fails")

    exit_code = main(
        argv=["fortigate-vpn-gui"],
        running_as_root=lambda: False,
        check_dependencies=lambda: report,
        present_dependency_error=presented.append,
        create_window=boom_window,
    )
    assert exit_code == 1
    assert presented == [report]
    stderr = capsys.readouterr().err
    assert "sudo apt install libxcb-cursor0" in stderr
    assert "does not install system packages automatically" in stderr


def _ok_report() -> PreflightReport:
    probes = HostProbes(
        library_exists=lambda name: True,
        executable_exists=lambda name: True,
        read_os_release=lambda: 'ID=ubuntu\nPRETTY_NAME="Ubuntu 24.04.3 LTS"\n',
    )
    return DependencyChecker(probes=probes).check()
