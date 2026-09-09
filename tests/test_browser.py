# SPDX-License-Identifier: GPL-3.0-or-later
"""System browser launcher tests. No real browser is opened."""

from __future__ import annotations

import subprocess

import pytest

from fortigate_vpn_gui.vpn.browser import BrowserLaunchError, SystemBrowserLauncher


def test_xdg_open_uses_list_argv_and_no_shell() -> None:
    seen: dict[str, object] = {}

    def runner(argv, **kwargs):
        seen["argv"] = argv
        seen["shell"] = kwargs.get("shell", False)
        return subprocess.CompletedProcess(argv, 0, "", "")

    launcher = SystemBrowserLauncher(
        which=lambda name: "/usr/bin/xdg-open" if name == "xdg-open" else None,
        runner=runner,
        webbrowser_open=lambda _url: (_ for _ in ()).throw(AssertionError("webbrowser")),
    )
    launcher.open("https://vpn.example.com/remote/saml/start")
    assert seen["argv"] == ["/usr/bin/xdg-open", "https://vpn.example.com/remote/saml/start"]
    assert seen["shell"] is False


def test_missing_browser_raises() -> None:
    launcher = SystemBrowserLauncher(
        which=lambda _name: None,
        runner=lambda *args, **kwargs: subprocess.CompletedProcess([], 1, "", ""),
        webbrowser_open=lambda _url: False,
    )
    with pytest.raises(BrowserLaunchError):
        launcher.open("https://vpn.example.com/remote/saml/start")
