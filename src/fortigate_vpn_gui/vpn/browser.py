# SPDX-License-Identifier: GPL-3.0-or-later
"""Open SAML sign-in pages in the user's system browser.

Uses ``xdg-open`` with a list argv when available, otherwise the stdlib
``webbrowser`` module. Never uses ``shell=True``. Tests inject a fake launcher.
"""

from __future__ import annotations

import shutil
import subprocess
import webbrowser
from collections.abc import Callable
from typing import Protocol

from fortigate_vpn_gui.vpn.url_safety import InvalidAuthUrl, validate_auth_url

Which = Callable[[str], str | None]
ProcessRunner = Callable[..., subprocess.CompletedProcess[str]]
WebBrowserOpen = Callable[[str], bool]


class BrowserLaunchError(RuntimeError):
    """The system browser could not be started."""


class BrowserLauncher(Protocol):
    def open(self, url: str) -> None: ...


class SystemBrowserLauncher:
    """Launch the desktop default browser for a validated http(s) URL."""

    def __init__(
        self,
        *,
        which: Which = shutil.which,
        runner: ProcessRunner | None = None,
        webbrowser_open: WebBrowserOpen | None = None,
    ) -> None:
        self._which = which
        self._runner = runner or _default_runner
        self._webbrowser_open = webbrowser_open or _default_webbrowser_open

    def open(self, url: str) -> None:
        try:
            validated = validate_auth_url(url)
        except InvalidAuthUrl as exc:
            raise BrowserLaunchError(
                "The sign-in URL from openfortivpn was not safe to open."
            ) from exc
        xdg = self._which("xdg-open")
        if xdg:
            try:
                completed = self._runner(
                    [xdg, validated],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    shell=False,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise BrowserLaunchError(_BROWSER_MISSING) from exc
            if completed.returncode == 0:
                return
        try:
            opened = self._webbrowser_open(validated)
        except Exception as exc:
            raise BrowserLaunchError(_BROWSER_MISSING) from exc
        if not opened:
            raise BrowserLaunchError(_BROWSER_MISSING)


def _default_runner(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, **kwargs)  # noqa: S603 — list argv, shell=False


def _default_webbrowser_open(url: str) -> bool:
    return bool(webbrowser.open(url, new=2, autoraise=True))


_BROWSER_MISSING = (
    "Could not open the system browser for SAML sign-in. "
    "Install a default browser or xdg-utils (xdg-open)."
)
