# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared fake openfortivpn process for backend tests."""

from __future__ import annotations

import threading
from subprocess import TimeoutExpired

from fortigate_vpn_gui.system.helper_client import InProcessHelperClient
from fortigate_vpn_gui.vpn.backend import VpnBackend
from fortigate_vpn_gui.vpn.browser import BrowserLaunchError
from fortigate_vpn_gui.vpn.capabilities import OpenfortivpnCapabilities
from fortigate_vpn_gui.vpn.log_buffer import LogBuffer


class FakeVpnProcess:
    def __init__(self, argv: list[str], on_output, on_exit) -> None:
        self.argv = list(argv)
        self._on_output = on_output
        self._on_exit = on_exit
        self.pid = 4242
        self._code: int | None = None
        self._done = threading.Event()
        self.started = False
        self.terminate_called = False
        self.kill_called = False
        self.exit_on_terminate = True
        self.raise_on_start: BaseException | None = None

    def start(self) -> None:
        if self.raise_on_start is not None:
            raise self.raise_on_start
        self.started = True

    def emit(self, line: str) -> None:
        self._on_output(line)

    def finish(self, code: int) -> None:
        if self._code is not None:
            return
        self._code = code
        self._done.set()
        self._on_exit(code)

    def terminate(self) -> None:
        self.terminate_called = True
        if self.exit_on_terminate:
            self.finish(0)

    def kill(self) -> None:
        self.kill_called = True
        if self._code is None:
            self.finish(-9)

    def poll(self) -> int | None:
        return self._code

    def wait(self, timeout: float | None = None) -> int:
        if self._code is not None:
            return self._code
        if not self._done.wait(timeout):
            raise TimeoutExpired(self.argv, timeout if timeout is not None else 0)
        assert self._code is not None
        return self._code


class FakeBrowser:
    def __init__(self) -> None:
        self.opened: list[str] = []
        self.fail = False

    def open(self, url: str) -> None:
        if self.fail:
            raise BrowserLaunchError(
                "Could not open the system browser for SAML sign-in. "
                "Install a default browser or xdg-utils (xdg-open)."
            )
        self.opened.append(url)


class FakeScheduler:
    def __init__(self) -> None:
        self.delay: float | None = None
        self.callback = None
        self.cancelled = False

    def __call__(self, delay: float, callback) -> object:
        self.delay = delay
        self.callback = callback
        self.cancelled = False
        return self.cancel

    def cancel(self) -> None:
        self.cancelled = True
        self.callback = None

    def fire(self) -> None:
        callback = self.callback
        if callback is not None:
            callback()


class VpnHarness:
    def __init__(
        self,
        *,
        executable: str | None = "/usr/local/bin/openfortivpn",
        version: str = "1.24.1",
        supports_saml: bool = True,
        supports_cookie_stdin: bool = True,
        helper_installed: bool = True,
        polkit_available: bool = True,
        privilege_denied: bool = False,
        helper_version: str = "0.5.0",
        version_mismatch: bool = False,
    ) -> None:
        self._process: FakeVpnProcess | None = None
        self.log = LogBuffer()
        self.browser = FakeBrowser()
        self.scheduler = FakeScheduler()
        if executable is None:
            self.capabilities = None
        else:
            self.capabilities = OpenfortivpnCapabilities(
                executable_path=executable,
                version=version,
                supports_saml=supports_saml,
                supports_cookie_stdin=supports_cookie_stdin,
                source="test",
            )
        self.helper = InProcessHelperClient(
            process_factory=self.factory,
            selector=self.selector,
            installed=helper_installed,
            helper_version=helper_version,
            polkit_available=polkit_available,
            denied=privilege_denied,
            version_mismatch=version_mismatch,
            grace_seconds=0.05,
        )
        self.backend = VpnBackend(
            log_buffer=self.log,
            helper=self.helper,
            locator=lambda: executable,
            selector=self.selector,
            browser=self.browser,
            schedule_timeout=self.scheduler,
            grace_seconds=0.05,
            saml_timeout_seconds=120.0,
        )

    @property
    def process(self) -> FakeVpnProcess | None:
        owned = self.helper.process
        if isinstance(owned, FakeVpnProcess):
            return owned
        return self._process

    @process.setter
    def process(self, value: FakeVpnProcess | None) -> None:
        self._process = value

    def selector(self, require_saml: bool) -> OpenfortivpnCapabilities | None:
        if self.capabilities is None:
            return None
        if require_saml and not self.capabilities.supports_saml:
            return None
        return self.capabilities

    def factory(self, argv: list[str], on_output, on_exit) -> FakeVpnProcess:
        self._process = FakeVpnProcess(argv, on_output, on_exit)
        return self._process
