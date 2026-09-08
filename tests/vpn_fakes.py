# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared fake openfortivpn process for backend tests."""

from __future__ import annotations

import threading
from subprocess import TimeoutExpired

from fortigate_vpn_gui.vpn.backend import VpnBackend
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


class VpnHarness:
    def __init__(self) -> None:
        self.process: FakeVpnProcess | None = None
        self.log = LogBuffer()
        self.backend = VpnBackend(
            log_buffer=self.log,
            process_factory=self.factory,
            locator=lambda: "/usr/bin/openfortivpn",
            grace_seconds=0.05,
        )

    def factory(self, argv: list[str], on_output, on_exit) -> FakeVpnProcess:
        self.process = FakeVpnProcess(argv, on_output, on_exit)
        return self.process
