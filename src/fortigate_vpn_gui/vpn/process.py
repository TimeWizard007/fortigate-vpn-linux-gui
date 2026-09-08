# SPDX-License-Identifier: GPL-3.0-or-later
"""openfortivpn process wrapper.

Uses ``subprocess.Popen`` with an argument list and ``shell=False``. stdout
and stderr are captured on a background thread so the GUI is not blocked.
"""

from __future__ import annotations

import os
import signal
import subprocess
import threading
from collections.abc import Callable
from typing import Protocol

OutputCallback = Callable[[str], None]
ExitCallback = Callable[[int], None]


class VpnProcess(Protocol):
    """Minimal process handle used by the backend (real or fake)."""

    argv: list[str]

    @property
    def pid(self) -> int | None: ...

    def start(self) -> None: ...

    def terminate(self) -> None: ...

    def kill(self) -> None: ...

    def poll(self) -> int | None: ...

    def wait(self, timeout: float | None = None) -> int: ...


ProcessFactory = Callable[[list[str], OutputCallback, ExitCallback], VpnProcess]


class SubprocessVpnProcess:
    """Real openfortivpn child process."""

    def __init__(
        self,
        argv: list[str],
        on_output: OutputCallback,
        on_exit: ExitCallback,
    ) -> None:
        self.argv = list(argv)
        self._on_output = on_output
        self._on_exit = on_exit
        self._proc: subprocess.Popen[str] | None = None
        self._reader: threading.Thread | None = None

    @property
    def pid(self) -> int | None:
        if self._proc is None:
            return None
        return self._proc.pid

    def start(self) -> None:
        self._proc = subprocess.Popen(  # noqa: S603 — list argv, shell=False
            self.argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            shell=False,
            start_new_session=True,
        )
        self._reader = threading.Thread(
            target=self._read_output,
            name="openfortivpn-log",
            daemon=True,
        )
        self._reader.start()

    def terminate(self) -> None:
        self._signal_child(signal.SIGTERM, fallback=lambda proc: proc.terminate())

    def kill(self) -> None:
        self._signal_child(signal.SIGKILL, fallback=lambda proc: proc.kill())

    def _signal_child(
        self,
        sig: signal.Signals,
        fallback: Callable[[subprocess.Popen[str]], None],
    ) -> None:
        if self._proc is None or self._proc.poll() is not None:
            return
        try:
            os.killpg(self._proc.pid, sig)
        except OSError:
            fallback(self._proc)

    def poll(self) -> int | None:
        if self._proc is None:
            return None
        return self._proc.poll()

    def wait(self, timeout: float | None = None) -> int:
        if self._proc is None:
            return 0
        return self._proc.wait(timeout=timeout)

    def _read_output(self) -> None:
        assert self._proc is not None
        stdout = self._proc.stdout
        if stdout is not None:
            for line in stdout:
                self._on_output(line.rstrip("\n"))
        code = self._proc.wait()
        self._on_exit(code)


def default_process_factory(
    argv: list[str],
    on_output: OutputCallback,
    on_exit: ExitCallback,
) -> VpnProcess:
    return SubprocessVpnProcess(argv, on_output, on_exit)
