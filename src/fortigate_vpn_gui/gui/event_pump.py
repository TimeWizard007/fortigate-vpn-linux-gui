# SPDX-License-Identifier: GPL-3.0-or-later
"""Marshal VPN backend events onto the Qt GUI thread."""

from __future__ import annotations

import queue

from PySide6.QtCore import QObject, QTimer, Signal

from fortigate_vpn_gui.vpn.backend import VpnBackend, VpnEvent
from fortigate_vpn_gui.vpn.log_buffer import LogBuffer, LogRecord


class BackendEventPump(QObject):
    """Queue callbacks from worker threads and emit Qt signals."""

    state_changed = Signal(object)
    user_error = Signal(object)
    log_record = Signal(object)

    def __init__(
        self,
        backend: VpnBackend,
        log_buffer: LogBuffer,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._queue: queue.SimpleQueue[tuple[str, object]] = queue.SimpleQueue()
        backend.subscribe(self._on_vpn_event)
        log_buffer.subscribe(self._on_log)
        self._timer = QTimer(self)
        self._timer.setInterval(25)
        self._timer.timeout.connect(self._drain)
        self._timer.start()

    def _on_vpn_event(self, event: VpnEvent) -> None:
        self._queue.put(("vpn", event))

    def _on_log(self, record: LogRecord) -> None:
        self._queue.put(("log", record))

    def _drain(self) -> None:
        while True:
            try:
                kind, payload = self._queue.get_nowait()
            except queue.Empty:
                return
            if kind == "log":
                self.log_record.emit(payload)
            elif kind == "vpn":
                event = payload
                assert isinstance(event, VpnEvent)
                if event.kind == "error":
                    self.user_error.emit(event)
                self.state_changed.emit(event.snapshot)
