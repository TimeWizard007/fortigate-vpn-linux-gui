# SPDX-License-Identifier: GPL-3.0-or-later
"""Marshal VPN backend events onto the Qt GUI thread."""

from __future__ import annotations

import queue
from collections.abc import Callable

from PySide6.QtCore import QObject, QTimer, Signal

from fortigate_vpn_gui.vpn.backend import VpnBackend, VpnEvent
from fortigate_vpn_gui.vpn.log_buffer import LogBuffer, LogRecord

_Put = Callable[[tuple[str, object]], None]


class _ThreadSafeMailbox:
    """Plain Python callback target. Safe to invoke from a helper worker.

    Must not be a QObject: PySide6 must not be entered from the worker thread.
    """

    __slots__ = ("_put", "_alive")

    def __init__(self, put: _Put) -> None:
        self._put = put
        self._alive = True

    def on_vpn(self, event: VpnEvent) -> None:
        self._post("vpn", event)

    def on_log(self, record: LogRecord) -> None:
        self._post("log", record)

    def post_shutdown(self) -> None:
        self._post("shutdown", None)

    def close(self) -> None:
        self._alive = False

    def _post(self, kind: str, payload: object) -> None:
        if not self._alive:
            return
        self._put((kind, payload))


class BackendEventPump(QObject):
    """Queue callbacks from worker threads and emit Qt signals."""

    state_changed = Signal(object)
    user_error = Signal(object)
    log_record = Signal(object)
    shutdown_complete = Signal()

    def __init__(
        self,
        backend: VpnBackend,
        log_buffer: LogBuffer,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._backend = backend
        self._log_buffer = log_buffer
        self._queue: queue.SimpleQueue[tuple[str, object]] = queue.SimpleQueue()
        self._subscribed = True
        self._mailbox = _ThreadSafeMailbox(self._queue.put)
        backend.subscribe(self._mailbox.on_vpn)
        log_buffer.subscribe(self._mailbox.on_log)
        self._timer = QTimer(self)
        self._timer.setInterval(25)
        self._timer.timeout.connect(self._drain)
        self._timer.start()

    @property
    def shutdown_mailbox(self) -> _ThreadSafeMailbox:
        return self._mailbox

    def schedule_drain(self) -> None:
        """GUI thread only. Flush tokens already posted (e.g. during closeEvent)."""
        self._drain()

    def stop(self) -> None:
        """Drop backend listeners and stop the timer. Safe to call twice."""
        self._timer.stop()
        self._mailbox.close()
        if not self._subscribed:
            return
        self._subscribed = False
        self._backend.unsubscribe(self._mailbox.on_vpn)
        self._log_buffer.unsubscribe(self._mailbox.on_log)

    def _drain(self) -> None:
        if not self._subscribed:
            return
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
            elif kind == "shutdown":
                self.shutdown_complete.emit()
