# SPDX-License-Identifier: GPL-3.0-or-later
"""In-memory application/backend log buffer.

Lines are redacted on insert. Nothing is written to disk in v0.3.x.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from threading import Lock

from fortigate_vpn_gui.vpn.log_redaction import redact_log_line


class LogLevel(Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


@dataclass(frozen=True)
class LogRecord:
    timestamp: datetime
    severity: LogLevel
    source: str
    message: str

    def format_line(self) -> str:
        stamp = self.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        return f"{stamp} {self.severity.value.upper():<7} [{self.source}] {self.message}"


LogListener = Callable[[LogRecord], None]


class LogBuffer:
    """Bounded, thread-safe log store."""

    def __init__(self, *, max_records: int = 2000) -> None:
        self._records: deque[LogRecord] = deque(maxlen=max_records)
        self._lock = Lock()
        self._listeners: list[LogListener] = []

    def subscribe(self, callback: LogListener) -> None:
        self._listeners.append(callback)

    def unsubscribe(self, callback: LogListener) -> None:
        with self._lock:
            self._listeners = [item for item in self._listeners if item is not callback]

    def append(self, source: str, message: str, *, severity: LogLevel | None = None) -> LogRecord:
        redacted = redact_log_line(message)
        level = severity if severity is not None else infer_severity(redacted)
        record = LogRecord(
            timestamp=datetime.now(tz=timezone.utc).astimezone(),
            severity=level,
            source=source,
            message=redacted,
        )
        with self._lock:
            self._records.append(record)
            listeners = list(self._listeners)
        for listener in listeners:
            listener(record)
        return record

    def clear(self) -> None:
        with self._lock:
            self._records.clear()

    def records(self) -> tuple[LogRecord, ...]:
        with self._lock:
            return tuple(self._records)

    def formatted_text(self) -> str:
        return "\n".join(record.format_line() for record in self.records())


def infer_severity(message: str) -> LogLevel:
    lowered = message.lower()
    if "error" in lowered or "failed" in lowered or "fatal" in lowered:
        return LogLevel.ERROR
    if "warn" in lowered:
        return LogLevel.WARNING
    if "debug" in lowered:
        return LogLevel.DEBUG
    return LogLevel.INFO


def iter_formatted(records: Iterable[LogRecord]) -> str:
    return "\n".join(record.format_line() for record in records)
