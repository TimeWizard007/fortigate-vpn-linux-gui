# SPDX-License-Identifier: GPL-3.0-or-later
"""In-memory logs page with redacted VPN and application messages."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from fortigate_vpn_gui.vpn.log_buffer import LogBuffer, LogRecord


class LogsPage(QWidget):
    """Read-only log view. Logs are not written to disk."""

    def __init__(self, log_buffer: LogBuffer, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._buffer = log_buffer

        title = QLabel("Logs")
        title.setStyleSheet("font-size: 20px; font-weight: 600;")
        intro = QLabel(
            "Application and openfortivpn output. Secrets are redacted. "
            "Logs stay in memory for this session and are not saved to disk."
        )
        intro.setWordWrap(True)

        self._view = QPlainTextEdit()
        self._view.setObjectName("logsView")
        self._view.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self._view.setReadOnly(True)
        self._view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)

        self._auto_scroll = QCheckBox("Auto-scroll")
        self._auto_scroll.setObjectName("logsAutoScroll")
        self._auto_scroll.setChecked(True)

        clear_button = QPushButton("Clear")
        clear_button.setObjectName("logsClearButton")
        clear_button.clicked.connect(self.clear)
        copy_button = QPushButton("Copy")
        copy_button.setObjectName("logsCopyButton")
        copy_button.clicked.connect(self.copy_all)

        buttons = QHBoxLayout()
        buttons.addWidget(clear_button)
        buttons.addWidget(copy_button)
        buttons.addWidget(self._auto_scroll)
        buttons.addStretch(1)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 24, 16)
        layout.setSpacing(12)
        layout.addWidget(title)
        layout.addWidget(intro)
        layout.addWidget(self._view, stretch=1)
        layout.addLayout(buttons)
        self.reload()

    def reload(self) -> None:
        self._view.setPlainText(self._buffer.formatted_text())
        if self._auto_scroll.isChecked():
            self._scroll_to_end()

    def append_record(self, record: LogRecord) -> None:
        if self._view.toPlainText():
            self._view.appendPlainText(record.format_line())
        else:
            self._view.setPlainText(record.format_line())
        if self._auto_scroll.isChecked():
            self._scroll_to_end()

    def clear(self) -> None:
        self._buffer.clear()
        self._view.clear()

    def copy_all(self) -> None:
        self._view.selectAll()
        self._view.copy()
        cursor = self._view.textCursor()
        cursor.clearSelection()
        self._view.setTextCursor(cursor)

    def text(self) -> str:
        return self._view.toPlainText()

    def _scroll_to_end(self) -> None:
        scrollbar = self._view.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
