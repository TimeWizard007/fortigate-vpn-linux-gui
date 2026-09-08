# SPDX-License-Identifier: GPL-3.0-or-later
"""Logs page tests. No disk persistence, network, or VPN tools."""

from __future__ import annotations

from fortigate_vpn_gui.gui.logs_page import LogsPage
from fortigate_vpn_gui.vpn.log_buffer import LogBuffer


def test_logs_page_append_clear_and_redaction(qapp) -> None:
    buffer = LogBuffer()
    page = LogsPage(buffer)
    record = buffer.append("openfortivpn", "password=hunter2 connected")
    page.append_record(record)
    text = page.text()
    assert "hunter2" not in text
    assert "password=***" in text
    assert "INFO" in text or "ERROR" in text
    page.clear()
    assert page.text() == ""
    assert buffer.records() == ()
    assert page._auto_scroll.isChecked() is True


def test_logs_page_copy(qapp) -> None:
    buffer = LogBuffer()
    page = LogsPage(buffer)
    record = buffer.append("vpn", "redacted line")
    page.append_record(record)
    page.copy_all()
    assert "redacted line" in qapp.clipboard().text()
