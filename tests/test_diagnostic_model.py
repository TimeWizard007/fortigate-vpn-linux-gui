# SPDX-License-Identifier: GPL-3.0-or-later
"""Diagnostic result model tests."""

from __future__ import annotations

from datetime import datetime, timezone

from fortigate_vpn_gui.diagnostics.model import (
    STATUS_LABEL,
    CheckStatus,
    DiagnosticCheck,
    DiagnosticRun,
)


def test_check_status_values() -> None:
    assert CheckStatus.PASS.value == "pass"
    assert CheckStatus.WARNING.value == "warning"
    assert CheckStatus.FAIL.value == "fail"
    assert CheckStatus.INFO.value == "info"
    assert CheckStatus.NOT_TESTED.value == "not_tested"
    assert STATUS_LABEL[CheckStatus.PASS] == "PASS"
    assert STATUS_LABEL[CheckStatus.WARNING] == "WARNING"
    assert STATUS_LABEL[CheckStatus.FAIL] == "FAIL"
    assert STATUS_LABEL[CheckStatus.INFO] == "INFO"
    assert STATUS_LABEL[CheckStatus.NOT_TESTED] == "NOT_TESTED"


def test_diagnostic_run_lookup() -> None:
    check = DiagnosticCheck(
        id="vpn.helper",
        label="VPN helper",
        status=CheckStatus.PASS,
        summary="ok",
    )
    now = datetime.now(timezone.utc)
    run = DiagnosticRun(started_at=now, finished_at=now, checks=(check,))
    assert run.check("vpn.helper") is check
    assert run.check("missing") is None
