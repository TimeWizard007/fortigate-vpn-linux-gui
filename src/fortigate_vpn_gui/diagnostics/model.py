# SPDX-License-Identifier: GPL-3.0-or-later
"""Diagnostic check result model.

Independent of Qt. Status values are stable identifiers for tests and reports.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class CheckStatus(Enum):
    """Outcome of one diagnostic check."""

    PASS = "pass"
    WARNING = "warning"
    FAIL = "fail"
    INFO = "info"
    NOT_TESTED = "not_tested"


STATUS_LABEL = {
    CheckStatus.PASS: "PASS",
    CheckStatus.WARNING: "WARNING",
    CheckStatus.FAIL: "FAIL",
    CheckStatus.INFO: "INFO",
    CheckStatus.NOT_TESTED: "NOT_TESTED",
}

GROUP_SYSTEM = "System"
GROUP_VPN = "VPN Components"
GROUP_PROFILE = "Profile / Gateway"
GROUP_NETWORK = "Network"
GROUP_TUNNEL = "Tunnel"

GROUP_ORDER = (
    GROUP_SYSTEM,
    GROUP_VPN,
    GROUP_PROFILE,
    GROUP_NETWORK,
    GROUP_TUNNEL,
)


@dataclass(frozen=True)
class DiagnosticCheck:
    """One independently reported diagnostic check."""

    id: str
    label: str
    status: CheckStatus
    summary: str
    detail: str = ""
    hint: str = ""
    group: str = ""


@dataclass(frozen=True)
class DiagnosticRun:
    """A complete diagnostics pass."""

    started_at: datetime
    finished_at: datetime
    checks: tuple[DiagnosticCheck, ...]
    cancelled: bool = False

    def check(self, check_id: str) -> DiagnosticCheck | None:
        for item in self.checks:
            if item.id == check_id:
                return item
        return None
