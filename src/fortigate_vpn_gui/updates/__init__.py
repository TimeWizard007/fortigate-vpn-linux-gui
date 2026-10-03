# SPDX-License-Identifier: GPL-3.0-or-later
"""Public GitHub Releases update checking. No telemetry."""

from __future__ import annotations

from fortigate_vpn_gui.updates.checker import (
    GITHUB_API_LATEST,
    UpdateCheckResult,
    check_for_update,
)
from fortigate_vpn_gui.updates.semver import compare_semver, parse_semver

__all__ = [
    "GITHUB_API_LATEST",
    "UpdateCheckResult",
    "check_for_update",
    "compare_semver",
    "parse_semver",
]
