# SPDX-License-Identifier: GPL-3.0-or-later
"""Encrypted profile Backup/Restore. Separate from secret-free Export/Import."""

from __future__ import annotations

from fortigate_vpn_gui.backup.format import (
    AUTH_FAILURE_MESSAGE,
    MIN_PASSWORD_LENGTH,
    RESTORE_FAILED_MESSAGE,
    BackupError,
    BackupFormatError,
)
from fortigate_vpn_gui.backup.payload import RestorePlan, RestoreSummaryRow, format_restore_summary
from fortigate_vpn_gui.backup.service import (
    RestoreBlockedError,
    create_backup,
    preflight_restore,
    restore_backup,
    validate_backup_password,
)

__all__ = [
    "AUTH_FAILURE_MESSAGE",
    "MIN_PASSWORD_LENGTH",
    "RESTORE_FAILED_MESSAGE",
    "BackupError",
    "BackupFormatError",
    "RestoreBlockedError",
    "RestorePlan",
    "RestoreSummaryRow",
    "create_backup",
    "format_restore_summary",
    "preflight_restore",
    "restore_backup",
    "validate_backup_password",
]
