# SPDX-License-Identifier: GPL-3.0-or-later
"""Classify openfortivpn output without exposing raw secrets to the GUI."""

from __future__ import annotations

from enum import Enum


class OutputHint(Enum):
    NONE = "none"
    CONNECTED = "connected"
    PERMISSION = "permission"
    AUTH_FAILURE = "auth_failure"


_CONNECTED = (
    "connected to gateway",
    "tunnel is up",
    "interface ppp",
    "ppp0 is up",
    "ppp1 is up",
)

_PERMISSION = (
    "permission denied",
    "operation not permitted",
    "must be root",
    "need to be root",
    "only root can",
    "you need to be root",
    "not permitted",
)

_AUTH = (
    "authentication failed",
    "authenticate failed",
    "login failed",
    "auth failed",
    "401 unauthorized",
    "403 forbidden",
    "incorrect password",
    "wrong password",
)


def classify_output(line: str) -> OutputHint:
    """Return a coarse hint derived from a redacted log line."""
    lowered = line.lower()
    if any(marker in lowered for marker in _PERMISSION):
        return OutputHint.PERMISSION
    if any(marker in lowered for marker in _AUTH):
        return OutputHint.AUTH_FAILURE
    if any(marker in lowered for marker in _CONNECTED):
        return OutputHint.CONNECTED
    return OutputHint.NONE
