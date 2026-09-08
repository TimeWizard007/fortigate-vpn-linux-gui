# SPDX-License-Identifier: GPL-3.0-or-later
"""VPN connection states and related data types."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ConnectionState(Enum):
    """Deterministic VPN process states."""

    DISCONNECTED = "disconnected"
    STARTING = "starting"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    DISCONNECTING = "disconnecting"
    FAILED = "failed"
    WAITING_FOR_AUTH = "waiting_for_auth"


BUSY_STATES = frozenset(
    {
        ConnectionState.STARTING,
        ConnectionState.CONNECTING,
        ConnectionState.CONNECTED,
        ConnectionState.DISCONNECTING,
        ConnectionState.WAITING_FOR_AUTH,
    }
)

CONNECTABLE_STATES = frozenset(
    {
        ConnectionState.DISCONNECTED,
        ConnectionState.FAILED,
    }
)


class VpnErrorCode(Enum):
    """Stable error identifiers for user-facing messages."""

    SSO_NOT_SUPPORTED = "sso_not_supported"
    OPENFORTIVPN_MISSING = "openfortivpn_missing"
    FAILED_TO_START = "failed_to_start"
    PERMISSION_DENIED = "permission_denied"
    AUTH_FAILURE = "authentication_failure"
    UNEXPECTED_EXIT = "unexpected_exit"
    INVALID_PROFILE = "invalid_profile"
    ALREADY_BUSY = "already_busy"
    NOT_CONNECTED = "not_connected"


@dataclass(frozen=True)
class ProcessInfo:
    """Public process snapshot. Never includes credentials."""

    pid: int | None
    executable: str | None
    argv: tuple[str, ...]


@dataclass(frozen=True)
class VpnSnapshot:
    """Point-in-time backend status for the GUI and diagnostics."""

    state: ConnectionState
    profile_id: str | None
    profile_name: str | None
    error_code: VpnErrorCode | None
    error_message: str | None
    process: ProcessInfo | None


def state_label(state: ConnectionState) -> str:
    """Human-readable status for the Connection page."""
    return {
        ConnectionState.DISCONNECTED: "Disconnected",
        ConnectionState.STARTING: "Starting",
        ConnectionState.CONNECTING: "Connecting",
        ConnectionState.CONNECTED: "Connected",
        ConnectionState.DISCONNECTING: "Disconnecting",
        ConnectionState.FAILED: "Failed",
        ConnectionState.WAITING_FOR_AUTH: "Waiting for authentication",
    }[state]


ALLOWED_TRANSITIONS: dict[ConnectionState, frozenset[ConnectionState]] = {
    ConnectionState.DISCONNECTED: frozenset({ConnectionState.STARTING, ConnectionState.FAILED}),
    ConnectionState.STARTING: frozenset(
        {ConnectionState.CONNECTING, ConnectionState.FAILED, ConnectionState.DISCONNECTING}
    ),
    ConnectionState.CONNECTING: frozenset(
        {
            ConnectionState.CONNECTED,
            ConnectionState.FAILED,
            ConnectionState.DISCONNECTING,
            ConnectionState.WAITING_FOR_AUTH,
        }
    ),
    ConnectionState.WAITING_FOR_AUTH: frozenset(
        {ConnectionState.CONNECTING, ConnectionState.FAILED, ConnectionState.DISCONNECTING}
    ),
    ConnectionState.CONNECTED: frozenset({ConnectionState.DISCONNECTING, ConnectionState.FAILED}),
    ConnectionState.DISCONNECTING: frozenset(
        {ConnectionState.DISCONNECTED, ConnectionState.FAILED}
    ),
    ConnectionState.FAILED: frozenset({ConnectionState.DISCONNECTED, ConnectionState.STARTING}),
}
