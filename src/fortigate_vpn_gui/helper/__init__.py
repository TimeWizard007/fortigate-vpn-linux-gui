# SPDX-License-Identifier: GPL-3.0-or-later
"""Minimal privileged VPN helper.

The helper is not a general command executor. It accepts structured connect,
disconnect, and status requests, validates every field again, and constructs
the openfortivpn argument vector itself.
"""

from __future__ import annotations

from fortigate_vpn_gui.helper.protocol import (
    HELPER_VERSION,
    INSTALLED_HELPER_PATH,
    POLKIT_ACTION_ID,
    PROTOCOL_VERSION,
)

__all__ = [
    "HELPER_VERSION",
    "INSTALLED_HELPER_PATH",
    "POLKIT_ACTION_ID",
    "PROTOCOL_VERSION",
]
