# SPDX-License-Identifier: GPL-3.0-or-later
"""Privileged-helper interface used by the unprivileged GUI.

The GUI asks a separate helper, authorized with polkit, to start and stop
openfortivpn. This package must not invoke sudo, install systemd units, or
modify the host from the GUI process.
"""

from __future__ import annotations

from fortigate_vpn_gui.system.helper_client import (
    HelperClient,
    InProcessHelperClient,
    PolkitHelperClient,
    default_helper_client,
)
from fortigate_vpn_gui.system.polkit import POLKIT_ACTION_ID

__all__ = [
    "POLKIT_ACTION_ID",
    "HelperClient",
    "InProcessHelperClient",
    "PolkitHelperClient",
    "default_helper_client",
]
