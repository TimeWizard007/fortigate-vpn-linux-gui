# SPDX-License-Identifier: GPL-3.0-or-later
"""VPN backend package.

The GUI talks to ``VpnBackend``. That service starts ``openfortivpn`` as the
current user, tracks connection state, and redacts process output. Privileged
helpers and SAML/SSO are not implemented in v0.3.x.
"""

from __future__ import annotations

from fortigate_vpn_gui.vpn.backend import VpnBackend, VpnEvent
from fortigate_vpn_gui.vpn.detect import OpenfortivpnDetection, detect_openfortivpn
from fortigate_vpn_gui.vpn.models import ConnectionState, ProcessInfo, VpnSnapshot

__all__ = [
    "ConnectionState",
    "OpenfortivpnDetection",
    "ProcessInfo",
    "VpnBackend",
    "VpnEvent",
    "VpnSnapshot",
    "detect_openfortivpn",
]
