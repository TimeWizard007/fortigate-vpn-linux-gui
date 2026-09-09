# SPDX-License-Identifier: GPL-3.0-or-later
"""polkit action identifiers for the privileged VPN helper.

The GUI never launches itself with pkexec. pkexec is used only to start the
minimal helper. This module does not invoke pkexec.
"""

from __future__ import annotations

from fortigate_vpn_gui.helper.protocol import INSTALLED_HELPER_PATH, POLKIT_ACTION_ID

POLKIT_POLICY_FILENAME = "com.fortigate-vpn-linux-gui.policy"
POLKIT_POLICY_INSTALL_PATH = "/usr/share/polkit-1/actions/com.fortigate-vpn-linux-gui.policy"

__all__ = [
    "INSTALLED_HELPER_PATH",
    "POLKIT_ACTION_ID",
    "POLKIT_POLICY_FILENAME",
    "POLKIT_POLICY_INSTALL_PATH",
]
