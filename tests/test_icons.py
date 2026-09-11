# SPDX-License-Identifier: GPL-3.0-or-later
"""Application icon tests. Offscreen Qt only."""

from __future__ import annotations

from fortigate_vpn_gui.gui.icons import application_icon
from fortigate_vpn_gui.metadata import ICON_NAME


def test_application_icon_is_available(qapp) -> None:
    icon = application_icon()
    assert icon.isNull() is False
    assert ICON_NAME == "fortigate-vpn-linux-gui"
