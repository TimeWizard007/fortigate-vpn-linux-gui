# SPDX-License-Identifier: GPL-3.0-or-later
"""Qt user interface.

Widgets in this package must not perform networking, authentication, or
privileged operations. Backend work belongs in ``fortigate_vpn_gui.vpn`` and
related non-GUI packages when those features are implemented.
"""

from __future__ import annotations

from fortigate_vpn_gui.gui.main_window import MainWindow

__all__ = ["MainWindow"]
