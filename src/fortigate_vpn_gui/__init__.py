# SPDX-License-Identifier: GPL-3.0-or-later
"""FortiGate VPN Linux GUI.

A native Linux desktop client for FortiGate SSL VPN and IPsec. Version 1.4.0
adds GUI profile management, import/export, and diagnostics on the frozen
v1.3.0 VPN backends. The GUI never runs as root.
"""

from __future__ import annotations

__all__ = ["APP_NAME", "__version__"]

__version__ = "1.4.0"
APP_NAME = "FortiGate VPN Linux GUI"
