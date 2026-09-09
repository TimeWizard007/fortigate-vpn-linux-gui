# SPDX-License-Identifier: GPL-3.0-or-later
"""FortiGate VPN Linux GUI.

A native Linux desktop client for FortiGate SSL VPN. Version 0.5.x adds a
polkit privileged helper and explicit FortiGate certificate pinning. The GUI
never runs as root.
"""

from __future__ import annotations

__all__ = ["APP_NAME", "__version__"]

__version__ = "0.5.0"
APP_NAME = "FortiGate VPN Linux GUI"
