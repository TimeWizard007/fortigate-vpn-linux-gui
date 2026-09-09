# SPDX-License-Identifier: GPL-3.0-or-later
"""VPN package.

Import leaf modules directly. This package initializer does not import
``VpnBackend`` or other GUI-side services, so the privileged helper can load
``vpn.capabilities``, ``vpn.process``, and similar modules without creating an
import cycle.
"""

from __future__ import annotations
