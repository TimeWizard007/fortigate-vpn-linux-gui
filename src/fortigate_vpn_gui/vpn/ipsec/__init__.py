# SPDX-License-Identifier: GPL-3.0-or-later
"""IPsec backend package.

Config generation and capability probing live here. The GUI never runs
charon or swanctl itself; the privileged helper owns those processes.
"""

from __future__ import annotations
