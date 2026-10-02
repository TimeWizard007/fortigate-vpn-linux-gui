# SPDX-License-Identifier: GPL-3.0-or-later
"""Narrow classifiers for known-benign private-charon messages.

Stock strongSwan 5.9.13 still reports CFG_REPLY attributes our plugin
already consumed. Those lines are not IKE/EAP/CHILD_SA failures.
Do not drop unrelated ERROR text.
"""

from __future__ import annotations

import re

# Types FortiGate sends that stock ike_config has no initiator handler for.
# INTERNAL_IP4_SUBNET is consumed by fvl-forticlient-vid (LIVE-PROVEN).
BENIGN_CFG_ATTRIBUTE_TYPES = (
    "INTERNAL_IP4_NETMASK",
    "INTERNAL_IP4_SUBNET",
    "INTERNAL_IP6_SUBNET",
    "APPLICATION_VERSION",
)

_BENIGN_CFG_ATTRIBUTE_RE = re.compile(
    r"handling (" + "|".join(BENIGN_CFG_ATTRIBUTE_TYPES) + r") attribute failed\s*$"
)


def is_benign_charon_noise(line: str) -> bool:
    """True when *line* is a known-benign stock CFG handler miss."""
    return _BENIGN_CFG_ATTRIBUTE_RE.search(line) is not None
