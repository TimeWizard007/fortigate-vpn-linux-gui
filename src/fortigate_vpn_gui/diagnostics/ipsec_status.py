# SPDX-License-Identifier: GPL-3.0-or-later
"""Parse IPsec XFRM policies without exposing keys or secrets."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Sequence
from dataclasses import dataclass

_SRC_DST = re.compile(r"^src\s+(\S+)\s+dst\s+(\S+)\s*$")
_DIR = re.compile(r"^\s*dir\s+(in|out|fwd)\b")
UNUSABLE_SELECTOR_WARNING = (
    "Tunnel established but no internal traffic selectors are installed."
)


@dataclass(frozen=True)
class XfrmPolicy:
    """One IPsec policy. Addresses only; no keys."""

    src: str
    dst: str
    direction: str


def parse_xfrm_policies(text: str) -> tuple[XfrmPolicy, ...]:
    """Parse ``ip xfrm policy`` output into src/dst/dir tuples."""
    policies: list[XfrmPolicy] = []
    src = ""
    dst = ""
    for raw in text.splitlines():
        line = raw.strip()
        match = _SRC_DST.match(line)
        if match is not None:
            src, dst = match.group(1), match.group(2)
            continue
        direction = _DIR.match(raw)
        if direction is not None and src and dst:
            policies.append(XfrmPolicy(src=src, dst=dst, direction=direction.group(1)))
            src, dst = "", ""
    return tuple(policies)


def network_of(selector: str) -> str:
    """Return the address part of a CIDR selector."""
    text = selector.strip()
    if "/" in text:
        text = text.split("/", 1)[0]
    return text


def is_gateway_only_remote_ts(
    policies: Sequence[XfrmPolicy],
    gateway_ips: Sequence[str],
) -> bool:
    """Return True when every outbound ESP selector is a gateway /32."""
    gateways = {_canonical(item) for item in gateway_ips if item}
    if not gateways:
        return False
    outbound = [item for item in policies if item.direction == "out"]
    if not outbound:
        return False
    for item in outbound:
        dest = _canonical(network_of(item.dst))
        if dest not in gateways:
            return False
        if not _is_host_selector(item.dst):
            return False
    return True


def virtual_ips_from_policies(policies: Sequence[XfrmPolicy]) -> tuple[str, ...]:
    """Local /32 sources on outbound policies (assigned VIP)."""
    found: list[str] = []
    seen: set[str] = set()
    for item in policies:
        if item.direction != "out":
            continue
        if not _is_host_selector(item.src):
            continue
        address = network_of(item.src)
        if address in seen:
            continue
        seen.add(address)
        found.append(address)
    return tuple(found)


def remote_selectors(policies: Sequence[XfrmPolicy]) -> tuple[str, ...]:
    found: list[str] = []
    seen: set[str] = set()
    for item in policies:
        if item.direction != "out":
            continue
        if item.dst in seen:
            continue
        seen.add(item.dst)
        found.append(item.dst)
    return tuple(found)


def local_selectors(policies: Sequence[XfrmPolicy]) -> tuple[str, ...]:
    found: list[str] = []
    seen: set[str] = set()
    for item in policies:
        if item.direction != "out":
            continue
        if item.src in seen:
            continue
        seen.add(item.src)
        found.append(item.src)
    return tuple(found)


def _is_host_selector(selector: str) -> bool:
    text = selector.strip()
    if "/" not in text:
        return True
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return False
    return network.prefixlen == network.max_prefixlen


def _canonical(address: str) -> str:
    try:
        return str(ipaddress.ip_address(address.strip()))
    except ValueError:
        return address.strip()
