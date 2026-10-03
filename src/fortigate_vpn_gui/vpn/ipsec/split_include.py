# SPDX-License-Identifier: GPL-3.0-or-later
"""Parse FortiGate IKEv2 Mode Config split-include and DNS attributes.

Stock strongSwan 5.9.13 installs CHILD_SA ``remote_ts = 0.0.0.0/0`` for
IKEv2 because:

- FortiGate does not narrow TSr on the HomeVPN IKEv2 SSO path
- ``INTERNAL_IP4_SUBNET`` has no initiator handler
- the unity plugin narrows TSr only for IKEv1 + Cisco Unity

This module consumes the CFG_REPLY attributes FortiClient already
requests in CP16. Prefixes are not secrets. Never parse or log PSK,
FCT_UID, tokenid, or SAML values.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

INTERNAL_IP4_DNS = 3
INTERNAL_IP4_SUBNET = 13
INTERNAL_DNS_DOMAIN = 25
UNITY_DEF_DOMAIN = 28674
UNITY_SPLITDNS_NAME = 28675
UNITY_SPLIT_INCLUDE = 28676
UNITY_LOCAL_LAN = 28678
FORTINET_PRIVATE_540C = 21516

WILDCARD_PREFIX = "0.0.0.0/0"
NONE_TOKEN = "(none)"

SPLIT_INCLUDE_LOG_PREFIX = "FortiClient compatibility: CFG_REPLY split-include "
DNS_LOG_PREFIX = "FortiClient compatibility: CFG_REPLY dns "
TUNNEL_MODE_LOG_PREFIX = "FortiClient compatibility: CFG_REPLY tunnel-mode="
NARROWED_LOG_PREFIX = "FortiClient compatibility: narrowed CHILD_SA remote TS to split-include "

_SPLIT_INCLUDE_RE = re.compile(
    r"FortiClient compatibility: CFG_REPLY split-include "
    r"count=(\d+) prefixes=(\S+) source=(\S+)"
)
_DNS_RE = re.compile(r"FortiClient compatibility: CFG_REPLY dns servers=(\S+) domains=(\S+)")
_TUNNEL_MODE_RE = re.compile(r"FortiClient compatibility: CFG_REPLY tunnel-mode=(split|full)")
_DOMAIN_RE = re.compile(r"^[A-Za-z0-9._~-]+$")


@dataclass(frozen=True)
class SplitIncludeInfo:
    """Negotiated split-tunnel and DNS attributes. No secrets."""

    prefixes: tuple[str, ...]
    source: str
    tunnel_mode: str
    dns_servers: tuple[str, ...] = ()
    dns_domains: tuple[str, ...] = ()

    @property
    def is_split(self) -> bool:
        return self.tunnel_mode == "split"

    @property
    def catch_all_dns(self) -> bool:
        """True when VPN DNS should hijack all queries (full-tunnel DNS)."""
        if self.requests_full_tunnel_dns:
            return True
        return not self.is_split

    @property
    def requests_full_tunnel_dns(self) -> bool:
        return any(_is_catch_all_domain(item) for item in self.dns_domains)

    def routes(self) -> tuple[str, ...]:
        """Prefixes that should use the IPsec tunnel. Empty means full tunnel."""
        if not self.is_split:
            return (WILDCARD_PREFIX,)
        return self.prefixes


def parse_ipv4_subnets(data: bytes, *, stride: int | None = None) -> tuple[str, ...]:
    """Parse RFC 7296 8-byte or Cisco Unity 14-byte IPv4 subnet encodings."""
    if not data:
        return ()
    found: list[str] = []
    offset = 0
    while len(data) - offset >= 8:
        prefix = _prefix_from_addr_mask(data[offset : offset + 4], data[offset + 4 : offset + 8])
        if prefix is not None:
            found.append(prefix)
        if stride is not None:
            offset += stride
            continue
        if len(data) - offset >= 14:
            offset += 14
        else:
            offset += 8
    return tuple(_unique(found))


def classify_cfg_reply_attributes(
    attributes: Mapping[int, Sequence[bytes]],
) -> SplitIncludeInfo:
    """Select split-include and DNS from received CFG_REPLY attributes.

    Priority for tunnel networks:

    1. UNITY_SPLIT_INCLUDE (0x7004)
    2. INTERNAL_IP4_SUBNET (13)
    3. Fortinet private 0x540c when it decodes as subnets
    4. UNITY_LOCAL_LAN (0x7006) as FortiClient's requested split-include
    """
    unity_include = _prefixes_from_values(attributes.get(UNITY_SPLIT_INCLUDE, ()), stride=14)
    rfc_subnet = _prefixes_from_values(attributes.get(INTERNAL_IP4_SUBNET, ()), stride=8)
    fortinet = _prefixes_from_values(attributes.get(FORTINET_PRIVATE_540C, ()))
    local_lan = _prefixes_from_values(attributes.get(UNITY_LOCAL_LAN, ()), stride=14)

    source = "none"
    selected: tuple[str, ...] = ()
    if unity_include:
        selected, source = unity_include, "UNITY_SPLIT_INCLUDE"
    elif rfc_subnet:
        selected, source = rfc_subnet, "INTERNAL_IP4_SUBNET"
    elif fortinet:
        selected, source = fortinet, "0x540c"
    elif local_lan:
        selected, source = local_lan, "UNITY_LOCAL_LAN"

    dns_servers = _dns_servers_from_values(attributes.get(INTERNAL_IP4_DNS, ()))
    dns_domains = _domains_from_values(
        (
            *attributes.get(INTERNAL_DNS_DOMAIN, ()),
            *attributes.get(UNITY_SPLITDNS_NAME, ()),
            *attributes.get(UNITY_DEF_DOMAIN, ()),
        )
    )
    if not selected or any(_is_wildcard(item) for item in selected):
        return SplitIncludeInfo(
            prefixes=(),
            source=source if selected else "none",
            tunnel_mode="full",
            dns_servers=dns_servers,
            dns_domains=dns_domains,
        )
    return SplitIncludeInfo(
        prefixes=selected,
        source=source,
        tunnel_mode="split",
        dns_servers=dns_servers,
        dns_domains=dns_domains,
    )


def format_split_include_log(info: SplitIncludeInfo) -> str:
    """Redacted diagnostic line: count, prefixes, source. No secrets."""
    prefixes = ",".join(info.prefixes) if info.prefixes else NONE_TOKEN
    return (
        f"{SPLIT_INCLUDE_LOG_PREFIX}count={len(info.prefixes)} "
        f"prefixes={prefixes} source={info.source}"
    )


def format_dns_log(info: SplitIncludeInfo) -> str:
    servers = ",".join(info.dns_servers) if info.dns_servers else NONE_TOKEN
    domains = ",".join(info.dns_domains) if info.dns_domains else NONE_TOKEN
    return f"{DNS_LOG_PREFIX}servers={servers} domains={domains}"


def format_tunnel_mode_log(info: SplitIncludeInfo) -> str:
    return f"{TUNNEL_MODE_LOG_PREFIX}{info.tunnel_mode}"


def format_narrowed_log(info: SplitIncludeInfo) -> str:
    return f"{NARROWED_LOG_PREFIX}count={len(info.prefixes)}"


def parse_split_include_log_line(line: str) -> SplitIncludeInfo | None:
    """Parse a plugin/helper split-include diagnostic line."""
    split_match = _SPLIT_INCLUDE_RE.search(line)
    mode_match = _TUNNEL_MODE_RE.search(line)
    dns_match = _DNS_RE.search(line)
    if split_match is None and mode_match is None and dns_match is None:
        return None
    prefixes: tuple[str, ...] = ()
    source = "none"
    tunnel_mode = "full"
    dns_servers: tuple[str, ...] = ()
    dns_domains: tuple[str, ...] = ()
    if split_match is not None:
        prefixes = _tokens(split_match.group(2))
        source = split_match.group(3)
        has_nets = prefixes and not any(_is_wildcard(item) for item in prefixes)
        tunnel_mode = "split" if has_nets else "full"
        if tunnel_mode == "full":
            prefixes = ()
    if mode_match is not None:
        tunnel_mode = mode_match.group(1)
        if tunnel_mode == "full":
            prefixes = ()
    if dns_match is not None:
        dns_servers = _tokens(dns_match.group(1))
        dns_domains = _tokens(dns_match.group(2))
    return SplitIncludeInfo(
        prefixes=prefixes,
        source=source,
        tunnel_mode=tunnel_mode,
        dns_servers=dns_servers,
        dns_domains=dns_domains,
    )


def merge_split_include_info(
    current: SplitIncludeInfo | None,
    incoming: SplitIncludeInfo,
) -> SplitIncludeInfo:
    """Combine partial diagnostic lines from the same CFG_REPLY."""
    if current is None:
        return incoming
    prefixes = incoming.prefixes or current.prefixes
    source = incoming.source if incoming.source != "none" else current.source
    if incoming.tunnel_mode == "split" or current.tunnel_mode == "split":
        has_nets = prefixes and not any(_is_wildcard(item) for item in prefixes)
        tunnel_mode = "split" if has_nets else "full"
    else:
        tunnel_mode = incoming.tunnel_mode
    if tunnel_mode == "full":
        prefixes = ()
    return SplitIncludeInfo(
        prefixes=prefixes,
        source=source,
        tunnel_mode=tunnel_mode,
        dns_servers=incoming.dns_servers or current.dns_servers,
        dns_domains=incoming.dns_domains or current.dns_domains,
    )


def installs_default_route(info: SplitIncludeInfo | None) -> bool:
    """True when table 220 / XFRM should keep 0.0.0.0/0."""
    if info is None:
        return True
    return not info.is_split


def apply_split_to_remote_ts(
    remote: Sequence[str],
    info: SplitIncludeInfo | None,
) -> tuple[str, ...]:
    """Return effective CHILD_SA remote selectors after POST-NOAUTH narrowing.

    Mirrors the plugin hook: replace a remaining IPv4 default with parsed
    split-include prefixes. Do not invent prefixes. Leave an already-narrowed
    list unchanged. Keep ``0.0.0.0/0`` when the gateway negotiates full tunnel.
    """
    current = tuple(remote)
    if info is None or not info.is_split or not info.prefixes:
        return current
    if not any(_is_wildcard(item) for item in current):
        return current
    return info.prefixes


def _prefixes_from_values(values: Sequence[bytes], *, stride: int | None = None) -> tuple[str, ...]:
    found: list[str] = []
    for item in values:
        found.extend(parse_ipv4_subnets(item, stride=stride))
    return tuple(_unique(found))


def _dns_servers_from_values(values: Sequence[bytes]) -> tuple[str, ...]:
    found: list[str] = []
    for item in values:
        if len(item) != 4:
            continue
        found.append(str(ipaddress.IPv4Address(item)))
    return tuple(_unique(found))


def _domains_from_values(values: Sequence[bytes]) -> tuple[str, ...]:
    found: list[str] = []
    for item in values:
        text = item.split(b"\x00", 1)[0].decode("ascii", errors="ignore").strip()
        if not text:
            continue
        for token in text.replace(",", " ").split():
            cleaned = token.strip(".").lower() if token not in {".", "~."} else token
            if token in {".", "~."}:
                found.append(token)
                continue
            if _DOMAIN_RE.match(cleaned) and cleaned:
                found.append(cleaned)
    return tuple(_unique(found))


def _prefix_from_addr_mask(addr: bytes, mask: bytes) -> str | None:
    if len(addr) != 4 or len(mask) != 4:
        return None
    try:
        network = ipaddress.IPv4Address(addr)
        netmask = ipaddress.IPv4Address(mask)
        prefixlen = ipaddress.IPv4Network(f"0.0.0.0/{netmask}").prefixlen
        return str(ipaddress.IPv4Network((int(network), prefixlen), strict=False))
    except ValueError:
        return None


def _is_wildcard(prefix: str) -> bool:
    try:
        network = ipaddress.ip_network(prefix, strict=False)
    except ValueError:
        return prefix == WILDCARD_PREFIX
    return network.version == 4 and network.prefixlen == 0


def _is_catch_all_domain(domain: str) -> bool:
    return domain in {".", "~.", WILDCARD_PREFIX}


def _tokens(raw: str) -> tuple[str, ...]:
    if not raw or raw == NONE_TOKEN:
        return ()
    return tuple(_unique(token for token in raw.split(",") if token and token != NONE_TOKEN))


def _unique(values: Sequence[str]) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for item in values:
        if item in seen:
            continue
        seen.add(item)
        found.append(item)
    return found
