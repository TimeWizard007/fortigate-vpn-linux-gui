# SPDX-License-Identifier: GPL-3.0-or-later
"""Detect UDP/500 and UDP/4500 occupancy without owning unrelated IKE daemons.

Two independent charon processes cannot both bind the standard IKE ports.
This module never kills a process, never unlinks /run/charon.pid, and never
treats a generic charon name or occupied port as application ownership.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

IKE_UDP_PORT = 500
IKE_NATT_UDP_PORT = 4500
_CGROUP_SERVICE = re.compile(r"([A-Za-z0-9_.:-]+\.service)")


@dataclass(frozen=True)
class IkeUdpBinding:
    """One UDP listener. Owner fields are omitted when unreadable."""

    port: int
    inode: int
    pid: int | None = None
    comm: str | None = None
    service: str | None = None
    owned: bool = False


@dataclass(frozen=True)
class IkePortReport:
    """Occupancy of the standard IKE ports. Never includes secrets."""

    port_500: tuple[IkeUdpBinding, ...]
    port_4500: tuple[IkeUdpBinding, ...]

    @property
    def occupied_500(self) -> bool:
        return bool(self.port_500)

    @property
    def occupied_4500(self) -> bool:
        return bool(self.port_4500)

    @property
    def occupied(self) -> bool:
        return self.occupied_500 or self.occupied_4500

    def unrelated_conflict(self, owned_pids: Iterable[int] = ()) -> bool:
        """Return True when a non-application-owned process holds 500 and/or 4500.

        Occupancy with an unknown PID is treated as unrelated: ownership must be
        proven, never inferred from the port or the name ``charon``.
        """
        owned = set(owned_pids)
        for binding in (*self.port_500, *self.port_4500):
            if binding.owned or (binding.pid is not None and binding.pid in owned):
                continue
            return True
        return False

    def primary_unrelated(self, owned_pids: Iterable[int] = ()) -> IkeUdpBinding | None:
        owned = set(owned_pids)
        for binding in (*self.port_500, *self.port_4500):
            if binding.owned or (binding.pid is not None and binding.pid in owned):
                continue
            return binding
        return None


ProcText = Callable[[], str]
InodeOwner = Callable[[int], IkeUdpBinding]


def inspect_ike_udp_ports(
    *,
    owned_pids: tuple[int, ...] = (),
    udp_text: str | None = None,
    udp6_text: str | None = None,
    owner_lookup: Callable[[int, int, set[int]], IkeUdpBinding] | None = None,
) -> IkePortReport:
    """Inspect IKE UDP listeners. Safe for the unprivileged GUI (owner may be omitted)."""
    table = udp_text if udp_text is not None else _read_proc_net("udp")
    table6 = udp6_text if udp6_text is not None else _read_proc_net("udp6")
    combined = f"{table}\n{table6}"
    owned = set(owned_pids)
    lookup = owner_lookup if owner_lookup is not None else _lookup_binding
    port_500 = _bindings_for_port(combined, IKE_UDP_PORT, owned, lookup)
    port_4500 = _bindings_for_port(combined, IKE_NATT_UDP_PORT, owned, lookup)
    return IkePortReport(port_500=port_500, port_4500=port_4500)


def format_ike_port_lines(report: IkePortReport) -> list[str]:
    """Human-readable occupancy lines. No secrets."""
    lines = [
        f"IKE port 500: {_occupancy_word(report.occupied_500)}",
        f"IKE NAT-T port 4500: {_occupancy_word(report.occupied_4500)}",
    ]
    owner = report.primary_unrelated() or (
        report.port_500[0] if report.port_500 else None
    ) or (report.port_4500[0] if report.port_4500 else None)
    if owner is None:
        return lines
    service = owner.service or owner.comm or "unknown"
    comm = owner.comm or "unknown"
    if owner.pid is None:
        lines.append(f"Owner: {service} (PID unavailable)")
        return lines
    lines.append(f"Owner: {service} / {comm}")
    lines.append(f"PID: {owner.pid}")
    return lines


def parse_udp_inodes(text: str, port: int) -> tuple[int, ...]:
    """Return socket inodes bound to *port* in a /proc/net/udp{,6} table."""
    needle = f"{port:04X}"
    found: list[int] = []
    seen: set[int] = set()
    for raw in text.splitlines():
        parts = raw.split()
        if len(parts) < 10:
            continue
        local = parts[1]
        if ":" not in local:
            continue
        _address, _, hex_port = local.rpartition(":")
        if hex_port.upper() != needle:
            continue
        try:
            inode = int(parts[9])
        except ValueError:
            continue
        if inode in seen:
            continue
        seen.add(inode)
        found.append(inode)
    return tuple(found)


def _bindings_for_port(
    text: str,
    port: int,
    owned: set[int],
    lookup: Callable[[int, int, set[int]], IkeUdpBinding],
) -> tuple[IkeUdpBinding, ...]:
    bindings: list[IkeUdpBinding] = []
    seen: set[tuple[int, int | None]] = set()
    for inode in parse_udp_inodes(text, port):
        binding = lookup(port, inode, owned)
        key = (binding.inode, binding.pid)
        if key in seen:
            continue
        seen.add(key)
        bindings.append(binding)
    return tuple(bindings)


def _lookup_binding(port: int, inode: int, owned: set[int]) -> IkeUdpBinding:
    pid = _pid_for_socket_inode(inode)
    if pid is None:
        return IkeUdpBinding(port=port, inode=inode)
    comm = _proc_comm(pid)
    service = _proc_service(pid)
    return IkeUdpBinding(
        port=port,
        inode=inode,
        pid=pid,
        comm=comm,
        service=service,
        owned=pid in owned,
    )


def _pid_for_socket_inode(inode: int) -> int | None:
    marker = f"socket:[{inode}]"
    proc = Path("/proc")
    try:
        entries = proc.iterdir()
    except OSError:
        return None
    for entry in entries:
        if not entry.name.isdigit():
            continue
        fd_dir = entry / "fd"
        try:
            for fd in fd_dir.iterdir():
                try:
                    target = fd.readlink()
                except OSError:
                    continue
                if str(target) == marker:
                    return int(entry.name)
        except OSError:
            continue
    return None


def _proc_comm(pid: int) -> str | None:
    try:
        return (Path("/proc") / str(pid) / "comm").read_text(encoding="utf-8").strip() or None
    except OSError:
        return None


def _proc_service(pid: int) -> str | None:
    try:
        text = (Path("/proc") / str(pid) / "cgroup").read_text(encoding="utf-8")
    except OSError:
        return None
    for line in text.splitlines():
        match = _CGROUP_SERVICE.search(line)
        if match is not None:
            return match.group(1)
    return None


def _read_proc_net(name: str) -> str:
    try:
        return (Path("/proc/net") / name).read_text(encoding="utf-8")
    except OSError:
        return ""


def _occupancy_word(occupied: bool) -> str:
    return "occupied" if occupied else "available"


def free_ike_port_report() -> IkePortReport:
    """Empty report used by tests that must not observe the host's IKE daemons."""
    return IkePortReport(port_500=(), port_4500=())
