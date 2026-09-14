# SPDX-License-Identifier: GPL-3.0-or-later
"""Temporary IPsec DNS via systemd-resolved. No permanent resolv.conf edits.

Ubuntu's /sbin/resolvconf talks to systemd-networkd (network1), which is not
running on a NetworkManager desktop. Charon is pointed at /usr/bin/true so it
does not call that path.

``resolvectl revert`` on a NetworkManager-managed link is not a restore: it
calls RevertLink() and clears the same per-link DNS slot that NetworkManager
filled with DHCP/static servers. NetworkManager does not automatically
SetLinkDNS again, which leaves systemd-resolved with no upstream (Chrome
DNS_PROBE_FINISHED_BAD_CONFIG until reboot).

The helper therefore snapshots the pre-VPN resolvectl state, overlays FortiGate
DNS only while connected, restores that snapshot, and asks NetworkManager to
reapply the existing connection profile (not a permanent connection modify).
"""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

LIVE_DNS_STATE = Path("/run/charon.fvl.dns")
DNS_STATE_VERSION = 2
_ROUTING_ALL = "~."

_DNS_SERVER_RE = re.compile(
    r"installing DNS server\s+(\d{1,3}(?:\.\d{1,3}){3})\b",
    re.IGNORECASE,
)
_VIP_RE = re.compile(
    r"(?:installing(?: new)?|adding) virtual IP\s+(\d{1,3}(?:\.\d{1,3}){3})\b"
    r"|got vips?:\s+(\d{1,3}(?:\.\d{1,3}){3})\b",
    re.IGNORECASE,
)
_LINK_VALUES_RE = re.compile(r"^Link\s+\d+\s+\(([^)]+)\):\s*(.*)$")

RunArgv = Callable[..., subprocess.CompletedProcess[str]]


@dataclass(frozen=True)
class LinkDnsSnapshot:
    """Pre-VPN systemd-resolved settings for one link."""

    interface: str
    servers: tuple[str, ...] = ()
    domains: tuple[str, ...] = ()
    default_route: bool | None = None


@dataclass(frozen=True)
class DnsState:
    """VPN overlay plus the pre-VPN snapshot needed to restore it."""

    interface: str
    servers: tuple[str, ...]
    pre_vpn: LinkDnsSnapshot | None = None
    nm_managed: bool = False


@dataclass(frozen=True)
class DnsRestoreResult:
    """Outcome of removing the IPsec DNS overlay."""

    restored: bool
    verified: bool
    detail: str
    status_text: str = ""


def parse_dns_server_line(line: str) -> str | None:
    """Return an IPv4 DNS address logged by the resolve plugin, if present."""
    match = _DNS_SERVER_RE.search(line)
    if match is None:
        return None
    return match.group(1)


def parse_virtual_ip_line(line: str) -> str | None:
    """Return a virtual IP logged by charon, if present."""
    match = _VIP_RE.search(line)
    if match is None:
        return None
    return match.group(1) or match.group(2)


def lookup_interface_for_address(
    address: str,
    *,
    run: RunArgv | None = None,
) -> str | None:
    """Return the interface that currently has *address*, or None."""
    runner = run or _run
    try:
        completed = runner(
            ["ip", "-o", "addr", "show", "to", f"{address}/32"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    stdout = completed.stdout or ""
    for raw in stdout.splitlines():
        parts = raw.split()
        if len(parts) >= 2:
            return parts[1]
    return None


def parse_resolvectl_link_values(text: str) -> tuple[str, ...]:
    """Parse ``resolvectl dns|domain LINK`` output into tokens."""
    values: list[str] = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        match = _LINK_VALUES_RE.match(line)
        rest = match.group(2).strip() if match else line
        if not rest or rest in {"(null)", "-", "n/a"}:
            continue
        values.extend(token for token in rest.split() if token)
    return tuple(values)


def parse_resolvectl_default_route(text: str) -> bool | None:
    """Parse ``resolvectl default-route LINK`` output."""
    tokens = parse_resolvectl_link_values(text)
    if not tokens:
        lowered = (text or "").strip().lower()
        if lowered in {"yes", "true", "1"}:
            return True
        if lowered in {"no", "false", "0"}:
            return False
        return None
    last = tokens[-1].lower()
    if last in {"yes", "true", "1"}:
        return True
    if last in {"no", "false", "0"}:
        return False
    return None


def inspect_link_dns(
    interface: str,
    *,
    run: RunArgv | None = None,
) -> LinkDnsSnapshot:
    """Read the current systemd-resolved DNS configuration for *interface*."""
    if not interface:
        return LinkDnsSnapshot(interface="")
    runner = run or _run
    servers = parse_resolvectl_link_values(
        _resolvectl_stdout(["resolvectl", "dns", interface], runner)
    )
    domains = parse_resolvectl_link_values(
        _resolvectl_stdout(["resolvectl", "domain", interface], runner)
    )
    default_route = parse_resolvectl_default_route(
        _resolvectl_stdout(["resolvectl", "default-route", interface], runner)
    )
    return LinkDnsSnapshot(
        interface=interface,
        servers=servers,
        domains=domains,
        default_route=default_route,
    )


def link_is_nm_managed(interface: str, *, run: RunArgv | None = None) -> bool:
    """Return True when NetworkManager reports *interface* as managed."""
    if not interface:
        return False
    runner = run or _run
    try:
        completed = runner(
            ["nmcli", "-t", "-f", "GENERAL.NM-MANAGED", "device", "show", interface],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    if completed.returncode != 0:
        return False
    text = f"{completed.stdout or ''}\n{completed.stderr or ''}".strip().lower()
    if not text:
        return False
    last = text.splitlines()[-1]
    value = last.rsplit(":", 1)[-1].strip()
    return value in {"yes", "true", "1"}


def apply_resolved_dns(
    interface: str,
    servers: Sequence[str],
    *,
    run: RunArgv | None = None,
) -> None:
    """Overlay VPN nameservers on *interface* via resolvectl (runtime only)."""
    if not interface or not servers:
        raise ValueError("VPN DNS apply requires an interface and at least one server.")
    runner = run or _run
    _run_checked(
        runner,
        ["resolvectl", "dns", interface, *servers],
        "resolvectl dns failed",
    )
    completed = _try_run(runner, ["resolvectl", "domain", interface, _ROUTING_ALL])
    if completed is not None and completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()
        raise RuntimeError(detail or "resolvectl domain failed")


def apply_temporary_vpn_dns(
    interface: str,
    servers: Sequence[str],
    state_path: Path,
    *,
    run: RunArgv | None = None,
) -> DnsState:
    """Snapshot pre-VPN DNS, persist it, then overlay FortiGate DNS."""
    runner = run or _run
    snapshot = inspect_link_dns(interface, run=runner)
    nm_managed = link_is_nm_managed(interface, run=runner)
    state = DnsState(
        interface=interface,
        servers=tuple(servers),
        pre_vpn=snapshot,
        nm_managed=nm_managed,
    )
    write_dns_state(state_path, state)
    try:
        apply_resolved_dns(interface, servers, run=runner)
    except Exception:
        restore_from_state_path(state_path, run=runner)
        raise
    return state


def restore_dns_state(state: DnsState, *, run: RunArgv | None = None) -> DnsRestoreResult:
    """Remove the VPN overlay and restore a usable pre-VPN resolver config."""
    runner = run or _run
    interface = state.interface
    snapshot = state.pre_vpn
    effective = snapshot or LinkDnsSnapshot(interface=interface)
    allow_empty = snapshot is not None and not snapshot.servers
    if snapshot is not None:
        _apply_snapshot(snapshot, run=runner)
    reapplied = False
    if state.nm_managed or snapshot is None:
        reapplied = _nm_reapply(interface, run=runner)
    _flush_resolver_caches(run=runner)
    current = inspect_link_dns(interface, run=runner)
    verified, detail = verify_dns_restored(
        current,
        pre_vpn=effective,
        vpn_servers=state.servers,
        allow_empty=allow_empty,
    )
    if not verified:
        _apply_snapshot(effective, run=runner)
        _flush_resolver_caches(run=runner)
        current = inspect_link_dns(interface, run=runner)
        verified, detail = verify_dns_restored(
            current,
            pre_vpn=effective,
            vpn_servers=state.servers,
            allow_empty=allow_empty,
        )
    status_text = _resolvectl_stdout(["resolvectl", "status", interface], runner)
    bits = [detail]
    if state.nm_managed or snapshot is None:
        bits.append("nmcli reapply " + ("ok" if reapplied else "skipped-or-failed"))
    return DnsRestoreResult(
        restored=verified,
        verified=verified,
        detail="; ".join(bit for bit in bits if bit),
        status_text=status_text.strip(),
    )


def verify_dns_restored(
    current: LinkDnsSnapshot,
    *,
    pre_vpn: LinkDnsSnapshot,
    vpn_servers: Sequence[str],
    allow_empty: bool = False,
) -> tuple[bool, str]:
    """Return whether *current* is a usable post-VPN resolver configuration."""
    pre_servers = set(pre_vpn.servers)
    pre_domains = set(pre_vpn.domains)
    leftover_vpn = [
        server for server in vpn_servers if server in current.servers and server not in pre_servers
    ]
    leftover_catch_all = _ROUTING_ALL in current.domains and _ROUTING_ALL not in pre_domains
    if leftover_vpn:
        return False, f"VPN DNS still present: {', '.join(leftover_vpn)}"
    if leftover_catch_all:
        return False, "routing domain ~. is still installed"
    if not current.servers:
        if allow_empty:
            return True, "no DNS servers before VPN; none after cleanup"
        return False, "resolver has no DNS servers after cleanup"
    return True, f"DNS servers {', '.join(current.servers)}"


def write_dns_state(path: Path, state: DnsState) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload: dict[str, object] = {
        "version": DNS_STATE_VERSION,
        "interface": state.interface,
        "servers": list(state.servers),
        "nm_managed": state.nm_managed,
    }
    if state.pre_vpn is not None:
        payload["pre_vpn"] = {
            "interface": state.pre_vpn.interface,
            "servers": list(state.pre_vpn.servers),
            "domains": list(state.pre_vpn.domains),
            "default_route": state.pre_vpn.default_route,
        }
    path.write_text(json.dumps(payload), encoding="utf-8")
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def read_dns_state(path: Path) -> DnsState | None:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return None
    interface = payload.get("interface")
    servers = payload.get("servers")
    if not isinstance(interface, str) or not interface:
        return None
    if not isinstance(servers, list):
        return None
    addresses = tuple(item for item in servers if isinstance(item, str) and item)
    if not addresses:
        return None
    nm_managed = payload.get("nm_managed") is True
    pre_vpn = _read_snapshot(payload.get("pre_vpn"), fallback_interface=interface)
    return DnsState(
        interface=interface,
        servers=addresses,
        pre_vpn=pre_vpn,
        nm_managed=nm_managed,
    )


def restore_from_state_path(path: Path, *, run: RunArgv | None = None) -> DnsRestoreResult | None:
    """Restore DNS recorded in *path* and delete the file. Best-effort."""
    state = read_dns_state(path)
    result: DnsRestoreResult | None = None
    if state is not None:
        try:
            result = restore_dns_state(state, run=run)
        except (OSError, subprocess.TimeoutExpired, RuntimeError, ValueError):
            result = DnsRestoreResult(
                restored=False,
                verified=False,
                detail="DNS restore failed",
            )
    try:
        path.unlink()
    except FileNotFoundError:
        return result
    except OSError:
        return result
    return result


def _read_snapshot(payload: object, *, fallback_interface: str) -> LinkDnsSnapshot | None:
    if not isinstance(payload, dict):
        return None
    interface = payload.get("interface")
    if not isinstance(interface, str) or not interface:
        interface = fallback_interface
    servers = payload.get("servers")
    domains = payload.get("domains")
    server_tuple = (
        tuple(item for item in servers if isinstance(item, str) and item)
        if isinstance(servers, list)
        else ()
    )
    domain_tuple = (
        tuple(item for item in domains if isinstance(item, str) and item)
        if isinstance(domains, list)
        else ()
    )
    default_route = payload.get("default_route")
    if not isinstance(default_route, bool):
        default_route = None
    return LinkDnsSnapshot(
        interface=interface,
        servers=server_tuple,
        domains=domain_tuple,
        default_route=default_route,
    )


def _apply_snapshot(snapshot: LinkDnsSnapshot, *, run: RunArgv) -> None:
    interface = snapshot.interface
    if not interface:
        return
    if snapshot.servers:
        _try_run(run, ["resolvectl", "dns", interface, *snapshot.servers])
    else:
        _try_run(run, ["resolvectl", "dns", interface, ""])
    if snapshot.domains:
        _try_run(run, ["resolvectl", "domain", interface, *snapshot.domains])
    else:
        _try_run(run, ["resolvectl", "domain", interface, ""])
    if snapshot.default_route is True:
        _try_run(run, ["resolvectl", "default-route", interface, "yes"])
    elif snapshot.default_route is False:
        _try_run(run, ["resolvectl", "default-route", interface, "no"])


def _nm_reapply(interface: str, *, run: RunArgv) -> bool:
    """Ask NetworkManager to push the saved connection profile again.

    This does not modify the persistent connection; it reapplies DHCP/static
    DNS that NetworkManager already owns.
    """
    if not interface:
        return False
    completed = _try_run(run, ["nmcli", "device", "reapply", interface])
    return completed is not None and completed.returncode == 0


def _flush_resolver_caches(*, run: RunArgv) -> None:
    _try_run(run, ["resolvectl", "flush-caches"])


def _resolvectl_stdout(argv: list[str], run: RunArgv) -> str:
    completed = _try_run(run, argv)
    if completed is None:
        return ""
    return completed.stdout or ""


def _run_checked(run: RunArgv, argv: list[str], fallback: str) -> None:
    completed = _try_run(run, argv)
    if completed is None:
        raise RuntimeError(fallback)
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()
        raise RuntimeError(detail or fallback)


def _try_run(run: RunArgv, argv: list[str]) -> subprocess.CompletedProcess[str] | None:
    try:
        return run(
            argv,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def _run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, **kwargs)  # noqa: S603
