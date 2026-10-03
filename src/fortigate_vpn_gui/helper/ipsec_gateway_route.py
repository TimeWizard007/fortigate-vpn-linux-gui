# SPDX-License-Identifier: GPL-3.0-or-later
"""Preserve a pre-existing unicast host route to the IPsec gateway.

Disconnect DNS restore (``nmcli device reapply``) and private-charon VIP
removal can delete a more-specific main-table ``/32`` to the IKE/SAML
endpoint. The next unprivileged ``:1001`` bootstrap then follows the
default route and fails with ``IpsecSamlConnectError``.

This module snapshots an *explicit* IPv4 host route that already existed
before private charon started, then restores it after *all* other
teardown. It does not invent routes, does not hard-code addresses, and
never writes ``src`` (that might be a stale VIP).
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import stat
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

LIVE_GATEWAY_ROUTE_STATE = Path("/run/charon.fvl.gwroute")
LIVE_SWANCTL_DIR = Path("/etc/swanctl/fortigate-vpn-linux-gui")
GATEWAY_ROUTE_STATE_VERSION = 1
RunArgv = Callable[..., subprocess.CompletedProcess[str]]
ResolveHost = Callable[[str], str | None]

_VIA_TOKEN = "via"
_DEV_TOKEN = "dev"


@dataclass(frozen=True)
class GatewayHostRoute:
    """Main-table IPv4 host route to the VPN endpoint. Not a secret."""

    destination: str
    device: str
    via: str | None = None


@dataclass(frozen=True)
class GatewayRouteRestoreResult:
    """Outcome of restoring a snapshotted host route. Messages are not secrets."""

    attempted: bool
    restored: bool
    verified: bool
    detail: str


def gateway_route_state_path(runtime_dir: Path) -> Path:
    """Return the helper-owned gateway-route snapshot path."""
    try:
        live = runtime_dir.resolve() == LIVE_SWANCTL_DIR.resolve()
    except OSError:
        live = runtime_dir == LIVE_SWANCTL_DIR
    if live:
        return LIVE_GATEWAY_ROUTE_STATE
    return runtime_dir / "gateway-route.json"


def snapshot_explicit_host_route(
    gateway: str,
    *,
    run: RunArgv | None = None,
    resolve: ResolveHost | None = None,
) -> GatewayHostRoute | None:
    """Return a pre-existing main-table /32 route to *gateway*, if any."""
    route, _reason = snapshot_explicit_host_route_with_reason(gateway, run=run, resolve=resolve)
    return route


def snapshot_explicit_host_route_with_reason(
    gateway: str,
    *,
    run: RunArgv | None = None,
    resolve: ResolveHost | None = None,
) -> tuple[GatewayHostRoute | None, str]:
    """Return ``(route, reason)``. *reason* is safe to log when route is None."""
    runner = run or _run
    host = gateway.strip()
    if not host or host.startswith("-") or any(char in host for char in " \t\n;|&"):
        return None, "gateway missing or invalid"
    resolver = resolve or resolve_ipv4_destination
    destination = resolver(host)
    if destination is None:
        return None, "gateway did not resolve to IPv4"
    route = _read_exact_host_route(destination, run=runner)
    if route is None:
        return None, "no explicit main-table /32"
    return route, "captured"


def restore_explicit_host_route(
    route: GatewayHostRoute | None,
    *,
    run: RunArgv | None = None,
) -> bool:
    """Reinstall *route* when the explicit host route is missing or changed."""
    result = restore_and_verify_explicit_host_route(route, run=run)
    return result.restored or result.verified


def restore_and_verify_explicit_host_route(
    route: GatewayHostRoute | None,
    *,
    run: RunArgv | None = None,
    retries: int = 1,
) -> GatewayRouteRestoreResult:
    """Replace the /32 if needed, then read it back from the kernel model."""
    if route is None:
        return GatewayRouteRestoreResult(
            attempted=False, restored=False, verified=False, detail="no snapshot"
        )
    runner = run or _run
    attempts = max(int(retries), 0) + 1
    last_replace_ok = False
    for index in range(attempts):
        current = _read_exact_host_route(route.destination, run=runner)
        if _route_matches(current, route):
            return GatewayRouteRestoreResult(
                attempted=True,
                restored=last_replace_ok,
                verified=True,
                detail="verified",
            )
        argv = [
            "ip",
            "-4",
            "route",
            "replace",
            f"{route.destination}/32",
        ]
        if route.via:
            argv.extend(["via", route.via])
        argv.extend(["dev", route.device, "table", "main"])
        completed = _try_run(runner, argv)
        if completed is None or completed.returncode != 0:
            raw = ""
            if completed is not None:
                raw = (completed.stderr or completed.stdout or "").strip()
                raw = raw.splitlines()[0] if raw.splitlines() else f"exit {completed.returncode}"
            else:
                raw = "replace command failed"
            return GatewayRouteRestoreResult(
                attempted=True,
                restored=False,
                verified=False,
                detail=_safe_ip_error(raw),
            )
        last_replace_ok = True
        current = _read_exact_host_route(route.destination, run=runner)
        if _route_matches(current, route):
            return GatewayRouteRestoreResult(
                attempted=True, restored=True, verified=True, detail="verified"
            )
        if index + 1 < attempts:
            time.sleep(0.2)
    return GatewayRouteRestoreResult(
        attempted=True,
        restored=last_replace_ok,
        verified=False,
        detail="kernel does not have the snapshotted /32",
    )


def verify_explicit_host_route(
    route: GatewayHostRoute | None, *, run: RunArgv | None = None
) -> bool:
    """Return True when the kernel still has the snapshotted main-table /32."""
    if route is None:
        return False
    current = _read_exact_host_route(route.destination, run=run or _run)
    return _route_matches(current, route)


def write_gateway_route_state(path: Path, route: GatewayHostRoute) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": GATEWAY_ROUTE_STATE_VERSION,
        "destination": route.destination,
        "device": route.device,
        "via": route.via,
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def read_gateway_route_state(path: Path) -> GatewayHostRoute | None:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return None
    destination = payload.get("destination")
    device = payload.get("device")
    via = payload.get("via")
    if not isinstance(destination, str) or not isinstance(device, str) or not device:
        return None
    if not _is_ipv4(destination):
        return None
    via_text = via if isinstance(via, str) and _is_ipv4(via) else None
    if not _safe_device(device):
        return None
    return GatewayHostRoute(destination=destination, device=device, via=via_text)


def restore_from_gateway_route_path(
    path: Path | None,
    *,
    run: RunArgv | None = None,
    unlink: bool = True,
) -> bool:
    """Restore a snapshotted host route. Unlink the snapshot after a verified restore."""
    result = restore_from_gateway_route_path_result(path, run=run, unlink=unlink)
    return result.verified or result.restored


def restore_from_gateway_route_path_result(
    path: Path | None,
    *,
    run: RunArgv | None = None,
    unlink: bool = True,
) -> GatewayRouteRestoreResult:
    if path is None:
        return GatewayRouteRestoreResult(
            attempted=False, restored=False, verified=False, detail="no snapshot path"
        )
    route = read_gateway_route_state(path)
    result = restore_and_verify_explicit_host_route(route, run=run)
    if unlink and (result.verified or route is None):
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass
    return result


def parse_host_route_line(text: str, *, destination: str) -> GatewayHostRoute | None:
    """Parse one ``ip route`` line. Ignores default, covering, and table 220."""
    if not text or not text.strip():
        return None
    first = text.strip().splitlines()[0].strip()
    lowered = first.lower()
    if not first or lowered.startswith("default ") or "unreachable" in lowered:
        return None
    if "table" in lowered and "table main" not in lowered and "table 254" not in lowered:
        if "table 220" in lowered:
            return None
        if "table" in lowered:
            return None
    tokens = first.split()
    if not tokens:
        return None
    dest_token = tokens[0]
    if dest_token in {"unicast", "unicast:"}:
        if len(tokens) < 2:
            return None
        dest_token = tokens[1]
    if dest_token not in {destination, f"{destination}/32"}:
        return None
    via = _token_after(tokens, _VIA_TOKEN)
    device = _token_after(tokens, _DEV_TOKEN)
    if device is None or not _safe_device(device):
        return None
    if via is not None and not _is_ipv4(via):
        return None
    return GatewayHostRoute(destination=destination, device=device, via=via)


def resolve_ipv4_destination(gateway: str) -> str | None:
    """Resolve *gateway* to an IPv4 address without consulting the route table."""
    host = gateway.strip()
    if not host:
        return None
    if _is_ipv4(host):
        return host
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_DGRAM)
    except OSError:
        return None
    for family, _kind, _proto, _canon, sockaddr in infos:
        if family != socket.AF_INET or not sockaddr:
            continue
        address = sockaddr[0]
        if isinstance(address, str) and _is_ipv4(address):
            return address
    return None


def _read_exact_host_route(destination: str, *, run: RunArgv) -> GatewayHostRoute | None:
    queries = (
        ["ip", "-4", "route", "show", "exact", f"{destination}/32", "table", "main"],
        ["ip", "-4", "route", "show", "exact", f"{destination}/32"],
        ["ip", "-4", "route", "show", "table", "main"],
    )
    for argv in queries:
        completed = _try_run(run, argv)
        if completed is None or completed.returncode != 0:
            continue
        stdout = completed.stdout or ""
        if "exact" in argv:
            parsed = parse_host_route_line(stdout, destination=destination)
            if parsed is not None:
                return parsed
            continue
        for line in stdout.splitlines():
            parsed = parse_host_route_line(line, destination=destination)
            if parsed is not None:
                return parsed
    return None


def _route_matches(current: GatewayHostRoute | None, expected: GatewayHostRoute) -> bool:
    return (
        current is not None
        and current.destination == expected.destination
        and current.device == expected.device
        and current.via == expected.via
    )


def _token_after(tokens: list[str], name: str) -> str | None:
    try:
        index = tokens.index(name)
    except ValueError:
        return None
    if index + 1 >= len(tokens):
        return None
    return tokens[index + 1]


def _is_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        return False
    return True


def _safe_device(value: str) -> bool:
    return bool(value) and all(char.isalnum() or char in "._-" for char in value)


def _safe_ip_error(text: str) -> str:
    cleaned = " ".join(text.split())
    if len(cleaned) > 120:
        cleaned = cleaned[:117] + "..."
    return cleaned or "replace command failed"


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


__all__ = [
    "LIVE_GATEWAY_ROUTE_STATE",
    "GatewayHostRoute",
    "GatewayRouteRestoreResult",
    "gateway_route_state_path",
    "parse_host_route_line",
    "read_gateway_route_state",
    "restore_and_verify_explicit_host_route",
    "restore_explicit_host_route",
    "restore_from_gateway_route_path",
    "restore_from_gateway_route_path_result",
    "resolve_ipv4_destination",
    "snapshot_explicit_host_route",
    "snapshot_explicit_host_route_with_reason",
    "verify_explicit_host_route",
    "write_gateway_route_state",
]
