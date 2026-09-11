# SPDX-License-Identifier: GPL-3.0-or-later
"""Network and tunnel diagnostic check tests."""

from __future__ import annotations

import socket
import threading
from dataclasses import replace

from fortigate_vpn_gui.diagnostics.checks import (
    CommandResult,
    DnsResult,
    InterfaceInfo,
    TcpResult,
    check_connection_state,
    check_dns,
    check_route,
    check_tcp,
    check_vpn_interface,
    check_vpn_routes,
    default_tcp_connect,
    is_likely_vpn_interface,
    parse_ip_brief_addr,
    parse_ip_literal,
    parse_ip_route_get,
)
from fortigate_vpn_gui.diagnostics.model import CheckStatus
from fortigate_vpn_gui.profiles.model import build_profile
from fortigate_vpn_gui.vpn.models import ConnectionState
from tests.vpn_fakes import VpnHarness


def _snapshot(state: ConnectionState = ConnectionState.DISCONNECTED, **kwargs):
    return replace(VpnHarness().backend.snapshot(), state=state, **kwargs)


def test_dns_hostname_success_and_multiple_addresses() -> None:
    profile = build_profile(name="Office", gateway="vpn.example.com", port=443)

    def resolve(host, timeout=3.0):
        assert host == "vpn.example.com"
        return DnsResult(addresses=("203.0.113.10", "203.0.113.11"))

    check, addresses = check_dns(profile, resolve=resolve, include_network=True)
    assert check.status is CheckStatus.PASS
    assert "203.0.113.10" in check.summary
    assert "203.0.113.11" in check.summary
    assert addresses == ("203.0.113.10", "203.0.113.11")


def test_dns_resolution_failure() -> None:
    profile = build_profile(name="Office", gateway="vpn.example.com")
    check, addresses = check_dns(
        profile,
        resolve=lambda *a, **k: DnsResult(error="Name or service not known"),
        include_network=True,
    )
    assert check.status is CheckStatus.FAIL
    assert addresses == ()


def test_dns_ip_not_required() -> None:
    profile = build_profile(name="Office", gateway="203.0.113.10")
    check, addresses = check_dns(
        profile,
        resolve=lambda *a, **k: DnsResult(error="should not be called"),
        include_network=True,
    )
    assert check.status is CheckStatus.INFO
    assert "not required" in check.summary.lower()
    assert addresses == ("203.0.113.10",)
    assert parse_ip_literal("203.0.113.10") == "203.0.113.10"


def test_route_valid_output() -> None:
    profile = build_profile(name="Office", gateway="vpn.example.com")
    output = "203.0.113.10 via 192.168.1.1 dev enp5s0 src 192.168.1.20 uid 1000"
    parsed = parse_ip_route_get(output)
    assert parsed is not None
    assert parsed.device == "enp5s0"
    check = check_route(
        profile,
        ("203.0.113.10",),
        dns_failed=False,
        include_network=True,
        which=lambda name: "/sbin/ip" if name == "ip" else None,
        run_command=lambda argv, timeout=3.0: CommandResult(returncode=0, stdout=output),
    )
    assert check.status is CheckStatus.PASS
    assert "via 192.168.1.1" in check.summary
    assert "dev enp5s0" in check.summary
    assert "src 192.168.1.20" in check.summary


def test_route_none_missing_ip_timeout_and_dns_failed() -> None:
    profile = build_profile(name="Office", gateway="vpn.example.com")
    no_route = check_route(
        profile,
        ("203.0.113.10",),
        dns_failed=False,
        include_network=True,
        which=lambda name: "/sbin/ip",
        run_command=lambda *a, **k: CommandResult(
            returncode=1, stderr="RTNETLINK answers: Network is unreachable"
        ),
    )
    missing_ip = check_route(
        profile,
        ("203.0.113.10",),
        dns_failed=False,
        include_network=True,
        which=lambda name: None,
        run_command=lambda *a, **k: CommandResult(missing=True),
    )
    timeout = check_route(
        profile,
        ("203.0.113.10",),
        dns_failed=False,
        include_network=True,
        which=lambda name: "/sbin/ip",
        run_command=lambda *a, **k: CommandResult(timed_out=True),
    )
    dns = check_route(
        profile,
        (),
        dns_failed=True,
        include_network=True,
        which=lambda name: "/sbin/ip",
        run_command=lambda *a, **k: CommandResult(),
    )
    assert no_route.status is CheckStatus.FAIL
    assert missing_ip.status is CheckStatus.WARNING
    assert "ip command" in missing_ip.summary
    assert timeout.status is CheckStatus.WARNING
    assert dns.status is CheckStatus.NOT_TESTED
    assert "DNS" in dns.summary


def test_tcp_local_server_reachable() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    threading.Thread(target=lambda: server.accept(), daemon=True).start()
    profile = build_profile(name="Office", gateway="127.0.0.1", port=port)
    check = check_tcp(
        profile,
        ("127.0.0.1",),
        dns_failed=False,
        include_network=True,
        connect=default_tcp_connect,
    )
    server.close()
    assert check.status is CheckStatus.PASS
    assert "reachable" in check.summary
    assert "does not prove" in check.detail.lower()


def test_tcp_refused_timeout_unreachable_and_dns() -> None:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    profile = build_profile(name="Office", gateway="127.0.0.1", port=port)
    refused = check_tcp(
        profile,
        ("127.0.0.1",),
        dns_failed=False,
        include_network=True,
        connect=default_tcp_connect,
    )
    timeout = check_tcp(
        profile,
        ("127.0.0.1",),
        dns_failed=False,
        include_network=True,
        connect=lambda *a, **k: TcpResult(kind="timeout", error="timed out"),
    )
    unreachable = check_tcp(
        profile,
        ("127.0.0.1",),
        dns_failed=False,
        include_network=True,
        connect=lambda *a, **k: TcpResult(kind="unreachable", error="network unreachable"),
    )
    dns = check_tcp(
        profile,
        (),
        dns_failed=True,
        include_network=True,
        connect=lambda *a, **k: TcpResult(ok=True, elapsed_ms=1),
    )
    assert refused.status is CheckStatus.FAIL
    assert "refused" in refused.summary.lower()
    assert timeout.status is CheckStatus.FAIL
    assert "timed out" in timeout.summary.lower()
    assert unreachable.status is CheckStatus.FAIL
    assert "unreachable" in unreachable.summary.lower()
    assert dns.status is CheckStatus.NOT_TESTED


def test_vpn_interface_disconnected_and_non_ppp0() -> None:
    disconnected, iface = check_vpn_interface(
        _snapshot(ConnectionState.DISCONNECTED),
        include_network=True,
        list_interfaces=lambda: (InterfaceInfo("ppp0", "10.0.0.1", "UNKNOWN"),),
    )
    connected, found = check_vpn_interface(
        _snapshot(ConnectionState.CONNECTED),
        include_network=True,
        list_interfaces=lambda: (
            InterfaceInfo("enp5s0", "192.168.1.20", "UP"),
            InterfaceInfo("tun1", "10.7.0.2", "UNKNOWN"),
        ),
    )
    assert disconnected.status is CheckStatus.INFO
    assert iface is None
    assert "No VPN interface" in disconnected.summary
    assert connected.status is CheckStatus.PASS
    assert found is not None
    assert found.name == "tun1"
    assert "10.7.0.2" in connected.summary
    assert is_likely_vpn_interface("tun1")
    assert is_likely_vpn_interface("ppp12")
    assert not is_likely_vpn_interface("enp5s0")
    parsed = parse_ip_brief_addr("tun1             UNKNOWN        10.7.0.2/32\n")
    assert parsed[0].name == "tun1"


def test_vpn_routes_are_info_when_connected() -> None:
    snapshot = _snapshot(ConnectionState.CONNECTED)
    iface = InterfaceInfo("tun1", "10.7.0.2", "UNKNOWN")
    check = check_vpn_routes(
        snapshot,
        iface,
        include_network=True,
        which=lambda name: "/sbin/ip",
        run_command=lambda argv, timeout=3.0: CommandResult(
            returncode=0, stdout="default via 10.7.0.1\n"
        ),
    )
    empty = check_vpn_routes(
        snapshot,
        iface,
        include_network=True,
        which=lambda name: "/sbin/ip",
        run_command=lambda *a, **k: CommandResult(returncode=0, stdout=""),
    )
    idle = check_vpn_routes(
        _snapshot(ConnectionState.DISCONNECTED),
        None,
        include_network=True,
        which=lambda name: "/sbin/ip",
        run_command=lambda *a, **k: CommandResult(),
    )
    assert check.status is CheckStatus.INFO
    assert empty.status is CheckStatus.INFO
    assert "split-tunnel" in empty.summary.lower()
    assert idle.status is CheckStatus.INFO


def test_connection_state_failed_sanitized() -> None:
    snap = _snapshot(
        ConnectionState.FAILED,
        last_failure_reason="password=supersecret authentication failed",
    )
    check = check_connection_state(snap)
    assert check.status is CheckStatus.FAIL
    assert "Failed" in check.summary
    assert "supersecret" not in check.summary
    assert "supersecret" not in check.detail
