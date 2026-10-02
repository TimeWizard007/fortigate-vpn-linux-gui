# SPDX-License-Identifier: GPL-3.0-or-later
"""FortiGate IKEv2 CFG_REPLY split-include parsing and DNS routing."""

from __future__ import annotations

import ipaddress
from pathlib import Path

from fortigate_vpn_gui.diagnostics.ipsec_status import (
    is_wildcard_remote_ts,
    parse_table_220_routes,
    parse_xfrm_policies,
    split_remote_selectors,
    table_220_has_default,
)
from fortigate_vpn_gui.helper.ike_ports import free_ike_port_report
from fortigate_vpn_gui.helper.ipsec_dns import apply_temporary_vpn_dns
from fortigate_vpn_gui.helper.protocol import HelperEventKind
from fortigate_vpn_gui.helper.service import HelperService, SwanctlCommandResult
from fortigate_vpn_gui.helper.validation import connect_request_from_fields
from fortigate_vpn_gui.profiles.ipsec import default_ipsec_settings
from fortigate_vpn_gui.vpn.ipsec.detect import IpsecBackendCapabilities
from fortigate_vpn_gui.vpn.ipsec.secrets import IpsecCredentials
from fortigate_vpn_gui.vpn.ipsec.split_include import (
    FORTINET_PRIVATE_540C,
    INTERNAL_DNS_DOMAIN,
    INTERNAL_IP4_DNS,
    INTERNAL_IP4_SUBNET,
    UNITY_LOCAL_LAN,
    UNITY_SPLIT_INCLUDE,
    WILDCARD_PREFIX,
    SplitIncludeInfo,
    apply_split_to_remote_ts,
    classify_cfg_reply_attributes,
    format_dns_log,
    format_split_include_log,
    format_tunnel_mode_log,
    installs_default_route,
    merge_split_include_info,
    parse_ipv4_subnets,
    parse_split_include_log_line,
)
from fortigate_vpn_gui.vpn.log_redaction import redact_log_line
from tests.test_ipsec_dns import FakeResolved, _assert_no_resolvectl_revert
from tests.vpn_fakes import FakeVpnProcess


def _addr_mask(network: str) -> bytes:
    net = ipaddress.IPv4Network(network, strict=False)
    return net.network_address.packed + net.netmask.packed


def _unity(network: str) -> bytes:
    return _addr_mask(network) + b"\x00" * 6


def test_parse_rfc_and_unity_subnet_encodings() -> None:
    rfc = parse_ipv4_subnets(_addr_mask("10.1.0.0/16") + _addr_mask("10.2.0.0/16"), stride=8)
    unity = parse_ipv4_subnets(_unity("192.0.2.0/24") + _unity("198.51.100.0/24"), stride=14)
    assert rfc == ("10.1.0.0/16", "10.2.0.0/16")
    assert unity == ("192.0.2.0/24", "198.51.100.0/24")
    padded_optional = parse_ipv4_subnets(_addr_mask("203.0.113.0/24"))
    assert padded_optional == ("203.0.113.0/24",)


def test_internal_ip4_subnet_is_split_include_not_default_route() -> None:
    info = classify_cfg_reply_attributes(
        {
            INTERNAL_IP4_SUBNET: [_addr_mask("10.10.10.0/24"), _addr_mask("10.10.20.0/24")],
            INTERNAL_IP4_DNS: [ipaddress.IPv4Address("192.0.2.53").packed],
        }
    )
    assert info.is_split is True
    assert info.source == "INTERNAL_IP4_SUBNET"
    assert info.prefixes == ("10.10.10.0/24", "10.10.20.0/24")
    assert info.routes() == info.prefixes
    assert WILDCARD_PREFIX not in info.routes()
    assert installs_default_route(info) is False
    assert info.catch_all_dns is False
    assert info.dns_servers == ("192.0.2.53",)


def test_unity_split_include_wins_over_local_lan() -> None:
    info = classify_cfg_reply_attributes(
        {
            UNITY_SPLIT_INCLUDE: [_unity("10.0.0.0/8")],
            UNITY_LOCAL_LAN: [_unity("192.168.1.0/24")],
        }
    )
    assert info.source == "UNITY_SPLIT_INCLUDE"
    assert info.prefixes == ("10.0.0.0/8",)


def test_unity_local_lan_is_forticlient_split_include_fallback() -> None:
    info = classify_cfg_reply_attributes({UNITY_LOCAL_LAN: [_unity("10.20.30.0/24")]})
    assert info.source == "UNITY_LOCAL_LAN"
    assert info.prefixes == ("10.20.30.0/24",)
    assert info.is_split is True


def test_fortinet_private_540c_used_when_standard_attrs_absent() -> None:
    info = classify_cfg_reply_attributes({FORTINET_PRIVATE_540C: [_addr_mask("172.16.0.0/12")]})
    assert info.source == "0x540c"
    assert info.prefixes == ("172.16.0.0/12",)


def test_wildcard_prefix_keeps_full_tunnel() -> None:
    info = classify_cfg_reply_attributes(
        {INTERNAL_IP4_SUBNET: [_addr_mask("0.0.0.0/0")]}
    )
    assert info.is_split is False
    assert info.routes() == (WILDCARD_PREFIX,)
    assert installs_default_route(info) is True
    assert info.catch_all_dns is True


def test_missing_split_attrs_keep_full_tunnel() -> None:
    info = classify_cfg_reply_attributes(
        {INTERNAL_IP4_DNS: [ipaddress.IPv4Address("192.0.2.53").packed]}
    )
    assert info.is_split is False
    assert installs_default_route(info) is True
    assert info.catch_all_dns is True
    assert info.dns_servers == ("192.0.2.53",)


def test_split_dns_domains_disable_catch_all() -> None:
    info = classify_cfg_reply_attributes(
        {
            INTERNAL_IP4_SUBNET: [_addr_mask("10.0.0.0/8")],
            INTERNAL_DNS_DOMAIN: [b"corp.example"],
        }
    )
    assert info.is_split is True
    assert info.catch_all_dns is False
    assert info.dns_domains == ("corp.example",)
    assert info.requests_full_tunnel_dns is False


def test_explicit_catch_all_dns_domain_on_split_tunnel() -> None:
    info = classify_cfg_reply_attributes(
        {
            INTERNAL_IP4_SUBNET: [_addr_mask("10.0.0.0/8")],
            INTERNAL_DNS_DOMAIN: [b"~."],
        }
    )
    assert info.is_split is True
    assert info.catch_all_dns is True
    assert info.requests_full_tunnel_dns is True


def test_split_include_logs_are_parseable_and_non_secret() -> None:
    info = classify_cfg_reply_attributes(
        {
            INTERNAL_IP4_SUBNET: [_addr_mask("10.9.8.0/24")],
            INTERNAL_IP4_DNS: [ipaddress.IPv4Address("192.0.2.53").packed],
            INTERNAL_DNS_DOMAIN: [b"internal.test"],
        }
    )
    split_line = format_split_include_log(info)
    dns_line = format_dns_log(info)
    mode_line = format_tunnel_mode_log(info)
    assert "tokenid" not in split_line.lower()
    assert "FCT_UID" not in split_line
    assert "psk" not in split_line.lower()
    parsed = merge_split_include_info(
        parse_split_include_log_line(split_line),
        merge_split_include_info(
            parse_split_include_log_line(dns_line),
            parse_split_include_log_line(mode_line),
        ),
    )
    assert parsed is not None
    assert parsed.prefixes == ("10.9.8.0/24",)
    assert parsed.tunnel_mode == "split"
    assert parsed.dns_servers == ("192.0.2.53",)
    assert parsed.dns_domains == ("internal.test",)
    assert installs_default_route(parsed) is False


def test_xfrm_helpers_distinguish_split_and_full() -> None:
    split = parse_xfrm_policies(
        "src 10.10.80.10/32 dst 10.10.10.0/24\n\tdir out priority 1\n"
        "src 10.10.80.10/32 dst 10.10.20.0/24\n\tdir out priority 1\n"
    )
    full = parse_xfrm_policies("src 10.10.80.10/32 dst 0.0.0.0/0\n\tdir out priority 1\n")
    assert is_wildcard_remote_ts(split) is False
    assert split_remote_selectors(split) == ("10.10.10.0/24", "10.10.20.0/24")
    assert is_wildcard_remote_ts(full) is True
    assert split_remote_selectors(full) == ()


def test_split_dns_apply_does_not_install_routing_all(tmp_path: Path) -> None:
    fake = FakeResolved()
    state_path = tmp_path / "dns.state"
    apply_temporary_vpn_dns(
        "wlp5s0",
        ["192.0.2.53"],
        state_path,
        domains=("internal.test",),
        catch_all=False,
        run=fake.run,
    )
    assert fake.links["wlp5s0"]["servers"] == ["192.0.2.53"]
    assert fake.links["wlp5s0"]["domains"] == ["internal.test"]
    assert "~." not in fake.links["wlp5s0"]["domains"]
    assert fake.links["wlp5s0"]["default_route"] is False


def test_split_dns_without_domains_does_not_hijack(tmp_path: Path) -> None:
    fake = FakeResolved()
    state_path = tmp_path / "dns.state"
    apply_temporary_vpn_dns(
        "wlp5s0",
        ["192.0.2.53"],
        state_path,
        catch_all=False,
        run=fake.run,
    )
    assert fake.links["wlp5s0"]["servers"] == ["192.0.2.53"]
    assert "~." not in fake.links["wlp5s0"]["domains"]
    assert fake.links["wlp5s0"]["default_route"] is False


def test_full_tunnel_dns_still_installs_routing_all(tmp_path: Path) -> None:
    fake = FakeResolved()
    state_path = tmp_path / "dns.state"
    apply_temporary_vpn_dns("wlp5s0", ["192.0.2.53"], state_path, run=fake.run)
    assert fake.links["wlp5s0"]["domains"] == ["~."]


def test_helper_split_include_skips_default_route_and_restores(tmp_path: Path, monkeypatch) -> None:
    fake = FakeResolved()
    monkeypatch.setattr("fortigate_vpn_gui.helper.ipsec_dns._run", fake.run)
    monkeypatch.setattr(
        "fortigate_vpn_gui.helper.service.lookup_interface_for_address",
        lambda address, run=None: "wlp5s0" if address == "10.10.80.10" else None,
    )
    held: dict[str, FakeVpnProcess] = {}

    def factory(argv, on_output, on_exit, env=None):
        proc = FakeVpnProcess(argv, on_output, on_exit, env=env)
        held["proc"] = proc
        return proc

    service = HelperService(
        process_factory=factory,
        ipsec_discover=lambda: IpsecBackendCapabilities(
            charon_path="/usr/lib/ipsec/charon",
            swanctl_path="/usr/sbin/swanctl",
            available=True,
            source="test",
        ),
        runtime_dir_factory=lambda: tmp_path / "run",
        swanctl_runner=lambda argv, timeout: SwanctlCommandResult(returncode=0),
        vici_wait=lambda path, timeout: True,
        ike_port_probe=free_ike_port_report,
    )
    (tmp_path / "run").mkdir()
    service.connect(
        connect_request_from_fields(
            gateway="vpn.example.com",
            port=500,
            auth_mode="standard",
            backend="ipsec",
            ipsec=default_ipsec_settings().to_json(),
        ),
        credentials=IpsecCredentials(psk="super-psk", username="ada", password="hunter2"),
    )
    held["proc"].emit(
        "FortiClient compatibility: CFG_REPLY split-include "
        "count=2 prefixes=10.10.10.0/24,10.10.20.0/24 source=INTERNAL_IP4_SUBNET"
    )
    held["proc"].emit("FortiClient compatibility: CFG_REPLY dns servers=192.0.2.53 domains=(none)")
    held["proc"].emit("FortiClient compatibility: CFG_REPLY tunnel-mode=split")
    held["proc"].emit("installing virtual IP 10.10.80.10")
    held["proc"].emit("installing DNS server 192.0.2.53 via resolvconf")
    service.wait_for_ipsec_setup(timeout=2.0)
    held["proc"].emit("13[IKE] CHILD_SA fortigate{1} established with SPIs c1-c2")
    assert fake.links["wlp5s0"]["servers"] == ["192.0.2.53"]
    assert "~." not in fake.links["wlp5s0"]["domains"]
    assert fake.links["wlp5s0"]["default_route"] is False
    service.disconnect()
    assert fake.links["wlp5s0"]["servers"] == ["10.10.30.1"]
    assert "~." not in fake.links["wlp5s0"]["domains"]
    assert not (tmp_path / "run").exists()
    _assert_no_resolvectl_revert(fake.calls)
    assert "super-psk" not in str(fake.calls)


def test_helper_full_tunnel_cfg_reply_keeps_catch_all_dns(tmp_path: Path, monkeypatch) -> None:
    fake = FakeResolved()
    monkeypatch.setattr("fortigate_vpn_gui.helper.ipsec_dns._run", fake.run)
    monkeypatch.setattr(
        "fortigate_vpn_gui.helper.service.lookup_interface_for_address",
        lambda address, run=None: "wlp5s0" if address == "10.10.80.10" else None,
    )
    held: dict[str, FakeVpnProcess] = {}

    def factory(argv, on_output, on_exit, env=None):
        proc = FakeVpnProcess(argv, on_output, on_exit, env=env)
        held["proc"] = proc
        return proc

    service = HelperService(
        process_factory=factory,
        ipsec_discover=lambda: IpsecBackendCapabilities(
            charon_path="/usr/lib/ipsec/charon",
            swanctl_path="/usr/sbin/swanctl",
            available=True,
            source="test",
        ),
        runtime_dir_factory=lambda: tmp_path / "run",
        swanctl_runner=lambda argv, timeout: SwanctlCommandResult(returncode=0),
        vici_wait=lambda path, timeout: True,
        ike_port_probe=free_ike_port_report,
    )
    (tmp_path / "run").mkdir()
    service.connect(
        connect_request_from_fields(
            gateway="vpn.example.com",
            port=500,
            auth_mode="standard",
            backend="ipsec",
            ipsec=default_ipsec_settings().to_json(),
        ),
        credentials=IpsecCredentials(psk="super-psk", username="ada", password="hunter2"),
    )
    held["proc"].emit(
        "FortiClient compatibility: CFG_REPLY split-include count=0 prefixes=(none) source=none"
    )
    held["proc"].emit("FortiClient compatibility: CFG_REPLY tunnel-mode=full")
    held["proc"].emit("installing virtual IP 10.10.80.10")
    held["proc"].emit("installing DNS server 192.0.2.53 via resolvconf")
    service.wait_for_ipsec_setup(timeout=2.0)
    held["proc"].emit("13[IKE] CHILD_SA fortigate{1} established with SPIs c1-c2")
    assert fake.links["wlp5s0"]["domains"] == ["~."]
    service.disconnect()
    assert "~." not in fake.links["wlp5s0"]["domains"]


_SEVEN_SPLIT_PREFIXES = (
    "192.0.2.0/24",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.10.0/24",
    "100.64.0.0/10",
)


def test_parsed_subnets_become_effective_remote_child_sa_selectors() -> None:
    info = classify_cfg_reply_attributes(
        {INTERNAL_IP4_SUBNET: [_addr_mask(item) for item in _SEVEN_SPLIT_PREFIXES]}
    )
    assert info.is_split is True
    assert info.source == "INTERNAL_IP4_SUBNET"
    assert info.prefixes == _SEVEN_SPLIT_PREFIXES
    remote = apply_split_to_remote_ts((WILDCARD_PREFIX,), info)
    assert remote == _SEVEN_SPLIT_PREFIXES
    assert WILDCARD_PREFIX not in remote
    assert len(remote) == 7
    xfrm = parse_xfrm_policies(
        "\n".join(f"src 192.0.2.8/32 dst {item}\n\tdir out priority 1\n" for item in remote)
    )
    assert is_wildcard_remote_ts(xfrm) is False
    assert split_remote_selectors(xfrm) == _SEVEN_SPLIT_PREFIXES
    table = parse_table_220_routes(
        "\n".join(f"{item} via 203.0.113.1 dev eth0 proto static src 192.0.2.8" for item in remote)
    )
    assert table_220_has_default(table) is False
    assert WILDCARD_PREFIX not in table
    assert table == _SEVEN_SPLIT_PREFIXES


def test_full_tunnel_keeps_wildcard_remote_ts_and_table_220_default() -> None:
    info = classify_cfg_reply_attributes({})
    remote = apply_split_to_remote_ts((WILDCARD_PREFIX,), info)
    assert remote == (WILDCARD_PREFIX,)
    xfrm = parse_xfrm_policies("src 192.0.2.8/32 dst 0.0.0.0/0\n\tdir out priority 1\n")
    assert is_wildcard_remote_ts(xfrm) is True
    table = parse_table_220_routes("default via 203.0.113.1 dev eth0 proto static src 192.0.2.8")
    assert table_220_has_default(table) is True


def test_malformed_or_empty_split_does_not_invent_selectors() -> None:
    empty = SplitIncludeInfo(prefixes=(), source="INTERNAL_IP4_SUBNET", tunnel_mode="split")
    assert apply_split_to_remote_ts((WILDCARD_PREFIX,), empty) == (WILDCARD_PREFIX,)
    garbage = classify_cfg_reply_attributes({INTERNAL_IP4_SUBNET: [b"\x00\x01"]})
    assert garbage.is_split is False
    assert garbage.prefixes == ()
    assert apply_split_to_remote_ts((WILDCARD_PREFIX,), garbage) == (WILDCARD_PREFIX,)
    already = apply_split_to_remote_ts(("192.0.2.0/24", "198.51.100.0/24"), empty)
    assert already == ("192.0.2.0/24", "198.51.100.0/24")
    split = classify_cfg_reply_attributes({INTERNAL_IP4_SUBNET: [_addr_mask("192.0.2.0/24")]})
    unchanged = apply_split_to_remote_ts(("192.0.2.0/24",), split)
    assert unchanged == ("192.0.2.0/24",)


def test_helper_redacts_eap_identity_before_log_events(tmp_path: Path) -> None:
    uid = "0123456789abcdef0123456789abcdef"
    events: list[object] = []
    held: dict[str, FakeVpnProcess] = {}

    def factory(argv, on_output, on_exit, env=None):
        proc = FakeVpnProcess(argv, on_output, on_exit, env=env)
        held["proc"] = proc
        return proc

    service = HelperService(
        process_factory=factory,
        ipsec_discover=lambda: IpsecBackendCapabilities(
            charon_path="/usr/lib/ipsec/charon",
            swanctl_path="/usr/sbin/swanctl",
            available=True,
            source="test",
        ),
        runtime_dir_factory=lambda: tmp_path / "run",
        swanctl_runner=lambda argv, timeout: SwanctlCommandResult(returncode=0),
        vici_wait=lambda path, timeout: True,
        ike_port_probe=free_ike_port_report,
        listener=events.append,
    )
    (tmp_path / "run").mkdir()
    service.connect(
        connect_request_from_fields(
            gateway="vpn.example.com",
            port=500,
            auth_mode="standard",
            backend="ipsec",
            ipsec=default_ipsec_settings().to_json(),
        ),
        credentials=IpsecCredentials(psk="super-psk", username="ada", password="hunter2"),
    )
    split_line = (
        "FortiClient compatibility: CFG_REPLY split-include "
        "count=2 prefixes=192.0.2.0/24,198.51.100.0/24 source=INTERNAL_IP4_SUBNET"
    )
    held["proc"].emit(f"server requested EAP_IDENTITY (id 0x01), sending '{uid}'")
    held["proc"].emit(split_line)
    logs = [
        getattr(event, "line", "") or ""
        for event in events
        if getattr(event, "kind", None) is HelperEventKind.LOG
    ]
    assert any("sending '***'" in line for line in logs)
    assert all(uid not in line for line in logs)
    assert all("super-psk" not in line for line in logs)
    assert any(split_line in line for line in logs)
    assert redact_log_line(split_line) == split_line
    service.disconnect()
