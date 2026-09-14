# SPDX-License-Identifier: GPL-3.0-or-later
"""IPsec DNS apply/restore and XFRM selector diagnostics."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from fortigate_vpn_gui.diagnostics.checks import CommandResult, check_ipsec_tunnel
from fortigate_vpn_gui.diagnostics.ipsec_status import (
    UNUSABLE_SELECTOR_WARNING,
    is_gateway_only_remote_ts,
    parse_xfrm_policies,
)
from fortigate_vpn_gui.diagnostics.model import CheckStatus
from fortigate_vpn_gui.diagnostics.service import DiagnosticRequest, DiagnosticService
from fortigate_vpn_gui.helper.ipsec_dns import (
    DnsState,
    LinkDnsSnapshot,
    apply_temporary_vpn_dns,
    parse_dns_server_line,
    parse_resolvectl_link_values,
    parse_virtual_ip_line,
    read_dns_state,
    restore_from_state_path,
    verify_dns_restored,
    write_dns_state,
)
from fortigate_vpn_gui.helper.ipsec_runtime import wipe_ipsec_runtime, write_ipsec_runtime
from fortigate_vpn_gui.helper.service import HelperService, SwanctlCommandResult
from fortigate_vpn_gui.helper.validation import connect_request_from_fields
from fortigate_vpn_gui.profiles.ipsec import default_ipsec_settings
from fortigate_vpn_gui.profiles.model import build_profile
from fortigate_vpn_gui.vpn.classify import OutputHint, classify_output
from fortigate_vpn_gui.vpn.ipsec.detect import IpsecBackendCapabilities
from fortigate_vpn_gui.vpn.ipsec.secrets import IpsecCredentials
from fortigate_vpn_gui.vpn.models import ConnectionState, VpnSnapshot
from tests.vpn_fakes import FakeVpnProcess, VpnHarness

_XFRM_GATEWAY_ONLY = """
src 172.31.40.10/32 dst 93.105.89.35/32
	dir out priority 399999 ptype main
	tmpl src 10.10.30.103 dst 93.105.89.35
		proto esp reqid 1 mode tunnel
src 93.105.89.35/32 dst 172.31.40.10/32
	dir fwd priority 399999 ptype main
	tmpl src 93.105.89.35 dst 10.10.30.103
		proto esp reqid 1 mode tunnel
src 93.105.89.35/32 dst 172.31.40.10/32
	dir in priority 399999 ptype main
	tmpl src 93.105.89.35 dst 10.10.30.103
		proto esp reqid 1 mode tunnel
"""

_XFRM_SPLIT = """
src 172.31.40.10/32 dst 10.0.0.0/8
	dir out priority 399999 ptype main
	tmpl src 10.10.30.103 dst 93.105.89.35
		proto esp reqid 1 mode tunnel
src 10.0.0.0/8 dst 172.31.40.10/32
	dir in priority 399999 ptype main
	tmpl src 93.105.89.35 dst 10.10.30.103
		proto esp reqid 1 mode tunnel
"""


class FakeResolved:
    """In-memory NetworkManager + systemd-resolved stand-in."""

    def __init__(
        self,
        interface: str = "wlp5s0",
        *,
        servers: tuple[str, ...] = ("10.10.30.1",),
        domains: tuple[str, ...] = (),
        default_route: bool = True,
        nm_managed: bool = True,
    ) -> None:
        self.interface = interface
        self.nm_managed = nm_managed
        self.profile_servers = list(servers)
        self.profile_domains = list(domains)
        self.profile_default_route = default_route
        self.links: dict[str, dict[str, object]] = {
            interface: {
                "servers": list(servers),
                "domains": list(domains),
                "default_route": default_route,
            }
        }
        self.calls: list[list[str]] = []
        self.fail_vpn_overlay = False
        self.reapply_clears = False

    def run(self, argv, **kwargs):
        del kwargs
        cmd = list(argv)
        self.calls.append(cmd)
        if cmd[:3] == ["ip", "-o", "addr"]:
            return _completed(f"3: {self.interface}    inet 172.31.40.10/32")
        if cmd[:2] == ["nmcli", "-t"]:
            value = "yes" if self.nm_managed else "no"
            return _completed(f"GENERAL.NM-MANAGED:{value}")
        if cmd[:3] == ["nmcli", "device", "reapply"]:
            iface = cmd[3]
            if self.reapply_clears:
                self._set(iface, [], [], True)
            else:
                self._set(
                    iface,
                    list(self.profile_servers),
                    list(self.profile_domains),
                    self.profile_default_route,
                )
            return _completed()
        if cmd[:2] == ["resolvectl", "flush-caches"]:
            return _completed()
        if cmd[0] == "resolvectl" and cmd[1] == "status":
            iface = cmd[2] if len(cmd) > 2 else self.interface
            link = self._link(iface)
            servers = " ".join(link["servers"]) or "(none)"
            domains = " ".join(link["domains"]) or "(none)"
            return _completed(
                f"Link 3 ({iface})\n       DNS Servers: {servers}\n        DNS Domain: {domains}\n"
            )
        if cmd[0] == "resolvectl" and cmd[1] in {"dns", "domain", "default-route"}:
            return self._resolvectl(cmd)
        return _completed(returncode=1, stderr="unexpected")

    def _resolvectl(self, cmd: list[str]) -> subprocess.CompletedProcess[str]:
        action, iface = cmd[1], cmd[2]
        values = cmd[3:]
        link = self._link(iface)
        if action == "dns":
            if not values:
                return _completed(self._link_line(iface, link["servers"]))
            if self.fail_vpn_overlay and values and values[0] and values != self.profile_servers:
                return _completed(returncode=1, stderr="overlay failed")
            link["servers"] = [] if values == [""] else list(values)
            return _completed()
        if action == "domain":
            if not values:
                return _completed(self._link_line(iface, link["domains"]))
            link["domains"] = [] if values == [""] else list(values)
            return _completed()
        if action == "default-route":
            if not values:
                flag = "yes" if link["default_route"] else "no"
                return _completed(self._link_line(iface, [flag]))
            link["default_route"] = values[0] == "yes"
            return _completed()
        return _completed(returncode=1)

    def _link(self, iface: str) -> dict[str, object]:
        if iface not in self.links:
            self.links[iface] = {"servers": [], "domains": [], "default_route": True}
        return self.links[iface]

    def _set(self, iface: str, servers: list[str], domains: list[str], default_route: bool) -> None:
        self.links[iface] = {
            "servers": servers,
            "domains": domains,
            "default_route": default_route,
        }

    @staticmethod
    def _link_line(iface: str, values: list[str]) -> str:
        rest = " ".join(values)
        return f"Link 3 ({iface}): {rest}"


def _completed(stdout: str = "", stderr: str = "", returncode: int = 0):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def _assert_no_resolvectl_revert(calls: list[list[str]]) -> None:
    assert not any(cmd[:2] == ["resolvectl", "revert"] for cmd in calls)


def test_parse_charon_dns_and_vip_lines() -> None:
    assert parse_dns_server_line("installing DNS server 10.0.0.240 via resolvconf") == "10.0.0.240"
    assert parse_virtual_ip_line("installing virtual IP 172.31.40.10") == "172.31.40.10"
    assert parse_virtual_ip_line("got VIPs: 172.31.40.10") == "172.31.40.10"
    assert parse_dns_server_line("CHILD_SA fortigate established") is None


def test_parse_resolvectl_link_values_keeps_ipv6() -> None:
    text = "Link 3 (wlp5s0): 10.10.30.1 2001:4860:4860::8888"
    assert parse_resolvectl_link_values(text) == ("10.10.30.1", "2001:4860:4860::8888")
    assert parse_resolvectl_link_values("Link 3 (wlp5s0):") == ()


def test_dns_state_before_during_after_vpn(tmp_path: Path) -> None:
    fake = FakeResolved()
    state_path = tmp_path / "dns.state"
    applied = apply_temporary_vpn_dns("wlp5s0", ["10.0.0.240"], state_path, run=fake.run)
    assert applied.pre_vpn is not None
    assert applied.pre_vpn.servers == ("10.10.30.1",)
    assert applied.nm_managed is True
    assert fake.links["wlp5s0"]["servers"] == ["10.0.0.240"]
    assert fake.links["wlp5s0"]["domains"] == ["~."]
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    assert payload["pre_vpn"]["servers"] == ["10.10.30.1"]
    assert "super-psk" not in state_path.read_text(encoding="utf-8")
    result = restore_from_state_path(state_path, run=fake.run)
    assert result is not None
    assert result.verified is True
    assert fake.links["wlp5s0"]["servers"] == ["10.10.30.1"]
    assert "~." not in fake.links["wlp5s0"]["domains"]
    assert "10.0.0.240" not in fake.links["wlp5s0"]["servers"]
    _assert_no_resolvectl_revert(fake.calls)
    assert ["nmcli", "device", "reapply", "wlp5s0"] in fake.calls
    assert ["resolvectl", "flush-caches"] in fake.calls
    assert ["resolvectl", "status", "wlp5s0"] in fake.calls
    assert not state_path.exists()


def test_networkmanager_restore_does_not_use_revert(tmp_path: Path) -> None:
    fake = FakeResolved(nm_managed=True)
    state_path = tmp_path / "dns.state"
    apply_temporary_vpn_dns("wlp5s0", ["10.0.0.240"], state_path, run=fake.run)
    restore_from_state_path(state_path, run=fake.run)
    _assert_no_resolvectl_revert(fake.calls)
    assert fake.links["wlp5s0"]["servers"] == ["10.10.30.1"]


def test_nm_reapply_empty_falls_back_to_snapshot(tmp_path: Path) -> None:
    fake = FakeResolved(nm_managed=True)
    fake.reapply_clears = True
    state_path = tmp_path / "dns.state"
    apply_temporary_vpn_dns("wlp5s0", ["10.0.0.240"], state_path, run=fake.run)
    result = restore_from_state_path(state_path, run=fake.run)
    assert result is not None
    assert result.verified is True
    assert fake.links["wlp5s0"]["servers"] == ["10.10.30.1"]
    assert "~." not in fake.links["wlp5s0"]["domains"]
    _assert_no_resolvectl_revert(fake.calls)


def test_no_dns_before_vpn_is_restored_without_catch_all(tmp_path: Path) -> None:
    fake = FakeResolved(servers=(), nm_managed=True)
    state_path = tmp_path / "dns.state"
    apply_temporary_vpn_dns("wlp5s0", ["10.0.0.240"], state_path, run=fake.run)
    assert fake.links["wlp5s0"]["servers"] == ["10.0.0.240"]
    result = restore_from_state_path(state_path, run=fake.run)
    assert result is not None
    assert result.verified is True
    assert "10.0.0.240" not in fake.links["wlp5s0"]["servers"]
    assert "~." not in fake.links["wlp5s0"]["domains"]


def test_failed_apply_restores_pre_vpn_dns(tmp_path: Path) -> None:
    fake = FakeResolved()
    fake.fail_vpn_overlay = True
    state_path = tmp_path / "dns.state"
    try:
        apply_temporary_vpn_dns("wlp5s0", ["10.0.0.240"], state_path, run=fake.run)
    except RuntimeError:
        pass
    else:
        raise AssertionError("overlay should fail")
    assert fake.links["wlp5s0"]["servers"] == ["10.10.30.1"]
    assert "~." not in fake.links["wlp5s0"]["domains"]
    assert not state_path.exists()
    _assert_no_resolvectl_revert(fake.calls)


def test_stale_runtime_cleanup_restores_dns(tmp_path: Path) -> None:
    fake = FakeResolved()
    state_path = tmp_path / "dns.state"
    apply_temporary_vpn_dns("wlp5s0", ["10.0.0.240"], state_path, run=fake.run)
    assert fake.links["wlp5s0"]["servers"] == ["10.0.0.240"]
    result = restore_from_state_path(state_path, run=fake.run)
    assert result is not None and result.verified
    assert fake.links["wlp5s0"]["servers"] == ["10.10.30.1"]
    assert not state_path.exists()


def test_legacy_state_without_snapshot_uses_nm_reapply(tmp_path: Path) -> None:
    fake = FakeResolved()
    fake._set("wlp5s0", ["10.0.0.240"], ["~."], True)
    state_path = tmp_path / "dns.state"
    write_dns_state(
        state_path,
        DnsState(interface="wlp5s0", servers=("10.0.0.240",), pre_vpn=None, nm_managed=False),
    )
    result = restore_from_state_path(state_path, run=fake.run)
    assert result is not None
    assert result.verified is True
    assert fake.links["wlp5s0"]["servers"] == ["10.10.30.1"]
    assert "~." not in fake.links["wlp5s0"]["domains"]
    assert ["nmcli", "device", "reapply", "wlp5s0"] in fake.calls
    _assert_no_resolvectl_revert(fake.calls)


def test_repeated_connect_disconnect_restores_each_time(tmp_path: Path) -> None:
    fake = FakeResolved()
    state_path = tmp_path / "dns.state"
    for _ in range(2):
        apply_temporary_vpn_dns("wlp5s0", ["10.0.0.240"], state_path, run=fake.run)
        assert fake.links["wlp5s0"]["servers"] == ["10.0.0.240"]
        restore_from_state_path(state_path, run=fake.run)
        assert fake.links["wlp5s0"]["servers"] == ["10.10.30.1"]
        assert "~." not in fake.links["wlp5s0"]["domains"]
    _assert_no_resolvectl_revert(fake.calls)


def test_verify_rejects_gateway_only_vpn_leftover() -> None:
    current = LinkDnsSnapshot(interface="wlp5s0", servers=("10.0.0.240",), domains=("~.",))
    pre = LinkDnsSnapshot(interface="wlp5s0", servers=("10.10.30.1",), domains=())
    ok, detail = verify_dns_restored(
        current, pre_vpn=pre, vpn_servers=("10.0.0.240",), allow_empty=False
    )
    assert ok is False
    assert "10.0.0.240" in detail


def test_helper_applies_and_restores_vpn_dns(tmp_path: Path, monkeypatch) -> None:
    fake = FakeResolved()
    monkeypatch.setattr("fortigate_vpn_gui.helper.ipsec_dns._run", fake.run)
    monkeypatch.setattr(
        "fortigate_vpn_gui.helper.service.lookup_interface_for_address",
        lambda address, run=None: "wlp5s0" if address == "172.31.40.10" else None,
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
    held["proc"].emit("installing virtual IP 172.31.40.10")
    held["proc"].emit("installing DNS server 10.0.0.240 via resolvconf")
    service.wait_for_ipsec_setup(timeout=2.0)
    held["proc"].emit("13[IKE] CHILD_SA fortigate{1} established with SPIs c1-c2")
    assert fake.links["wlp5s0"]["servers"] == ["10.0.0.240"]
    assert fake.links["wlp5s0"]["domains"] == ["~."]
    dns_state = tmp_path / "run" / "dns.state"
    saved = read_dns_state(dns_state)
    assert saved is not None
    assert saved.pre_vpn is not None
    assert saved.pre_vpn.servers == ("10.10.30.1",)
    service.disconnect()
    assert fake.links["wlp5s0"]["servers"] == ["10.10.30.1"]
    assert "~." not in fake.links["wlp5s0"]["domains"]
    assert "10.0.0.240" not in fake.links["wlp5s0"]["servers"]
    assert not (tmp_path / "run").exists()
    _assert_no_resolvectl_revert(fake.calls)
    assert "super-psk" not in str(fake.calls)
    assert "hunter2" not in str(fake.calls)


def test_helper_failed_connect_restores_dns(tmp_path: Path, monkeypatch) -> None:
    fake = FakeResolved()
    monkeypatch.setattr("fortigate_vpn_gui.helper.ipsec_dns._run", fake.run)
    monkeypatch.setattr(
        "fortigate_vpn_gui.helper.service.lookup_interface_for_address",
        lambda address, run=None: "wlp5s0" if address == "172.31.40.10" else None,
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
        swanctl_runner=lambda argv, timeout: SwanctlCommandResult(returncode=1, stderr="failed"),
        vici_wait=lambda path, timeout: True,
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
    held["proc"].emit("installing virtual IP 172.31.40.10")
    held["proc"].emit("installing DNS server 10.0.0.240 via resolvconf")
    service.wait_for_ipsec_setup(timeout=2.0)
    assert fake.links["wlp5s0"]["servers"] == ["10.10.30.1"]
    assert "~." not in fake.links["wlp5s0"]["domains"]


def test_write_ipsec_runtime_restores_stale_dns(tmp_path: Path, monkeypatch) -> None:
    fake = FakeResolved()
    monkeypatch.setattr("fortigate_vpn_gui.helper.ipsec_dns._run", fake.run)
    runtime_dir = tmp_path / "run"
    runtime_dir.mkdir()
    state_path = runtime_dir / "dns.state"
    apply_temporary_vpn_dns("wlp5s0", ["10.0.0.240"], state_path, run=fake.run)
    credentials = IpsecCredentials(psk="super-psk", username="ada", password="hunter2")
    files = write_ipsec_runtime(
        gateway="vpn.example.com",
        port=500,
        settings=default_ipsec_settings(),
        credentials=credentials,
        runtime_dir=runtime_dir,
    )
    assert fake.links["wlp5s0"]["servers"] == ["10.10.30.1"]
    assert not state_path.exists()
    wipe_ipsec_runtime(files)
    assert "super-psk" not in str(fake.calls)


def test_network1_dns_failure_is_not_ssl_dns_hint() -> None:
    line = "Failed to set DNS configuration: Unit dbus-org.freedesktop.network1.service not found."
    assert classify_output(line) is OutputHint.NONE
    assert classify_output("ERROR: DNS nameserver update failed") is OutputHint.DNS_FAILURE


def test_xfrm_gateway_only_remote_ts_is_unusable() -> None:
    policies = parse_xfrm_policies(_XFRM_GATEWAY_ONLY)
    assert is_gateway_only_remote_ts(policies, ["93.105.89.35"])
    split = parse_xfrm_policies(_XFRM_SPLIT)
    assert not is_gateway_only_remote_ts(split, ["93.105.89.35"])


def test_diagnostics_warn_when_child_sa_only_covers_gateway() -> None:
    profile = build_profile(
        name="IPsec",
        gateway="93.105.89.35",
        port=500,
        vpn_type="ipsec",
        ipsec=default_ipsec_settings().to_json(),
    )
    snapshot = VpnSnapshot(
        state=ConnectionState.CONNECTED,
        profile_id=profile.id,
        profile_name=profile.name,
        error_code=None,
        error_message=None,
        process=None,
        vpn_backend="ipsec",
    )

    def run_command(argv, timeout=3.0):
        del timeout
        if argv[-2:] == ["xfrm", "policy"]:
            return CommandResult(returncode=0, stdout=_XFRM_GATEWAY_ONLY)
        return CommandResult(returncode=0, stdout="")

    check = check_ipsec_tunnel(
        snapshot,
        profile,
        ["93.105.89.35"],
        include_network=False,
        which=lambda name: f"/sbin/{name}",
        run_command=run_command,
    )
    assert check.status is CheckStatus.WARNING
    assert check.summary == UNUSABLE_SELECTOR_WARNING
    assert "172.31.40.10" in (check.detail or "")
    assert "super-psk" not in (check.detail or "")
    assert "hmac" not in (check.detail or "").lower()


def test_diagnostics_pass_when_split_include_is_installed() -> None:
    profile = build_profile(
        name="IPsec",
        gateway="93.105.89.35",
        port=500,
        vpn_type="ipsec",
        ipsec=default_ipsec_settings().to_json(),
    )
    snapshot = VpnSnapshot(
        state=ConnectionState.CONNECTED,
        profile_id=profile.id,
        profile_name=profile.name,
        error_code=None,
        error_message=None,
        process=None,
        vpn_backend="ipsec",
    )
    check = check_ipsec_tunnel(
        snapshot,
        profile,
        ["93.105.89.35"],
        include_network=False,
        which=lambda name: f"/sbin/{name}",
        run_command=lambda argv, timeout=3.0: CommandResult(returncode=0, stdout=_XFRM_SPLIT),
    )
    assert check.status is CheckStatus.PASS
    assert "10.0.0.0/8" in check.summary


def test_ssl_diagnostics_omit_ipsec_selector_check() -> None:
    harness = VpnHarness()
    profile = build_profile(name="SSL", gateway="vpn.example.com", port=443)
    run = DiagnosticService().collect_local(
        DiagnosticRequest(
            snapshot=harness.backend.snapshot(),
            profile=profile,
            include_network=False,
        )
    )
    assert run.check("tunnel.ipsec") is None
    assert run.check("vpn.ipsec") is not None
