# SPDX-License-Identifier: GPL-3.0-or-later
"""Pre-VPN gateway host-route snapshot/restore. Synthetic addresses only."""

from __future__ import annotations

import subprocess
import threading
from pathlib import Path

from fortigate_vpn_gui.helper.ike_ports import free_ike_port_report
from fortigate_vpn_gui.helper.ipsec_gateway_route import (
    GatewayHostRoute,
    parse_host_route_line,
    restore_and_verify_explicit_host_route,
    restore_explicit_host_route,
    restore_from_gateway_route_path,
    snapshot_explicit_host_route,
    snapshot_explicit_host_route_with_reason,
    write_gateway_route_state,
)
from fortigate_vpn_gui.helper.ipsec_runtime import wipe_ipsec_runtime, write_ipsec_runtime
from fortigate_vpn_gui.helper.protocol import BACKEND_IPSEC
from fortigate_vpn_gui.helper.service import HelperService, SwanctlCommandResult
from fortigate_vpn_gui.helper.validation import connect_request_from_fields
from fortigate_vpn_gui.profiles.ipsec import default_ipsec_settings
from fortigate_vpn_gui.vpn.ipsec.detect import IpsecBackendCapabilities
from fortigate_vpn_gui.vpn.ipsec.secrets import IpsecCredentials
from tests.test_ipsec_dns import FakeResolved
from tests.vpn_fakes import FakeVpnProcess

_DEST = "192.0.2.8"
_VIA = "10.91.124.15"
_DEV = "wlp5s0"


class FakeIp:
    """In-memory ``ip route`` stand-in. Does not touch the host routing table."""

    def __init__(self) -> None:
        self.host_routes: dict[str, str] = {}
        self.calls: list[list[str]] = []
        self.replace_error: str | None = None
        self.hide_after_replace = False

    def run(self, argv, **kwargs):
        self.calls.append(list(argv))
        if argv[:4] == ["ip", "-4", "route", "show"] and "exact" in argv:
            dest = argv[argv.index("exact") + 1].split("/", 1)[0]
            stdout = self.host_routes.get(dest, "")
            return subprocess.CompletedProcess(argv, 0, stdout=stdout, stderr="")
        if argv[:4] == ["ip", "-4", "route", "show"] and argv[-2:] == ["table", "main"]:
            stdout = "\n".join(self.host_routes.values())
            return subprocess.CompletedProcess(argv, 0, stdout=stdout, stderr="")
        if argv[:4] == ["ip", "-4", "route", "replace"]:
            if self.replace_error is not None:
                return subprocess.CompletedProcess(
                    argv, 1, stdout="", stderr=self.replace_error
                )
            dest = argv[4].split("/", 1)[0]
            if self.hide_after_replace:
                self.host_routes.pop(dest, None)
            else:
                self.host_routes[dest] = " ".join(argv[4:])
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
        return subprocess.CompletedProcess(argv, 1, stdout="", stderr="unexpected")


def test_parse_host_route_ignores_default_and_table_220() -> None:
    assert parse_host_route_line("default via 10.0.0.1 dev eno1", destination="192.0.2.1") is None
    assert (
        parse_host_route_line(
            "192.0.2.1 via 10.91.124.15 dev wlp5s0 table 220",
            destination="192.0.2.1",
        )
        is None
    )
    route = parse_host_route_line(
        "192.0.2.1 via 10.91.124.15 dev wlp5s0",
        destination="192.0.2.1",
    )
    assert route == GatewayHostRoute(
        destination="192.0.2.1",
        device="wlp5s0",
        via="10.91.124.15",
    )


def test_no_initial_host_route_does_not_invent_one() -> None:
    fake = FakeIp()
    route, reason = snapshot_explicit_host_route_with_reason(_DEST, run=fake.run)
    assert route is None
    assert "no explicit main-table /32" in reason
    assert not any(call[3:4] == ["replace"] for call in fake.calls)


def test_covering_default_only_does_not_invent_slash32() -> None:
    fake = FakeIp()
    fake.host_routes["default"] = "default via 10.0.0.1 dev eno1"
    route = snapshot_explicit_host_route(
        "vpn.example.com", run=fake.run, resolve=lambda _host: "192.0.2.1"
    )
    assert route is None
    assert restore_explicit_host_route(None, run=fake.run) is False
    assert not any(call[3:4] == ["replace"] for call in fake.calls)


def test_hostname_snapshot_uses_resolver_not_route_get() -> None:
    fake = FakeIp()
    fake.host_routes["192.0.2.1"] = "192.0.2.1 via 10.91.124.15 dev wlp5s0"
    route = snapshot_explicit_host_route(
        "vpn.example.com", run=fake.run, resolve=lambda _host: "192.0.2.1"
    )
    assert route is not None
    assert route.destination == "192.0.2.1"
    assert not any(call[3:4] == ["get"] for call in fake.calls)


def test_restore_replaces_missing_host_route_without_src() -> None:
    fake = FakeIp()
    route = GatewayHostRoute(destination=_DEST, device=_DEV, via=_VIA)
    result = restore_and_verify_explicit_host_route(route, run=fake.run)
    assert result.verified is True
    replace = [call for call in fake.calls if call[3:4] == ["replace"]][0]
    assert f"{_DEST}/32" in replace
    assert "via" in replace and _VIA in replace
    assert "dev" in replace and _DEV in replace
    assert "src" not in replace


def test_restore_command_failure_is_reported() -> None:
    fake = FakeIp()
    fake.replace_error = "Network is unreachable"
    route = GatewayHostRoute(destination=_DEST, device=_DEV, via=_VIA)
    result = restore_and_verify_explicit_host_route(route, run=fake.run, retries=0)
    assert result.attempted is True
    assert result.verified is False
    assert "unreachable" in result.detail.lower() or "failed" in result.detail.lower()
    assert _DEST not in fake.host_routes


def test_verification_failure_when_kernel_hides_route() -> None:
    fake = FakeIp()
    fake.hide_after_replace = True
    route = GatewayHostRoute(destination=_DEST, device=_DEV, via=_VIA)
    result = restore_and_verify_explicit_host_route(route, run=fake.run, retries=0)
    assert result.attempted is True
    assert result.verified is False
    assert "kernel" in result.detail.lower()


def _connect_helper(tmp_path: Path, monkeypatch, *, async_exit: bool = False):
    fake_ip = FakeIp()
    fake_ip.host_routes[_DEST] = f"{_DEST} via {_VIA} dev {_DEV}"
    fake_dns = FakeResolved()
    ordered: list[list[str]] = []
    logs: list[str] = []

    def combined_run(argv, **kwargs):
        cmd = list(argv)
        ordered.append(cmd)
        if cmd[:3] == ["ip", "-4", "route"]:
            return fake_ip.run(argv, **kwargs)
        result = fake_dns.run(argv, **kwargs)
        if cmd[:3] == ["nmcli", "device", "reapply"]:
            fake_ip.host_routes.pop(_DEST, None)
        return result

    monkeypatch.setattr("fortigate_vpn_gui.helper.ipsec_dns._run", combined_run)
    monkeypatch.setattr("fortigate_vpn_gui.helper.ipsec_gateway_route._run", combined_run)
    monkeypatch.setattr(
        "fortigate_vpn_gui.helper.service.lookup_interface_for_address",
        lambda address, run=None: "wlp5s0" if address == "172.31.40.10" else None,
    )
    held: dict[str, FakeVpnProcess] = {}

    def factory(argv, on_output, on_exit, env=None):
        proc = FakeVpnProcess(argv, on_output, on_exit, env=env)
        if async_exit:
            proc.exit_on_terminate = False

            def terminate() -> None:
                proc.terminate_called = True
                fake_ip.host_routes.pop(_DEST, None)
                worker = threading.Thread(target=lambda: proc.finish(0), daemon=True)
                worker.start()

            proc.terminate = terminate  # type: ignore[method-assign]
        else:
            original = proc.terminate

            def terminate() -> None:
                fake_ip.host_routes.pop(_DEST, None)
                original()

            proc.terminate = terminate  # type: ignore[method-assign]
        held["proc"] = proc
        return proc

    def runner(argv, timeout, env=None):
        del argv, timeout, env
        return SwanctlCommandResult(returncode=0)

    service = HelperService(
        process_factory=factory,
        ipsec_discover=lambda: IpsecBackendCapabilities(
            charon_path="/usr/lib/ipsec/charon",
            swanctl_path="/usr/sbin/swanctl",
            available=True,
            source="test",
        ),
        runtime_dir_factory=lambda: tmp_path / "run",
        swanctl_runner=runner,
        vici_wait=lambda path, timeout: True,
        ike_port_probe=free_ike_port_report,
        listener=lambda event: logs.append(event.line or "") if event.line else None,
    )
    (tmp_path / "run").mkdir()
    service.connect(
        connect_request_from_fields(
            gateway=_DEST,
            port=500,
            auth_mode="standard",
            backend=BACKEND_IPSEC,
            ipsec=default_ipsec_settings().to_json(),
        ),
        credentials=IpsecCredentials(psk="super-psk", username="ada", password="hunter2"),
    )
    held["proc"].emit("installing virtual IP 172.31.40.10")
    held["proc"].emit("installing DNS server 10.0.0.240 via resolvconf")
    service.wait_for_ipsec_setup(timeout=2.0)
    held["proc"].emit("13[IKE] CHILD_SA fortigate{1} established with SPIs c1-c2")
    return service, fake_ip, ordered, logs, held


def _second_saml_bootstrap_follows_host_route(fake_ip: FakeIp) -> bool:
    """Unprivileged :1001 POST follows the kernel main table.

    After teardown, an explicit /32 must still win over the other NIC default.
    """
    route = snapshot_explicit_host_route(_DEST, run=fake_ip.run)
    return (
        route is not None
        and route.destination == _DEST
        and route.device == _DEV
        and route.via == _VIA
    )


def test_full_teardown_restores_slash32_after_all_route_mutations(
    tmp_path: Path, monkeypatch
) -> None:
    service, fake_ip, ordered, logs, held = _connect_helper(
        tmp_path, monkeypatch, async_exit=True
    )
    assert any("Gateway route snapshot captured:" in line for line in logs)
    assert _DEST in fake_ip.host_routes
    service.disconnect(wait=True)
    assert _DEST in fake_ip.host_routes
    last_reapply = max(
        i for i, cmd in enumerate(ordered) if cmd[:3] == ["nmcli", "device", "reapply"]
    )
    last_replace = max(i for i, cmd in enumerate(ordered) if cmd[3:4] == ["replace"])
    assert last_replace > last_reapply
    replace = next(cmd for cmd in reversed(ordered) if cmd[3:4] == ["replace"])
    assert f"{_DEST}/32" in replace
    assert "src" not in replace
    joined = "\n".join(logs)
    assert "Gateway route restore starting" in joined
    assert "Gateway route restore completed" in joined
    assert "Gateway route restore verified:" in joined
    assert "Gateway route restore failed:" not in joined
    assert "super-psk" not in joined
    assert "tokenid" not in joined.lower()
    again = snapshot_explicit_host_route(_DEST, run=fake_ip.run)
    assert again is not None
    assert again.destination == _DEST
    assert again.device == _DEV
    assert again.via == _VIA
    assert _second_saml_bootstrap_follows_host_route(fake_ip)
    assert not (tmp_path / "run").exists()
    assert held["proc"].terminate_called is True


def test_normal_disconnect_restores_slash32_after_dns_reapply(
    tmp_path: Path, monkeypatch
) -> None:
    service, fake_ip, ordered, logs, held = _connect_helper(tmp_path, monkeypatch)
    service.disconnect(wait=True)
    assert _DEST in fake_ip.host_routes
    last_reapply = max(
        i for i, cmd in enumerate(ordered) if cmd[:3] == ["nmcli", "device", "reapply"]
    )
    last_replace = max(i for i, cmd in enumerate(ordered) if cmd[3:4] == ["replace"])
    assert last_replace > last_reapply
    assert _second_saml_bootstrap_follows_host_route(fake_ip)
    assert any("Gateway route restore verified:" in line for line in logs)
    assert held["proc"].terminate_called is True


def test_duplicate_cleanup_is_idempotent(tmp_path: Path, monkeypatch) -> None:
    service, fake_ip, _ordered, _logs, held = _connect_helper(tmp_path, monkeypatch)
    service.disconnect(wait=True)
    service.disconnect(wait=True)
    held["proc"].finish(0)
    assert _DEST in fake_ip.host_routes
    assert not (tmp_path / "run").exists()


def test_unexpected_charon_exit_restores_slash32(tmp_path: Path, monkeypatch) -> None:
    service, fake_ip, ordered, logs, held = _connect_helper(tmp_path, monkeypatch)
    fake_ip.host_routes.pop(_DEST, None)
    held["proc"].finish(1)
    assert _DEST in fake_ip.host_routes
    assert any("Gateway route restore verified:" in line for line in logs)
    last_reapply = max(
        i for i, cmd in enumerate(ordered) if cmd[:3] == ["nmcli", "device", "reapply"]
    )
    last_replace = max(i for i, cmd in enumerate(ordered) if cmd[3:4] == ["replace"])
    assert last_replace > last_reapply
    service.disconnect(wait=True)


def test_runtime_wipe_does_not_restore_after_files_are_gone(tmp_path: Path) -> None:
    fake = FakeIp()
    files = write_ipsec_runtime(
        gateway=_DEST,
        port=500,
        settings=default_ipsec_settings(),
        credentials=IpsecCredentials(psk="super-psk", username="ada", password="hunter2"),
        runtime_dir=tmp_path / "run",
    )
    route = GatewayHostRoute(destination=_DEST, device=_DEV, via=_VIA)
    write_gateway_route_state(files.gateway_route, route)
    fake.host_routes.pop(_DEST, None)
    restored = restore_from_gateway_route_path(files.gateway_route, run=fake.run)
    assert restored is True
    wipe_ipsec_runtime(files)
    assert not (tmp_path / "run").exists()
