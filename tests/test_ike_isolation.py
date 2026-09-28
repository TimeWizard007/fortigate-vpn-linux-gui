# SPDX-License-Identifier: GPL-3.0-or-later
"""IPsec isolation from system strongSwan. Never talks to /run/charon.vici."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from fortigate_vpn_gui.diagnostics.checks import check_ike_ports
from fortigate_vpn_gui.diagnostics.model import CheckStatus
from fortigate_vpn_gui.gui.connection_page import ConnectionPage
from fortigate_vpn_gui.helper.ike_ports import (
    IkePortReport,
    IkeUdpBinding,
    format_ike_port_lines,
    inspect_ike_udp_ports,
    parse_udp_inodes,
)
from fortigate_vpn_gui.helper.ipsec_runtime import (
    SYSTEM_CHARON_PID,
    SYSTEM_VICI_SOCKET,
    _unlink_if_exists,
    inspect_owned_ipsec_state,
    is_protected_system_ipsec_path,
    recover_owned_ipsec_leftovers,
    write_ipsec_runtime,
)
from fortigate_vpn_gui.helper.protocol import HelperError
from fortigate_vpn_gui.helper.service import HelperService, default_swanctl_runner
from fortigate_vpn_gui.helper.validation import connect_request_from_fields
from fortigate_vpn_gui.profiles.ipsec import default_ipsec_settings
from fortigate_vpn_gui.profiles.manager import ProfileManager
from fortigate_vpn_gui.vpn.classify import (
    IKE_PORT_CONFLICT_MESSAGE,
    OutputHint,
    classify_output,
    user_message_for_hint,
)
from fortigate_vpn_gui.vpn.ipsec.commands import SYSTEM_VICI_URI, build_swanctl_environment
from fortigate_vpn_gui.vpn.ipsec.detect import IpsecBackendCapabilities
from fortigate_vpn_gui.vpn.ipsec.secrets import IpsecCredentials
from fortigate_vpn_gui.vpn.ipsec.swanctl import build_strongswan_conf, build_swanctl_client_conf
from fortigate_vpn_gui.vpn.models import ConnectionState, VpnErrorCode, VpnSnapshot
from tests.vpn_fakes import FakeVpnProcess, VpnHarness

_UDP_500 = (
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt"
    "   uid  timeout inode\n"
    "   1: 00000000:01F4 00000000:0000 07 00000000:00000000 00:00000000 00000000"
    "     0        0 11111 1 0000000000000000 0\n"
)
_UDP_4500 = (
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt"
    "   uid  timeout inode\n"
    "   2: 00000000:1194 00000000:0000 07 00000000:00000000 00:00000000 00000000"
    "     0        0 22222 1 0000000000000000 0\n"
)
_UDP_BOTH = _UDP_500 + _UDP_4500


def _unrelated_charon(*, ports: tuple[int, ...] = (500, 4500)) -> IkePortReport:
    bindings_500: list[IkeUdpBinding] = []
    bindings_4500: list[IkeUdpBinding] = []
    if 500 in ports:
        bindings_500.append(
            IkeUdpBinding(
                port=500,
                inode=11111,
                pid=3615,
                comm="charon",
                service="strongswan-starter.service",
            )
        )
    if 4500 in ports:
        bindings_4500.append(
            IkeUdpBinding(
                port=4500,
                inode=22222,
                pid=3615,
                comm="charon",
                service="strongswan-starter.service",
            )
        )
    return IkePortReport(port_500=tuple(bindings_500), port_4500=tuple(bindings_4500))


def _owned_charon() -> IkePortReport:
    owned = IkeUdpBinding(
        port=500,
        inode=1,
        pid=4242,
        comm="charon",
        service=None,
        owned=True,
    )
    return IkePortReport(port_500=(owned,), port_4500=())


def _disconnected() -> VpnSnapshot:
    return VpnSnapshot(
        state=ConnectionState.DISCONNECTED,
        profile_id=None,
        profile_name=None,
        error_code=None,
        error_message=None,
        process=None,
        vpn_backend=None,
    )


def test_no_system_charon_ports_are_available() -> None:
    report = inspect_ike_udp_ports(udp_text="", udp6_text="", owned_pids=())
    assert report.occupied is False
    assert report.unrelated_conflict() is False
    lines = format_ike_port_lines(report)
    assert lines[0] == "IKE port 500: available"
    assert lines[1] == "IKE NAT-T port 4500: available"


def test_application_owned_charon_is_not_an_unrelated_conflict() -> None:
    report = _owned_charon()
    assert report.occupied_500 is True
    assert report.unrelated_conflict(owned_pids=(4242,)) is False


def test_unrelated_system_charon_is_a_conflict() -> None:
    report = _unrelated_charon()
    assert report.unrelated_conflict() is True
    assert report.unrelated_conflict(owned_pids=(999,)) is True
    owner = report.primary_unrelated()
    assert owner is not None
    assert owner.pid == 3615
    assert owner.service == "strongswan-starter.service"
    assert owner.comm == "charon"


def test_udp_500_occupied() -> None:
    assert parse_udp_inodes(_UDP_500, 500) == (11111,)
    assert parse_udp_inodes(_UDP_500, 4500) == ()
    report = inspect_ike_udp_ports(
        udp_text=_UDP_500,
        udp6_text="",
        owned_pids=(),
        owner_lookup=lambda port, inode, owned: IkeUdpBinding(
            port=port, inode=inode, pid=3615, comm="charon"
        ),
    )
    assert report.occupied_500 is True
    assert report.occupied_4500 is False
    assert report.unrelated_conflict() is True


def test_udp_4500_occupied() -> None:
    assert parse_udp_inodes(_UDP_4500, 4500) == (22222,)
    report = inspect_ike_udp_ports(
        udp_text=_UDP_4500,
        udp6_text="",
        owned_pids=(),
        owner_lookup=lambda port, inode, owned: IkeUdpBinding(
            port=port, inode=inode, pid=3615, comm="charon"
        ),
    )
    assert report.occupied_4500 is True
    assert report.occupied_500 is False
    assert report.unrelated_conflict() is True


def test_both_ike_ports_occupied() -> None:
    report = inspect_ike_udp_ports(
        udp_text=_UDP_BOTH,
        udp6_text="",
        owned_pids=(),
        owner_lookup=lambda port, inode, owned: IkeUdpBinding(
            port=port, inode=inode, pid=3615, comm="charon"
        ),
    )
    assert report.occupied_500 is True
    assert report.occupied_4500 is True
    assert report.unrelated_conflict() is True


def test_system_charon_pid_path_is_protected() -> None:
    assert is_protected_system_ipsec_path(SYSTEM_CHARON_PID) is True
    assert is_protected_system_ipsec_path(Path("/var/run/charon.pid")) is True
    assert is_protected_system_ipsec_path(SYSTEM_VICI_SOCKET) is True
    assert is_protected_system_ipsec_path(Path("/run/charon.fvl.vici")) is False
    assert is_protected_system_ipsec_path(Path("/run/charon.fvl.pid")) is False


def test_system_pid_and_vici_are_never_unlinked(tmp_path: Path, monkeypatch) -> None:
    pid = tmp_path / "charon.pid"
    vici = tmp_path / "charon.vici"
    pid.write_text("3615", encoding="utf-8")
    vici.write_text("socket", encoding="utf-8")
    monkeypatch.setattr(
        "fortigate_vpn_gui.helper.ipsec_runtime._PROTECTED_SYSTEM_PATHS",
        (pid, vici),
    )
    _unlink_if_exists(pid)
    _unlink_if_exists(vici)
    assert pid.exists()
    assert vici.exists()


def test_system_charon_pid_is_not_proof_of_app_ownership(monkeypatch, tmp_path: Path) -> None:
    missing = tmp_path / "missing"
    monkeypatch.setattr(
        "fortigate_vpn_gui.helper.ipsec_runtime.LIVE_STRONGSWAN_CONF", missing / "conf"
    )
    monkeypatch.setattr(
        "fortigate_vpn_gui.helper.ipsec_runtime.LIVE_DNS_STATE_PATH", missing / "dns"
    )
    monkeypatch.setattr("fortigate_vpn_gui.helper.ipsec_runtime.LIVE_SWANCTL_DIR", missing / "swan")
    monkeypatch.setattr("fortigate_vpn_gui.helper.ipsec_runtime.owned_charon_pids", lambda: ())
    monkeypatch.setattr("fortigate_vpn_gui.helper.ipsec_runtime._charon_pids", lambda: (3615,))
    leftover = inspect_owned_ipsec_state()
    assert leftover.has_owned_leftover is False
    assert leftover.other_charon_running is True
    assert leftover.owned_charon_pids == ()


def test_system_vici_socket_is_not_the_application_endpoint() -> None:
    conf = build_strongswan_conf(vici_socket="/run/charon.fvl.vici")
    client = build_swanctl_client_conf(vici_socket="/run/charon.fvl.vici")
    assert SYSTEM_VICI_URI not in conf
    assert SYSTEM_VICI_URI not in client
    assert "unix:///run/charon.vici" not in conf
    assert "unix:///run/charon.vici" not in client
    env = build_swanctl_environment("/etc/swanctl/fortigate-vpn-linux-gui/vici-client.conf")
    assert env["STRONGSWAN_CONF"].endswith("vici-client.conf")
    assert "/run/charon.vici" not in env["STRONGSWAN_CONF"]


def test_default_swanctl_runner_refuses_system_vici() -> None:
    result = default_swanctl_runner(["/usr/sbin/swanctl", "--stats"], 1.0)
    assert result.returncode == 78
    assert "STRONGSWAN_CONF" in result.stderr
    assert "super-psk" not in result.stderr


def test_cleanup_with_unrelated_charon_does_not_kill_it(monkeypatch, tmp_path: Path) -> None:
    conf = tmp_path / "charon.fvl.conf"
    dns = tmp_path / "charon.fvl.dns"
    swan = tmp_path / "swanctl"
    vici = tmp_path / "charon.fvl.vici"
    pid_file = tmp_path / "charon.fvl.pid"
    system_pid = tmp_path / "system.pid"
    system_vici = tmp_path / "system.vici"
    conf.write_text("owned", encoding="utf-8")
    system_pid.write_text("3615", encoding="utf-8")
    system_vici.write_text("system", encoding="utf-8")
    swan.mkdir()
    killed: list[int] = []
    monkeypatch.setattr("fortigate_vpn_gui.helper.ipsec_runtime.LIVE_STRONGSWAN_CONF", conf)
    monkeypatch.setattr("fortigate_vpn_gui.helper.ipsec_runtime.LIVE_DNS_STATE_PATH", dns)
    monkeypatch.setattr("fortigate_vpn_gui.helper.ipsec_runtime.LIVE_SWANCTL_DIR", swan)
    monkeypatch.setattr("fortigate_vpn_gui.helper.ipsec_runtime.LIVE_VICI_SOCKET", vici)
    monkeypatch.setattr("fortigate_vpn_gui.helper.ipsec_runtime.LIVE_PID_FILE", pid_file)
    monkeypatch.setattr(
        "fortigate_vpn_gui.helper.ipsec_runtime._PROTECTED_SYSTEM_PATHS",
        (system_pid, system_vici),
    )
    monkeypatch.setattr("fortigate_vpn_gui.helper.ipsec_runtime.owned_charon_pids", lambda: (111,))
    monkeypatch.setattr("fortigate_vpn_gui.helper.ipsec_runtime._charon_pids", lambda: (111, 3615))
    monkeypatch.setattr(
        "fortigate_vpn_gui.helper.ipsec_runtime._signal_pid",
        lambda pid, sig: killed.append(pid),
    )
    monkeypatch.setattr("fortigate_vpn_gui.helper.ipsec_runtime._pid_alive", lambda pid: False)
    monkeypatch.setattr(
        "fortigate_vpn_gui.helper.ipsec_runtime.restore_from_state_path",
        lambda path: None,
    )
    leftover = recover_owned_ipsec_leftovers()
    assert leftover.has_owned_leftover is True
    assert 111 in killed
    assert 3615 not in killed
    assert system_pid.exists()
    assert system_vici.exists()
    assert not conf.exists()


def test_stale_application_runtime_is_owned(monkeypatch, tmp_path: Path) -> None:
    conf = tmp_path / "charon.fvl.conf"
    dns = tmp_path / "charon.fvl.dns"
    swan = tmp_path / "swanctl"
    conf.write_text("owned", encoding="utf-8")
    monkeypatch.setattr("fortigate_vpn_gui.helper.ipsec_runtime.LIVE_STRONGSWAN_CONF", conf)
    monkeypatch.setattr("fortigate_vpn_gui.helper.ipsec_runtime.LIVE_DNS_STATE_PATH", dns)
    monkeypatch.setattr("fortigate_vpn_gui.helper.ipsec_runtime.LIVE_SWANCTL_DIR", swan)
    monkeypatch.setattr("fortigate_vpn_gui.helper.ipsec_runtime.owned_charon_pids", lambda: ())
    monkeypatch.setattr("fortigate_vpn_gui.helper.ipsec_runtime._charon_pids", lambda: ())
    leftover = inspect_owned_ipsec_state()
    assert leftover.has_owned_leftover is True
    assert leftover.other_charon_running is False


def test_ike_port_conflict_fails_before_writing_secrets(tmp_path: Path) -> None:
    started: list[list[str]] = []

    def factory(argv, on_output, on_exit, env=None):
        started.append(list(argv))
        return FakeVpnProcess(argv, on_output, on_exit, env=env)

    service = HelperService(
        process_factory=factory,
        ipsec_discover=lambda: IpsecBackendCapabilities(
            charon_path="/usr/lib/ipsec/charon",
            swanctl_path="/usr/sbin/swanctl",
            available=True,
            source="test",
        ),
        runtime_dir_factory=lambda: tmp_path / "run",
        ike_port_probe=lambda owned_pids=(): _unrelated_charon(),
    )
    (tmp_path / "run").mkdir()
    with pytest.raises(HelperError) as caught:
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
    assert caught.value.code == "IKE_PORT_IN_USE"
    assert caught.value.message == IKE_PORT_CONFLICT_MESSAGE
    assert started == []
    assert not (tmp_path / "run" / "secrets.conf").exists()
    assert not (tmp_path / "run" / "swanctl.conf").exists()


def test_diagnostics_report_ike_port_conflict() -> None:
    check = check_ike_ports(_disconnected(), report=_unrelated_charon())
    assert check.status is CheckStatus.FAIL
    assert "500/4500" in check.summary
    assert "IKE port 500: occupied" in (check.detail or "")
    assert "IKE NAT-T port 4500: occupied" in (check.detail or "")
    assert "3615" in (check.detail or "")
    assert "strongswan-starter.service" in (check.detail or "")
    assert "super-psk" not in check.summary
    free = check_ike_ports(_disconnected(), report=IkePortReport(port_500=(), port_4500=()))
    assert free.status is CheckStatus.PASS
    assert "available" in free.summary.lower()


def test_connection_page_shows_ike_port_conflict_not_auth_failure(qapp, tmp_path: Path) -> None:
    manager = ProfileManager(config_dir=tmp_path / "cfg")
    manager.add(
        name="IPsec",
        gateway="vpn.example.com",
        port=500,
        vpn_type="ipsec",
        ipsec=default_ipsec_settings().to_json(),
    )
    harness = VpnHarness(
        ipsec_available=True,
        runtime_dir_factory=lambda: tmp_path / "run",
        ike_port_probe=lambda owned_pids=(): _unrelated_charon(),
    )
    page = ConnectionPage(manager, harness.backend, locator=lambda: "/usr/bin/openfortivpn")
    profile = manager.list_profiles()[0]
    harness.backend.connect(
        profile,
        credentials=IpsecCredentials(psk="super-psk", username="ada", password="hunter2"),
    )
    snapshot = harness.backend.snapshot()
    assert snapshot.error_code is VpnErrorCode.IKE_PORT_IN_USE
    assert snapshot.error_message == IKE_PORT_CONFLICT_MESSAGE
    failed = replace(
        snapshot,
        state=ConnectionState.FAILED,
        error_code=VpnErrorCode.IKE_PORT_IN_USE,
        error_message=IKE_PORT_CONFLICT_MESSAGE,
    )
    page.apply_snapshot(failed)
    assert page.failure_hint_visible() is True
    assert page.failure_hint_text() == IKE_PORT_CONFLICT_MESSAGE
    assert "authentication" not in page.failure_hint_text().lower()
    assert "negotiation" not in page.failure_hint_text().lower()
    assert "super-psk" not in page.failure_hint_text()


def test_classify_port_bind_failure_is_not_negotiation() -> None:
    assert (
        classify_output("unable to bind socket: Address already in use")
        is OutputHint.IKE_PORT_CONFLICT
    )
    assert classify_output("could not create any sockets") is OutputHint.IKE_PORT_CONFLICT
    assert (
        classify_output("charon already running ('/var/run/charon.pid' exists)")
        is OutputHint.IKE_PORT_CONFLICT
    )
    assert user_message_for_hint(OutputHint.IKE_PORT_CONFLICT) == IKE_PORT_CONFLICT_MESSAGE


def test_written_runtime_never_names_system_vici(tmp_path: Path) -> None:
    credentials = IpsecCredentials(psk="super-psk", username="ada", password="hunter2")
    files = write_ipsec_runtime(
        gateway="vpn.example.com",
        port=500,
        settings=default_ipsec_settings(),
        credentials=credentials,
        runtime_dir=tmp_path,
    )
    credentials.wipe()
    strongswan = files.strongswan_conf.read_text(encoding="utf-8")
    client = files.swanctl_client_conf.read_text(encoding="utf-8")
    assert SYSTEM_VICI_URI not in strongswan
    assert SYSTEM_VICI_URI not in client
    assert "unix:///run/charon.vici" not in strongswan
    assert "unix:///run/charon.vici" not in client
    assert "super-psk" not in strongswan
    assert "super-psk" not in client
    assert "hunter2" not in strongswan
