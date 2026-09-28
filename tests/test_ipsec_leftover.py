# SPDX-License-Identifier: GPL-3.0-or-later
"""Owned IPsec leftover detection/recovery. Never flushes unrelated XFRM."""

from __future__ import annotations

from pathlib import Path

from fortigate_vpn_gui.diagnostics.checks import check_ipsec_leftover
from fortigate_vpn_gui.diagnostics.model import CheckStatus
from fortigate_vpn_gui.helper.ipsec_runtime import (
    OwnedIpsecStaleState,
    inspect_owned_ipsec_state,
    recover_owned_ipsec_leftovers,
)
from fortigate_vpn_gui.vpn.models import ConnectionState, VpnSnapshot


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


def test_inspect_owned_state_ignores_unrelated_charon(monkeypatch, tmp_path: Path) -> None:
    conf = tmp_path / "charon.fvl.conf"
    dns = tmp_path / "charon.fvl.dns"
    swan = tmp_path / "swanctl"
    monkeypatch.setattr("fortigate_vpn_gui.helper.ipsec_runtime.LIVE_STRONGSWAN_CONF", conf)
    monkeypatch.setattr("fortigate_vpn_gui.helper.ipsec_runtime.LIVE_DNS_STATE_PATH", dns)
    monkeypatch.setattr("fortigate_vpn_gui.helper.ipsec_runtime.LIVE_SWANCTL_DIR", swan)
    monkeypatch.setattr("fortigate_vpn_gui.helper.ipsec_runtime.owned_charon_pids", lambda: ())
    monkeypatch.setattr("fortigate_vpn_gui.helper.ipsec_runtime._charon_pids", lambda: (999,))
    leftover = inspect_owned_ipsec_state()
    assert leftover.has_owned_leftover is False
    assert leftover.other_charon_running is True


def test_recover_owned_leftovers_does_not_signal_unrelated_charon(
    monkeypatch, tmp_path: Path
) -> None:
    conf = tmp_path / "charon.fvl.conf"
    dns = tmp_path / "charon.fvl.dns"
    swan = tmp_path / "swanctl"
    vici = tmp_path / "charon.fvl.vici"
    pid_file = tmp_path / "charon.fvl.pid"
    conf.write_text("owned", encoding="utf-8")
    dns.write_text("dns", encoding="utf-8")
    swan.mkdir()
    (swan / "secrets.conf").write_text("psk=super-secret", encoding="utf-8")
    killed: list[int] = []
    monkeypatch.setattr("fortigate_vpn_gui.helper.ipsec_runtime.LIVE_STRONGSWAN_CONF", conf)
    monkeypatch.setattr("fortigate_vpn_gui.helper.ipsec_runtime.LIVE_DNS_STATE_PATH", dns)
    monkeypatch.setattr("fortigate_vpn_gui.helper.ipsec_runtime.LIVE_SWANCTL_DIR", swan)
    monkeypatch.setattr("fortigate_vpn_gui.helper.ipsec_runtime.LIVE_VICI_SOCKET", vici)
    monkeypatch.setattr("fortigate_vpn_gui.helper.ipsec_runtime.LIVE_PID_FILE", pid_file)
    monkeypatch.setattr("fortigate_vpn_gui.helper.ipsec_runtime.owned_charon_pids", lambda: (111,))
    monkeypatch.setattr("fortigate_vpn_gui.helper.ipsec_runtime._charon_pids", lambda: (111, 999))
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
    assert 999 not in killed
    assert not conf.exists()
    assert not swan.exists()
    assert not dns.exists()


def test_recover_skips_live_paths_when_unprivileged(monkeypatch, tmp_path: Path) -> None:
    conf = tmp_path / "charon.fvl.conf"
    conf.write_text("owned", encoding="utf-8")
    monkeypatch.setattr(
        "fortigate_vpn_gui.helper.ipsec_runtime.LIVE_STRONGSWAN_CONF",
        Path("/run/charon.fvl.conf"),
    )
    monkeypatch.setattr("fortigate_vpn_gui.helper.ipsec_runtime.os.geteuid", lambda: 1000)
    monkeypatch.setattr(
        "fortigate_vpn_gui.helper.ipsec_runtime.inspect_owned_ipsec_state",
        lambda: OwnedIpsecStaleState(
            owned_conf_present=True,
            owned_dns_state_present=False,
            owned_swanctl_dir_present=False,
            owned_charon_pids=(),
            other_charon_running=False,
        ),
    )
    killed: list[int] = []
    monkeypatch.setattr(
        "fortigate_vpn_gui.helper.ipsec_runtime._signal_pid",
        lambda pid, sig: killed.append(pid),
    )
    leftover = recover_owned_ipsec_leftovers()
    assert leftover.has_owned_leftover is True
    assert killed == []
    assert conf.exists()

    monkeypatch.setattr(
        "fortigate_vpn_gui.diagnostics.checks.inspect_owned_ipsec_state",
        lambda: OwnedIpsecStaleState(
            owned_conf_present=True,
            owned_dns_state_present=True,
            owned_swanctl_dir_present=False,
            owned_charon_pids=(42,),
            other_charon_running=False,
        ),
    )
    check = check_ipsec_leftover(_disconnected())
    assert check.status is CheckStatus.WARNING
    assert "Leftover" in check.summary
    assert "42" in (check.detail or "")
