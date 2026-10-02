# SPDX-License-Identifier: GPL-3.0-or-later
"""Private-charon log noise filtering and application log dedup."""

from __future__ import annotations

from pathlib import Path

from fortigate_vpn_gui.helper.ike_ports import free_ike_port_report
from fortigate_vpn_gui.helper.protocol import HelperEventKind
from fortigate_vpn_gui.helper.service import HelperService, SwanctlCommandResult
from fortigate_vpn_gui.helper.validation import connect_request_from_fields
from fortigate_vpn_gui.profiles.ipsec import default_ipsec_settings
from fortigate_vpn_gui.profiles.model import build_profile
from fortigate_vpn_gui.vpn.ipsec.charon_noise import is_benign_charon_noise
from fortigate_vpn_gui.vpn.ipsec.detect import IpsecBackendCapabilities
from fortigate_vpn_gui.vpn.ipsec.forticlient_vid import PLUGINDIR, VID_ENABLED_LOG
from fortigate_vpn_gui.vpn.ipsec.secrets import IpsecCredentials
from fortigate_vpn_gui.vpn.ipsec.swanctl import NEVER_LOAD_CHARON_PLUGINS, charon_plugin_load_list
from tests.vpn_fakes import FakeVpnProcess, VpnHarness


def test_benign_cfg_handler_miss_is_narrow() -> None:
    assert is_benign_charon_noise("12[CFG] handling INTERNAL_IP4_SUBNET attribute failed")
    assert is_benign_charon_noise("12[CFG] handling INTERNAL_IP4_NETMASK attribute failed")
    assert is_benign_charon_noise("12[CFG] handling INTERNAL_IP6_SUBNET attribute failed")
    assert is_benign_charon_noise("12[CFG] handling APPLICATION_VERSION attribute failed")
    assert not is_benign_charon_noise("13[IKE] establishing CHILD_SA failed")
    assert not is_benign_charon_noise("plugin 'openssl' failed to load: not found")
    assert not is_benign_charon_noise("abort initialization due to invalid configuration")
    assert not is_benign_charon_noise("ERROR loading config")


def test_plugin_load_list_omits_optional_and_dangerous_plugins() -> None:
    load = charon_plugin_load_list(forticlient_vids=True)
    tokens = load.split()
    assert "fvl-forticlient-vid" in tokens
    for name in NEVER_LOAD_CHARON_PLUGINS:
        assert name not in tokens
    if (PLUGINDIR / "libstrongswan-kernel-netlink.so").is_file():
        assert "kernel-netlink" in tokens
    if (PLUGINDIR / "libstrongswan-eap-mschapv2.so").is_file():
        assert "eap-mschapv2" in tokens
    if (PLUGINDIR / "libstrongswan-xauth-generic.so").is_file():
        assert "xauth-generic" in tokens
    ikev1 = charon_plugin_load_list(forticlient_vids=False).split()
    assert "fvl-forticlient-vid" not in ikev1


def test_helper_drops_benign_cfg_noise_but_keeps_real_errors(tmp_path: Path) -> None:
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
    held["proc"].emit("12[CFG] handling INTERNAL_IP4_SUBNET attribute failed")
    held["proc"].emit("12[CFG] handling INTERNAL_IP4_NETMASK attribute failed")
    held["proc"].emit("13[IKE] establishing CHILD_SA failed")
    logs = [
        getattr(event, "line", "") or ""
        for event in events
        if getattr(event, "kind", None) is HelperEventKind.LOG
    ]
    assert not any("INTERNAL_IP4_SUBNET attribute failed" in line for line in logs)
    assert not any("INTERNAL_IP4_NETMASK attribute failed" in line for line in logs)
    assert any("establishing CHILD_SA failed" in line for line in logs)
    service.disconnect()


def test_raw_plugin_line_is_not_copied_to_vpn_source(tmp_path: Path) -> None:
    runtime = tmp_path / "run"
    runtime.mkdir()
    harness = VpnHarness(
        ipsec_available=True,
        runtime_dir_factory=lambda: runtime,
        vici_wait=lambda path, timeout: True,
    )
    profile = build_profile(
        name="IPsec",
        gateway="vpn.example.com",
        port=500,
        vpn_type="ipsec",
        ipsec=default_ipsec_settings().to_json(),
    )
    harness.backend.connect(
        profile,
        credentials=IpsecCredentials(psk="super-psk", username="ada", password="hunter2"),
    )
    assert harness.process is not None
    harness.process.emit(VID_ENABLED_LOG)
    harness.process.emit("12[CFG] handling INTERNAL_IP4_SUBNET attribute failed")
    harness.process.emit("13[IKE] establishing CHILD_SA failed")
    copies = [item for item in harness.log.records() if item.message == VID_ENABLED_LOG]
    assert len(copies) == 1
    assert copies[0].source == "ipsec"
    assert not any(item.source == "vpn" and item.message == VID_ENABLED_LOG for item in copies)
    joined = "\n".join(item.format_line() for item in harness.log.records())
    assert "INTERNAL_IP4_SUBNET attribute failed" not in joined
    failures = [
        item
        for item in harness.log.records()
        if "establishing CHILD_SA failed" in item.message
    ]
    assert len(failures) == 1
    assert failures[0].source == "ipsec"
    assert failures[0].severity.value == "error"
    harness.backend.disconnect(wait=True)
