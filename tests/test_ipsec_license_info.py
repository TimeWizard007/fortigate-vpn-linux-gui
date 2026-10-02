# SPDX-License-Identifier: GPL-3.0-or-later
"""Official-format Notify 0xF100 license-info framing and data-flow tests."""

from __future__ import annotations

from pathlib import Path

from fortigate_vpn_gui.helper.ipsec_runtime import wipe_ipsec_runtime, write_ipsec_runtime
from fortigate_vpn_gui.profiles.ipsec import default_ikev2_saml_settings, default_ipsec_settings
from fortigate_vpn_gui.system.ipsec_saml_uid import UID_LENGTH
from fortigate_vpn_gui.vpn.ipsec.forticlient_vid import (
    LICENSE_NOTIFY_ADDED_LOG,
    LICENSE_NOTIFY_LENGTH_LOG,
    LICENSE_NOTIFY_PLAN_LOG,
)
from fortigate_vpn_gui.vpn.ipsec.license_info import (
    EMS_KEYS,
    FCTVER_COMPAT,
    LICENSE_INFO_KEYS,
    LICENSE_NOTIFY_TYPE,
    LICENSE_NOTIFY_TYPE_HEX,
    LicenseInfoFields,
    NetAdapter,
    build_license_info,
    format_mac,
    format_mac_list,
    license_info_keys,
    should_skip_adapter,
)
from fortigate_vpn_gui.vpn.ipsec.secrets import IpsecCredentials
from fortigate_vpn_gui.vpn.log_redaction import redact_log_line

_UID = "0123456789abcdef0123456789abcdef"
_FIELDS = LicenseInfoFields(
    uid=_UID,
    ip="192.0.2.10",
    mac="aa-bb-cc-dd-ee-ff;",
    host="testhost",
    user="tester",
    osver="Linux",
)


def test_notify_type_is_private_0xf100() -> None:
    assert LICENSE_NOTIFY_TYPE == 61696
    assert LICENSE_NOTIFY_TYPE == 0xF100
    assert LICENSE_NOTIFY_TYPE_HEX == "0xF100"
    assert LICENSE_NOTIFY_TYPE != 16384
    assert LICENSE_NOTIFY_TYPE != 16417
    assert LICENSE_NOTIFY_TYPE != 16420


def test_license_info_framing_lf_nul_and_no_ems() -> None:
    blob = build_license_info(_FIELDS)
    assert blob.endswith(b"\x00")
    text = blob[:-1].decode("ascii")
    assert "\r" not in text
    assert text.endswith("\n")
    assert text.count("\n") == 9
    assert text.startswith("VER=1\n")
    assert f"FCTVER={FCTVER_COMPAT}\n" in text
    assert f"UID={_UID}\n" in text
    assert "IP=192.0.2.10\n" in text
    assert "MAC=aa-bb-cc-dd-ee-ff;\n" in text
    assert "HOST=testhost\n" in text
    assert "USER=tester\n" in text
    assert "OSVER=Linux\n" in text
    assert text.endswith("REG_STATUS=0\n")
    assert license_info_keys(blob) == LICENSE_INFO_KEYS
    for key in EMS_KEYS:
        assert f"{key}=" not in text
    assert blob[-1] == 0
    assert len(blob) == len(text) + 1
    assert UID_LENGTH == 32


def test_license_info_strips_newlines_from_values() -> None:
    blob = build_license_info(
        LicenseInfoFields(uid=_UID, host="bad\nhost", user="x\r\ny", osver="Linux\0x")
    )
    text = blob[:-1].decode("ascii")
    assert "\r" not in text
    assert "HOST=bad host\n" in text
    assert "USER=x  y\n" in text
    assert "OSVER=Linuxx\n" in text


def test_mac_format_and_official_skip_list() -> None:
    assert format_mac(bytes.fromhex("aabbccddeeff")) == "aa-bb-cc-dd-ee-ff;"
    physical = NetAdapter(name="eth0", mac=bytes.fromhex("aabbccddeeff"), description="eth0")
    vmware = NetAdapter(
        name="eth1", mac=bytes.fromhex("001122334455"), description="VMware Virtual Ethernet"
    )
    vbox = NetAdapter(name="eth2", mac=bytes.fromhex("001122334466"), description="VirtualBox")
    fortissl = NetAdapter(
        name="fortissl0",
        mac=bytes.fromhex("001122334477"),
        description="fortissl",
    )
    virt_mac = NetAdapter(name="eth3", mac=bytes.fromhex("00090f090001"), description="eth3")
    virt_mac2 = NetAdapter(name="eth4", mac=bytes.fromhex("00090ffe0001"), description="eth4")
    loop = NetAdapter(name="lo", mac=bytes.fromhex("000000000000"), description="lo")
    assert should_skip_adapter(physical) is False
    assert should_skip_adapter(vmware) is True
    assert should_skip_adapter(vbox) is True
    assert should_skip_adapter(fortissl) is True
    assert should_skip_adapter(virt_mac) is True
    assert should_skip_adapter(virt_mac2) is True
    assert should_skip_adapter(loop) is True
    assert format_mac_list((vmware, physical, virt_mac, fortissl)) == "aa-bb-cc-dd-ee-ff;"


def test_ikev2_sso_writes_0600_license_info_and_same_uid(tmp_path: Path) -> None:
    token = "TEST_ONLY_TOKEN_DO_NOT_USE"
    psk = "TEST_ONLY_PSK_DO_NOT_USE"
    files = write_ipsec_runtime(
        gateway="vpn.example.com",
        port=500,
        settings=default_ikev2_saml_settings(),
        credentials=IpsecCredentials(psk=psk, username=_UID, password=token),
        runtime_dir=tmp_path / "run",
        license_fields=_FIELDS,
    )
    assert files.license_info is not None
    blob = files.license_info.read_bytes()
    strongswan = files.strongswan_conf.read_text(encoding="utf-8")
    swanctl = files.swanctl_conf.read_text(encoding="utf-8")
    assert files.license_info.stat().st_mode & 0o777 == 0o600
    assert blob.endswith(b"\x00")
    assert b"\r" not in blob
    assert license_info_keys(blob) == LICENSE_INFO_KEYS
    assert f"UID={_UID}".encode("ascii") in blob
    assert _UID.encode("ascii") in blob
    assert b"EMSSN=" not in blob
    assert b"EMSID=" not in blob
    assert b"FCTTAGS=" not in blob
    assert b"REG_PASSWD=" not in blob
    assert f"license_info = {files.license_info}" in strongswan
    assert "0xF100" not in swanctl
    assert _UID not in strongswan
    assert token not in strongswan
    assert psk not in strongswan
    assert token not in blob.decode("ascii", "replace")
    wipe_ipsec_runtime(files)
    assert not files.license_info.exists()
    assert not (tmp_path / "run").exists()


def test_ikev1_runtime_does_not_write_license_info(tmp_path: Path) -> None:
    files = write_ipsec_runtime(
        gateway="vpn.example.com",
        port=500,
        settings=default_ipsec_settings(),
        credentials=IpsecCredentials(psk="super-psk", username="ada", password="hunter2"),
        runtime_dir=tmp_path / "run",
        license_fields=_FIELDS,
    )
    assert files.license_info is None
    assert not (tmp_path / "run" / "forticlient-license-info").exists()
    text = files.strongswan_conf.read_text(encoding="utf-8")
    assert "license_info" not in text
    assert "0xF100" not in text
    wipe_ipsec_runtime(files)


def test_structural_logs_do_not_include_inventory() -> None:
    blob = build_license_info(_FIELDS)
    plan = LICENSE_NOTIFY_PLAN_LOG
    added = LICENSE_NOTIFY_ADDED_LOG
    length = f"{LICENSE_NOTIFY_LENGTH_LOG}{len(blob)}"
    assert redact_log_line(plan) == plan
    assert redact_log_line(added) == added
    assert redact_log_line(length) == length
    assert _UID not in plan
    assert _UID not in added
    assert "192.0.2.10" not in length
    leaked = blob[:-1].decode("ascii")
    redacted = redact_log_line(leaked)
    assert _UID not in redacted
    assert "192.0.2.10" not in redacted
    assert "aa-bb-cc-dd-ee-ff" not in redacted
    assert "testhost" not in redacted
    assert "tester" not in redacted
    assert "Linux" not in redacted
    assert "UID=***" in redacted
    assert "MAC=***" in redacted
    assert "IP=***" in redacted
    assert "HOST=***" in redacted
    assert "USER=***" in redacted
    assert "OSVER=***" in redacted
