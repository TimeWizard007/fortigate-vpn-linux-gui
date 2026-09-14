# SPDX-License-Identifier: GPL-3.0-or-later
"""IPsec swanctl config generation and secret isolation."""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
from pathlib import Path

import pytest

from fortigate_vpn_gui.helper.ipsec_runtime import (
    LIVE_STRONGSWAN_CONF,
    LIVE_SWANCTL_DIR,
    LIVE_VICI_SOCKET,
    charon_runtime_paths,
    wipe_ipsec_runtime,
    write_ipsec_runtime,
)
from fortigate_vpn_gui.profiles.ipsec import default_ipsec_settings
from fortigate_vpn_gui.vpn.ipsec.commands import (
    STRONGSWAN_CONF_ENV,
    build_charon_argv,
    build_charon_environment,
    build_swanctl_initiate_argv,
    build_swanctl_list_conns_argv,
    build_swanctl_load_argv,
    build_swanctl_stats_argv,
    build_swanctl_terminate_argv,
)
from fortigate_vpn_gui.vpn.ipsec.secrets import (
    IpsecCredentials,
    build_swanctl_secrets,
    secrets_contain_plaintext,
)
from fortigate_vpn_gui.vpn.ipsec.swanctl import build_strongswan_conf, build_swanctl_conf


def test_swanctl_conf_uses_reference_proposals_without_secrets() -> None:
    settings = default_ipsec_settings()
    conf = build_swanctl_conf(
        gateway="vpn.example.com",
        port=500,
        settings=settings,
        xauth_id="ada",
    )
    assert "version = 1" in conf
    assert "aggressive = yes" in conf
    assert "aes256-sha256-modp2048" in conf
    assert "auth = xauth" in conf
    assert "vips = 0.0.0.0" in conf
    assert "local_ts = dynamic" in conf
    assert "remote_ts = 0.0.0.0/0" in conf
    assert "remote_ts = dynamic" not in conf
    assert "include secrets.conf" in conf
    assert "rekey_time = 86400s" in conf
    assert "secret-psk" not in conf
    assert "hunter2" not in conf


def test_strongswan_conf_isolates_vici_socket() -> None:
    conf = build_strongswan_conf(vici_socket="/run/charon.vici")
    assert "unix:///run/charon.vici" in conf
    assert "cisco_unity = yes" in conf
    assert "include /etc/strongswan.d/charon/*.conf" in conf
    assert "path = /usr/bin/true" in conf
    assert "ike = 2" in conf
    assert "cfg = 2" in conf
    assert "filelog" in conf
    assert "stderr" in conf
    assert "secret" not in conf.lower() or "secret =" not in conf.lower()


def test_live_charon_paths_are_apparmor_visible() -> None:
    conf, vici = charon_runtime_paths(LIVE_SWANCTL_DIR)
    assert conf == LIVE_STRONGSWAN_CONF
    assert vici == LIVE_VICI_SOCKET
    assert str(conf).startswith("/run/charon.")
    assert str(vici) == "/run/charon.vici"


def test_injected_runtime_keeps_files_together(tmp_path: Path) -> None:
    conf, vici = charon_runtime_paths(tmp_path / "run")
    assert conf == tmp_path / "run" / "strongswan.conf"
    assert vici == tmp_path / "run" / "charon.vici"


def test_split_live_layout_writes_apparmor_paths_and_wipes(
    tmp_path: Path, monkeypatch
) -> None:
    live_dir = tmp_path / "swanctl-live"
    strongswan = tmp_path / "charon.fvl.conf"
    vici = tmp_path / "charon.vici"
    dns_state = tmp_path / "charon.fvl.dns"
    monkeypatch.setattr(
        "fortigate_vpn_gui.helper.ipsec_runtime.LIVE_SWANCTL_DIR", live_dir
    )
    monkeypatch.setattr(
        "fortigate_vpn_gui.helper.ipsec_runtime.LIVE_STRONGSWAN_CONF", strongswan
    )
    monkeypatch.setattr(
        "fortigate_vpn_gui.helper.ipsec_runtime.LIVE_VICI_SOCKET", vici
    )
    monkeypatch.setattr(
        "fortigate_vpn_gui.helper.ipsec_runtime.LIVE_DNS_STATE_PATH", dns_state
    )
    credentials = IpsecCredentials(psk="super-psk", username="ada", password="hunter2")
    files = write_ipsec_runtime(
        gateway="vpn.example.com",
        port=500,
        settings=default_ipsec_settings(),
        credentials=credentials,
        runtime_dir=live_dir,
    )
    assert files.strongswan_conf == strongswan
    assert files.vici_socket == vici
    assert files.dns_state == dns_state
    assert files.runtime_dir == live_dir
    text = strongswan.read_text(encoding="utf-8")
    assert f"unix://{vici}" in text
    assert "cisco_unity = yes" in text
    assert "super-psk" not in text
    assert files.secrets.stat().st_mode & 0o777 == 0o600
    wipe_ipsec_runtime(files)
    assert not strongswan.exists()
    assert not dns_state.exists()
    assert not live_dir.exists()
    assert not files.secrets.exists()


def test_secrets_file_is_mode_0600_and_conf_has_no_psk(tmp_path: Path) -> None:
    credentials = IpsecCredentials(psk="super-psk", username="ada", password="hunter2")
    files = write_ipsec_runtime(
        gateway="vpn.example.com",
        port=500,
        settings=default_ipsec_settings(),
        credentials=credentials,
        runtime_dir=tmp_path,
    )
    conf = files.swanctl_conf.read_text(encoding="utf-8")
    secrets = files.secrets.read_text(encoding="utf-8")
    strongswan = files.strongswan_conf.read_text(encoding="utf-8")
    assert "super-psk" not in conf
    assert "hunter2" not in conf
    assert "super-psk" not in strongswan
    assert secrets_contain_plaintext(secrets, IpsecCredentials("super-psk", "ada", "hunter2"))
    assert files.secrets.stat().st_mode & 0o777 == 0o600
    credentials.wipe()
    assert credentials.psk == ""
    assert credentials.password == ""


def test_secret_quoting_escapes_quotes() -> None:
    credentials = IpsecCredentials(psk='a"b', username="user", password="pw")
    text = build_swanctl_secrets(credentials, local_id="local", peer_id="peer")
    assert r"a\"b" in text
    assert "id-local" not in text
    assert 'id = "local"' in text


def test_charon_and_swanctl_argv_have_no_secrets() -> None:
    charon = build_charon_argv("/usr/lib/ipsec/charon")
    env = build_charon_environment("/tmp/run/strongswan.conf", base_env={"PATH": "/usr/bin"})
    load = build_swanctl_load_argv("/usr/sbin/swanctl", "/tmp/run/swanctl.conf")
    initiate = build_swanctl_initiate_argv("/usr/sbin/swanctl")
    assert charon == ["/usr/lib/ipsec/charon"]
    assert "--conf" not in charon
    assert env[STRONGSWAN_CONF_ENV] == "/tmp/run/strongswan.conf"
    assert load == ["/usr/sbin/swanctl", "--load-all", "--file", "/tmp/run/swanctl.conf"]
    assert initiate == ["/usr/sbin/swanctl", "--initiate", "--child", "fortigate"]
    terminate = build_swanctl_terminate_argv("/usr/sbin/swanctl")
    stats = build_swanctl_stats_argv("/usr/sbin/swanctl")
    listed = build_swanctl_list_conns_argv("/usr/sbin/swanctl")
    assert terminate == ["/usr/sbin/swanctl", "--terminate", "--ike", "fortigate"]
    assert stats == ["/usr/sbin/swanctl", "--stats"]
    assert listed == ["/usr/sbin/swanctl", "--list-conns"]
    joined = " ".join(charon + load + initiate + terminate + stats + listed)
    assert "--unix" not in joined
    assert "--uri" not in joined
    assert "--file" not in initiate
    assert "--file" not in terminate
    assert "--file" not in stats
    assert "super-psk" not in joined
    assert "hunter2" not in joined
    assert all("super-psk" not in value for value in env.values())


def test_remote_ts_is_not_the_gateway_host_selector() -> None:
    settings = default_ipsec_settings()
    conf = build_swanctl_conf(
        gateway="93.105.89.35",
        port=500,
        settings=settings,
        xauth_id="ada",
    )
    assert 'remote_addrs = "93.105.89.35"' in conf
    assert "remote_ts = 0.0.0.0/0" in conf
    assert "remote_ts = 93.105.89.35" not in conf
    assert "remote_ts = 93.105.89.35/32" not in conf
    assert "10.0.0.0/8" not in conf


_CHARON = Path("/usr/lib/ipsec/charon")


def test_tmp_strongswan_conf_is_invalid_under_ubuntu_charon_apparmor(
    tmp_path: Path,
) -> None:
    if not _CHARON.is_file():
        pytest.skip("charon is not installed")
    vici = tmp_path / "charon.vici"
    conf = tmp_path / "strongswan.conf"
    conf.write_text(build_strongswan_conf(vici_socket=str(vici)), encoding="utf-8")
    env = os.environ.copy()
    env[STRONGSWAN_CONF_ENV] = str(conf)
    completed = subprocess.run(  # noqa: S603
        [str(_CHARON)],
        env=env,
        capture_output=True,
        text=True,
        timeout=3,
        check=False,
    )
    output = (completed.stdout or "") + (completed.stderr or "")
    if "Starting IKE charon daemon" in output:
        pytest.skip("charon is not AppArmor-confined in this environment")
    assert completed.returncode == 64
    assert "invalid configuration" in output


def test_generated_strongswan_conf_starts_private_charon(tmp_path: Path) -> None:
    if not _CHARON.is_file():
        pytest.skip("charon is not installed")
    if shutil.which("aa-exec") is None:
        pytest.skip("aa-exec is not installed")
    vici = tmp_path / "charon.vici"
    conf = tmp_path / "strongswan.conf"
    conf.write_text(build_strongswan_conf(vici_socket=str(vici)), encoding="utf-8")
    env = os.environ.copy()
    env[STRONGSWAN_CONF_ENV] = str(conf)
    proc = subprocess.Popen(  # noqa: S603
        ["aa-exec", "-p", "unconfined", "--", str(_CHARON)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    output = ""
    try:
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            if vici.exists():
                break
            if proc.poll() is not None:
                break
            time.sleep(0.05)
        if proc.stdout is not None:
            os.set_blocking(proc.stdout.fileno(), False)
            output = proc.stdout.read() or ""
        assert "Starting IKE charon daemon" in output
        assert "invalid configuration" not in output
        assert vici.exists()
        assert "super-psk" not in output
    finally:
        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=1)
        elif proc.stdout is not None:
            rest = proc.stdout.read() or ""
            output += rest
    assert "invalid configuration" not in output


_SWANCTL = Path("/usr/sbin/swanctl")
_LIBVICI = Path("/usr/lib/ipsec/libvici.so.0")
_SWANCTL_SETTINGS = Path("/etc/strongswan.d/swanctl.conf")


def test_live_load_argv_uses_private_swanctl_conf_not_global() -> None:
    argv = build_swanctl_load_argv("/usr/sbin/swanctl", str(LIVE_SWANCTL_DIR / "swanctl.conf"))
    assert argv == [
        "/usr/sbin/swanctl",
        "--load-all",
        "--file",
        "/etc/swanctl/fortigate-vpn-linux-gui/swanctl.conf",
    ]
    assert "/etc/swanctl/swanctl.conf" not in argv
    assert "--unix" not in argv
    assert "--uri" not in argv


def test_installed_ubuntu_swanctl_has_no_unix_option() -> None:
    if not _SWANCTL.is_file():
        pytest.skip("swanctl is not installed")
    data = _SWANCTL.read_bytes()
    assert b"--unix" not in data
    assert b"\x00unix\x00" not in data
    assert b"custom path to swanctl.conf" in data
    assert b"SWANCTL_DIR" in data
    assert b"%s.socket" in data
    assert b"%s.plugins.vici.socket" in data
    assert b"service URI to connect to" in data
    assert b"--load-all" in data


def test_installed_libvici_defaults_to_run_charon_vici() -> None:
    if not _LIBVICI.is_file():
        pytest.skip("libvici is not installed")
    data = _LIBVICI.read_bytes()
    assert b"unix:///var/run/charon.vici" in data


def test_ubuntu_swanctl_socket_setting_is_commented() -> None:
    if not _SWANCTL_SETTINGS.is_file():
        pytest.skip("strongSwan swanctl.conf snippet is not installed")
    text = _SWANCTL_SETTINGS.read_text(encoding="utf-8")
    assert "socket = unix://${piddir}/charon.vici" in text
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("socket"):
            pytest.fail("swanctl.socket is set; Ubuntu 5.9.13 should leave the default")
