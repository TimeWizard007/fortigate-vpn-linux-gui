# SPDX-License-Identifier: GPL-3.0-or-later
"""Real Ubuntu 5.9.13 charon + /usr/sbin/swanctl integration.

This is not a FortiGate live test. It uses the helper's generated runtime
and the installed swanctl. Production helper swanctl inherits
/etc/strongswan.conf (swanctl.socket commented out) and therefore the
libvici default unix:///var/run/charon.vici (/run/charon.vici). Tests that
cannot bind that path point swanctl at the private socket through
STRONGSWAN_CONF swanctl.socket — the mechanism command.c uses.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
from pathlib import Path

import pytest

from fortigate_vpn_gui.helper.ipsec_runtime import (
    LIVE_SWANCTL_DIR,
    wipe_ipsec_runtime,
    write_ipsec_runtime,
)
from fortigate_vpn_gui.profiles.ipsec import default_ipsec_settings
from fortigate_vpn_gui.vpn.ipsec.commands import (
    STRONGSWAN_CONF_ENV,
    build_charon_argv,
    build_charon_environment,
    build_swanctl_list_conns_argv,
    build_swanctl_load_argv,
    build_swanctl_stats_argv,
)
from fortigate_vpn_gui.vpn.ipsec.secrets import IpsecCredentials

_CHARON = Path("/usr/lib/ipsec/charon")
_SWANCTL = Path("/usr/sbin/swanctl")
_AA_EXEC = shutil.which("aa-exec")


def _require_binaries() -> None:
    if not _CHARON.is_file() or not _SWANCTL.is_file():
        pytest.skip("charon/swanctl are not installed")


def _require_aa_exec() -> None:
    if _AA_EXEC is None:
        pytest.skip("aa-exec is not installed")


def _unconfined(argv: list[str]) -> list[str]:
    if _AA_EXEC is None:
        pytest.skip("aa-exec is not installed")
    return [_AA_EXEC, "-p", "unconfined", "--", *argv]


def _minimal_swanctl_client_conf(path: Path, vici: Path | None = None) -> None:
    lines = ["swanctl {", "    load = nonce"]
    if vici is not None:
        lines.append(f"    socket = unix://{vici}")
    lines.extend(["}", ""])
    path.write_text("\n".join(lines), encoding="utf-8")


def _run_swanctl(
    argv: list[str],
    *,
    env: dict[str, str],
    timeout: float = 8.0,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(  # noqa: S603
            _unconfined(argv),
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        pytest.fail(f"swanctl timed out: {argv[1:]}; stdout={exc.stdout!r} stderr={exc.stderr!r}")


def _assert_supported_cli(text: str) -> None:
    lowered = text.lower()
    assert "unrecognized option '--unix'" not in text
    assert "unrecognized option '--file'" not in text
    assert "unrecognized option '--load-all'" not in text
    assert "unrecognized option '--stats'" not in text
    assert "unrecognized option '--list-conns'" not in text
    assert "invalid operation" not in lowered


def test_real_swanctl_accepts_generated_argv_without_unix(tmp_path: Path) -> None:
    _require_binaries()
    _require_aa_exec()
    conf = tmp_path / "swanctl.conf"
    conf.write_text("connections {\n}\n", encoding="utf-8")
    client = tmp_path / "swanctl-client.conf"
    _minimal_swanctl_client_conf(client)
    env = os.environ.copy()
    env[STRONGSWAN_CONF_ENV] = str(client)

    load_argv = build_swanctl_load_argv(str(_SWANCTL), str(conf))
    stats_argv = build_swanctl_stats_argv(str(_SWANCTL))
    list_argv = build_swanctl_list_conns_argv(str(_SWANCTL))
    assert load_argv[1:3] == ["--load-all", "--file"]
    for argv in (load_argv, stats_argv, list_argv):
        assert "--unix" not in argv
        assert "--uri" not in argv

    stats = _run_swanctl(stats_argv, env=env)
    stats_text = f"{stats.stdout}\n{stats.stderr}"
    _assert_supported_cli(stats_text)
    assert "connecting to" in stats_text.lower() or stats.returncode == 0

    loaded = _run_swanctl(load_argv, env=env)
    loaded_text = f"{loaded.stdout}\n{loaded.stderr}"
    _assert_supported_cli(loaded_text)

    listed = _run_swanctl(list_argv, env=env)
    _assert_supported_cli(f"{listed.stdout}\n{listed.stderr}")


def test_real_swanctl_reaches_private_charon_vici() -> None:
    """Production helper layout: STRONGSWAN_CONF=/run/charon.fvl.conf, VICI=/run/charon.vici.

    The helper runs as root. Unprivileged charon cannot keep kernel-ipsec, so this
    probe is skipped unless it has the same privilege the helper uses.
    """
    _require_binaries()
    if os.geteuid() != 0:
        pytest.skip("private charon VICI probe uses the helper's root /run layout")

    credentials = IpsecCredentials(psk="super-psk", username="ada", password="hunter2")
    files = write_ipsec_runtime(
        gateway="vpn.example.com",
        port=500,
        settings=default_ipsec_settings(),
        credentials=credentials,
        runtime_dir=LIVE_SWANCTL_DIR,
    )
    credentials.wipe()
    assert str(files.vici_socket) == "/run/charon.vici"
    assert str(files.strongswan_conf) == "/run/charon.fvl.conf"
    assert str(files.swanctl_conf) == "/etc/swanctl/fortigate-vpn-linux-gui/swanctl.conf"

    load_argv = build_swanctl_load_argv(str(_SWANCTL), str(files.swanctl_conf))
    stats_argv = build_swanctl_stats_argv(str(_SWANCTL))
    list_argv = build_swanctl_list_conns_argv(str(_SWANCTL))
    for argv in (load_argv, stats_argv, list_argv):
        assert "--unix" not in argv
        assert "--uri" not in argv
        assert "super-psk" not in argv
        assert "hunter2" not in argv
        assert "/etc/swanctl/swanctl.conf" not in argv

    charon_env = build_charon_environment(str(files.strongswan_conf))
    proc = subprocess.Popen(  # noqa: S603
        build_charon_argv(str(_CHARON)),
        env=charon_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    output = ""
    try:
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if files.vici_socket.exists() and proc.poll() is None:
                break
            if proc.poll() is not None:
                break
            time.sleep(0.05)
        if proc.stdout is not None:
            os.set_blocking(proc.stdout.fileno(), False)
            output = proc.stdout.read() or ""
        assert "Starting IKE charon daemon" in output
        assert "invalid configuration" not in output
        if proc.poll() is not None:
            pytest.fail(f"private charon exited before swanctl: {output}")

        # Production swanctl uses the compiled default /run/charon.vici.
        stats = _run_root_swanctl(stats_argv)
        stats_text = f"{stats.stdout}\n{stats.stderr}"
        _assert_supported_cli(stats_text)
        assert stats.returncode == 0, stats_text

        listed = _run_root_swanctl(list_argv)
        listed_text = f"{listed.stdout}\n{listed.stderr}"
        _assert_supported_cli(listed_text)
        assert listed.returncode == 0, listed_text

        loaded = _run_root_swanctl(load_argv, timeout=12.0)
        loaded_text = f"{loaded.stdout}\n{loaded.stderr}"
        _assert_supported_cli(loaded_text)
        assert "super-psk" not in loaded_text
        assert "hunter2" not in loaded_text
        if loaded.returncode != 0:
            pytest.fail(f"swanctl --load-all --file failed: {loaded_text}")

        after = _run_root_swanctl(list_argv)
        after_text = f"{after.stdout}\n{after.stderr}"
        _assert_supported_cli(after_text)
        assert after.returncode == 0, after_text
        assert "fortigate" in after_text.lower()
        assert "super-psk" not in after_text
    finally:
        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=1)
        wipe_ipsec_runtime(files)
    assert not files.secrets.exists()
    assert not files.strongswan_conf.exists()


def _run_root_swanctl(
    argv: list[str],
    *,
    timeout: float = 8.0,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(  # noqa: S603
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        pytest.fail(f"swanctl timed out: {argv[1:]}; stdout={exc.stdout!r} stderr={exc.stderr!r}")
