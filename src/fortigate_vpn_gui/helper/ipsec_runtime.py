# SPDX-License-Identifier: GPL-3.0-or-later
"""Privileged IPsec runtime files: swanctl.conf + 0600 secrets.

Ubuntu's charon AppArmor profile cannot read STRONGSWAN_CONF from /tmp.
libstrongswan then reports that as ``abort initialization due to invalid
configuration`` (exit 64). Live files therefore use paths that profile
already allows. Tests may still inject a single temporary directory.
"""

from __future__ import annotations

import os
import shutil
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from fortigate_vpn_gui.helper.ipsec_dns import (
    LIVE_DNS_STATE,
    restore_from_state_path,
)
from fortigate_vpn_gui.profiles.ipsec import IpsecSettings, parse_ipsec_settings
from fortigate_vpn_gui.vpn.ipsec.secrets import IpsecCredentials, build_swanctl_secrets
from fortigate_vpn_gui.vpn.ipsec.swanctl import (
    CHILD_NAME,
    build_strongswan_conf,
    build_swanctl_conf,
)

RuntimeFactory = Callable[[], Path]

# Ubuntu /etc/apparmor.d/usr.lib.ipsec.charon: /run/charon.* rw
LIVE_STRONGSWAN_CONF = Path("/run/charon.fvl.conf")
LIVE_DNS_STATE_PATH = LIVE_DNS_STATE
# Ubuntu /etc/apparmor.d/usr.sbin.swanctl: /run/charon.vici rw (exact path)
LIVE_VICI_SOCKET = Path("/run/charon.vici")
# Ubuntu swanctl may read /etc/swanctl/** ; not conf.d, so the distro daemon
# does not auto-load these secrets.
LIVE_SWANCTL_DIR = Path("/etc/swanctl/fortigate-vpn-linux-gui")


@dataclass(frozen=True)
class IpsecRuntimeFiles:
    """Paths written for one IPsec attempt. The secrets file is mode 0600."""

    runtime_dir: Path
    strongswan_conf: Path
    swanctl_conf: Path
    secrets: Path
    vici_socket: Path
    dns_state: Path


def create_runtime_dir() -> Path:
    """Create the live swanctl/secrets directory (helper-owned, mode 0700)."""
    LIVE_SWANCTL_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(LIVE_SWANCTL_DIR, stat.S_IRWXU)
    return LIVE_SWANCTL_DIR


def charon_runtime_paths(runtime_dir: Path) -> tuple[Path, Path]:
    """Return (strongswan.conf, vici socket) for *runtime_dir*.

    The live helper directory is split across AppArmor-visible paths. Injected
    test directories keep every file inside *runtime_dir*.
    """
    if _is_live_swanctl_dir(runtime_dir):
        return LIVE_STRONGSWAN_CONF, LIVE_VICI_SOCKET
    return runtime_dir / "strongswan.conf", runtime_dir / "charon.vici"


def dns_state_path(runtime_dir: Path) -> Path:
    """Return the helper-owned DNS revert record for *runtime_dir*."""
    if _is_live_swanctl_dir(runtime_dir):
        return LIVE_DNS_STATE_PATH
    return runtime_dir / "dns.state"


def write_ipsec_runtime(
    *,
    gateway: str,
    port: int,
    settings: IpsecSettings,
    credentials: IpsecCredentials,
    runtime_dir: Path,
) -> IpsecRuntimeFiles:
    """Write strongswan.conf, swanctl.conf, and secrets.conf."""
    runtime_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(runtime_dir, stat.S_IRWXU)
    strongswan_path, vici_socket = charon_runtime_paths(runtime_dir)
    dns_path = dns_state_path(runtime_dir)
    restore_from_state_path(dns_path)
    _prepare_unix_socket_path(vici_socket)
    strongswan_path.parent.mkdir(parents=True, exist_ok=True)
    conf_path = runtime_dir / "swanctl.conf"
    secrets_path = runtime_dir / "secrets.conf"
    strongswan_path.write_text(
        build_strongswan_conf(vici_socket=str(vici_socket)),
        encoding="utf-8",
    )
    os.chmod(strongswan_path, stat.S_IRUSR | stat.S_IWUSR)
    conf_path.write_text(
        build_swanctl_conf(
            gateway=gateway,
            port=port,
            settings=settings,
            xauth_id=credentials.username,
        ),
        encoding="utf-8",
    )
    os.chmod(conf_path, stat.S_IRUSR | stat.S_IWUSR)
    secrets_path.write_text(
        build_swanctl_secrets(
            credentials,
            local_id=settings.local_id,
            peer_id=settings.peer_id,
        ),
        encoding="utf-8",
    )
    os.chmod(secrets_path, stat.S_IRUSR | stat.S_IWUSR)
    return IpsecRuntimeFiles(
        runtime_dir=runtime_dir,
        strongswan_conf=strongswan_path,
        swanctl_conf=conf_path,
        secrets=secrets_path,
        vici_socket=vici_socket,
        dns_state=dns_path,
    )


def wipe_ipsec_runtime(files: IpsecRuntimeFiles | None) -> None:
    """Remove helper-owned IPsec runtime files, including split live paths."""
    if files is None:
        return
    restore_from_state_path(files.dns_state)
    for extra in (files.strongswan_conf, files.vici_socket, files.dns_state):
        if extra.parent != files.runtime_dir:
            _unlink_if_exists(extra)
    wipe_runtime_dir(files.runtime_dir)


def wipe_runtime_dir(path: Path | None) -> None:
    """Best-effort delete of a runtime directory, including secrets."""
    if path is None:
        return
    try:
        shutil.rmtree(path, ignore_errors=True)
    except OSError:
        pass
    if path == LIVE_SWANCTL_DIR:
        _unlink_if_exists(LIVE_STRONGSWAN_CONF)
        _unlink_if_exists(LIVE_VICI_SOCKET)
        _unlink_if_exists(LIVE_DNS_STATE_PATH)


def settings_from_request(payload: dict[str, object] | None) -> IpsecSettings:
    return parse_ipsec_settings(payload)


def child_name() -> str:
    return CHILD_NAME


def _is_live_swanctl_dir(path: Path) -> bool:
    try:
        return path.resolve() == LIVE_SWANCTL_DIR.resolve()
    except OSError:
        return path == LIVE_SWANCTL_DIR


def _prepare_unix_socket_path(path: Path) -> None:
    """Remove a stale vici path so private charon can bind it.

    Do not unlink while another charon process is running.
    """
    if not path.exists():
        return
    if _charon_process_running():
        return
    _unlink_if_exists(path)


def _charon_process_running() -> bool:
    proc = Path("/proc")
    try:
        entries = proc.iterdir()
    except OSError:
        return False
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            comm = (entry / "comm").read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if comm == "charon":
            return True
    return False


def _unlink_if_exists(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        return
    except OSError:
        return
