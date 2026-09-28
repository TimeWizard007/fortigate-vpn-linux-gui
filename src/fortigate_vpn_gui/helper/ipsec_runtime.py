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
    build_swanctl_client_conf,
    build_swanctl_conf,
)

RuntimeFactory = Callable[[], Path]

# Ubuntu /etc/apparmor.d/usr.lib.ipsec.charon: /run/charon.* rw
LIVE_STRONGSWAN_CONF = Path("/run/charon.fvl.conf")
LIVE_PID_FILE = Path("/run/charon.fvl.pid")
LIVE_DNS_STATE_PATH = LIVE_DNS_STATE
# Application-owned VICI. Never the system default /run/charon.vici.
LIVE_VICI_SOCKET = Path("/run/charon.fvl.vici")
# Ubuntu swanctl may read /etc/swanctl/** ; not conf.d, so the distro daemon
# does not auto-load these secrets.
LIVE_SWANCTL_DIR = Path("/etc/swanctl/fortigate-vpn-linux-gui")
SYSTEM_VICI_SOCKET = Path("/run/charon.vici")
SYSTEM_CHARON_PID = Path("/run/charon.pid")
SYSTEM_CHARON_PID_VARRUN = Path("/var/run/charon.pid")
_PROTECTED_SYSTEM_PATHS = (
    SYSTEM_VICI_SOCKET,
    Path("/var/run/charon.vici"),
    SYSTEM_CHARON_PID,
    SYSTEM_CHARON_PID_VARRUN,
)


@dataclass(frozen=True)
class IpsecRuntimeFiles:
    """Paths written for one IPsec attempt. The secrets file is mode 0600."""

    runtime_dir: Path
    strongswan_conf: Path
    swanctl_conf: Path
    swanctl_client_conf: Path
    secrets: Path
    vici_socket: Path
    pid_file: Path
    dns_state: Path


def create_runtime_dir() -> Path:
    """Create the live swanctl/secrets directory (helper-owned, mode 0700)."""
    LIVE_SWANCTL_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(LIVE_SWANCTL_DIR, stat.S_IRWXU)
    return LIVE_SWANCTL_DIR


def charon_runtime_paths(runtime_dir: Path) -> tuple[Path, Path, Path]:
    """Return (strongswan.conf, vici socket, pid file) for *runtime_dir*.

    The live helper directory is split across AppArmor-visible paths. Injected
    test directories keep every file inside *runtime_dir*.
    """
    if _is_live_swanctl_dir(runtime_dir):
        return LIVE_STRONGSWAN_CONF, LIVE_VICI_SOCKET, LIVE_PID_FILE
    return (
        runtime_dir / "strongswan.conf",
        runtime_dir / "charon.vici",
        runtime_dir / "charon.pid",
    )


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
    strongswan_path, vici_socket, pid_file = charon_runtime_paths(runtime_dir)
    dns_path = dns_state_path(runtime_dir)
    restore_from_state_path(dns_path)
    _prepare_unix_socket_path(vici_socket)
    strongswan_path.parent.mkdir(parents=True, exist_ok=True)
    conf_path = runtime_dir / "swanctl.conf"
    client_conf_path = runtime_dir / "vici-client.conf"
    secrets_path = runtime_dir / "secrets.conf"
    strongswan_path.write_text(
        build_strongswan_conf(vici_socket=str(vici_socket), pid_file=str(pid_file)),
        encoding="utf-8",
    )
    os.chmod(strongswan_path, stat.S_IRUSR | stat.S_IWUSR)
    client_conf_path.write_text(
        build_swanctl_client_conf(vici_socket=str(vici_socket)),
        encoding="utf-8",
    )
    os.chmod(client_conf_path, stat.S_IRUSR | stat.S_IWUSR)
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
        swanctl_client_conf=client_conf_path,
        secrets=secrets_path,
        vici_socket=vici_socket,
        pid_file=pid_file,
        dns_state=dns_path,
    )


def wipe_ipsec_runtime(files: IpsecRuntimeFiles | None) -> None:
    """Remove helper-owned IPsec runtime files, including split live paths."""
    if files is None:
        return
    restore_from_state_path(files.dns_state)
    for extra in (
        files.strongswan_conf,
        files.vici_socket,
        files.pid_file,
        files.dns_state,
    ):
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
        _unlink_if_exists(LIVE_PID_FILE)
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


def is_protected_system_ipsec_path(path: Path) -> bool:
    """Return True for system charon PID/VICI paths this application must never unlink."""
    candidates = [path]
    try:
        candidates.append(path.resolve())
    except OSError:
        pass
    for candidate in candidates:
        for protected in _PROTECTED_SYSTEM_PATHS:
            if _same_path(candidate, protected):
                return True
    return False


def _prepare_unix_socket_path(path: Path) -> None:
    """Remove a stale application-owned vici path so private charon can bind it.

    Never unlinks the system ``/run/charon.vici``. Stale private sockets may be
    removed even when an unrelated system charon is running.
    """
    if is_protected_system_ipsec_path(path):
        return
    if not path.exists():
        return
    if owned_charon_pids():
        return
    _unlink_if_exists(path)


@dataclass(frozen=True)
class OwnedIpsecStaleState:
    """Application-owned leftover IPsec artefacts. Never includes secrets."""

    owned_conf_present: bool
    owned_dns_state_present: bool
    owned_swanctl_dir_present: bool
    owned_charon_pids: tuple[int, ...]
    other_charon_running: bool

    @property
    def has_owned_leftover(self) -> bool:
        return bool(
            self.owned_conf_present
            or self.owned_dns_state_present
            or self.owned_swanctl_dir_present
            or self.owned_charon_pids
        )


def inspect_owned_ipsec_state() -> OwnedIpsecStaleState:
    """Detect leftover state that belongs to this application's private charon."""
    owned = owned_charon_pids()
    owned_set = set(owned)
    other = False
    for pid in _charon_pids():
        if pid not in owned_set:
            other = True
            break
    return OwnedIpsecStaleState(
        owned_conf_present=_path_exists(LIVE_STRONGSWAN_CONF),
        owned_dns_state_present=_path_exists(LIVE_DNS_STATE_PATH),
        owned_swanctl_dir_present=_path_exists(LIVE_SWANCTL_DIR),
        owned_charon_pids=owned,
        other_charon_running=other,
    )


def owned_charon_pids() -> tuple[int, ...]:
    """Return PIDs of charon processes using this application's STRONGSWAN_CONF."""
    marker = f"STRONGSWAN_CONF={LIVE_STRONGSWAN_CONF}"
    found: list[int] = []
    for pid in _charon_pids():
        environ = _proc_environ(pid)
        if environ is None:
            continue
        if marker.encode("utf-8") in environ or marker in environ.decode("utf-8", "replace"):
            found.append(pid)
    return tuple(found)


def recover_owned_ipsec_leftovers() -> OwnedIpsecStaleState:
    """Stop and wipe only application-owned leftover IPsec artefacts.

    Unrelated charon processes, system XFRM, and routes that this application
    did not install are left alone. DNS restore uses the helper-owned snapshot
    at ``/run/charon.fvl.dns`` only. Destructive cleanup of live paths requires
    root (the helper). Unprivileged callers still detect leftover state.
    """
    leftover = inspect_owned_ipsec_state()
    if not leftover.has_owned_leftover:
        return leftover
    live = LIVE_STRONGSWAN_CONF == Path("/run/charon.fvl.conf")
    if live and os.geteuid() != 0:
        return leftover
    stop_owned_leftover_charon()
    restore_from_state_path(LIVE_DNS_STATE_PATH)
    wipe_runtime_dir(LIVE_SWANCTL_DIR)
    _unlink_if_exists(LIVE_STRONGSWAN_CONF)
    _unlink_if_exists(LIVE_VICI_SOCKET)
    _unlink_if_exists(LIVE_PID_FILE)
    _unlink_if_exists(LIVE_DNS_STATE_PATH)
    return leftover


def stop_owned_leftover_charon() -> tuple[int, ...]:
    """Terminate only charon processes bound to /run/charon.fvl.conf.

    Unrelated system or third-party IPsec daemons are left alone. DNS restore
    and runtime file deletion remain the caller's responsibility via
    ``wipe_ipsec_runtime``.
    """
    import signal
    import time

    pids = owned_charon_pids()
    for pid in pids:
        _signal_pid(pid, signal.SIGTERM)
    deadline = time.monotonic() + 1.5
    remaining = set(pids)
    while remaining and time.monotonic() < deadline:
        remaining = {pid for pid in remaining if _pid_alive(pid)}
        if remaining:
            time.sleep(0.05)
    for pid in remaining:
        _signal_pid(pid, signal.SIGKILL)
    return pids


def _charon_pids() -> tuple[int, ...]:
    proc = Path("/proc")
    found: list[int] = []
    try:
        entries = proc.iterdir()
    except OSError:
        return ()
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            comm = (entry / "comm").read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if comm == "charon":
            found.append(int(entry.name))
    return tuple(found)


def _proc_environ(pid: int) -> bytes | None:
    try:
        return (Path("/proc") / str(pid) / "environ").read_bytes()
    except OSError:
        return None


def _pid_alive(pid: int) -> bool:
    return (Path("/proc") / str(pid)).exists()


def _signal_pid(pid: int, sig: int) -> None:
    import os

    try:
        os.kill(pid, sig)
    except OSError:
        return


def _path_exists(path: Path) -> bool:
    try:
        return path.exists()
    except OSError:
        return False


def _same_path(left: Path, right: Path) -> bool:
    if left == right:
        return True
    try:
        return left.resolve() == right.resolve()
    except OSError:
        return str(left) == str(right)


def _unlink_if_exists(path: Path) -> None:
    if is_protected_system_ipsec_path(path):
        return
    try:
        path.unlink()
    except FileNotFoundError:
        return
    except OSError:
        return
