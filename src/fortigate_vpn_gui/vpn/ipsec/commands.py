# SPDX-License-Identifier: GPL-3.0-or-later
"""Allowlisted charon/swanctl argv builders. Secrets never appear on argv."""

from __future__ import annotations

import os
from collections.abc import Mapping

from fortigate_vpn_gui.vpn.ipsec.detect import (
    is_approved_charon_path,
    is_approved_swanctl_path,
)
from fortigate_vpn_gui.vpn.ipsec.swanctl import CHILD_NAME, CONNECTION_NAME

# Ubuntu strongSwan 5.9.13 charon has no --conf. libstrongswan selects the
# config file via STRONGSWAN_CONF, then the compiled default /etc/strongswan.conf.
STRONGSWAN_CONF_ENV = "STRONGSWAN_CONF"

# Ubuntu 5.9.13 swanctl has no --unix. command_dispatch() selects the VICI URI
# from swanctl.socket, then swanctl.plugins.vici.socket, then libvici's compiled
# default unix:///var/run/charon.vici (/run/charon.vici). Live private charon
# binds that default path, so production argv must not override the socket.
# --file is valid only on --load-all, after the operation (load_all.c).


def build_charon_argv(charon_path: str) -> list[str]:
    """Return private charon argv. Configuration is not passed on argv."""
    if not is_approved_charon_path(charon_path):
        raise ValueError("Refusing to execute a binary that is not an approved charon path.")
    return [charon_path]


def build_charon_environment(
    conf_path: str,
    *,
    base_env: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Return an env dict that points libstrongswan at the private strongswan.conf."""
    if not conf_path or any(ord(char) < 32 for char in conf_path):
        raise ValueError("IPsec configuration path is invalid.")
    env = dict(os.environ if base_env is None else base_env)
    env[STRONGSWAN_CONF_ENV] = conf_path
    return env


def build_swanctl_load_argv(swanctl_path: str, conf_path: str) -> list[str]:
    """Load swanctl.conf (and included secrets) via --load-all --file.

    Ubuntu 5.9.13 accepts --file only as a --load-all option. The operation
    must be the first token; a leading --file is a global -f (--flush-certs).
    """
    _require_swanctl(swanctl_path)
    _require_path(conf_path)
    return [swanctl_path, "--load-all", "--file", conf_path]


def build_swanctl_initiate_argv(
    swanctl_path: str,
    *,
    child: str = CHILD_NAME,
) -> list[str]:
    """Initiate the named CHILD SA. Does not take a PSK or password."""
    _require_swanctl(swanctl_path)
    return [swanctl_path, "--initiate", "--child", child]


def build_swanctl_terminate_argv(
    swanctl_path: str,
    *,
    ike: str = CONNECTION_NAME,
) -> list[str]:
    """Terminate the IKE SA. Does not take a PSK or password."""
    _require_swanctl(swanctl_path)
    return [swanctl_path, "--terminate", "--ike", ike]


def build_swanctl_stats_argv(swanctl_path: str) -> list[str]:
    """Ask the daemon for stats. Harmless probe of the default VICI socket."""
    _require_swanctl(swanctl_path)
    return [swanctl_path, "--stats"]


def build_swanctl_list_conns_argv(swanctl_path: str) -> list[str]:
    """List connections loaded into the daemon we are talking to."""
    _require_swanctl(swanctl_path)
    return [swanctl_path, "--list-conns"]


def _require_swanctl(path: str) -> None:
    if not is_approved_swanctl_path(path):
        raise ValueError("Refusing to execute a binary that is not an approved swanctl path.")


def _require_path(path: str) -> None:
    if not path or any(ord(char) < 32 for char in path):
        raise ValueError("IPsec configuration path is invalid.")
