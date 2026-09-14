# SPDX-License-Identifier: GPL-3.0-or-later
"""Generate a strongSwan swanctl.conf from non-secret IPsec settings.

Secrets are never written into this file. The helper writes credentials to a
separate 0600 secrets file that is included at load time.
"""

from __future__ import annotations

from fortigate_vpn_gui.profiles.ipsec import IpsecSettings

CONNECTION_NAME = "fortigate"
CHILD_NAME = "fortigate"
SECRETS_INCLUDE = "secrets.conf"


def build_swanctl_conf(
    *,
    gateway: str,
    port: int,
    settings: IpsecSettings,
    xauth_id: str,
) -> str:
    """Return swanctl.conf text. *xauth_id* is the username, not a password."""
    version = "1" if settings.ike_version == "ikev1" else "2"
    aggressive = "yes" if settings.ike_mode == "aggressive" else "no"
    encap = "yes" if settings.nat_traversal else "no"
    dpd_delay = f"{settings.dpd_interval}s" if settings.dpd else "0s"
    replay = "32" if settings.replay_detection else "0"
    local_id = _quoted(settings.local_id) if settings.local_id else None
    peer_id = _quoted(settings.peer_id) if settings.peer_id else None
    xauth = _quoted(xauth_id) if xauth_id else None
    lines = [
        "connections {",
        f"    {CONNECTION_NAME} {{",
        f"        version = {version}",
        f"        aggressive = {aggressive}",
        "        mobike = no",
        "        unique = replace",
        f"        encap = {encap}",
        f"        dpd_delay = {dpd_delay}",
        f"        rekey_time = {settings.phase1_lifetime}s",
        f"        proposals = {settings.phase1_proposal()}",
        f"        remote_addrs = {_quoted(gateway)}",
        f"        remote_port = {port}",
        "        vips = 0.0.0.0",
        "        local-psk {",
        "            auth = psk",
    ]
    if local_id:
        lines.append(f"            id = {local_id}")
    lines.extend(
        [
            "        }",
            "        remote-psk {",
            "            auth = psk",
        ]
    )
    if peer_id:
        lines.append(f"            id = {peer_id}")
    lines.append("        }")
    if settings.auth_method == "psk_xauth":
        lines.extend(
            [
                "        local-xauth {",
                "            auth = xauth",
            ]
        )
        if xauth:
            lines.append(f"            xauth_id = {xauth}")
        lines.append("        }")
    lines.extend(
        [
            "        children {",
            f"            {CHILD_NAME} {{",
            f"                esp_proposals = {settings.phase2_proposal()}",
            f"                rekey_time = {settings.phase2_lifetime}s",
            f"                replay_window = {replay}",
            "                dpd_action = restart",
            "                mode = tunnel",
            "                local_ts = dynamic",
            "                remote_ts = 0.0.0.0/0",
            "            }",
            "        }",
            "    }",
            "}",
            "",
            f"include {SECRETS_INCLUDE}",
            "",
        ]
    )
    return "\n".join(lines)


def build_strongswan_conf(*, vici_socket: str) -> str:
    """Private charon config: distro plugins, isolated vici socket, stderr logs.

    ``remote_ts = dynamic`` is not set here; swanctl.conf uses ``0.0.0.0/0`` so
    FortiGate/Unity can narrow. ``cisco_unity = yes`` sends the Cisco Unity
    vendor ID so IKEv1 Mode Config can return UNITY_SPLIT_INCLUDE.
    """
    socket = vici_socket.replace("\\", "\\\\")
    return "\n".join(
        [
            "charon {",
            "    load_modular = yes",
            "    cisco_unity = yes",
            "    install_routes = yes",
            "    install_virtual_ip = yes",
            "    filelog {",
            "        stderr {",
            "            default = 1",
            "            ike = 2",
            "            cfg = 2",
            "            ike_name = yes",
            "        }",
            "    }",
            "    plugins {",
            "        include /etc/strongswan.d/charon/*.conf",
            "        vici {",
            f"            socket = unix://{socket}",
            "        }",
            "        resolve {",
            "            resolvconf {",
            "                path = /usr/bin/true",
            "            }",
            "        }",
            "    }",
            "}",
            "",
        ]
    )


def _quoted(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'
