# SPDX-License-Identifier: GPL-3.0-or-later
"""Generate a strongSwan swanctl.conf from non-secret IPsec settings.

Secrets are never written into this file. The helper writes credentials to a
separate 0600 secrets file that is included at load time.

IKEv2 SSO uses EAP-only local authentication plus remote PSK. Dual
``local-psk`` + ``local-eap`` is RFC 4739 multiple authentication: without
peer ``MULTIPLE_AUTH_SUPPORTED``, strongSwan 5.9.13 sets
``COND_AUTHENTICATED`` after the first IKE_AUTH and ``child_create`` then
fails on the intermediate EAP/REQ/ID (no SA). The PSK secret and
``remote-psk`` stay so responder AUTH can be verified. The plugin still
omits initiator AUTH from first IKE_AUTH if a PSK builder adds it.
"""

from __future__ import annotations

from fortigate_vpn_gui.profiles.ipsec import IpsecSettings
from fortigate_vpn_gui.vpn.ipsec.forticlient_vid import PLUGIN_NAME, PLUGINDIR

# Plugins required for IKEv1 Aggressive PSK+XAuth and IKEv2 EAP-MSCHAPv2+PSK.
# Names are requested only when the matching libstrongswan-*.so exists, except
# fvl-forticlient-vid which is always requested on the SSO path.
REQUIRED_CHARON_PLUGINS = (
    "openssl",
    "aes",
    "aesni",
    "sha1",
    "sha2",
    "md5",
    "hmac",
    "gmp",
    "random",
    "nonce",
    "pem",
    "pkcs1",
    "pkcs8",
    "x509",
    "pubkey",
    "kernel-netlink",
    "socket-default",
    "vici",
    "attr",
    "resolve",
    "unity",
    "xauth-generic",
    "eap-identity",
    "eap-mschapv2",
    "fips-prf",
    "gcm",
    "xcbc",
    "kdf",
    "mgf1",
    "drbg",
)
NEVER_LOAD_CHARON_PLUGINS = frozenset(
    {
        "kernel-libipsec",
        "bypass-lan",
        "stroke",
        "test-vectors",
        "ldap",
        "pkcs11",
        "rdrand",
        "gcrypt",
        "af-alg",
        "curve25519",
        "chapoly",
        "cmac",
        "ctr",
        "ccm",
        "ntru",
        "curl",
    }
)

CONNECTION_NAME = "fortigate"
CHILD_NAME = "fortigate"
SECRETS_INCLUDE = "secrets.conf"
# swanctl talks VICI only. It still initializes libstrongswan, whose default
# plugin set requests distro optional modules (test-vectors, ldap, …).
SWANCTL_CLIENT_PLUGINS = ("vici",)


def build_swanctl_conf(
    *,
    gateway: str,
    port: int,
    settings: IpsecSettings,
    xauth_id: str,
) -> str:
    """Return swanctl.conf text. *xauth_id* is XAuth username or EAP identity."""
    version = "1" if settings.ike_version == "ikev1" else "2"
    aggressive = "yes" if settings.ike_mode == "aggressive" else "no"
    encap = "yes" if settings.nat_traversal else "no"
    dpd_delay = f"{settings.dpd_interval}s" if settings.dpd else "0s"
    replay = "32" if settings.replay_detection else "0"
    local_id = _quoted(settings.local_id) if settings.local_id else None
    peer_id = _quoted(settings.peer_id) if settings.peer_id else None
    local_auth_id = _quoted(xauth_id) if xauth_id else None
    eap = settings.auth_method == "eap"
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
    ]
    if not eap:
        lines.extend(
            [
                "        local-psk {",
                "            auth = psk",
            ]
        )
        if local_id:
            lines.append(f"            id = {local_id}")
        lines.append("        }")
    lines.extend(
        [
            "        remote-psk {",
            "            auth = psk",
        ]
    )
    if peer_id:
        lines.append(f"            id = {peer_id}")
    lines.append("        }")
    if eap:
        lines.extend(
            [
                "        local-eap {",
                "            auth = eap-mschapv2",
            ]
        )
        if local_id:
            lines.append(f"            id = {local_id}")
        if local_auth_id:
            lines.append(f"            eap_id = {local_auth_id}")
        lines.append("        }")
    elif settings.auth_method == "psk_xauth":
        lines.extend(
            [
                "        local-xauth {",
                "            auth = xauth",
            ]
        )
        if local_auth_id:
            lines.append(f"            xauth_id = {local_auth_id}")
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


def build_strongswan_conf(
    *,
    vici_socket: str,
    pid_file: str | None = None,
    cisco_unity: bool = True,
    forticlient_vids: bool = False,
    license_info_path: str | None = None,
) -> str:
    """Private charon config: distro plugins, isolated vici socket, stderr logs.

    Ubuntu 5.9.13 ``swanctl`` has no ``--unix``. Both ``charon.plugins.vici.socket``
    and ``swanctl.socket`` must name the application-owned VICI path so the
    helper never falls back to the compiled default ``unix:///var/run/charon.vici``.

    ``remote_ts = dynamic`` is not set here; swanctl.conf uses ``0.0.0.0/0`` so
    FortiGate/Unity can narrow. ``cisco_unity = yes`` sends the Cisco Unity
    vendor ID so IKEv1 Mode Config can return UNITY_SPLIT_INCLUDE. IKEv2 EAP
    leaves it off; the FortiClient plugin consumes CFG_REPLY split-include
    (INTERNAL_IP4_SUBNET / Unity) and narrows CHILD_SA remote TS locally.

    ``forticlient_vids`` loads the application-owned ``fvl-forticlient-vid``
    plugin for the v1.3 IKEv2 SSO path only. It is not written into
    ``/etc/strongswan.d/charon/``, so system charon does not load it.
    The plugin adds FortiClient Vendor IDs on ``IKE_SA_INIT`` and, on the
    first initiator ``IKE_AUTH``, removes ``N(EAP_ONLY)`` and
    ``N(MSG_ID_SYN_SUP)`` then adds empty ``N(INITIAL_CONTACT)`` and
    private Notify ``0xF100`` (license-info path is a 0600 file; the
    blob is never written into this conf).

    Distro ``/etc/strongswan.d/charon/*.conf`` is not included: those
    snippets request optional plugins that are often not installed and
    would log ERROR at startup. ``load_modular = no`` plus an explicit
    ``load`` list requests only plugins needed for the supported IKEv1
    and IKEv2 paths, and only when the ``.so`` is present.
    """
    socket = vici_socket.replace("\\", "\\\\")
    unity = "yes" if cisco_unity else "no"
    load = charon_plugin_load_list(forticlient_vids=forticlient_vids)
    lines = [
        "charon {",
        "    load_modular = no",
        f"    load = {load}",
        f"    cisco_unity = {unity}",
        "    install_routes = yes",
        "    install_virtual_ip = yes",
    ]
    if pid_file:
        pid = pid_file.replace("\\", "\\\\")
        lines.append(f"    pidfile = {pid}")
    lines.extend(
        [
            "    filelog {",
            "        stderr {",
            "            default = 1",
            "            ike = 2",
            "            cfg = 2",
            "            ike_name = yes",
            "        }",
            "    }",
            "    plugins {",
            "        vici {",
            f"            socket = unix://{socket}",
            "        }",
            "        resolve {",
            "            resolvconf {",
            "                path = /usr/bin/true",
            "            }",
            "        }",
        ]
    )
    if forticlient_vids:
        lines.extend(
            [
                f"        {PLUGIN_NAME} {{",
                "            load = yes",
            ]
        )
        if license_info_path:
            info = license_info_path.replace("\\", "\\\\")
            lines.append(f"            license_info = {info}")
        lines.append("        }")
    lines.extend(
        [
            "    }",
            "}",
            "",
            "swanctl {",
            f"    socket = unix://{socket}",
            "    plugins {",
            "        vici {",
            f"            socket = unix://{socket}",
            "        }",
            "    }",
            "}",
            "",
        ]
    )
    return "\n".join(lines)


def build_swanctl_client_conf(*, vici_socket: str) -> str:
    """STRONGSWAN_CONF for swanctl only. Must never name the system VICI socket.

    Ubuntu ``swanctl`` calls ``library_init(NULL, "swanctl")`` then
    ``plugins->load(settings "swanctl.load", compiled PLUGINS)``. Without
    ``swanctl.load`` the compiled default list requests distro optional
    plugins (test-vectors, ldap, pkcs11, …) and logs ``plugin '…': failed
    to load`` even when private charon itself is clean. ``libstrongswan.load``
    is the settings fallback namespace. Distro ``/etc/strongswan.d/`` is
    not included.
    """
    socket = vici_socket.replace("\\", "\\\\")
    load = " ".join(SWANCTL_CLIENT_PLUGINS)
    plugin_block = (
        "    load_modular = no",
        f"    load = {load}",
        "    plugins {",
        "        vici {",
        f"            socket = unix://{socket}",
        "        }",
        "    }",
    )
    return "\n".join(
        [
            "libstrongswan {",
            *plugin_block,
            "}",
            "",
            "charon {",
            *plugin_block,
            "}",
            "",
            "swanctl {",
            *plugin_block,
            f"    socket = unix://{socket}",
            "}",
            "",
        ]
    )


def charon_plugin_load_list(*, forticlient_vids: bool = False) -> str:
    """Return the private charon ``load`` list. Never includes system-only extras."""
    available = _installed_charon_plugins()
    names = [name for name in REQUIRED_CHARON_PLUGINS if name in available]
    if forticlient_vids and PLUGIN_NAME not in names:
        names.append(PLUGIN_NAME)
    return " ".join(name for name in names if name not in NEVER_LOAD_CHARON_PLUGINS)


def _installed_charon_plugins() -> set[str]:
    found: set[str] = set()
    try:
        entries = PLUGINDIR.iterdir()
    except OSError:
        entries = ()
    for entry in entries:
        name = entry.name
        if not name.startswith("libstrongswan-") or not name.endswith(".so"):
            continue
        found.add(name[len("libstrongswan-") : -len(".so")])
    return found


def _quoted(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'
