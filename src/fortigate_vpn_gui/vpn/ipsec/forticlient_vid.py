# SPDX-License-Identifier: GPL-3.0-or-later
"""FortiClient IKEv2 SSO compatibility constants and private-charon load paths.

Vendor ID 16-byte values are copied from the golden FortiClient 7.4.8.2066
``IKE_SA_INIT`` capture. They are capability advertisements, not secrets.
Do not regenerate them from display strings.

The private plugin also removes RFC 5998 ``N(EAP_ONLY)`` (type 16417) and
RFC 6311 ``N(MSG_ID_SYN_SUP)`` (type 16420) from the first outbound
initiator ``IKE_AUTH``, then adds one empty RFC 7296 ``N(INITIAL_CONTACT)``
(type 16384; charon short name ``INIT_CONTACT``) and private Notify
``0xF100`` / 61696 (FortiClient license-info, including the trailing NUL).

On the same first ``IKE_AUTH`` the plugin replaces CFG_REQUEST with the
golden FortiClient list of 16 empty request attributes (payload length
72). Diagnostics log attribute types and count only, never values.

The same first ``IKE_AUTH`` then repositions the existing Notify
``0xF100`` immediately after ``INITIAL_CONTACT`` and before
CFG_REQUEST, and omits the initiator AUTH payload from that first
message only. IKEv2 SSO swanctl uses EAP-only local authentication
plus remote PSK so ``child_create`` waits for ``COND_AUTHENTICATED``
instead of failing on an intermediate EAP ``IKE_AUTH`` without SA.
The PSK secret and remote PSK stay configured. Later ``IKE_AUTH`` /
EAP is unchanged.

Incoming ``CFG_REPLY`` is parsed for split-include and DNS attributes
(``INTERNAL_IP4_SUBNET``, Unity split-include/local-LAN, Fortinet
``0x540c`` when it decodes as subnets, ``INTERNAL_IP4_DNS``,
``INTERNAL_DNS_DOMAIN``). When FortiGate leaves TSr at ``0.0.0.0/0``
the plugin replaces the initiator's effective remote TS list on
``NARROW_INITIATOR_POST_NOAUTH`` (IKE_AUTH CHILD_SA) and
``NARROW_INITIATOR_POST_AUTH`` (CREATE_CHILD_SA rekey). Stock
strongSwan 5.9.13 fires POST_NOAUTH, not POST_AUTH, for the initial
IKE_AUTH CHILD_SA. Full tunnel is preserved when no split-include is
returned or a prefix is ``0.0.0.0/0``. CP16 request types are unchanged.

The plugin is loaded only by this application's private charon when the
profile is IKEv2 + EAP (the v1.3 FortiGate SAML/SSO path). System charon
is never given a ``/etc/strongswan.d/charon/`` snippet for this plugin.
"""

from __future__ import annotations

from pathlib import Path

from fortigate_vpn_gui.profiles.ipsec import IpsecSettings

PLUGIN_NAME = "fvl-forticlient-vid"
PLUGIN_SONAME = f"libstrongswan-{PLUGIN_NAME}.so"
PLUGINDIR = Path("/usr/lib/ipsec/plugins")
PLUGINDIR_PATH = PLUGINDIR / PLUGIN_SONAME
APP_PLUGIN_DIR = Path("/usr/libexec/fortigate-vpn-linux-gui/plugins")
APP_PLUGIN_PATH = APP_PLUGIN_DIR / PLUGIN_SONAME
SYSTEM_PLUGIN_CONF = Path(f"/etc/strongswan.d/charon/{PLUGIN_NAME}.conf")

# Exact raw Vendor ID bytes from the golden FortiClient IKE_SA_INIT.
VID_CONNECT_LICENSE = bytes.fromhex("4c53427b6d465d1b337bb755a37a7fef")
VID_ENDPOINT_CONTROL = bytes.fromhex("b4f01ca951e9da8d0bafbbd34ad3044e")
VID_EAP_EXTENSION = bytes.fromhex("c1dc4350476b98a429b91781914ca43e")
FORTICLIENT_IKE_SA_INIT_VIDS = (
    VID_CONNECT_LICENSE,
    VID_ENDPOINT_CONTROL,
    VID_EAP_EXTENSION,
)

# RFC 5998 / RFC 6311 / RFC 7296 / private-use notify types for first IKE_AUTH.
EAP_ONLY_NOTIFY_TYPE = 16417
MSG_ID_SYN_SUP_NOTIFY_TYPE = 16420
INITIAL_CONTACT_NOTIFY_TYPE = 16384

VID_ENABLED_LOG = "FortiClient compatibility Vendor IDs enabled for private IKEv2 SSO runtime"
VID_COUNT_LOG = "3 Vendor IDs configured for IKE_SA_INIT"
EAP_ONLY_OMIT_PLAN_LOG = "FortiClient compatibility: first IKE_AUTH will omit EAP_ONLY"
EAP_ONLY_REMOVED_LOG = "FortiClient compatibility: removed EAP_ONLY from first IKE_AUTH"
MSG_ID_SYN_SUP_OMIT_PLAN_LOG = "FortiClient compatibility: first IKE_AUTH will omit MSG_ID_SYN_SUP"
MSG_ID_SYN_SUP_REMOVED_LOG = "FortiClient compatibility: removed MSG_ID_SYN_SUP from first IKE_AUTH"
INITIAL_CONTACT_PLAN_LOG = "FortiClient compatibility: first IKE_AUTH will add INITIAL_CONTACT"
INITIAL_CONTACT_ADDED_LOG = "FortiClient compatibility: added INITIAL_CONTACT to first IKE_AUTH"
LICENSE_NOTIFY_PLAN_LOG = "FortiClient compatibility: first IKE_AUTH will add private Notify 0xF100"
LICENSE_NOTIFY_ADDED_LOG = "FortiClient compatibility: added private Notify 0xF100"
LICENSE_NOTIFY_LENGTH_LOG = "FortiClient compatibility: license-info payload length: "
LICENSE_NOTIFY_MISSING_LOG = (
    "FortiClient compatibility: license-info missing; Notify 0xF100 not added"
)
LICENSE_NOTIFY_REPOSITION_PLAN_LOG = (
    "FortiClient compatibility: first IKE_AUTH will reposition Notify 0xF100 before CFG_REQUEST"
)
LICENSE_NOTIFY_REPOSITIONED_LOG = (
    "FortiClient compatibility: repositioned Notify 0xF100 before CFG_REQUEST"
)
LICENSE_NOTIFY_NOT_REPOSITIONED_LOG = "FortiClient compatibility: Notify 0xF100 not repositioned"
AUTH_OMIT_PLAN_LOG = "FortiClient compatibility: first IKE_AUTH will omit initiator AUTH"
AUTH_OMITTED_LOG = "FortiClient compatibility: omitted initiator AUTH from first IKE_AUTH"
EAP_LOCAL_PLAN_LOG = (
    "FortiClient compatibility: EAP-only local authentication; "
    "CHILD_SA deferred until EAP completes"
)
# Golden FortiClient first IKE_AUTH CFG_REQUEST: 16 empty 4-byte attributes.
GOLDEN_CP_REQUEST_TYPES = (
    1,  # INTERNAL_IP4_ADDRESS
    2,  # INTERNAL_IP4_NETMASK
    7,  # APPLICATION_VERSION
    3,  # INTERNAL_IP4_DNS
    4,  # INTERNAL_IP4_NBNS
    13,  # INTERNAL_IP4_SUBNET
    8,  # INTERNAL_IP6_ADDRESS
    10,  # INTERNAL_IP6_DNS
    11,  # INTERNAL_IP6_NBNS
    15,  # INTERNAL_IP6_SUBNET
    25,  # INTERNAL_DNS_DOMAIN
    21516,  # 0x540c Fortinet private; meaning unknown
    28678,  # 0x7006 UNITY_LOCAL_LAN
    21514,  # 0x540a auto-negotiate
    21515,  # 0x540b KEEP_ALIVE
    28673,  # 0x7001 SAVE_PASSWD / UNITY_SAVE_PASSWD
)
GOLDEN_CP_REQUEST_TYPES_TEXT = ",".join(str(item) for item in GOLDEN_CP_REQUEST_TYPES)
CP_REQUEST_PLAN_LOG = "FortiClient compatibility: first IKE_AUTH will rewrite CP request attributes"
CP_REQUEST_REWRITTEN_LOG = (
    "FortiClient compatibility: first IKE_AUTH CP request attributes: "
    f"16 types {GOLDEN_CP_REQUEST_TYPES_TEXT}"
)
SPLIT_INCLUDE_PLAN_LOG = (
    "FortiClient compatibility: CFG_REPLY split-include will narrow CHILD_SA remote TS"
)
PLUGIN_MISSING_MESSAGE = (
    "FortiClient compatibility plugin was not found for the private IKEv2 SSO runtime."
)
LICENSE_INFO_BUILD_FAILED_MESSAGE = (
    "FortiClient compatibility license-info could not be built for the private IKEv2 SSO runtime."
)


def should_emit_forticlient_vids(settings: IpsecSettings) -> bool:
    """Return True only for the v1.3 FortiGate IKEv2 SAML/SSO/EAP combo."""
    return settings.allows_saml_preauth()


def plugin_is_installed(*, path: Path | None = None) -> bool:
    """Return True when the uniquely named plugin .so is present for charon."""
    candidate = path if path is not None else PLUGINDIR_PATH
    try:
        return candidate.is_file()
    except OSError:
        return False


def system_plugin_conf_present(*, path: Path | None = None) -> bool:
    """Return True if a system-wide plugin snippet exists (must stay absent)."""
    candidate = path if path is not None else SYSTEM_PLUGIN_CONF
    try:
        return candidate.exists()
    except OSError:
        return False
