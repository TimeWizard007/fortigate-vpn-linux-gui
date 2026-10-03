# SPDX-License-Identifier: GPL-3.0-or-later
"""FortiClient IKE_SA_INIT Vendor ID PoC: constants, scoping, isolation."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import signal
import subprocess
import time
from pathlib import Path

import pytest

from fortigate_vpn_gui.diagnostics.checks import check_forticlient_vid_plugin
from fortigate_vpn_gui.diagnostics.model import CheckStatus
from fortigate_vpn_gui.helper.ike_ports import free_ike_port_report
from fortigate_vpn_gui.helper.protocol import (
    BACKEND_IPSEC,
    HELPER_VERSION,
    PROTOCOL_VERSION,
    HelperError,
)
from fortigate_vpn_gui.helper.service import HelperService, SwanctlCommandResult
from fortigate_vpn_gui.helper.validation import connect_request_from_fields
from fortigate_vpn_gui.profiles.ipsec import default_ikev2_saml_settings, default_ipsec_settings
from fortigate_vpn_gui.profiles.model import build_profile
from fortigate_vpn_gui.vpn.ipsec.detect import IpsecBackendCapabilities
from fortigate_vpn_gui.vpn.ipsec.forticlient_vid import (
    APP_PLUGIN_PATH,
    AUTH_OMIT_PLAN_LOG,
    AUTH_OMITTED_LOG,
    CP_REQUEST_PLAN_LOG,
    CP_REQUEST_REWRITTEN_LOG,
    EAP_LOCAL_PLAN_LOG,
    EAP_ONLY_NOTIFY_TYPE,
    EAP_ONLY_OMIT_PLAN_LOG,
    EAP_ONLY_REMOVED_LOG,
    FORTICLIENT_IKE_SA_INIT_VIDS,
    GOLDEN_CP_REQUEST_TYPES,
    GOLDEN_CP_REQUEST_TYPES_TEXT,
    INITIAL_CONTACT_ADDED_LOG,
    INITIAL_CONTACT_NOTIFY_TYPE,
    INITIAL_CONTACT_PLAN_LOG,
    LICENSE_NOTIFY_ADDED_LOG,
    LICENSE_NOTIFY_LENGTH_LOG,
    LICENSE_NOTIFY_MISSING_LOG,
    LICENSE_NOTIFY_PLAN_LOG,
    LICENSE_NOTIFY_REPOSITION_PLAN_LOG,
    LICENSE_NOTIFY_REPOSITIONED_LOG,
    MSG_ID_SYN_SUP_NOTIFY_TYPE,
    MSG_ID_SYN_SUP_OMIT_PLAN_LOG,
    MSG_ID_SYN_SUP_REMOVED_LOG,
    PLUGIN_MISSING_MESSAGE,
    PLUGIN_NAME,
    PLUGIN_SONAME,
    PLUGINDIR_PATH,
    SPLIT_INCLUDE_PLAN_LOG,
    SYSTEM_PLUGIN_CONF,
    VID_CONNECT_LICENSE,
    VID_COUNT_LOG,
    VID_EAP_EXTENSION,
    VID_ENABLED_LOG,
    VID_ENDPOINT_CONTROL,
    plugin_is_installed,
    should_emit_forticlient_vids,
)
from fortigate_vpn_gui.vpn.ipsec.license_info import LICENSE_NOTIFY_TYPE, LicenseInfoFields
from fortigate_vpn_gui.vpn.ipsec.secrets import IpsecCredentials, build_swanctl_secrets
from fortigate_vpn_gui.vpn.ipsec.swanctl import build_strongswan_conf, build_swanctl_conf
from fortigate_vpn_gui.vpn.log_redaction import redact_log_line
from tests.vpn_fakes import FakeVpnProcess

ROOT = Path(__file__).resolve().parents[1]
PLUGIN_C = ROOT / "native" / "fvl-forticlient-vid" / "fvl_forticlient_vid_plugin.c"
PLUGIN_MAKEFILE = ROOT / "native" / "fvl-forticlient-vid" / "Makefile"
SS_SRC = ROOT / "downloads" / "strongswan-5.9.13"
CP_TYPE_NAME_MAP = {
    "INTERNAL_IP4_ADDRESS": 1,
    "INTERNAL_IP4_NETMASK": 2,
    "APPLICATION_VERSION": 7,
    "INTERNAL_IP4_DNS": 3,
    "INTERNAL_IP4_NBNS": 4,
    "INTERNAL_IP4_SUBNET": 13,
    "INTERNAL_IP6_ADDRESS": 8,
    "INTERNAL_IP6_DNS": 10,
    "INTERNAL_IP6_NBNS": 11,
    "INTERNAL_IP6_SUBNET": 15,
    "INTERNAL_DNS_DOMAIN": 25,
    "UNITY_LOCAL_LAN": 28678,
    "UNITY_SAVE_PASSWD": 28673,
}
FIRST_AUTH_HOOK = (
    "remove_compat_notifies(message); add_initial_contact(message); "
    "add_license_notify(message); rewrite_cp_request(message); "
    "reposition_license_notify(message); omit_initiator_auth(message);"
)
REPOSITION_ORDER = (
    "append_payloads_of_type(message, list, PLV2_ID_INITIATOR); "
    "append_notifies_of_type(message, list, INITIAL_CONTACT); "
    "append_notifies_of_type(message, list, (notify_type_t)FVL_LICENSE_NOTIFY_TYPE); "
    "append_payloads_of_type(message, list, PLV2_AUTH); "
    "append_payloads_of_type(message, list, PLV2_CONFIGURATION);"
)


def _c_byte_list(raw: bytes) -> str:
    return ", ".join(f"0x{byte:02x}" for byte in raw)


def _parse_c_cp_request_types(text: str) -> tuple[int, ...]:
    match = re.search(
        r"static const uint16_t fvl_cp_request_types\[\] = \{([^}]+)\}",
        text,
        re.S,
    )
    assert match is not None
    values: list[int] = []
    for raw in match.group(1).split(","):
        token = re.sub(r"/\*.*?\*/", "", raw, flags=re.S).strip()
        if not token:
            continue
        if token in CP_TYPE_NAME_MAP:
            values.append(CP_TYPE_NAME_MAP[token])
        elif token.startswith("0x"):
            values.append(int(token, 16))
        else:
            values.append(int(token))
    return tuple(values)


def test_vendor_id_bytes_are_exact_and_not_reencoded() -> None:
    assert VID_CONNECT_LICENSE == bytes.fromhex("4c53427b6d465d1b337bb755a37a7fef")
    assert VID_ENDPOINT_CONTROL == bytes.fromhex("b4f01ca951e9da8d0bafbbd34ad3044e")
    assert VID_EAP_EXTENSION == bytes.fromhex("c1dc4350476b98a429b91781914ca43e")
    assert FORTICLIENT_IKE_SA_INIT_VIDS == (
        VID_CONNECT_LICENSE,
        VID_ENDPOINT_CONTROL,
        VID_EAP_EXTENSION,
    )
    assert hashlib.md5(b"Fortinet Endpoint Control").digest() == VID_ENDPOINT_CONTROL
    assert hashlib.md5(b"Forticlient EAP Extension").digest() == VID_EAP_EXTENSION
    assert hashlib.md5(b"Forticlient Connect License").digest() != VID_CONNECT_LICENSE
    assert all(len(item) == 16 for item in FORTICLIENT_IKE_SA_INIT_VIDS)
    assert VID_CONNECT_LICENSE.hex() == "4c53427b6d465d1b337bb755a37a7fef"


def test_eap_only_notify_constant_is_rfc_5998() -> None:
    assert EAP_ONLY_NOTIFY_TYPE == 16417
    assert EAP_ONLY_NOTIFY_TYPE == 0x4021
    assert MSG_ID_SYN_SUP_NOTIFY_TYPE == 16420
    assert MSG_ID_SYN_SUP_NOTIFY_TYPE == 0x4024
    assert INITIAL_CONTACT_NOTIFY_TYPE == 16384
    assert INITIAL_CONTACT_NOTIFY_TYPE == 0x4000
    assert LICENSE_NOTIFY_TYPE == 61696
    assert LICENSE_NOTIFY_TYPE == 0xF100
    assert MSG_ID_SYN_SUP_NOTIFY_TYPE != EAP_ONLY_NOTIFY_TYPE
    assert INITIAL_CONTACT_NOTIFY_TYPE != EAP_ONLY_NOTIFY_TYPE
    assert LICENSE_NOTIFY_TYPE != INITIAL_CONTACT_NOTIFY_TYPE


def test_golden_cp_request_has_exactly_16_empty_unique_types() -> None:
    assert GOLDEN_CP_REQUEST_TYPES == (
        1,
        2,
        7,
        3,
        4,
        13,
        8,
        10,
        11,
        15,
        25,
        21516,
        28678,
        21514,
        21515,
        28673,
    )
    assert len(GOLDEN_CP_REQUEST_TYPES) == 16
    assert len(set(GOLDEN_CP_REQUEST_TYPES)) == 16
    assert GOLDEN_CP_REQUEST_TYPES[0] == 1
    assert GOLDEN_CP_REQUEST_TYPES[3] == 3
    assert 21514 in GOLDEN_CP_REQUEST_TYPES
    assert 21515 in GOLDEN_CP_REQUEST_TYPES
    assert 28673 in GOLDEN_CP_REQUEST_TYPES
    assert 21516 in GOLDEN_CP_REQUEST_TYPES
    assert 28678 in GOLDEN_CP_REQUEST_TYPES
    assert GOLDEN_CP_REQUEST_TYPES_TEXT == (
        "1,2,7,3,4,13,8,10,11,15,25,21516,28678,21514,21515,28673"
    )
    assert CP_REQUEST_REWRITTEN_LOG.endswith(GOLDEN_CP_REQUEST_TYPES_TEXT)
    assert "types 16" not in CP_REQUEST_REWRITTEN_LOG
    parsed = _parse_c_cp_request_types(PLUGIN_C.read_text(encoding="utf-8"))
    assert parsed == GOLDEN_CP_REQUEST_TYPES
    assert len(parsed) == 16
    assert len(set(parsed)) == 16


def test_c_plugin_rewrites_first_ike_auth_cp_request_only() -> None:
    text = PLUGIN_C.read_text(encoding="utf-8")
    compact = re.sub(r"\s+", " ", text)
    parsed = _parse_c_cp_request_types(text)
    assert parsed == GOLDEN_CP_REQUEST_TYPES
    assert "cp_payload_create_type" in text
    assert "configuration_attribute_create_chunk" in text
    assert "PLV2_CONFIGURATION_ATTRIBUTE" in text
    assert "chunk_empty" in text
    assert "CFG_REQUEST" in text
    assert "rewrite_cp_request" in text
    assert text.count("rewrite_cp_request(message)") == 1
    assert "INTERNAL_IP4_ADDRESS" in text
    assert "INTERNAL_IP4_DNS" in text
    assert "0x540a" in text
    assert "0x540b" in text
    assert "0x540c" in text
    assert "UNITY_LOCAL_LAN" in text
    assert "UNITY_SAVE_PASSWD" in text
    assert "do not log attribute bytes" in text
    assert FIRST_AUTH_HOOK in compact
    assert "get_message_id(message) == 1" in compact
    sa_init_block = text.split("if (exchange == IKE_SA_INIT)")[1].split("IKE_AUTH")[0]
    assert "rewrite_cp_request" not in sa_init_block
    ike_auth_block = text.split("if (exchange == IKE_AUTH")[1].split("return TRUE;")[0]
    assert "rewrite_cp_request(message)" in ike_auth_block
    assert "reposition_license_notify(message)" in ike_auth_block
    assert "omit_initiator_auth(message)" in ike_auth_block
    assert CP_REQUEST_REWRITTEN_LOG.split("16 types")[0] in text
    assert "FortiClient compatibility: first IKE_AUTH CP request attributes:" in text
    assert "%u types %s" in text
    assert text.count("notify_payload_create_from_protocol_and_type") == 2
    assert "EAP_ONLY_AUTHENTICATION" in text
    assert "IKEV2_MESSAGE_ID_SYNC_SUPPORTED" in text
    assert "INITIAL_CONTACT" in text
    assert "FVL_LICENSE_NOTIFY_TYPE 61696" in text


def test_c_plugin_repositions_0xf100_after_initial_contact_before_cp() -> None:
    text = PLUGIN_C.read_text(encoding="utf-8")
    compact = re.sub(r"\s+", " ", text)
    fn = text.split("static void reposition_license_notify(")[1].split(
        "static void omit_initiator_auth("
    )[0]
    fn_compact = re.sub(r"\s+", " ", fn)
    assert "reposition_license_notify" in text
    assert text.count("reposition_license_notify(message)") == 1
    assert text.count("omit_initiator_auth(message)") == 1
    assert FIRST_AUTH_HOOK in compact
    assert REPOSITION_ORDER in fn_compact
    assert "append_payloads_of_type(message, list, PLV2_AUTH)" in fn_compact
    assert "append_payloads_of_type(message, list, PLV2_CONFIGURATION)" in fn_compact
    assert "count_notify_type(list, (notify_type_t)FVL_LICENSE_NOTIFY_TYPE) != 1" in fn_compact
    assert "count_payload_type(list, PLV2_AUTH) < 1" in fn_compact
    assert "disable_sort" in fn
    assert "payload->destroy" not in fn
    assert "set_notification_data" not in fn
    assert "set_auth_method" not in fn
    assert "ca_setauth" not in fn
    assert "fvl_cp_request_types" not in fn
    assert LICENSE_NOTIFY_REPOSITIONED_LOG in text
    assert "repositioned Notify 0xF100 before CFG_REQUEST" in text
    sa_init_block = text.split("if (exchange == IKE_SA_INIT)")[1].split("IKE_AUTH")[0]
    assert "reposition_license_notify" not in sa_init_block
    assert "omit_initiator_auth" not in sa_init_block
    ike_auth_block = text.split("if (exchange == IKE_AUTH")[1].split("return TRUE;")[0]
    assert "reposition_license_notify(message)" in ike_auth_block
    assert "omit_initiator_auth(message)" in ike_auth_block
    assert "get_message_id(message) == 1" in compact
    assert text.count("FVL_LICENSE_NOTIFY_TYPE 61696") == 1
    assert "add_forticlient_vids" in text
    assert "EAP_ONLY_AUTHENTICATION" in text
    assert "IKEV2_MESSAGE_ID_SYNC_SUPPORTED" in text
    assert "add_initial_contact" in text
    parsed = _parse_c_cp_request_types(text)
    assert parsed == GOLDEN_CP_REQUEST_TYPES


@pytest.mark.skipif(
    not (SS_SRC / "src" / "libcharon" / "encoding" / "payloads" / "cp_payload.h").is_file(),
    reason="strongSwan 5.9.13 headers were not fetched",
)
def test_plugin_uses_verified_5_9_13_cp_request_api() -> None:
    header = (SS_SRC / "src" / "libcharon" / "encoding" / "payloads" / "cp_payload.h").read_text(
        encoding="utf-8"
    )
    attr_header = (
        SS_SRC / "src" / "libcharon" / "encoding" / "payloads" / "configuration_attribute.h"
    ).read_text(encoding="utf-8")
    types_header = (SS_SRC / "src" / "libcharon" / "attributes" / "attributes.h").read_text(
        encoding="utf-8"
    )
    plugin = PLUGIN_C.read_text(encoding="utf-8")
    compact = re.sub(r"\s+", " ", plugin)
    assert "CFG_REQUEST = 1," in header
    assert "cp_payload_create_type" in header
    assert "add_attribute" in header
    assert "configuration_attribute_create_chunk" in attr_header
    assert "INTERNAL_IP4_ADDRESS    = 1," in types_header
    assert "INTERNAL_IP4_NETMASK    = 2," in types_header
    assert "APPLICATION_VERSION     = 7," in types_header
    assert "INTERNAL_IP4_DNS        = 3," in types_header
    assert (
        "INTERNAL_DNS_DOMAIN		= 25," in types_header or "INTERNAL_DNS_DOMAIN" in types_header
    )
    assert "UNITY_SAVE_PASSWD       = 28673," in types_header
    assert "UNITY_LOCAL_LAN         = 28678," in types_header
    assert "cp_payload_create_type(PLV2_CONFIGURATION, CFG_REQUEST)" in compact
    assert "configuration_attribute_create_chunk(" in compact
    assert "chunk_empty" in compact
    assert FIRST_AUTH_HOOK in compact


@pytest.mark.skipif(
    not (SS_SRC / "src" / "libcharon" / "encoding" / "payloads" / "notify_payload.h").is_file(),
    reason="strongSwan 5.9.13 headers were not fetched",
)
def test_plugin_uses_verified_5_9_13_initial_contact_api() -> None:
    header = (
        SS_SRC / "src" / "libcharon" / "encoding" / "payloads" / "notify_payload.h"
    ).read_text(encoding="utf-8")
    proposal = (SS_SRC / "src" / "libstrongswan" / "crypto" / "proposal" / "proposal.h").read_text(
        encoding="utf-8"
    )
    names = (SS_SRC / "src" / "libcharon" / "encoding" / "payloads" / "notify_payload.c").read_text(
        encoding="utf-8"
    )
    plugin = PLUGIN_C.read_text(encoding="utf-8")
    compact = re.sub(r"\s+", " ", plugin)
    assert "INITIAL_CONTACT = 16384," in header
    assert "INITIAL_CONTACT_IKEV1 = 24578," in header
    assert "PROTO_NONE = 0," in proposal
    assert '"INIT_CONTACT"' in names
    assert "notify_payload_create_from_protocol_and_type" in header
    assert "set_notification_data" in header
    assert "notify_payload_create_from_protocol_and_type(" in compact
    assert "PLV2_NOTIFY, PROTO_NONE, INITIAL_CONTACT" in compact
    assert "PLV2_NOTIFY, PROTO_NONE, (notify_type_t)FVL_LICENSE_NOTIFY_TYPE" in compact
    assert "notify->set_notification_data(notify, data)" in compact
    assert "message->add_payload(message, (payload_t*)notify)" in compact
    assert "INITIAL_CONTACT_IKEV1" not in plugin
    assert plugin.count("add_initial_contact(message)") == 1
    assert plugin.count("add_license_notify(message)") == 1
    assert plugin.count("reposition_license_notify(message)") == 1
    assert plugin.count("omit_initiator_auth(message)") == 1
    assert FIRST_AUTH_HOOK in compact
    assert INITIAL_CONTACT_NOTIFY_TYPE == 16384
    assert LICENSE_NOTIFY_TYPE == 61696


@pytest.mark.skipif(
    not (SS_SRC / "src" / "libcharon" / "encoding" / "message.h").is_file(),
    reason="strongSwan 5.9.13 headers were not fetched",
)
def test_plugin_uses_verified_5_9_13_disable_sort_api() -> None:
    header = (SS_SRC / "src" / "libcharon" / "encoding" / "message.h").read_text(encoding="utf-8")
    plugin = PLUGIN_C.read_text(encoding="utf-8")
    compact = re.sub(r"\s+", " ", plugin)
    assert "void (*disable_sort)(message_t *this);" in header
    assert "message->disable_sort(message)" in compact
    assert "reposition_license_notify" in plugin


def test_c_plugin_contains_the_same_raw_vendor_ids() -> None:
    text = PLUGIN_C.read_text(encoding="utf-8")
    compact = re.sub(r"\s+", " ", text.lower())
    for raw in FORTICLIENT_IKE_SA_INIT_VIDS:
        assert _c_byte_list(raw) in compact
    assert "ike_sa_init" in compact
    assert "add_forticlient_vids" in text
    assert "sending FortiClient compatibility vendor IDs" in text
    assert "ike_auth" in compact
    assert "plv2_vendor_id" in compact
    assert "fvl_forticlient_vid_plugin_create" in text
    assert PLUGIN_MAKEFILE.is_file()
    makefile = PLUGIN_MAKEFILE.read_text(encoding="utf-8")
    config = (PLUGIN_C.parent / "config.h").read_text(encoding="utf-8")
    assert "libstrongswan-$(PLUGIN_NAME).so" in makefile
    assert "/usr/lib/ipsec" in makefile
    assert "check-symbols" in makefile
    assert "check-fvl-forticlient-vid-symbols.sh" in makefile
    assert "HAVE_EXPLICIT_BZERO" in config
    assert "_DEFAULT_SOURCE" in config


def test_c_plugin_removes_first_ike_auth_compat_notifies() -> None:
    text = PLUGIN_C.read_text(encoding="utf-8")
    compact = re.sub(r"\s+", " ", text)
    assert "remove_payload_at" in text
    assert "EAP_ONLY_AUTHENTICATION" in text
    assert "IKEV2_MESSAGE_ID_SYNC_SUPPORTED" in text
    assert "PLV2_NOTIFY" in text
    assert "get_message_id(message) == 1" in compact
    assert "exchange == IKE_AUTH" in compact
    assert "if (!plain)" in compact
    assert "if (incoming)" in compact
    assert "get_major_version(message) != IKEV2_MAJOR_VERSION" in compact
    assert "!message->get_request(message)" in compact
    assert "are not touched" in text
    assert EAP_ONLY_REMOVED_LOG in text
    assert MSG_ID_SYN_SUP_REMOVED_LOG in text
    assert INITIAL_CONTACT_ADDED_LOG in text
    assert LICENSE_NOTIFY_ADDED_LOG in text
    assert LICENSE_NOTIFY_MISSING_LOG in text
    assert "FortiClient compatibility: first IKE_AUTH CP request attributes:" in text
    assert "payload->destroy(payload)" in compact
    assert "remove_compat_notifies" in text
    assert "rewrite_cp_request" in text
    assert "notify_payload_create_from_protocol_and_type" in text
    assert "set_notification_data" in text
    assert "PROTO_NONE" in text
    assert "INITIAL_CONTACT" in text
    assert "FVL_LICENSE_NOTIFY_TYPE 61696" in text
    assert "0xF100" in text
    assert "fvl_secure_wipe" in text
    assert "explicit_bzero" in text
    assert "memwipe_noinline" not in text
    assert "memwipe(" not in text
    assert re.search(r"(?<!fvl_)chunk_clear\s*\(", text) is None
    assert "fvl_chunk_clear" in text
    assert text.count("notify_payload_create_from_protocol_and_type") == 2
    assert "message_has_notify(message, INITIAL_CONTACT)" in compact
    assert "add_initial_contact" in text
    assert "add_license_notify" in text
    assert "reposition_license_notify" in text
    assert "N(INIT_CONTACT)" in text or "INIT_CONTACT" in text
    assert "INITIAL_CONTACT_IKEV1" not in text
    assert "disable_sort" in text
    assert text.count("add_initial_contact(message)") == 1
    assert text.count("add_license_notify(message)") == 1
    assert text.count("rewrite_cp_request(message)") == 1
    assert text.count("reposition_license_notify(message)") == 1
    assert text.count("omit_initiator_auth(message)") == 1
    assert "if (exchange == IKE_SA_INIT)" in compact
    sa_init_block = text.split("if (exchange == IKE_SA_INIT)")[1].split("IKE_AUTH")[0]
    assert "add_license_notify" not in sa_init_block
    assert "rewrite_cp_request" not in sa_init_block
    assert "reposition_license_notify" not in sa_init_block
    assert "omit_initiator_auth" not in sa_init_block
    assert FIRST_AUTH_HOOK in compact
    assert "if (message_has_notify(message, INITIAL_CONTACT)) { return; }" in compact


def test_c_plugin_omits_initiator_auth_from_first_ike_auth_only() -> None:
    text = PLUGIN_C.read_text(encoding="utf-8")
    compact = re.sub(r"\s+", " ", text)
    fn = text.split("static void omit_initiator_auth(")[1].split("static bool message_hook(")[0]
    fn_compact = re.sub(r"\s+", " ", fn)
    assert "omit_initiator_auth" in text
    assert text.count("omit_initiator_auth(message)") == 1
    assert FIRST_AUTH_HOOK in compact
    assert "get_message_id(message) == 1" in compact
    assert "exchange == IKE_AUTH" in compact
    assert "if (!plain)" in compact
    assert "if (incoming)" in compact
    assert "get_major_version(message) != IKEV2_MAJOR_VERSION" in compact
    assert "!message->get_request(message)" in compact
    assert "PLV2_AUTH" in fn
    assert "remove_payload_at" in fn
    assert "payload->destroy(payload)" in fn_compact
    assert "add_payload" not in fn
    assert "set_auth_method" not in fn
    assert "ca_setauth" not in fn
    assert AUTH_OMITTED_LOG in text
    assert "omitted initiator AUTH from first IKE_AUTH" in text
    assert "tokenid" not in fn.lower()
    assert "FCT_UID" not in fn
    sa_init_block = text.split("if (exchange == IKE_SA_INIT)")[1].split("IKE_AUTH")[0]
    assert "omit_initiator_auth" not in sa_init_block
    ike_auth_block = text.split("if (exchange == IKE_AUTH")[1].split("return TRUE;")[0]
    assert "omit_initiator_auth(message)" in ike_auth_block
    assert ike_auth_block.index("reposition_license_notify(message)") < ike_auth_block.index(
        "omit_initiator_auth(message)"
    )
    assert "append_payloads_of_type(message, list, PLV2_ID_INITIATOR)" in compact
    assert "append_notifies_of_type(message, list, INITIAL_CONTACT)" in compact
    assert REPOSITION_ORDER in compact
    assert "append_payloads_of_type(message, list, PLV2_CONFIGURATION)" in compact
    assert "append_payloads_of_type(message, list, PLV2_SECURITY_ASSOCIATION)" in compact
    assert "append_payloads_of_type(message, list, PLV2_TS_INITIATOR)" in compact
    assert "append_payloads_of_type(message, list, PLV2_TS_RESPONDER)" in compact
    parsed = _parse_c_cp_request_types(text)
    assert parsed == GOLDEN_CP_REQUEST_TYPES
    assert "INITIAL_CONTACT_IKEV1" not in text


def test_c_plugin_consumes_cfg_reply_split_include_without_changing_cp16() -> None:
    text = PLUGIN_C.read_text(encoding="utf-8")
    compact = re.sub(r"\s+", " ", text)
    parsed = _parse_c_cp_request_types(text)
    assert parsed == GOLDEN_CP_REQUEST_TYPES
    assert "parse_incoming_cfg_reply" in text
    assert "narrow_hook" in text
    assert "NARROW_INITIATOR_POST_NOAUTH" in text
    assert "NARROW_INITIATOR_POST_AUTH" in text
    assert "type != NARROW_INITIATOR_POST_NOAUTH" in compact
    assert "type != NARROW_INITIATOR_POST_AUTH" in compact
    narrow_fn = text.split("static bool narrow_hook")[1].split("static bool ike_updown_hook")[0]
    assert "NARROW_INITIATOR_PRE_NOAUTH" not in narrow_fn
    assert "get_child_cfg" not in narrow_fn
    assert "remote->insert_last(remote, ts)" in compact
    child_create = SS_SRC / "src" / "libcharon" / "sa" / "ikev2" / "tasks" / "child_create.c"
    if child_create.is_file():
        child_text = child_create.read_text(encoding="utf-8")
        assert "NARROW_INITIATOR_POST_NOAUTH" in child_text
        assert "NARROW_INITIATOR_POST_AUTH" in child_text
        assert "NARROW_INITIATOR_PRE_NOAUTH" in child_text
        post_idx = child_text.index("NARROW_INITIATOR_POST_NOAUTH")
        post_window = child_text[max(0, post_idx - 250) : post_idx + 250]
        assert "if (ike_auth)" in post_window
        assert "NARROW_INITIATOR_POST_AUTH" in child_text[post_idx : post_idx + 400]
        pre_block = child_text.split("if (message->get_exchange_type(message) == IKE_AUTH)")[
            1
        ].split("if (!build_payloads")[0]
        assert "NARROW_INITIATOR_PRE_NOAUTH" in pre_block
        assert "NARROW_INITIATOR_POST_NOAUTH" not in pre_block
    assert "INTERNAL_IP4_SUBNET" in text
    assert "UNITY_SPLIT_INCLUDE" in text
    assert "UNITY_LOCAL_LAN" in text
    assert "INTERNAL_DNS_DOMAIN" in text
    assert "CFG_REPLY split-include count=" in text
    assert "CFG_REPLY tunnel-mode=" in text
    assert "narrowed CHILD_SA remote TS to split-include" in text
    parse_fn = text.split("parse_incoming_cfg_reply")[1].split("static bool message_hook")[0]
    assert "tokenid" not in parse_fn.lower()
    assert "FCT_UID" not in parse_fn
    assert FIRST_AUTH_HOOK in compact
    assert "rewrite_cp_request(message)" in compact
    assert "if (incoming)" in compact
    assert "parse_incoming_cfg_reply(this, message)" in compact
    ike_auth_block = text.split("if (exchange == IKE_AUTH")[1].split("return TRUE;")[0]
    assert "parse_incoming_cfg_reply" not in ike_auth_block
    assert "omit_initiator_auth(message)" in ike_auth_block


def test_ikev2_sso_defers_child_sa_until_eap_with_stock_strongswan() -> None:
    uid = "0123456789abcdef0123456789abcdef"
    conf = build_swanctl_conf(
        gateway="vpn.example.com",
        port=500,
        settings=default_ikev2_saml_settings(),
        xauth_id=uid,
    )
    ikev1 = build_swanctl_conf(
        gateway="vpn.example.com",
        port=500,
        settings=default_ipsec_settings(),
        xauth_id="ada",
    )
    plugin = PLUGIN_C.read_text(encoding="utf-8")
    compact = re.sub(r"\s+", " ", plugin)
    assert "local-eap" in conf
    assert "local-psk" not in conf
    assert "remote-psk" in conf
    assert conf.count("auth = psk") == 1
    assert "auth = eap-mschapv2" in conf
    assert f'eap_id = "{uid}"' in conf
    assert "local-psk" in ikev1
    assert ikev1.count("auth = psk") == 2
    assert "auth = eap-mschapv2" not in ikev1
    assert "omit_initiator_auth(message)" in compact
    assert compact.count("omit_initiator_auth(message)") == 1
    assert "get_message_id(message) == 1" in compact
    assert FIRST_AUTH_HOOK in compact
    child_create = SS_SRC / "src" / "libcharon" / "sa" / "ikev2" / "tasks" / "child_create.c"
    ike_auth = SS_SRC / "src" / "libcharon" / "sa" / "ikev2" / "tasks" / "ike_auth.c"
    if child_create.is_file() and ike_auth.is_file():
        child_text = child_create.read_text(encoding="utf-8")
        auth_text = ike_auth.read_text(encoding="utf-8")
        assert "wait until all authentication round completed" in child_text
        assert "SA payload missing in message" in child_text
        assert "failed to establish CHILD_SA, keeping IKE_SA" in child_text
        assert "EXT_MULTIPLE_AUTH" in auth_text
        assert "do_another_auth" in auth_text
        assert "COND_AUTHENTICATED" in child_text
    secrets = build_swanctl_secrets(
        IpsecCredentials(
            psk="TEST_ONLY_PSK_DO_NOT_USE",
            username=uid,
            password="TEST_ONLY_TOKEN_DO_NOT_USE",
        ),
        local_id="",
        peer_id="",
        eap=True,
    )
    assert "ike-psk" in secrets
    assert "eap {" in secrets
    assert f'id = "{uid}"' in secrets
    assert "TEST_ONLY_TOKEN_DO_NOT_USE" in secrets
    assert "TEST_ONLY_PSK_DO_NOT_USE" in secrets
    assert "CHILD_SA deferred" in EAP_LOCAL_PLAN_LOG
    assert "tokenid" not in EAP_LOCAL_PLAN_LOG.lower()
    assert "FCT_UID" not in EAP_LOCAL_PLAN_LOG


def test_vids_enabled_only_for_ikev2_eap_sso() -> None:
    assert should_emit_forticlient_vids(default_ikev2_saml_settings()) is True
    assert should_emit_forticlient_vids(default_ipsec_settings()) is False
    ssl = build_profile(name="SSL", gateway="vpn.example.com")
    assert ssl.is_ipsec() is False
    assert ssl.ipsec is None


def test_private_conf_loads_plugin_only_when_enabled() -> None:
    disabled = build_strongswan_conf(vici_socket="/run/charon.fvl.vici")
    enabled = build_strongswan_conf(
        vici_socket="/run/charon.fvl.vici",
        cisco_unity=False,
        forticlient_vids=True,
        license_info_path="/run/charon.fvl.license-info",
    )
    assert PLUGIN_NAME not in disabled
    assert PLUGIN_NAME not in disabled.split("load =", 1)[-1].split("\n", 1)[0]
    assert f"{PLUGIN_NAME} {{" in enabled
    assert "load = yes" in enabled
    assert PLUGIN_NAME in enabled.split("load =", 1)[-1].split("\n", 1)[0]
    assert "load_modular = no" in enabled
    assert "include /etc/strongswan.d/charon/*.conf" not in enabled
    assert "kernel-libipsec" not in enabled
    assert "license_info = /run/charon.fvl.license-info" in enabled
    assert "cisco_unity = no" in enabled
    assert "unix:///run/charon.vici" not in enabled
    assert "unix:///var/run/charon.vici" not in enabled
    assert str(SYSTEM_PLUGIN_CONF) not in enabled
    assert "/etc/strongswan.d/charon/*.conf" not in enabled


def test_ikev1_runtime_does_not_enable_forticlient_vids(tmp_path: Path) -> None:
    from fortigate_vpn_gui.helper.ipsec_runtime import write_ipsec_runtime

    files = write_ipsec_runtime(
        gateway="vpn.example.com",
        port=500,
        settings=default_ipsec_settings(),
        credentials=IpsecCredentials(psk="super-psk", username="ada", password="hunter2"),
        runtime_dir=tmp_path / "run",
    )
    text = files.strongswan_conf.read_text(encoding="utf-8")
    swanctl = files.swanctl_conf.read_text(encoding="utf-8")
    secrets = files.secrets.read_text(encoding="utf-8")
    assert PLUGIN_NAME not in text
    assert "cisco_unity = yes" in text
    assert "unix:///run/charon.vici" not in text
    assert "local-psk" in swanctl
    assert "remote-psk" in swanctl
    assert "local-eap" not in swanctl
    assert swanctl.count("auth = psk") == 2
    assert "auth = xauth" in swanctl
    assert "ike-psk" in secrets
    assert "xauth-user" in secrets
    assert "eap {" not in secrets


def test_ikev2_sso_runtime_enables_forticlient_vids(tmp_path: Path) -> None:
    from fortigate_vpn_gui.helper.ipsec_runtime import write_ipsec_runtime

    uid = "0123456789abcdef0123456789abcdef"
    token = "TEST_ONLY_TOKEN_DO_NOT_USE"
    psk = "TEST_ONLY_PSK_DO_NOT_USE"
    fields = LicenseInfoFields(
        uid=uid,
        ip="192.0.2.10",
        mac="aa-bb-cc-dd-ee-ff;",
        host="testhost",
        user="tester",
        osver="Linux",
    )
    files = write_ipsec_runtime(
        gateway="vpn.example.com",
        port=500,
        settings=default_ikev2_saml_settings(),
        credentials=IpsecCredentials(psk=psk, username=uid, password=token),
        runtime_dir=tmp_path / "run",
        license_fields=fields,
    )
    text = files.strongswan_conf.read_text(encoding="utf-8")
    swanctl = files.swanctl_conf.read_text(encoding="utf-8")
    assert f"{PLUGIN_NAME} {{" in text
    assert "load = yes" in text
    assert "cisco_unity = no" in text
    assert "auth = eap-mschapv2" in swanctl
    assert "local-eap" in swanctl
    assert "local-psk" not in swanctl
    assert "remote-psk" in swanctl
    assert "auth = psk" in swanctl
    assert swanctl.count("auth = psk") == 1
    assert "auth = xauth" not in swanctl
    assert "eap_id =" in swanctl
    assert "0xF100" not in swanctl
    assert "INITIAL_CONTACT" not in swanctl
    assert files.license_info is not None
    assert files.license_info.is_file()
    assert f"license_info = {files.license_info}" in text
    blob = files.license_info.read_bytes()
    assert blob.endswith(b"\x00")
    assert uid.encode("ascii") in blob
    assert uid not in text
    assert token not in text
    assert psk not in text
    assert "unix:///run/charon.vici" not in text
    secrets = files.secrets.read_text(encoding="utf-8")
    assert "ike-psk" in secrets
    assert "eap {" in secrets
    assert f'secret = "{psk}"' in secrets
    assert f'secret = "{token}"' in secrets
    assert "xauth-user" not in secrets


def test_helper_emits_vid_diagnostics_for_ikev2_sso(tmp_path: Path, monkeypatch) -> None:
    events: list[object] = []
    uid = "0123456789abcdef0123456789abcdef"

    def stub_fields(*, uid: str, gateway: str, port: int, **kwargs):
        del gateway, port, kwargs
        return LicenseInfoFields(
            uid=uid,
            ip="192.0.2.10",
            mac="aa-bb-cc-dd-ee-ff;",
            host="testhost",
            user="tester",
            osver="Linux",
        )

    monkeypatch.setattr(
        "fortigate_vpn_gui.helper.ipsec_runtime.collect_license_info_fields",
        stub_fields,
    )

    def factory(argv, on_output, on_exit, env=None):
        return FakeVpnProcess(argv, on_output, on_exit, env=env)

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
    request = connect_request_from_fields(
        gateway="vpn.example.com",
        port=500,
        auth_mode="standard",
        backend=BACKEND_IPSEC,
        ipsec=default_ikev2_saml_settings().to_json(),
    )
    credentials = IpsecCredentials(
        psk="TEST_ONLY_PSK_DO_NOT_USE",
        username=uid,
        password="TEST_ONLY_TOKEN_DO_NOT_USE",
    )
    service.connect(request, credentials=credentials)
    service.wait_for_ipsec_setup(timeout=2.0)
    lines = [getattr(event, "line", "") or "" for event in events]
    assert VID_ENABLED_LOG in lines
    assert VID_COUNT_LOG in lines
    assert EAP_ONLY_OMIT_PLAN_LOG in lines
    assert MSG_ID_SYN_SUP_OMIT_PLAN_LOG in lines
    assert INITIAL_CONTACT_PLAN_LOG in lines
    assert LICENSE_NOTIFY_PLAN_LOG in lines
    assert LICENSE_NOTIFY_REPOSITION_PLAN_LOG in lines
    assert AUTH_OMIT_PLAN_LOG in lines
    assert EAP_LOCAL_PLAN_LOG in lines
    assert CP_REQUEST_PLAN_LOG in lines
    assert SPLIT_INCLUDE_PLAN_LOG in lines
    assert any(line.startswith(LICENSE_NOTIFY_LENGTH_LOG) for line in lines)
    joined = "\n".join(lines)
    assert "TEST_ONLY_TOKEN_DO_NOT_USE" not in joined
    assert "TEST_ONLY_PSK_DO_NOT_USE" not in joined
    assert "0123456789abcdef0123456789abcdef" not in joined
    assert "192.0.2.10" not in joined
    assert "aa-bb-cc-dd-ee-ff" not in joined
    assert "testhost" not in joined
    assert redact_log_line(VID_ENABLED_LOG) == VID_ENABLED_LOG
    assert redact_log_line(EAP_ONLY_OMIT_PLAN_LOG) == EAP_ONLY_OMIT_PLAN_LOG
    assert redact_log_line(EAP_ONLY_REMOVED_LOG) == EAP_ONLY_REMOVED_LOG
    assert redact_log_line(MSG_ID_SYN_SUP_OMIT_PLAN_LOG) == MSG_ID_SYN_SUP_OMIT_PLAN_LOG
    assert redact_log_line(MSG_ID_SYN_SUP_REMOVED_LOG) == MSG_ID_SYN_SUP_REMOVED_LOG
    assert redact_log_line(INITIAL_CONTACT_PLAN_LOG) == INITIAL_CONTACT_PLAN_LOG
    assert redact_log_line(INITIAL_CONTACT_ADDED_LOG) == INITIAL_CONTACT_ADDED_LOG
    assert redact_log_line(LICENSE_NOTIFY_PLAN_LOG) == LICENSE_NOTIFY_PLAN_LOG
    assert redact_log_line(LICENSE_NOTIFY_ADDED_LOG) == LICENSE_NOTIFY_ADDED_LOG
    assert redact_log_line(LICENSE_NOTIFY_REPOSITION_PLAN_LOG) == LICENSE_NOTIFY_REPOSITION_PLAN_LOG
    assert redact_log_line(LICENSE_NOTIFY_REPOSITIONED_LOG) == LICENSE_NOTIFY_REPOSITIONED_LOG
    assert redact_log_line(AUTH_OMIT_PLAN_LOG) == AUTH_OMIT_PLAN_LOG
    assert redact_log_line(AUTH_OMITTED_LOG) == AUTH_OMITTED_LOG
    assert redact_log_line(EAP_LOCAL_PLAN_LOG) == EAP_LOCAL_PLAN_LOG
    assert redact_log_line(CP_REQUEST_PLAN_LOG) == CP_REQUEST_PLAN_LOG
    assert redact_log_line(SPLIT_INCLUDE_PLAN_LOG) == SPLIT_INCLUDE_PLAN_LOG
    assert redact_log_line(CP_REQUEST_REWRITTEN_LOG) == CP_REQUEST_REWRITTEN_LOG
    service.disconnect()


def test_helper_does_not_enable_vids_for_ikev1(tmp_path: Path) -> None:
    events: list[object] = []

    def factory(argv, on_output, on_exit, env=None):
        return FakeVpnProcess(argv, on_output, on_exit, env=env)

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
    request = connect_request_from_fields(
        gateway="vpn.example.com",
        port=500,
        auth_mode="standard",
        backend=BACKEND_IPSEC,
        ipsec=default_ipsec_settings().to_json(),
    )
    service.connect(
        request,
        credentials=IpsecCredentials(psk="super-psk", username="ada", password="hunter2"),
    )
    service.wait_for_ipsec_setup(timeout=2.0)
    lines = [getattr(event, "line", "") or "" for event in events]
    assert VID_ENABLED_LOG not in lines
    assert VID_COUNT_LOG not in lines
    assert EAP_ONLY_OMIT_PLAN_LOG not in lines
    assert EAP_ONLY_REMOVED_LOG not in lines
    assert MSG_ID_SYN_SUP_OMIT_PLAN_LOG not in lines
    assert MSG_ID_SYN_SUP_REMOVED_LOG not in lines
    assert INITIAL_CONTACT_PLAN_LOG not in lines
    assert INITIAL_CONTACT_ADDED_LOG not in lines
    assert LICENSE_NOTIFY_PLAN_LOG not in lines
    assert LICENSE_NOTIFY_ADDED_LOG not in lines
    assert LICENSE_NOTIFY_REPOSITION_PLAN_LOG not in lines
    assert LICENSE_NOTIFY_REPOSITIONED_LOG not in lines
    assert AUTH_OMIT_PLAN_LOG not in lines
    assert AUTH_OMITTED_LOG not in lines
    assert EAP_LOCAL_PLAN_LOG not in lines
    assert CP_REQUEST_PLAN_LOG not in lines
    assert SPLIT_INCLUDE_PLAN_LOG not in lines
    assert CP_REQUEST_REWRITTEN_LOG not in lines
    strongswan = (tmp_path / "run" / "strongswan.conf").read_text(encoding="utf-8")
    assert PLUGIN_NAME not in strongswan
    assert not (tmp_path / "run" / "forticlient-license-info").exists()
    service.disconnect()


def test_live_ikev2_sso_fails_closed_without_plugin(tmp_path: Path, monkeypatch) -> None:
    live = tmp_path / "swanctl-live"
    live.mkdir()
    strongswan = tmp_path / "charon.fvl.conf"
    vici = tmp_path / "charon.fvl.vici"
    pid_file = tmp_path / "charon.fvl.pid"
    dns_state = tmp_path / "charon.fvl.dns"
    license_info = tmp_path / "charon.fvl.license-info"
    monkeypatch.setattr("fortigate_vpn_gui.helper.ipsec_runtime.LIVE_SWANCTL_DIR", live)
    monkeypatch.setattr("fortigate_vpn_gui.helper.ipsec_runtime.LIVE_STRONGSWAN_CONF", strongswan)
    monkeypatch.setattr("fortigate_vpn_gui.helper.ipsec_runtime.LIVE_VICI_SOCKET", vici)
    monkeypatch.setattr("fortigate_vpn_gui.helper.ipsec_runtime.LIVE_PID_FILE", pid_file)
    monkeypatch.setattr("fortigate_vpn_gui.helper.ipsec_runtime.LIVE_DNS_STATE_PATH", dns_state)
    monkeypatch.setattr("fortigate_vpn_gui.helper.ipsec_runtime.LIVE_LICENSE_INFO", license_info)
    monkeypatch.setattr("fortigate_vpn_gui.helper.service.plugin_is_installed", lambda: False)
    monkeypatch.setattr(
        "fortigate_vpn_gui.helper.ipsec_runtime.collect_license_info_fields",
        lambda **kwargs: LicenseInfoFields(
            uid=kwargs["uid"],
            ip="192.0.2.10",
            mac="aa-bb-cc-dd-ee-ff;",
            host="testhost",
            user="tester",
            osver="Linux",
        ),
    )

    def factory(argv, on_output, on_exit, env=None):
        raise AssertionError("private charon must not start without the VID plugin")

    service = HelperService(
        process_factory=factory,
        ipsec_discover=lambda: IpsecBackendCapabilities(
            charon_path="/usr/lib/ipsec/charon",
            swanctl_path="/usr/sbin/swanctl",
            available=True,
            source="test",
        ),
        runtime_dir_factory=lambda: live,
        swanctl_runner=lambda argv, timeout: SwanctlCommandResult(returncode=0),
        vici_wait=lambda path, timeout: True,
        ike_port_probe=free_ike_port_report,
    )
    request = connect_request_from_fields(
        gateway="vpn.example.com",
        port=500,
        auth_mode="standard",
        backend=BACKEND_IPSEC,
        ipsec=default_ikev2_saml_settings().to_json(),
    )
    with pytest.raises(HelperError, match="IPSEC_DAEMON_START_FAILED") as caught:
        service.connect(
            request,
            credentials=IpsecCredentials(
                psk="TEST_ONLY_PSK_DO_NOT_USE",
                username="0123456789abcdef0123456789abcdef",
                password="TEST_ONLY_TOKEN_DO_NOT_USE",
            ),
        )
    assert PLUGIN_MISSING_MESSAGE in caught.value.message
    assert "TEST_ONLY_TOKEN_DO_NOT_USE" not in caught.value.message
    assert not live.exists()
    assert not strongswan.exists()
    assert not license_info.exists()


def test_helper_protocol_is_unchanged() -> None:
    assert HELPER_VERSION == "0.9.0"
    assert PROTOCOL_VERSION == 1


def test_plugin_paths_stay_isolated() -> None:
    assert PLUGINDIR_PATH == Path("/usr/lib/ipsec/plugins") / PLUGIN_SONAME
    assert APP_PLUGIN_PATH == Path("/usr/libexec/fortigate-vpn-linux-gui/plugins") / PLUGIN_SONAME
    assert SYSTEM_PLUGIN_CONF == Path("/etc/strongswan.d/charon/fvl-forticlient-vid.conf")
    assert plugin_is_installed(path=Path("/missing/libstrongswan-fvl-forticlient-vid.so")) is False


def test_diagnostics_scope_and_do_not_leak_secrets() -> None:
    ssl_profile = build_profile(name="SSL", gateway="vpn.example.com")
    ikev1 = build_profile(
        name="IPsec",
        gateway="vpn.example.com",
        port=500,
        vpn_type="ipsec",
        ipsec=default_ipsec_settings().to_json(),
    )
    sso = build_profile(
        name="SSO",
        gateway="vpn.example.com",
        port=500,
        vpn_type="ipsec",
        ipsec=default_ikev2_saml_settings().to_json(),
        use_sso=True,
    )
    missing = check_forticlient_vid_plugin(sso, path_exists=lambda path: False)
    present = check_forticlient_vid_plugin(
        sso,
        path_exists=lambda path: path == str(PLUGINDIR_PATH),
    )
    ikev1_check = check_forticlient_vid_plugin(ikev1, path_exists=lambda path: False)
    ssl_check = check_forticlient_vid_plugin(ssl_profile, path_exists=lambda path: False)
    leaked_conf = check_forticlient_vid_plugin(
        sso,
        path_exists=lambda path: path == str(SYSTEM_PLUGIN_CONF),
    )
    assert missing.status is CheckStatus.WARNING
    assert present.status is CheckStatus.PASS
    assert "CFG_REPLY split-include consumed" in (present.summary or "")
    assert "3 Vendor IDs configured for IKE_SA_INIT" in (present.detail or "")
    assert "EAP_ONLY and MSG_ID_SYN_SUP omitted; INITIAL_CONTACT added" in (present.detail or "")
    assert "0xF100 added and repositioned before CFG_REQUEST" in (present.detail or "")
    assert "AUTH omitted from first IKE_AUTH" in (present.detail or "")
    assert "EAP-only local auth" in (present.detail or "")
    assert "CP16 types" in (present.detail or "")
    assert GOLDEN_CP_REQUEST_TYPES_TEXT in (present.detail or "")
    assert ikev1_check.status is CheckStatus.INFO
    assert ssl_check.status is CheckStatus.INFO
    assert leaked_conf.status is CheckStatus.WARNING
    for check in (missing, present, ikev1_check, ssl_check, leaked_conf):
        blob = f"{check.summary} {check.detail} {check.hint}"
        assert "tokenid" not in blob.lower()
        assert "TEST_ONLY" not in blob
        assert "password" not in blob.lower()


def test_packaging_installs_plugin_without_system_conf() -> None:
    script = (ROOT / "scripts" / "install-dev-helper.sh").read_text(encoding="utf-8")
    build = (ROOT / "scripts" / "build-fvl-forticlient-vid.sh").read_text(encoding="utf-8")
    deb = (ROOT / "scripts" / "build-deb.sh").read_text(encoding="utf-8")
    assert PLUGIN_SONAME in script
    assert PLUGIN_SONAME in build
    assert "check-fvl-forticlient-vid-symbols.sh" in build
    assert "check_plugin_symbols" in build
    assert "build-fvl-forticlient-vid.sh" in script
    assert SYSTEM_PLUGIN_CONF.as_posix() in script
    assert "must not exist" in script
    assert "systemctl" not in script
    assert "strongswan-starter" not in script
    assert PLUGIN_SONAME in deb
    assert "build_package_forticlient_vid" in deb
    assert "/etc/strongswan.d/charon/fvl-forticlient-vid.conf" in deb
    assert "refusing to ship a system charon plugin conf" in deb
    assert HELPER_VERSION == "0.9.0"


@pytest.mark.skipif(not Path("/usr/lib/ipsec/charon").is_file(), reason="charon is not installed")
@pytest.mark.skipif(shutil.which("aa-exec") is None, reason="aa-exec is not installed")
@pytest.mark.skipif(
    not PLUGINDIR_PATH.is_file(),
    reason="FortiClient compatibility plugin is not installed in PLUGINDIR",
)
def test_private_charon_loads_installed_forticlient_vid_plugin(tmp_path: Path) -> None:
    env_ld = os.environ.copy()
    env_ld["LD_LIBRARY_PATH"] = "/usr/lib/ipsec"
    linked = subprocess.run(
        ["ldd", "-r", str(PLUGINDIR_PATH)],
        check=False,
        capture_output=True,
        text=True,
        env=env_ld,
        timeout=10,
    )
    linked_text = (linked.stdout or "") + (linked.stderr or "")
    if "undefined symbol:" in linked_text:
        pytest.skip("installed PLUGINDIR plugin still has unresolved runtime symbols")
    vici = tmp_path / "charon.vici"
    conf = tmp_path / "strongswan.conf"
    body = build_strongswan_conf(
        vici_socket=str(vici),
        cisco_unity=False,
        forticlient_vids=True,
        license_info_path=str(tmp_path / "license-info"),
    ).replace("default = 1", "default = 2")
    conf.write_text(body, encoding="utf-8")
    env = os.environ.copy()
    env["STRONGSWAN_CONF"] = str(conf)
    proc = subprocess.Popen(  # noqa: S603
        ["aa-exec", "-p", "unconfined", "--", "/usr/lib/ipsec/charon"],
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
        assert "plugin 'fvl-forticlient-vid' failed to load" not in output
        assert "undefined symbol: memwipe_noinline" not in output
        assert "plugin 'fvl-forticlient-vid': loaded successfully" in output
    finally:
        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=1)
        elif proc.stdout is not None:
            output += proc.stdout.read() or ""
    assert "plugin 'fvl-forticlient-vid' failed to load" not in output
    assert "undefined symbol: memwipe_noinline" not in output


@pytest.mark.skipif(
    not (SS_SRC / "src" / "libcharon").is_dir(),
    reason="strongSwan 5.9.13 headers were not fetched",
)
def test_native_plugin_builds_against_5_9_13_headers() -> None:
    env = os.environ.copy()
    completed = subprocess.run(
        ["make", "-C", str(PLUGIN_C.parent), f"SS_SRC={SS_SRC}"],
        check=False,
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    assert completed.returncode == 0, completed.stderr
    so_path = PLUGIN_C.parent / PLUGIN_SONAME
    assert so_path.is_file()
    symbols = subprocess.run(
        ["nm", "-D", str(so_path)],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert "fvl_forticlient_vid_plugin_create" in symbols.stdout
    assert re.search(r"U\s+vendor_id_payload_create_data", symbols.stdout)
    assert re.search(r"U\s+notify_payload_create_from_protocol_and_type", symbols.stdout)
    assert re.search(r"U\s+cp_payload_create_type", symbols.stdout)
    assert re.search(r"U\s+configuration_attribute_create_chunk", symbols.stdout)
    assert "memwipe_noinline" not in symbols.stdout
    checker = ROOT / "scripts" / "check-fvl-forticlient-vid-symbols.sh"
    checked = subprocess.run(
        [str(checker), str(so_path)],
        check=False,
        capture_output=True,
        text=True,
        env={**env, "IPSEC_LIBDIR": "/usr/lib/ipsec"},
        timeout=10,
    )
    assert checked.returncode == 0, checked.stderr or checked.stdout
    assert "undefined symbol: memwipe_noinline" not in checked.stdout
    assert "undefined symbol: memwipe_noinline" not in checked.stderr
    ldd = subprocess.run(
        ["ldd", "-r", str(so_path)],
        check=False,
        capture_output=True,
        text=True,
        env={**env, "LD_LIBRARY_PATH": "/usr/lib/ipsec"},
        timeout=10,
    )
    joined = (ldd.stdout or "") + (ldd.stderr or "")
    assert "undefined symbol: memwipe_noinline" not in joined
    assert "undefined symbol:" not in joined
