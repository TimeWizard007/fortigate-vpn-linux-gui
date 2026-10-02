# SPDX-License-Identifier: GPL-3.0-or-later
"""openfortivpn output classification tests. No real VPN."""

from __future__ import annotations

from fortigate_vpn_gui.vpn.classify import (
    IKE_AUTH_TIMEOUT_MESSAGE,
    IKE_SA_INIT_TIMEOUT_MESSAGE,
    OutputHint,
    classify_ipsec_initiate_logs,
    classify_output,
    initiate_failure_report,
    user_message_for_hint,
)


def test_gateway_connected_is_not_tunnel_ready() -> None:
    assert classify_output("INFO:   Connected to gateway.") is OutputHint.GATEWAY_CONNECTED
    assert classify_output("INFO:   Authenticated.") is OutputHint.NONE
    assert classify_output("INFO:   Interface ppp0 is UP.") is OutputHint.NONE
    assert classify_output("INFO:   Tunnel is up") is OutputHint.NONE


def test_tunnel_ready_is_canonical_connected_signal() -> None:
    assert classify_output("INFO:   Tunnel is up and running.") is OutputHint.CONNECTED
    assert classify_output("tunnel is up and running") is OutputHint.CONNECTED


def test_ipsec_child_sa_is_connected() -> None:
    assert (
        classify_output("13[IKE] CHILD_SA fortigate{1} established with SPIs c1-c2")
        is OutputHint.CONNECTED
    )
    assert classify_output("IPsec CHILD SA established") is OutputHint.CONNECTED


def test_ike_established_is_not_connected() -> None:
    assert (
        classify_output("13[IKE] IKE_SA fortigate[1] established between 1.2.3.4 and 5.6.7.8")
        is OutputHint.IKE_ESTABLISHED
    )
    assert user_message_for_hint(OutputHint.IKE_ESTABLISHED) is None


def test_ssl_and_ipsec_failure_hints_are_conservative() -> None:
    assert (
        classify_output("Could not resolve hostname vpn.example.com") is OutputHint.DNS_RESOLUTION
    )
    assert classify_output("connect: Network is unreachable") is OutputHint.GATEWAY_UNREACHABLE
    assert classify_output("SAML authentication failed") is OutputHint.SAML_REJECTED
    assert (
        classify_output("authorization for privileged VPN access was denied")
        is OutputHint.PERMISSION
    )
    assert classify_output("PSK authentication failed") is OutputHint.PSK_FAILURE
    assert classify_output("XAuth authentication failed") is OutputHint.XAUTH_FAILURE
    assert classify_output("EAP authentication failed") is OutputHint.EAP_FAILURE
    assert classify_output("NO_PROPOSAL_CHOSEN") is OutputHint.PROPOSAL_MISMATCH
    assert classify_output("establishing CHILD_SA failed") is OutputHint.CHILD_SA_FAILURE
    assert classify_output("installing virtual IP failed") is OutputHint.VIP_FAILURE
    assert classify_output("establishing IKE_SA failed, giving up") is OutputHint.IKE_TIMEOUT
    assert classify_output("unable to start charon") is OutputHint.CHARON_FAILURE
    assert classify_output("failed to load connections") is OutputHint.SWANCTL_FAILURE
    assert (
        classify_output("unable to bind socket: Address already in use")
        is OutputHint.IKE_PORT_CONFLICT
    )
    assert classify_output("IKE_SA failed for unknown reason") is OutputHint.IPSEC_NEGOTIATION
    assert "See Diagnostics" in (user_message_for_hint(OutputHint.IPSEC_NEGOTIATION) or "")
    assert "500/4500" in (user_message_for_hint(OutputHint.IKE_PORT_CONFLICT) or "")
    assert user_message_for_hint(OutputHint.NONE) is None
    assert user_message_for_hint(OutputHint.CONNECTED) is None


def test_ikev2_eap_progress_and_failure_are_distinct() -> None:
    initiating = "13[IKE] initiating IKE_SA fortigate[1] to 1.2.3.4"
    assert classify_output(initiating) is OutputHint.IKE_SA_INIT
    assert classify_output("13[IKE] EAP method EAP_MSCHAPV2 selected") is OutputHint.EAP_IN_PROGRESS
    assert classify_output("received EAP_FAILURE") is OutputHint.EAP_FAILURE
    assert classify_output("eap-mschapv2 failed") is OutputHint.EAP_FAILURE
    assert "IKEv2 authentication failed" in (user_message_for_hint(OutputHint.EAP_FAILURE) or "")
    assert user_message_for_hint(OutputHint.IKE_SA_INIT) is None
    assert user_message_for_hint(OutputHint.EAP_IN_PROGRESS) is None
    assert classify_output("IKE_SA failed for unknown reason") is OutputHint.IPSEC_NEGOTIATION


_IKE_AUTH_TIMEOUT_LOGS = (
    "13[IKE] initiating IKE_SA fortigate[1] to 203.0.113.10",
    "13[IKE] generating IKE_SA_INIT request 0 [ SA KE No N(NATD_S_IP) N(NATD_D_IP) "
    "N(FRAG_SUP) N(HASH_ALG) N(REDIR_SUP) ]",
    "13[IKE] parsed IKE_SA_INIT response 0 [ SA KE No N(NATD_S_IP) N(NATD_D_IP) N(FRAG_SUP) ]",
    "13[CFG] selected proposal: IKE:AES_CBC_128/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/ECP_384",
    "13[CFG] loaded IKE shared key 'ike-psk'",
    "13[CFG] loaded EAP shared key 'eap' for '0123456789abcdef0123456789abcdef'",
    "13[IKE] generating IKE_AUTH request 1 [ IDi AUTH CPRQ(ADDR DNS) SA TSi TSr "
    "N(EAP_ONLY) N(MSG_ID_SYN_SUP) ]",
    "13[NET] sending packet: from 192.0.2.8[4500] to 203.0.113.10[4500] (256 bytes)",
    "13[IKE] retransmit 5 of request with message ID 1",
    "13[IKE] giving up after 5 retransmits",
    "13[IKE] establishing IKE_SA failed, giving up",
)

_IKE_SA_INIT_TIMEOUT_LOGS = (
    "13[IKE] initiating IKE_SA fortigate[1] to 203.0.113.10",
    "13[IKE] generating IKE_SA_INIT request 0 [ SA KE No N(NATD_S_IP) N(NATD_D_IP) ]",
    "13[IKE] retransmit 5 of request with message ID 0",
    "13[IKE] giving up after 5 retransmits",
    "13[IKE] establishing IKE_SA failed, giving up",
)

_EAP_FAILURE_LOGS = (
    "13[IKE] initiating IKE_SA fortigate[1] to 203.0.113.10",
    "13[IKE] generating IKE_SA_INIT request 0 [ SA KE No ]",
    "13[IKE] parsed IKE_SA_INIT response 0 [ SA KE No ]",
    "13[IKE] generating IKE_AUTH request 1 [ IDi AUTH SA TSi TSr ]",
    "13[IKE] parsed IKE_AUTH response 1 [ IDr AUTH EAP ]",
    "13[IKE] EAP method EAP_MSCHAPV2 selected",
    "13[IKE] received EAP_FAILURE",
)

_PROPOSAL_LOGS = (
    "13[IKE] initiating IKE_SA fortigate[1] to 203.0.113.10",
    "13[IKE] generating IKE_SA_INIT request 0 [ SA KE No ]",
    "13[IKE] received NO_PROPOSAL_CHOSEN notify",
)

_CHILD_SA_LOGS = (
    "13[IKE] initiating IKE_SA fortigate[1] to 203.0.113.10",
    "13[IKE] parsed IKE_SA_INIT response 0 [ SA KE No ]",
    "13[IKE] generating IKE_AUTH request 1 [ IDi AUTH SA TSi TSr ]",
    "13[IKE] parsed IKE_AUTH response 1 [ IDr AUTH EAP ]",
    "13[IKE] EAP method EAP_MSCHAPV2 selected",
    "13[IKE] establishing CHILD_SA failed",
)

_VIP_LOGS = (
    "13[IKE] initiating IKE_SA fortigate[1] to 203.0.113.10",
    "13[IKE] parsed IKE_SA_INIT response 0 [ SA KE No ]",
    "13[IKE] generating IKE_AUTH request 1 [ IDi AUTH CPRQ(ADDR DNS) SA TSi TSr ]",
    "13[IKE] parsed IKE_AUTH response 1 [ IDr AUTH CP(ADDR) SA TSi TSr ]",
    "13[IKE] installing virtual IP failed",
)


def test_ike_sa_init_success_then_ike_auth_timeout_is_not_eap_failure() -> None:
    hint = classify_ipsec_initiate_logs(_IKE_AUTH_TIMEOUT_LOGS)
    assert hint is OutputHint.IKE_AUTH_TIMEOUT
    assert hint is not OutputHint.EAP_FAILURE
    assert hint is not OutputHint.IKE_SA_INIT_TIMEOUT
    code, message = initiate_failure_report(hint)
    assert code == "IKE_AUTH_TIMEOUT"
    assert message == IKE_AUTH_TIMEOUT_MESSAGE
    assert "EAP" not in message
    assert "tokenid" not in message.lower()
    assert "fct_uid" not in message.lower()
    assert user_message_for_hint(hint) == IKE_AUTH_TIMEOUT_MESSAGE
    assert classify_output("13[IKE] EAP method EAP_MSCHAPV2 selected") is OutputHint.EAP_IN_PROGRESS


def test_ike_sa_init_timeout_is_distinct_from_ike_auth_timeout() -> None:
    hint = classify_ipsec_initiate_logs(_IKE_SA_INIT_TIMEOUT_LOGS)
    assert hint is OutputHint.IKE_SA_INIT_TIMEOUT
    code, message = initiate_failure_report(hint)
    assert code == "IKE_SA_INIT_TIMEOUT"
    assert message == IKE_SA_INIT_TIMEOUT_MESSAGE
    assert "IKE_AUTH" not in message


def test_eap_failure_still_requires_eap_exchange_evidence() -> None:
    hint = classify_ipsec_initiate_logs(_EAP_FAILURE_LOGS)
    assert hint is OutputHint.EAP_FAILURE
    code, message = initiate_failure_report(hint)
    assert code == "IPSEC_EAP_FAILURE"
    assert "IKEv2 authentication failed" in message
    loaded_only = (
        "13[CFG] loaded EAP shared key 'eap' for '0123456789abcdef0123456789abcdef'",
        "13[IKE] initiating IKE_SA fortigate[1] to 203.0.113.10",
        "13[IKE] parsed IKE_SA_INIT response 0 [ SA KE No ]",
        "13[IKE] generating IKE_AUTH request 1 [ IDi AUTH SA TSi TSr ]",
        "13[IKE] retransmit 5 of request with message ID 1",
        "13[IKE] establishing IKE_SA failed, giving up",
    )
    assert classify_ipsec_initiate_logs(loaded_only) is OutputHint.IKE_AUTH_TIMEOUT


def test_proposal_child_and_mode_config_failures_are_not_ike_auth_timeout() -> None:
    assert classify_ipsec_initiate_logs(_PROPOSAL_LOGS) is OutputHint.PROPOSAL_MISMATCH
    assert classify_ipsec_initiate_logs(_CHILD_SA_LOGS) is OutputHint.CHILD_SA_FAILURE
    assert classify_ipsec_initiate_logs(_VIP_LOGS) is OutputHint.VIP_FAILURE
    assert initiate_failure_report(OutputHint.PROPOSAL_MISMATCH)[0] == "IPSEC_PROPOSAL_MISMATCH"
    assert initiate_failure_report(OutputHint.CHILD_SA_FAILURE)[0] == "IPSEC_CHILD_SA_FAILED"
    assert initiate_failure_report(OutputHint.VIP_FAILURE)[0] == "IPSEC_VIP_FAILED"


def test_stock_cfg_attribute_handler_miss_is_not_a_failure() -> None:
    line = "12[CFG] handling INTERNAL_IP4_SUBNET attribute failed"
    assert classify_output(line) is OutputHint.NONE
    assert (
        classify_output("12[CFG] handling INTERNAL_IP4_NETMASK attribute failed")
        is OutputHint.NONE
    )
    assert (
        classify_output("12[CFG] handling INTERNAL_IP6_SUBNET attribute failed")
        is OutputHint.NONE
    )
    assert (
        classify_output("12[CFG] handling APPLICATION_VERSION attribute failed")
        is OutputHint.NONE
    )
    assert (
        classify_output("13[IKE] establishing CHILD_SA failed") is OutputHint.CHILD_SA_FAILURE
    )
    assert classify_output("plugin 'openssl' failed to load: not found") is not OutputHint.NONE
