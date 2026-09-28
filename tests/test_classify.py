# SPDX-License-Identifier: GPL-3.0-or-later
"""openfortivpn output classification tests. No real VPN."""

from __future__ import annotations

from fortigate_vpn_gui.vpn.classify import OutputHint, classify_output, user_message_for_hint


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
