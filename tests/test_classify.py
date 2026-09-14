# SPDX-License-Identifier: GPL-3.0-or-later
"""openfortivpn output classification tests. No real VPN."""

from __future__ import annotations

from fortigate_vpn_gui.vpn.classify import OutputHint, classify_output


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
