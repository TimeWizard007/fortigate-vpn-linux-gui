# SPDX-License-Identifier: GPL-3.0-or-later
"""Classify VPN backend output without exposing raw secrets to the GUI.

Hints are only returned when the line proves a cause. Unknown failures stay
generic so the Connection page does not invent a diagnosis.
"""

from __future__ import annotations

from enum import Enum


class OutputHint(Enum):
    NONE = "none"
    GATEWAY_CONNECTED = "gateway_connected"
    CONNECTED = "connected"
    PERMISSION = "permission"
    AUTH_FAILURE = "auth_failure"
    CERTIFICATE = "certificate"
    PPP_FAILURE = "ppp_failure"
    ROUTE_FAILURE = "route_failure"
    DNS_FAILURE = "dns_failure"
    DNS_RESOLUTION = "dns_resolution"
    GATEWAY_UNREACHABLE = "gateway_unreachable"
    SAML_REJECTED = "saml_rejected"
    IKE_TIMEOUT = "ike_timeout"
    PSK_FAILURE = "psk_failure"
    XAUTH_FAILURE = "xauth_failure"
    EAP_FAILURE = "eap_failure"
    PROPOSAL_MISMATCH = "proposal_mismatch"
    CHILD_SA_FAILURE = "child_sa_failure"
    VIP_FAILURE = "vip_failure"
    CHARON_FAILURE = "charon_failure"
    SWANCTL_FAILURE = "swanctl_failure"
    IPSEC_NEGOTIATION = "ipsec_negotiation"
    IKE_ESTABLISHED = "ike_established"
    IKE_PORT_CONFLICT = "ike_port_conflict"


IKE_PORT_CONFLICT_MESSAGE = (
    "IPsec cannot start because another IKE service is using UDP ports 500/4500. "
    "See Diagnostics for details."
)


_TUNNEL_READY = "tunnel is up and running"
_GATEWAY_CONNECTED = "connected to gateway"

_PERMISSION = (
    "permission denied",
    "operation not permitted",
    "must be root",
    "need to be root",
    "only root can",
    "you need to be root",
    "not permitted",
    "authorization for privileged vpn access was denied",
)

_AUTH = (
    "authentication failed",
    "authenticate failed",
    "login failed",
    "auth failed",
    "401 unauthorized",
    "403 forbidden",
    "incorrect password",
    "wrong password",
)

_SAML_REJECTED = (
    "saml authentication failed",
    "saml login failed",
    "saml failed",
    "sso authentication failed",
)

_CERTIFICATE = ("gateway certificate validation failed",)

_DNS_RESOLUTION = (
    "name or service not known",
    "could not resolve",
    "temporary failure in name resolution",
    "nodename nor servname provided",
    "no address associated with hostname",
)

_GATEWAY_UNREACHABLE = (
    "no route to host",
    "network is unreachable",
    "connection refused",
    "connection timed out",
    "connect: timeout",
    "host is unreachable",
)

_PSK = (
    "invalid hash_v1",
    "invalid ikev1 hash",
    "calculated hash",
    "psk authentication failed",
    "pre-shared key authentication failed",
)

_XAUTH = (
    "xauth authentication failed",
    "xauth failed",
    "extended authentication failed",
)

_EAP = (
    "eap authentication failed",
    "eap failed",
    "eap method failed",
)

_PROPOSAL = (
    "no_proposal_chosen",
    "no matching proposal",
    "no proposal chosen",
    "proposal mismatch",
    "no acceptable proposal",
)

_IKE_TIMEOUT = (
    "establishing ike_sa failed, giving up",
    "ike_sa ... giving up",
    "timeout while establishing ike",
    "retransmit 5",
    "giving up after 5 retransmits",
)

_CHILD = (
    "establishing child_sa failed",
    "child_sa ... failed",
    "could not install child",
    "unable to install child",
)

_VIP = (
    "installing virtual ip failed",
    "no virtual ip found",
    "failed to install virtual ip",
    "mode config failed",
    "modecfg failed",
)

_CHARON = (
    "abort initialization due to invalid configuration",
    "charon has died",
    "unable to start charon",
    "charon failed",
)

_IKE_PORT = (
    "unable to bind socket: address already in use",
    "could not create any sockets",
    "charon already running",
)

_SWANCTL = (
    "failed to load",
    "swanctl loaded 0",
    "no connections found",
    "unable to load",
)

_IPSEC_GENERIC = (
    "ike_sa",
    "child_sa",
    "swanctl",
    "charon",
    "ipsec",
)

_FAILURE_MARKERS = ("error", "failed", "failure", "fatal")


def classify_output(line: str) -> OutputHint:
    """Return a coarse hint derived from a redacted log line."""
    lowered = line.lower()
    if any(marker in lowered for marker in _CERTIFICATE):
        return OutputHint.CERTIFICATE
    if any(marker in lowered for marker in _SAML_REJECTED):
        return OutputHint.SAML_REJECTED
    if any(marker in lowered for marker in _PERMISSION):
        return OutputHint.PERMISSION
    if any(marker in lowered for marker in _PSK) and _looks_like_failure(lowered):
        return OutputHint.PSK_FAILURE
    if any(marker in lowered for marker in _XAUTH) and _looks_like_failure(lowered):
        return OutputHint.XAUTH_FAILURE
    if any(marker in lowered for marker in _EAP) and _looks_like_failure(lowered):
        return OutputHint.EAP_FAILURE
    if any(marker in lowered for marker in _PROPOSAL):
        return OutputHint.PROPOSAL_MISMATCH
    if any(marker in lowered for marker in _CHILD) and _looks_like_failure(lowered):
        return OutputHint.CHILD_SA_FAILURE
    if any(marker in lowered for marker in _VIP) and _looks_like_failure(lowered):
        return OutputHint.VIP_FAILURE
    if any(marker in lowered for marker in _IKE_TIMEOUT):
        return OutputHint.IKE_TIMEOUT
    if any(marker in lowered for marker in _IKE_PORT):
        return OutputHint.IKE_PORT_CONFLICT
    if any(marker in lowered for marker in _CHARON):
        return OutputHint.CHARON_FAILURE
    if any(marker in lowered for marker in _SWANCTL) and _looks_like_failure(lowered):
        return OutputHint.SWANCTL_FAILURE
    if any(marker in lowered for marker in _DNS_RESOLUTION):
        return OutputHint.DNS_RESOLUTION
    if any(marker in lowered for marker in _GATEWAY_UNREACHABLE):
        return OutputHint.GATEWAY_UNREACHABLE
    if any(marker in lowered for marker in _AUTH):
        return OutputHint.AUTH_FAILURE
    if _looks_like_failure(lowered):
        if "ppp" in lowered:
            return OutputHint.PPP_FAILURE
        if "route" in lowered:
            return OutputHint.ROUTE_FAILURE
        if "network1.service" in lowered or "dbus-org.freedesktop.network1" in lowered:
            return OutputHint.NONE
        if "dns" in lowered or "nameserver" in lowered:
            return OutputHint.DNS_FAILURE
        if any(marker in lowered for marker in _IPSEC_GENERIC):
            return OutputHint.IPSEC_NEGOTIATION
    if _TUNNEL_READY in lowered:
        return OutputHint.CONNECTED
    if "child_sa" in lowered and "established" in lowered:
        return OutputHint.CONNECTED
    if "ipsec child sa established" in lowered:
        return OutputHint.CONNECTED
    if "ike_sa" in lowered and "established" in lowered:
        return OutputHint.IKE_ESTABLISHED
    if _GATEWAY_CONNECTED in lowered:
        return OutputHint.GATEWAY_CONNECTED
    return OutputHint.NONE


def user_message_for_hint(hint: OutputHint) -> str | None:
    """Return a conservative Connection-page sentence, or None if unknown."""
    return {
        OutputHint.GATEWAY_UNREACHABLE: "The VPN gateway could not be reached.",
        OutputHint.DNS_RESOLUTION: "The gateway hostname could not be resolved.",
        OutputHint.CERTIFICATE: (
            "The FortiGate gateway certificate could not be validated. "
            "See Diagnostics for details."
        ),
        OutputHint.SAML_REJECTED: "SAML authentication was rejected.",
        OutputHint.AUTH_FAILURE: "Authentication failed.",
        OutputHint.PERMISSION: "Privileged helper authorization was rejected.",
        OutputHint.PPP_FAILURE: (
            "The VPN tunnel could not configure PPP. See Diagnostics for details."
        ),
        OutputHint.ROUTE_FAILURE: (
            "The VPN tunnel could not update routes. See Diagnostics for details."
        ),
        OutputHint.DNS_FAILURE: "VPN DNS could not be applied. See Diagnostics for details.",
        OutputHint.IKE_TIMEOUT: "IKE negotiation timed out. See Diagnostics for details.",
        OutputHint.PSK_FAILURE: (
            "IPsec authentication failed (pre-shared key). See Diagnostics for details."
        ),
        OutputHint.XAUTH_FAILURE: "XAuth authentication failed. See Diagnostics for details.",
        OutputHint.EAP_FAILURE: "EAP authentication failed. See Diagnostics for details.",
        OutputHint.PROPOSAL_MISMATCH: "IPsec proposal mismatch. See Diagnostics for details.",
        OutputHint.CHILD_SA_FAILURE: "IPsec CHILD_SA failed. See Diagnostics for details.",
        OutputHint.VIP_FAILURE: (
            "Mode Config / virtual IP assignment failed. See Diagnostics for details."
        ),
        OutputHint.CHARON_FAILURE: "The IPsec daemon failed. See Diagnostics for details.",
        OutputHint.IKE_PORT_CONFLICT: IKE_PORT_CONFLICT_MESSAGE,
        OutputHint.SWANCTL_FAILURE: "swanctl failed. See Diagnostics for details.",
        OutputHint.IPSEC_NEGOTIATION: "IPsec negotiation failed. See Diagnostics for details.",
    }.get(hint)


def _looks_like_failure(lowered: str) -> bool:
    return any(marker in lowered for marker in _FAILURE_MARKERS)
