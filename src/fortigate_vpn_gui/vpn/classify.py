# SPDX-License-Identifier: GPL-3.0-or-later
"""Classify VPN backend output without exposing raw secrets to the GUI.

Hints are only returned when the line proves a cause. Unknown failures stay
generic so the Connection page does not invent a diagnosis.
"""

from __future__ import annotations

from collections.abc import Sequence
from enum import Enum

from fortigate_vpn_gui.vpn.ipsec.charon_noise import is_benign_charon_noise


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
    IKE_SA_INIT_TIMEOUT = "ike_sa_init_timeout"
    IKE_AUTH_TIMEOUT = "ike_auth_timeout"
    PSK_FAILURE = "psk_failure"
    XAUTH_FAILURE = "xauth_failure"
    EAP_FAILURE = "eap_failure"
    EAP_IN_PROGRESS = "eap_in_progress"
    PROPOSAL_MISMATCH = "proposal_mismatch"
    CHILD_SA_FAILURE = "child_sa_failure"
    VIP_FAILURE = "vip_failure"
    CHARON_FAILURE = "charon_failure"
    SWANCTL_FAILURE = "swanctl_failure"
    IPSEC_NEGOTIATION = "ipsec_negotiation"
    IKE_ESTABLISHED = "ike_established"
    IKE_SA_INIT = "ike_sa_init"
    IKE_PORT_CONFLICT = "ike_port_conflict"


IKE_PORT_CONFLICT_MESSAGE = (
    "IPsec cannot start because another IKE service is using UDP ports 500/4500. "
    "See Diagnostics for details."
)
IKE_AUTH_TIMEOUT_MESSAGE = (
    "IKE_AUTH timed out: FortiGate did not respond to the first IKE_AUTH request."
)
IKE_SA_INIT_TIMEOUT_MESSAGE = "IKE_SA_INIT timed out: FortiGate did not respond to IKE_SA_INIT."
IKE_TIMEOUT_MESSAGE = "IKE negotiation timed out. See Diagnostics for details."
IPSEC_INITIATE_FAILED_MESSAGE = "IPsec initiation failed. See Logs for non-secret details."


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
    "received eap_failure",
    "eap_mschapv2 failed",
    "eap-mschapv2 failed",
    "mschapv2 authentication failed",
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
    if is_benign_charon_noise(line):
        return OutputHint.NONE
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
    if "initiating ike_sa" in lowered and not _looks_like_failure(lowered):
        return OutputHint.IKE_SA_INIT
    if (
        "eap method" in lowered or "selected eap" in lowered or "sending eap" in lowered
    ) and not _looks_like_failure(lowered):
        return OutputHint.EAP_IN_PROGRESS
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
            "The FortiGate gateway certificate could not be validated. See Diagnostics for details."
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
        OutputHint.IKE_TIMEOUT: IKE_TIMEOUT_MESSAGE,
        OutputHint.IKE_SA_INIT_TIMEOUT: IKE_SA_INIT_TIMEOUT_MESSAGE,
        OutputHint.IKE_AUTH_TIMEOUT: IKE_AUTH_TIMEOUT_MESSAGE,
        OutputHint.PSK_FAILURE: (
            "IPsec authentication failed (pre-shared key). See Diagnostics for details."
        ),
        OutputHint.XAUTH_FAILURE: "XAuth authentication failed. See Diagnostics for details.",
        OutputHint.EAP_FAILURE: "IKEv2 authentication failed. See Diagnostics for details.",
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


def classify_ipsec_initiate_logs(lines: Sequence[str]) -> OutputHint:
    """Classify a failed ``swanctl --initiate`` from collected redacted logs.

    Timeout is split only when the exchange stage is proven. EAP failure
    requires EAP *exchange* evidence, not an EAP secret being loaded.
    """
    hints = [classify_output(line) for line in lines]
    for wanted in (
        OutputHint.CHARON_FAILURE,
        OutputHint.IKE_PORT_CONFLICT,
        OutputHint.SWANCTL_FAILURE,
        OutputHint.PROPOSAL_MISMATCH,
        OutputHint.EAP_FAILURE,
        OutputHint.PSK_FAILURE,
        OutputHint.XAUTH_FAILURE,
        OutputHint.CHILD_SA_FAILURE,
        OutputHint.VIP_FAILURE,
    ):
        if wanted in hints:
            return wanted

    joined = "\n".join(lines).lower()
    sa_init_sent = "generating ike_sa_init request" in joined or "initiating ike_sa" in joined
    sa_init_response = "parsed ike_sa_init response" in joined
    ike_auth_sent = "generating ike_auth request" in joined
    ike_auth_response = (
        "parsed ike_auth response" in joined or "received ike_auth response" in joined
    )
    eap_started = OutputHint.EAP_IN_PROGRESS in hints

    if sa_init_response and ike_auth_sent and not ike_auth_response and not eap_started:
        return OutputHint.IKE_AUTH_TIMEOUT
    if sa_init_sent and not sa_init_response:
        return OutputHint.IKE_SA_INIT_TIMEOUT
    if OutputHint.IKE_TIMEOUT in hints:
        if ike_auth_sent and not ike_auth_response and not eap_started:
            return OutputHint.IKE_AUTH_TIMEOUT
        if not sa_init_response:
            return OutputHint.IKE_SA_INIT_TIMEOUT
        return OutputHint.IKE_TIMEOUT
    if OutputHint.IPSEC_NEGOTIATION in hints:
        return OutputHint.IPSEC_NEGOTIATION
    return OutputHint.NONE


def initiate_failure_report(hint: OutputHint) -> tuple[str, str]:
    """Return ``(helper error code, user message)`` for a failed IKE initiate."""
    mapping = {
        OutputHint.IKE_AUTH_TIMEOUT: ("IKE_AUTH_TIMEOUT", IKE_AUTH_TIMEOUT_MESSAGE),
        OutputHint.IKE_SA_INIT_TIMEOUT: ("IKE_SA_INIT_TIMEOUT", IKE_SA_INIT_TIMEOUT_MESSAGE),
        OutputHint.IKE_TIMEOUT: ("IKE_NEGOTIATION_TIMEOUT", IKE_TIMEOUT_MESSAGE),
        OutputHint.EAP_FAILURE: (
            "IPSEC_EAP_FAILURE",
            user_message_for_hint(OutputHint.EAP_FAILURE) or IPSEC_INITIATE_FAILED_MESSAGE,
        ),
        OutputHint.PROPOSAL_MISMATCH: (
            "IPSEC_PROPOSAL_MISMATCH",
            user_message_for_hint(OutputHint.PROPOSAL_MISMATCH) or IPSEC_INITIATE_FAILED_MESSAGE,
        ),
        OutputHint.CHILD_SA_FAILURE: (
            "IPSEC_CHILD_SA_FAILED",
            user_message_for_hint(OutputHint.CHILD_SA_FAILURE) or IPSEC_INITIATE_FAILED_MESSAGE,
        ),
        OutputHint.VIP_FAILURE: (
            "IPSEC_VIP_FAILED",
            user_message_for_hint(OutputHint.VIP_FAILURE) or IPSEC_INITIATE_FAILED_MESSAGE,
        ),
        OutputHint.PSK_FAILURE: (
            "IPSEC_PSK_FAILURE",
            user_message_for_hint(OutputHint.PSK_FAILURE) or IPSEC_INITIATE_FAILED_MESSAGE,
        ),
        OutputHint.XAUTH_FAILURE: (
            "IPSEC_XAUTH_FAILURE",
            user_message_for_hint(OutputHint.XAUTH_FAILURE) or IPSEC_INITIATE_FAILED_MESSAGE,
        ),
        OutputHint.SWANCTL_FAILURE: (
            "IPSEC_SWANCTL_FAILED",
            user_message_for_hint(OutputHint.SWANCTL_FAILURE) or IPSEC_INITIATE_FAILED_MESSAGE,
        ),
        OutputHint.CHARON_FAILURE: (
            "IPSEC_DAEMON_START_FAILED",
            user_message_for_hint(OutputHint.CHARON_FAILURE) or IPSEC_INITIATE_FAILED_MESSAGE,
        ),
        OutputHint.IKE_PORT_CONFLICT: ("IKE_PORT_IN_USE", IKE_PORT_CONFLICT_MESSAGE),
        OutputHint.IPSEC_NEGOTIATION: (
            "IPSEC_NEGOTIATION_FAILED",
            user_message_for_hint(OutputHint.IPSEC_NEGOTIATION) or IPSEC_INITIATE_FAILED_MESSAGE,
        ),
    }
    return mapping.get(hint, ("VPN_PROCESS_FAILED", IPSEC_INITIATE_FAILED_MESSAGE))


def _looks_like_failure(lowered: str) -> bool:
    return any(marker in lowered for marker in _FAILURE_MARKERS)
