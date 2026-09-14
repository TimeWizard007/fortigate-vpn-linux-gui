# SPDX-License-Identifier: GPL-3.0-or-later
"""Classify openfortivpn output without exposing raw secrets to the GUI."""

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

_CERTIFICATE = ("gateway certificate validation failed",)

_FAILURE_MARKERS = ("error", "failed", "failure", "fatal")


def classify_output(line: str) -> OutputHint:
    """Return a coarse hint derived from a redacted log line."""
    lowered = line.lower()
    if any(marker in lowered for marker in _CERTIFICATE):
        return OutputHint.CERTIFICATE
    if any(marker in lowered for marker in _PERMISSION):
        return OutputHint.PERMISSION
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
    if _TUNNEL_READY in lowered:
        return OutputHint.CONNECTED
    if "child_sa" in lowered and "established" in lowered:
        return OutputHint.CONNECTED
    if "ipsec child sa established" in lowered:
        return OutputHint.CONNECTED
    if _GATEWAY_CONNECTED in lowered:
        return OutputHint.GATEWAY_CONNECTED
    return OutputHint.NONE


def _looks_like_failure(lowered: str) -> bool:
    return any(marker in lowered for marker in _FAILURE_MARKERS)
