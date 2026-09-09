# SPDX-License-Identifier: GPL-3.0-or-later
"""SAML parser tests. No process execution."""

from __future__ import annotations

from fortigate_vpn_gui.vpn.saml_parse import SamlEventKind, parse_saml_output


def test_detects_listener_readiness() -> None:
    result = parse_saml_output("INFO:   Listening for SAML login on port 8020")
    assert result.kind is SamlEventKind.LISTENER_READY
    assert result.url is None


def test_detects_auth_url_case_insensitive() -> None:
    line = "INFO:   Authenticate at 'https://vpn.example.com:443/remote/saml/start?redirect=1'"
    result = parse_saml_output(line)
    assert result.kind is SamlEventKind.AUTH_URL
    assert result.url == "https://vpn.example.com:443/remote/saml/start?redirect=1"
    lower = parse_saml_output("authenticate AT https://vpn.example.com/remote/saml/start")
    assert lower.kind is SamlEventKind.AUTH_URL


def test_detects_success_and_failure() -> None:
    assert parse_saml_output("DEBUG:  Incoming HTTP connection").kind is SamlEventKind.SUCCESS
    assert parse_saml_output(
        "ERROR:  Finally failed to retrieve SAML authentication token"
    ).kind is (SamlEventKind.FAILURE)


def test_ignores_unrelated_output() -> None:
    assert parse_saml_output("INFO:   Connected to gateway.").kind is SamlEventKind.NONE
    assert parse_saml_output("DEBUG:  Loaded configuration file").kind is SamlEventKind.NONE
