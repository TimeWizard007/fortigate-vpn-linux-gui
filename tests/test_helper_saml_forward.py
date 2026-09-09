# SPDX-License-Identifier: GPL-3.0-or-later
"""SAML URL handoff from helper to unprivileged GUI browser."""

from __future__ import annotations

from fortigate_vpn_gui.profiles.model import build_profile
from tests.vpn_fakes import VpnHarness

_AUTH_URL = "https://vpn.example.com:443/remote/saml/start?redirect=1&id=secret-session"


def test_helper_saml_event_opens_unprivileged_browser_once() -> None:
    harness = VpnHarness()
    harness.backend.connect(build_profile(name="Office", gateway="vpn.example.com", use_sso=True))
    assert harness.process is not None
    harness.process.emit(f"INFO:   Authenticate at '{_AUTH_URL}'")
    assert harness.browser.opened == [_AUTH_URL]
    harness.process.emit(f"INFO:   Authenticate at '{_AUTH_URL}'")
    assert harness.browser.opened == [_AUTH_URL]
    assert harness.backend.snapshot().safe_auth_url is not None
    assert "secret-session" not in (harness.backend.snapshot().safe_auth_url or "")
    joined = " ".join(record.message for record in harness.log.records())
    assert "secret-session" not in joined
