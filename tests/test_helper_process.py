# SPDX-License-Identifier: GPL-3.0-or-later
"""Helper process ownership tests. No real VPN process is started."""

from __future__ import annotations

import pytest

from fortigate_vpn_gui.helper.protocol import ConnectRequest, HelperError, HelperProtocolError
from fortigate_vpn_gui.helper.service import HelperService
from tests.vpn_fakes import FakeVpnProcess, VpnHarness


def test_connect_disconnect_and_no_orphan() -> None:
    harness = VpnHarness()
    from fortigate_vpn_gui.profiles.model import build_profile

    harness.backend.connect(build_profile(name="Office", gateway="vpn.example.com", use_sso=False))
    assert harness.process is not None
    assert harness.process.started
    assert harness.process.pid == 4242
    harness.backend.disconnect(wait=True)
    assert harness.process.terminate_called
    assert harness.helper.is_running() is False
    assert harness.process.poll() == 0


def test_kill_fallback_and_no_orphan() -> None:
    harness = VpnHarness()
    from fortigate_vpn_gui.profiles.model import build_profile

    harness.backend.connect(build_profile(name="Office", gateway="vpn.example.com", use_sso=False))
    assert harness.process is not None
    harness.process.exit_on_terminate = False
    harness.backend.disconnect(wait=True, grace_seconds=0.01)
    assert harness.process.terminate_called
    assert harness.process.kill_called
    assert harness.process.poll() == -9


def test_helper_rejects_duplicate_connection() -> None:
    created: list[FakeVpnProcess] = []

    def factory(argv, on_output, on_exit):
        proc = FakeVpnProcess(argv, on_output, on_exit)
        created.append(proc)
        return proc

    service = HelperService(process_factory=factory, selector=lambda _saml: _caps())
    request = ConnectRequest(gateway="vpn.example.com", port=443, auth_mode="standard")
    service.connect(request)
    with pytest.raises(HelperProtocolError, match="ALREADY_CONNECTED"):
        service.connect(request)
    assert len(created) == 1
    service.disconnect(wait=True)


def test_helper_error_on_missing_binary() -> None:
    service = HelperService(
        process_factory=lambda *args: pytest.fail("must not start"),
        selector=lambda _saml: None,
    )
    with pytest.raises(HelperError, match="OPENFORTIVPN_MISSING"):
        service.connect(ConnectRequest(gateway="vpn.example.com", port=443, auth_mode="standard"))


def _caps():
    from fortigate_vpn_gui.vpn.capabilities import OpenfortivpnCapabilities

    return OpenfortivpnCapabilities(
        executable_path="/usr/local/bin/openfortivpn",
        version="1.24.1",
        supports_saml=True,
        supports_cookie_stdin=True,
        source="test",
    )
