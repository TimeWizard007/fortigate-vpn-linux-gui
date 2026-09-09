# SPDX-License-Identifier: GPL-3.0-or-later
"""polkit helper client tests. No real pkexec, sudo, or VPN."""

from __future__ import annotations

import io

import pytest

from fortigate_vpn_gui.helper.protocol import HELPER_VERSION, ConnectRequest, HelperError
from fortigate_vpn_gui.system.helper_client import InProcessHelperClient, PolkitHelperClient
from tests.vpn_fakes import VpnHarness


def _request() -> ConnectRequest:
    return ConnectRequest(gateway="vpn.example.com", port=443, auth_mode="saml")


def test_inprocess_authorized_probe() -> None:
    harness = VpnHarness()
    probe = harness.helper.probe()
    assert probe.installed is True
    assert probe.polkit_available is True
    assert probe.authorization_mechanism == "polkit"
    assert probe.status == "ready"
    assert probe.helper_version == HELPER_VERSION


def test_privilege_denied() -> None:
    harness = VpnHarness(privilege_denied=True)
    with pytest.raises(HelperError, match="PRIVILEGE_DENIED"):
        harness.helper.connect(_request(), lambda event: None)


def test_backend_privilege_denied_message() -> None:
    from fortigate_vpn_gui.profiles.model import build_profile
    from fortigate_vpn_gui.vpn.models import VpnErrorCode

    harness = VpnHarness(privilege_denied=True)
    codes: list[VpnErrorCode] = []
    harness.backend.subscribe(
        lambda event: codes.append(event.error_code) if event.error_code else None
    )
    harness.backend.connect(build_profile(name="Office", gateway="vpn.example.com", use_sso=True))
    assert VpnErrorCode.PRIVILEGE_DENIED in codes
    assert harness.process is None
    assert "denied" in (harness.backend.snapshot().error_message or "").lower()


def test_helper_missing() -> None:
    harness = VpnHarness(helper_installed=False)
    from fortigate_vpn_gui.profiles.model import build_profile
    from fortigate_vpn_gui.vpn.models import VpnErrorCode

    codes: list[VpnErrorCode] = []
    harness.backend.subscribe(
        lambda event: codes.append(event.error_code) if event.error_code else None
    )
    harness.backend.connect(build_profile(name="Office", gateway="vpn.example.com", use_sso=True))
    assert VpnErrorCode.HELPER_NOT_AVAILABLE in codes
    assert harness.process is None


def test_polkit_unavailable() -> None:
    harness = VpnHarness(polkit_available=False)
    from fortigate_vpn_gui.profiles.model import build_profile
    from fortigate_vpn_gui.vpn.models import VpnErrorCode

    codes: list[VpnErrorCode] = []
    harness.backend.subscribe(
        lambda event: codes.append(event.error_code) if event.error_code else None
    )
    harness.backend.connect(build_profile(name="Office", gateway="vpn.example.com"))
    assert VpnErrorCode.POLKIT_UNAVAILABLE in codes


def test_helper_version_mismatch() -> None:
    harness = VpnHarness(helper_version="0.4.0", version_mismatch=True)
    from fortigate_vpn_gui.profiles.model import build_profile
    from fortigate_vpn_gui.vpn.models import VpnErrorCode

    codes: list[VpnErrorCode] = []
    harness.backend.subscribe(
        lambda event: codes.append(event.error_code) if event.error_code else None
    )
    harness.backend.connect(build_profile(name="Office", gateway="vpn.example.com"))
    assert VpnErrorCode.HELPER_VERSION_MISMATCH in codes


class _DeadProc:
    def __init__(self, code: int, stderr: str) -> None:
        self.returncode = code
        self.stdin = io.StringIO()
        self.stdout = io.StringIO("")
        self.stderr = io.StringIO(stderr)

    def poll(self) -> int:
        return self.returncode

    def wait(self, timeout=None) -> int:
        return self.returncode

    def kill(self) -> None:
        return None

    def terminate(self) -> None:
        return None


def _completed(stdout: str = "", stderr: str = "", returncode: int = 0):
    return type("R", (), {"stdout": stdout, "stderr": stderr, "returncode": returncode})()


def test_polkit_client_helper_missing() -> None:
    client = PolkitHelperClient(
        helper_path="/usr/libexec/fortigate-vpn-linux-gui/vpn-helper",
        which=lambda name: "/usr/bin/pkexec" if name == "pkexec" else None,
        path_exists=lambda path: False,
        version_runner=lambda argv: pytest.fail("must not run helper"),
    )
    probe = client.probe()
    assert probe.installed is False
    assert probe.status == "missing"
    with pytest.raises(HelperError, match="HELPER_NOT_AVAILABLE"):
        client.connect(_request(), lambda event: None)


def test_polkit_client_pkexec_missing() -> None:
    client = PolkitHelperClient(
        helper_path="/usr/libexec/fortigate-vpn-linux-gui/vpn-helper",
        which=lambda name: None,
        path_exists=lambda path: True,
        version_runner=lambda argv: _completed(HELPER_VERSION),
    )
    probe = client.probe()
    assert probe.polkit_available is False
    assert probe.status == "polkit_unavailable"
    assert probe.helper_version == HELPER_VERSION


def test_polkit_client_denied_spawn() -> None:
    client = PolkitHelperClient(
        helper_path="/usr/libexec/fortigate-vpn-linux-gui/vpn-helper",
        which=lambda name: "/usr/bin/pkexec",
        path_exists=lambda path: True,
        popen=lambda *args, **kwargs: _DeadProc(127, "not authorized\n"),
        version_runner=lambda argv: _completed(HELPER_VERSION),
    )
    with pytest.raises(HelperError, match="PRIVILEGE_DENIED"):
        client.connect(_request(), lambda event: None)


def test_polkit_client_version_mismatch() -> None:
    client = PolkitHelperClient(
        helper_path="/usr/libexec/fortigate-vpn-linux-gui/vpn-helper",
        which=lambda name: "/usr/bin/pkexec",
        path_exists=lambda path: True,
        version_runner=lambda argv: _completed("0.4.0\n"),
    )
    probe = client.probe()
    assert probe.version_mismatch is True
    assert probe.status == "version_mismatch"
    assert probe.helper_version == "0.4.0"
    with pytest.raises(HelperError, match="HELPER_VERSION_MISMATCH"):
        client.connect(_request(), lambda event: None)


def test_polkit_client_crash_is_startup_failed_not_version() -> None:
    traceback = (
        "Traceback (most recent call last):\n"
        "ImportError: cannot import name 'HelperService'\n"
    )
    client = PolkitHelperClient(
        helper_path="/usr/libexec/fortigate-vpn-linux-gui/vpn-helper",
        which=lambda name: "/usr/bin/pkexec",
        path_exists=lambda path: True,
        version_runner=lambda argv: _completed(stdout="", stderr=traceback, returncode=1),
    )
    probe = client.probe()
    assert probe.status == "startup_failed"
    assert probe.helper_version is None
    assert probe.version_mismatch is False
    assert "Traceback" not in (probe.helper_version or "")
    assert probe.startup_detail is not None
    with pytest.raises(HelperError, match="HELPER_STARTUP_FAILED"):
        client.connect(_request(), lambda event: None)


def test_polkit_client_malformed_output_is_startup_failed() -> None:
    client = PolkitHelperClient(
        helper_path="/usr/libexec/fortigate-vpn-linux-gui/vpn-helper",
        which=lambda name: "/usr/bin/pkexec",
        path_exists=lambda path: True,
        version_runner=lambda argv: _completed("not-a-version\n"),
    )
    probe = client.probe()
    assert probe.status == "startup_failed"
    assert probe.helper_version is None


def test_polkit_client_no_response_is_startup_failed() -> None:
    client = PolkitHelperClient(
        helper_path="/usr/libexec/fortigate-vpn-linux-gui/vpn-helper",
        which=lambda name: "/usr/bin/pkexec",
        path_exists=lambda path: True,
        version_runner=lambda argv: _completed("", "", 0),
    )
    probe = client.probe()
    assert probe.status == "startup_failed"
    assert probe.helper_version is None


def test_polkit_client_valid_hello_json() -> None:
    from fortigate_vpn_gui.helper.handshake import encode_hello_line

    client = PolkitHelperClient(
        helper_path="/usr/libexec/fortigate-vpn-linux-gui/vpn-helper",
        which=lambda name: "/usr/bin/pkexec",
        path_exists=lambda path: True,
        version_runner=lambda argv: _completed(encode_hello_line() + "\n"),
    )
    probe = client.probe()
    assert probe.status == "ready"
    assert probe.helper_version == HELPER_VERSION


def test_polkit_client_does_not_use_stderr_as_version() -> None:
    client = PolkitHelperClient(
        helper_path="/usr/libexec/fortigate-vpn-linux-gui/vpn-helper",
        which=lambda name: "/usr/bin/pkexec",
        path_exists=lambda path: True,
        version_runner=lambda argv: _completed(stdout="", stderr="0.9.9\n", returncode=0),
    )
    probe = client.probe()
    assert probe.helper_version is None
    assert probe.status == "startup_failed"


def test_inprocess_client_is_not_pkexec() -> None:
    client = InProcessHelperClient()
    assert client.probe().authorization_mechanism == "polkit"
    assert "pkexec" not in str(client.probe())
