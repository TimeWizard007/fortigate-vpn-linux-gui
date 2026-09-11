# SPDX-License-Identifier: GPL-3.0-or-later
"""Diagnostic check unit tests. Network and binaries are injected."""

from __future__ import annotations

from dataclasses import replace

from fortigate_vpn_gui.diagnostics.checks import (
    CommandResult,
    check_certificate_pin,
    check_helper,
    check_openfortivpn,
    check_platform,
    check_polkit_authorization,
    check_polkit_policy,
    check_profile_context,
)
from fortigate_vpn_gui.diagnostics.model import CheckStatus
from fortigate_vpn_gui.helper.handshake import encode_hello_line
from fortigate_vpn_gui.helper.protocol import HELPER_VERSION, POLKIT_ACTION_ID
from fortigate_vpn_gui.profiles.model import build_profile
from fortigate_vpn_gui.vpn.detect import OpenfortivpnDetection
from fortigate_vpn_gui.vpn.models import ConnectionState
from tests.vpn_fakes import VpnHarness

_FINGERPRINT = "ab" * 32


def _snapshot(state: ConnectionState = ConnectionState.DISCONNECTED, **kwargs):
    return replace(VpnHarness().backend.snapshot(), state=state, **kwargs)


def test_platform_check_is_info() -> None:
    check = check_platform(
        snapshot=_snapshot(),
        app_version="0.9.0",
        helper_protocol="0.7.0",
        os_name="Ubuntu 24.04.3 LTS",
        kernel="6.8.0",
        arch="x86_64",
        session_type="Wayland",
    )
    assert check.status is CheckStatus.INFO
    assert "0.9.0" in check.detail
    assert "0.7.0" in check.detail
    assert "Wayland" in check.summary


def test_openfortivpn_found_and_saml_supported() -> None:
    def run_command(argv, timeout=3.0):
        assert argv[0] == "/usr/bin/openfortivpn"
        assert timeout > 0
        if argv[1] == "--version":
            return CommandResult(returncode=0, stdout="openfortivpn 1.24.1\n")
        if argv[1] == "--help":
            return CommandResult(returncode=0, stdout="Usage: openfortivpn [--saml-login]\n")
        raise AssertionError(argv)

    check = check_openfortivpn(
        which=lambda name: None,
        is_executable=lambda path: path == "/usr/bin/openfortivpn",
        extra_paths=("/usr/bin/openfortivpn",),
        run_command=run_command,
        probe_version=True,
    )
    assert check.status is CheckStatus.PASS
    assert check.summary == "openfortivpn 1.24.1 — SAML supported"
    assert check.detail == "Effective VPN binary: /usr/bin/openfortivpn"


def test_openfortivpn_missing() -> None:
    check = check_openfortivpn(
        which=lambda name: None,
        is_executable=lambda path: False,
        extra_paths=(),
        run_command=lambda *a, **k: CommandResult(missing=True),
        probe_version=True,
    )
    assert check.status is CheckStatus.FAIL
    assert "not found" in check.summary.lower()
    assert "Reinstall FortiGate VPN Linux GUI" in check.hint


def test_openfortivpn_timeout() -> None:
    check = check_openfortivpn(
        which=lambda name: None,
        is_executable=lambda path: path == "/usr/bin/openfortivpn",
        extra_paths=("/usr/bin/openfortivpn",),
        run_command=lambda *a, **k: CommandResult(timed_out=True),
        probe_version=True,
    )
    assert check.status is CheckStatus.WARNING
    assert "timed out" in check.summary.lower()


def test_stock_openfortivpn_without_saml_is_not_pass() -> None:
    def run_command(argv, timeout=3.0):
        if argv[1] == "--version":
            return CommandResult(returncode=0, stdout="openfortivpn 1.21.0\n")
        return CommandResult(returncode=0, stdout="Usage: openfortivpn [--cookie-on-stdin]\n")

    warning = check_openfortivpn(
        is_executable=lambda path: path == "/usr/bin/openfortivpn",
        extra_paths=("/usr/bin/openfortivpn",),
        run_command=run_command,
        profile=build_profile(name="Office", gateway="vpn.example.com", use_sso=False),
    )
    assert warning.status is CheckStatus.WARNING
    assert warning.summary == "openfortivpn 1.21.0 — SAML support unavailable"
    assert warning.detail == "Effective VPN binary: /usr/bin/openfortivpn"

    failed = check_openfortivpn(
        is_executable=lambda path: path == "/usr/bin/openfortivpn",
        extra_paths=("/usr/bin/openfortivpn",),
        run_command=run_command,
        profile=build_profile(name="Office", gateway="vpn.example.com", use_sso=True),
    )
    assert failed.status is CheckStatus.FAIL
    assert failed.summary == "openfortivpn 1.21.0 — SAML support unavailable"


def test_openfortivpn_diagnostics_prefers_package_owned_binary() -> None:
    package = "/usr/libexec/fortigate-vpn-linux-gui/openfortivpn"

    def run_command(argv, timeout=3.0):
        exe = argv[0]
        if exe == package:
            if argv[1] == "--version":
                return CommandResult(returncode=0, stdout="openfortivpn 1.24.1\n")
            return CommandResult(returncode=0, stdout="Usage: [--saml-login]\n")
        if argv[1] == "--version":
            return CommandResult(returncode=0, stdout="openfortivpn 1.21.0\n")
        return CommandResult(returncode=0, stdout="Usage: [--cookie-on-stdin]\n")

    check = check_openfortivpn(
        is_executable=lambda path: path
        in {package, "/usr/local/bin/openfortivpn", "/usr/bin/openfortivpn"},
        run_command=run_command,
        profile=build_profile(name="Office", gateway="vpn.example.com", use_sso=True),
    )
    assert check.status is CheckStatus.PASS
    assert check.summary == "openfortivpn 1.24.1 — SAML supported"
    assert check.detail == f"Effective VPN binary: {package}"


def test_openfortivpn_missing_via_detect() -> None:
    check = check_openfortivpn(
        detect=lambda **kwargs: OpenfortivpnDetection(available=False, path=None, version=None),
        probe_version=False,
    )
    assert check.status is CheckStatus.FAIL


def test_helper_installed_compatible() -> None:
    def run_command(argv, timeout=3.0):
        assert argv[0].endswith("vpn-helper")
        assert argv[1] == "--version"
        assert "pkexec" not in argv
        return CommandResult(returncode=0, stdout=encode_hello_line() + "\n")

    check = check_helper(
        helper_path="/tmp/vpn-helper",
        path_exists=lambda path: True,
        is_executable=lambda path: True,
        run_command=run_command,
        expected_version=HELPER_VERSION,
        probe_version=True,
    )
    assert check.status is CheckStatus.PASS
    assert "compatible" in check.summary.lower()
    assert HELPER_VERSION in check.detail


def test_helper_missing() -> None:
    check = check_helper(
        helper_path="/missing/vpn-helper",
        path_exists=lambda path: False,
        is_executable=lambda path: False,
        probe_version=True,
        run_command=lambda *a, **k: CommandResult(),
    )
    assert check.status is CheckStatus.FAIL
    assert "not installed" in check.summary.lower()


def test_helper_not_executable() -> None:
    check = check_helper(
        helper_path="/tmp/vpn-helper",
        path_exists=lambda path: True,
        is_executable=lambda path: False,
        probe_version=False,
    )
    assert check.status is CheckStatus.FAIL
    assert "not executable" in check.summary.lower()


def test_polkit_policy_present(tmp_path) -> None:
    policy = tmp_path / "com.fortigate-vpn-linux-gui.policy"
    policy.write_text(f'<action id="{POLKIT_ACTION_ID}"/>\n', encoding="utf-8")
    check = check_polkit_policy(
        policy_path=str(policy),
        path_exists=lambda path: path == str(policy),
        read_text=lambda path: policy.read_text(encoding="utf-8"),
    )
    assert check.status is CheckStatus.PASS
    assert check.summary == "Policy installed."


def test_polkit_policy_missing() -> None:
    check = check_polkit_policy(
        policy_path="/missing/policy",
        path_exists=lambda path: False,
    )
    assert check.status is CheckStatus.FAIL


def test_polkit_diagnostics_does_not_invoke_pkexec() -> None:
    check = check_polkit_policy(path_exists=lambda path: False)
    auth = check_polkit_authorization()
    assert check.status is CheckStatus.FAIL
    assert auth.status is CheckStatus.INFO
    assert "when a VPN is started" in auth.summary


def test_profile_context_and_missing() -> None:
    profile = build_profile(name="Office", gateway="vpn.example.com", port=17414, use_sso=True)
    present = check_profile_context(profile)
    missing = check_profile_context(None)
    assert present.status is CheckStatus.INFO
    assert "Office" in present.summary
    assert "vpn.example.com:17414" in present.summary
    assert "SAML" in present.summary
    assert "password" not in present.summary.lower()
    assert missing.status is CheckStatus.INFO
    assert "No profile" in missing.summary


def test_certificate_pin_states() -> None:
    none = check_certificate_pin(None)
    empty = check_certificate_pin(build_profile(name="Office", gateway="vpn.example.com"))
    pinned = check_certificate_pin(
        build_profile(
            name="Office",
            gateway="vpn.example.com",
            trusted_cert_sha256=_FINGERPRINT,
        )
    )
    assert none.status is CheckStatus.NOT_TESTED
    assert empty.status is CheckStatus.INFO
    assert "No trusted certificate" in empty.summary
    assert pinned.status is CheckStatus.PASS
    assert "ab" in pinned.detail.lower()
