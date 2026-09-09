# SPDX-License-Identifier: GPL-3.0-or-later
"""Certificate trust workflow tests. No real VPN or pkexec."""

from __future__ import annotations

from fortigate_vpn_gui.profiles.model import build_profile
from fortigate_vpn_gui.vpn.models import VpnErrorCode
from tests.vpn_fakes import VpnHarness

_DIGEST_A = "aa" * 32
_DIGEST_B = "bb" * 32

_FAIL = "ERROR: Gateway certificate validation failed"
_CERT_LINES = (
    _FAIL,
    "ERROR:  Gateway certificate:",
    "ERROR:      subject:",
    "ERROR:          /CN=vpn.example.com",
    "ERROR:      issuer:",
    "ERROR:          /C=US/O=Example CA",
    f"ERROR:      sha256 digest: {_DIGEST_A}",
)


def _emit_cert(harness: VpnHarness, digest: str = _DIGEST_A) -> None:
    assert harness.process is not None
    for line in _CERT_LINES:
        harness.process.emit(line.replace(_DIGEST_A, digest))
    harness.process.finish(1)


def test_unknown_certificate_prompts_untrusted() -> None:
    harness = VpnHarness()
    profile = build_profile(name="Office", gateway="vpn.example.com", use_sso=True)
    harness.backend.connect(profile)
    _emit_cert(harness)
    snapshot = harness.backend.snapshot()
    assert snapshot.error_code is VpnErrorCode.CERTIFICATE_UNTRUSTED
    assert snapshot.presented_certificate is not None
    assert snapshot.presented_certificate.sha256 == _DIGEST_A
    assert snapshot.presented_certificate.subject == "CN=vpn.example.com"


def test_matching_pinned_cert_is_passed_on_argv() -> None:
    harness = VpnHarness()
    profile = build_profile(
        name="Office",
        gateway="vpn.example.com",
        use_sso=True,
        trusted_cert_sha256=_DIGEST_A,
    )
    harness.backend.connect(profile)
    assert harness.process is not None
    assert "--trusted-cert" in harness.process.argv
    assert _DIGEST_A in harness.process.argv
    assert harness.process.argv[harness.process.argv.index("--trusted-cert") + 1] == _DIGEST_A


def test_changed_certificate_never_auto_replaces_pin() -> None:
    harness = VpnHarness()
    profile = build_profile(
        name="Office",
        gateway="vpn.example.com",
        use_sso=True,
        trusted_cert_sha256=_DIGEST_A,
    )
    harness.backend.connect(profile)
    _emit_cert(harness, _DIGEST_B)
    snapshot = harness.backend.snapshot()
    assert snapshot.error_code is VpnErrorCode.CERTIFICATE_CHANGED
    assert snapshot.presented_certificate is not None
    assert snapshot.presented_certificate.sha256 == _DIGEST_B
    assert profile.trusted_cert_sha256 == _DIGEST_A


def test_retry_uses_trusted_cert_after_pin() -> None:
    harness = VpnHarness()
    profile = build_profile(name="Office", gateway="vpn.example.com", use_sso=True)
    harness.backend.connect(profile)
    _emit_cert(harness)
    pinned = build_profile(
        profile_id=profile.id,
        name=profile.name,
        gateway=profile.gateway,
        port=profile.port,
        use_sso=True,
        trusted_cert_sha256=_DIGEST_A,
    )
    harness.backend.disconnect(wait=True)
    harness.backend.connect(pinned)
    assert harness.process is not None
    assert harness.process.argv[-2:] == ["--trusted-cert", _DIGEST_A]
    assert "--saml-login" in harness.process.argv
