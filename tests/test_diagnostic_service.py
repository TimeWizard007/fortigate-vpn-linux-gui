# SPDX-License-Identifier: GPL-3.0-or-later
"""Diagnostic service isolation, cancellation, and viewmodel tests."""

from __future__ import annotations

from dataclasses import replace

from fortigate_vpn_gui.diagnostics.checks import CommandResult, DnsResult, TcpResult
from fortigate_vpn_gui.diagnostics.model import CheckStatus
from fortigate_vpn_gui.diagnostics.service import (
    DiagnosticDeps,
    DiagnosticRequest,
    DiagnosticService,
)
from fortigate_vpn_gui.diagnostics.viewmodel import DiagnosticsViewModel
from fortigate_vpn_gui.helper.handshake import encode_hello_line
from fortigate_vpn_gui.helper.protocol import HELPER_VERSION, POLKIT_ACTION_ID
from fortigate_vpn_gui.profiles.model import build_profile
from fortigate_vpn_gui.vpn.detect import OpenfortivpnDetection
from tests.vpn_fakes import VpnHarness


def _deps(**kwargs) -> DiagnosticDeps:
    defaults = dict(
        which=lambda name: None,
        path_exists=lambda path: False,
        is_executable=lambda path: False,
        read_text=lambda path: "",
        resolve_host=lambda *a, **k: DnsResult(error="unused"),
        tcp_connect=lambda *a, **k: TcpResult(kind="error", error="unused"),
        list_interfaces=lambda: (),
        run_argv=lambda *a, **k: CommandResult(missing=True),
        os_name="Ubuntu 24.04 LTS",
        kernel="6.8.0-test",
        arch="x86_64",
        session_type="Wayland",
        detect=lambda **kw: OpenfortivpnDetection(available=False, path=None, version=None),
    )
    defaults.update(kwargs)
    return DiagnosticDeps(**defaults)


def test_service_dns_failure_does_not_abort_local_checks() -> None:
    profile = build_profile(name="Office", gateway="vpn.example.com")
    hello = encode_hello_line()

    def run_argv(argv, timeout=3.0):
        if argv and argv[-1] == "--version" and "openfortivpn" in argv[0]:
            return CommandResult(returncode=0, stdout="openfortivpn 1.24.1\n")
        if argv and argv[-1] == "--help" and "openfortivpn" in argv[0]:
            return CommandResult(returncode=0, stdout="Usage: openfortivpn [--saml-login]\n")
        if argv and argv[-1] == "--version":
            return CommandResult(returncode=0, stdout=hello + "\n")
        return CommandResult(missing=True)

    service = DiagnosticService(
        _deps(
            path_exists=lambda path: True,
            is_executable=lambda path: True,
            read_text=lambda path: f'id="{POLKIT_ACTION_ID}"',
            run_argv=run_argv,
            detect=None,
            resolve_host=lambda *a, **k: DnsResult(error="Name or service not known"),
        )
    )
    run = service.run(DiagnosticRequest(snapshot=VpnHarness().backend.snapshot(), profile=profile))
    ofvpn = run.check("vpn.openfortivpn")
    helper = run.check("vpn.helper")
    polkit = run.check("vpn.polkit")
    dns = run.check("network.dns")
    route = run.check("network.route")
    tcp = run.check("network.tcp")
    assert ofvpn is not None and ofvpn.status is CheckStatus.PASS
    assert helper is not None and helper.status is CheckStatus.PASS
    assert polkit is not None and polkit.status is CheckStatus.PASS
    assert dns is not None and dns.status is CheckStatus.FAIL
    assert route is not None and route.status is CheckStatus.NOT_TESTED
    assert tcp is not None and tcp.status is CheckStatus.NOT_TESTED
    assert HELPER_VERSION == "0.7.0"


def test_service_internal_failure_is_isolated() -> None:
    def boom(*args, **kwargs):
        raise RuntimeError("dns exploded password=secret123")

    service = DiagnosticService(_deps(resolve_host=boom))
    profile = build_profile(name="Office", gateway="vpn.example.com")
    run = service.run(DiagnosticRequest(snapshot=VpnHarness().backend.snapshot(), profile=profile))
    assert run.check("vpn.openfortivpn") is not None
    assert run.check("vpn.helper") is not None
    dns = run.check("network.dns")
    assert dns is not None and dns.status is CheckStatus.FAIL
    assert "secret123" not in (dns.detail or "")


def test_viewmodel_prevents_duplicate_runs() -> None:
    service = DiagnosticService(_deps())
    viewmodel = DiagnosticsViewModel(service)
    request = DiagnosticRequest(snapshot=VpnHarness().backend.snapshot(), profile=None)
    assert viewmodel.can_start() is True
    viewmodel._running = True
    assert viewmodel.can_start() is False
    try:
        viewmodel.execute(request)
        raise AssertionError("duplicate run should raise")
    except RuntimeError:
        pass
    viewmodel._running = False
    run = viewmodel.execute(request)
    assert run.checks
    assert viewmodel.running is False
    viewmodel.mark_profile_changed("abc")
    assert viewmodel.stale is True
    assert "profile changed" in viewmodel.last_run_label()


def test_lightweight_run_skips_network_probes() -> None:
    called = {"dns": False}

    def resolve(*args, **kwargs):
        called["dns"] = True
        return DnsResult(addresses=("203.0.113.10",))

    service = DiagnosticService(_deps(resolve_host=resolve))
    run = service.collect_local(
        DiagnosticRequest(
            snapshot=VpnHarness().backend.snapshot(),
            profile=build_profile(name="Office", gateway="vpn.example.com"),
        )
    )
    assert called["dns"] is False
    dns = run.check("network.dns")
    assert dns is not None and dns.status is CheckStatus.NOT_TESTED


def test_service_uses_connected_snapshot() -> None:
    snapshot = replace(
        VpnHarness().backend.snapshot(),
        state=__import__(
            "fortigate_vpn_gui.vpn.models", fromlist=["ConnectionState"]
        ).ConnectionState.CONNECTED,
    )
    service = DiagnosticService(
        _deps(
            list_interfaces=lambda: (),
        )
    )
    run = service.run(DiagnosticRequest(snapshot=snapshot, profile=None, include_network=True))
    connection = run.check("tunnel.connection")
    iface = run.check("tunnel.interface")
    assert connection is not None
    assert "Connected" in connection.summary
    assert iface is not None
    assert iface.status.value in {"warning", "info", "pass"}
