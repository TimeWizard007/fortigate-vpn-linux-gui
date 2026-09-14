# SPDX-License-Identifier: GPL-3.0-or-later
"""Run diagnostic checks with failure isolation and cancellation."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone

from fortigate_vpn_gui import __version__ as APP_VERSION
from fortigate_vpn_gui.diagnostics.checks import (
    InterfaceInfo,
    ListInterfaces,
    ResolveHost,
    RunArgv,
    TcpConnect,
    Which,
    check_certificate_pin,
    check_connection_state,
    check_dns,
    check_helper,
    check_ipsec_backend,
    check_ipsec_tunnel,
    check_openfortivpn,
    check_platform,
    check_polkit_authorization,
    check_polkit_policy,
    check_profile_context,
    check_route,
    check_tcp,
    check_vpn_interface,
    check_vpn_routes,
    default_resolve_host,
    default_tcp_connect,
    parse_ip_literal,
)
from fortigate_vpn_gui.diagnostics.model import (
    GROUP_NETWORK,
    GROUP_PROFILE,
    GROUP_SYSTEM,
    GROUP_TUNNEL,
    GROUP_VPN,
    CheckStatus,
    DiagnosticCheck,
    DiagnosticRun,
)
from fortigate_vpn_gui.diagnostics.sanitization import sanitize_diagnostic_text
from fortigate_vpn_gui.diagnostics.subprocess_run import run_argv
from fortigate_vpn_gui.helper.protocol import HELPER_VERSION
from fortigate_vpn_gui.profiles.model import ConnectionProfile
from fortigate_vpn_gui.system.helper_client import resolve_helper_path
from fortigate_vpn_gui.system.polkit import POLKIT_POLICY_INSTALL_PATH
from fortigate_vpn_gui.vpn.capabilities import default_is_executable
from fortigate_vpn_gui.vpn.models import VpnSnapshot

CancelFlag = Callable[[], bool]
PathExists = Callable[[str], bool]
IsExecutable = Callable[[str], bool]
ReadText = Callable[[str], str]
Clock = Callable[[], datetime]


@dataclass
class DiagnosticDeps:
    """Injectable collaborators for tests. Production uses system defaults."""

    run_argv: RunArgv = run_argv
    which: Which | None = None
    path_exists: PathExists | None = None
    is_executable: IsExecutable | None = None
    read_text: ReadText | None = None
    resolve_host: ResolveHost = default_resolve_host
    tcp_connect: TcpConnect = default_tcp_connect
    list_interfaces: ListInterfaces | None = None
    helper_path: str = field(default_factory=resolve_helper_path)
    policy_path: str = POLKIT_POLICY_INSTALL_PATH
    detect: Callable[..., object] | None = None
    expected_helper_version: str = HELPER_VERSION
    os_name: str | None = None
    kernel: str | None = None
    arch: str | None = None
    session_type: str | None = None
    clock: Clock = field(default=lambda: datetime.now(timezone.utc))


@dataclass(frozen=True)
class DiagnosticRequest:
    """Inputs for one diagnostics pass."""

    snapshot: VpnSnapshot
    profile: ConnectionProfile | None
    include_network: bool = True
    app_version: str = APP_VERSION
    helper_protocol: str = HELPER_VERSION


class DiagnosticService:
    """Run diagnostic checks. One failure does not abort the rest."""

    def __init__(self, deps: DiagnosticDeps | None = None) -> None:
        self._deps = deps or DiagnosticDeps()

    def collect_local(
        self, request: DiagnosticRequest, *, cancel: CancelFlag | None = None
    ) -> DiagnosticRun:
        """Lightweight status: no gateway or network probes."""
        local = DiagnosticRequest(
            snapshot=request.snapshot,
            profile=request.profile,
            include_network=False,
            app_version=request.app_version,
            helper_protocol=request.helper_protocol,
        )
        return self.run(local, cancel=cancel)

    def run(self, request: DiagnosticRequest, *, cancel: CancelFlag | None = None) -> DiagnosticRun:
        """Run all checks. Network probes run only when ``include_network`` is true."""
        started = self._deps.clock()
        checks: list[DiagnosticCheck] = []
        dns_addresses: tuple[str, ...] = ()
        dns_failed = False
        interface: InterfaceInfo | None = None
        cancelled = False

        def add(check: DiagnosticCheck) -> None:
            checks.append(check)

        def should_stop() -> bool:
            return cancel is not None and cancel()

        isolated: list[tuple[str, Callable[[], None]]] = [
            (
                "system.platform",
                lambda: add(
                    self._safe(
                        "system.platform",
                        "Application / platform",
                        GROUP_SYSTEM,
                        lambda: check_platform(
                            snapshot=request.snapshot,
                            app_version=request.app_version,
                            helper_protocol=request.helper_protocol,
                            os_name=self._deps.os_name,
                            kernel=self._deps.kernel,
                            arch=self._deps.arch,
                            session_type=self._deps.session_type,
                        ),
                    )
                ),
            ),
            (
                "vpn.openfortivpn",
                lambda: add(
                    self._safe(
                        "vpn.openfortivpn",
                        "openfortivpn",
                        GROUP_VPN,
                        lambda: check_openfortivpn(
                            which=self._deps.which,
                            is_executable=self._deps.is_executable or default_is_executable,
                            run_command=self._deps.run_argv,
                            probe_version=True,
                            detect=self._deps.detect,
                            profile=request.profile,
                        ),
                    )
                ),
            ),
            (
                "vpn.ipsec",
                lambda: add(
                    self._safe(
                        "vpn.ipsec",
                        "IPsec backend",
                        GROUP_VPN,
                        lambda: check_ipsec_backend(
                            request.profile,
                            is_executable=self._deps.is_executable or default_is_executable,
                        ),
                    )
                ),
            ),
            (
                "vpn.helper",
                lambda: add(
                    self._safe(
                        "vpn.helper",
                        "VPN helper",
                        GROUP_VPN,
                        lambda: check_helper(
                            helper_path=self._deps.helper_path,
                            path_exists=self._deps.path_exists,
                            is_executable=self._deps.is_executable,
                            run_command=self._deps.run_argv,
                            expected_version=self._deps.expected_helper_version,
                            probe_version=True,
                        ),
                    )
                ),
            ),
            (
                "vpn.polkit",
                lambda: add(
                    self._safe(
                        "vpn.polkit",
                        "polkit policy",
                        GROUP_VPN,
                        lambda: check_polkit_policy(
                            policy_path=self._deps.policy_path,
                            path_exists=self._deps.path_exists,
                            read_text=self._deps.read_text,
                        ),
                    )
                ),
            ),
            (
                "vpn.polkit_auth",
                lambda: add(
                    self._safe(
                        "vpn.polkit_auth",
                        "polkit prompt",
                        GROUP_VPN,
                        check_polkit_authorization,
                    )
                ),
            ),
            (
                "profile.context",
                lambda: add(
                    self._safe(
                        "profile.context",
                        "Selected profile",
                        GROUP_PROFILE,
                        lambda: check_profile_context(request.profile),
                    )
                ),
            ),
            (
                "profile.certificate",
                lambda: add(
                    self._safe(
                        "profile.certificate",
                        "Gateway certificate pin",
                        GROUP_PROFILE,
                        lambda: check_certificate_pin(request.profile),
                    )
                ),
            ),
        ]

        for _name, step in isolated:
            if should_stop():
                cancelled = True
                break
            step()

        if not cancelled and not should_stop():
            check, resolved = self._safe_dns(request)
            add(check)
            dns_addresses = resolved
            dns_failed = check.status is CheckStatus.FAIL
        elif not cancelled:
            cancelled = True

        if not cancelled and not should_stop():
            add(
                self._safe(
                    "network.route",
                    "Route to gateway",
                    GROUP_NETWORK,
                    lambda: check_route(
                        request.profile,
                        dns_addresses,
                        dns_failed=dns_failed,
                        include_network=request.include_network,
                        which=self._deps.which,
                        run_command=self._deps.run_argv,
                    ),
                )
            )
        elif not cancelled:
            cancelled = True

        if not cancelled and not should_stop():
            add(
                self._safe(
                    "network.tcp",
                    "Gateway TCP",
                    GROUP_NETWORK,
                    lambda: check_tcp(
                        request.profile,
                        dns_addresses,
                        dns_failed=dns_failed,
                        include_network=request.include_network,
                        connect=self._deps.tcp_connect,
                    ),
                )
            )
        elif not cancelled:
            cancelled = True

        if not cancelled and not should_stop():
            add(
                self._safe(
                    "tunnel.connection",
                    "Connection state",
                    GROUP_TUNNEL,
                    lambda: check_connection_state(request.snapshot),
                )
            )
        elif not cancelled:
            cancelled = True

        if not cancelled and not should_stop():
            iface_check, interface = self._safe_iface(request)
            add(iface_check)
        elif not cancelled:
            cancelled = True

        if not cancelled and not should_stop():
            add(
                self._safe(
                    "tunnel.routes",
                    "VPN routes",
                    GROUP_TUNNEL,
                    lambda: check_vpn_routes(
                        request.snapshot,
                        interface,
                        include_network=request.include_network,
                        which=self._deps.which,
                        run_command=self._deps.run_argv,
                    ),
                )
            )
        elif not cancelled:
            cancelled = True

        if not cancelled and not should_stop():
            if request.profile is not None and request.profile.is_ipsec():
                gateway_ips = dns_addresses
                literal = parse_ip_literal(request.profile.gateway)
                if literal and literal not in gateway_ips:
                    gateway_ips = (*gateway_ips, literal)
                add(
                    self._safe(
                        "tunnel.ipsec",
                        "IPsec tunnel",
                        GROUP_TUNNEL,
                        lambda: check_ipsec_tunnel(
                            request.snapshot,
                            request.profile,
                            gateway_ips,
                            include_network=request.include_network,
                            which=self._deps.which,
                            run_command=self._deps.run_argv,
                        ),
                    )
                )
        elif not cancelled:
            cancelled = True

        finished = self._deps.clock()
        return DiagnosticRun(
            started_at=started,
            finished_at=finished,
            checks=tuple(checks),
            cancelled=cancelled,
        )

    def _safe(
        self,
        check_id: str,
        label: str,
        group: str,
        factory: Callable[[], DiagnosticCheck],
    ) -> DiagnosticCheck:
        try:
            return factory()
        except Exception as exc:
            return DiagnosticCheck(
                id=check_id,
                label=label,
                status=CheckStatus.FAIL,
                summary="This check failed internally.",
                detail=sanitize_diagnostic_text(str(exc)),
                group=group,
            )

    def _safe_dns(self, request: DiagnosticRequest) -> tuple[DiagnosticCheck, tuple[str, ...]]:
        try:
            return check_dns(
                request.profile,
                resolve=self._deps.resolve_host,
                include_network=request.include_network,
            )
        except Exception as exc:
            return (
                DiagnosticCheck(
                    id="network.dns",
                    label="DNS resolution",
                    status=CheckStatus.FAIL,
                    summary="This check failed internally.",
                    detail=sanitize_diagnostic_text(str(exc)),
                    group=GROUP_NETWORK,
                ),
                (),
            )

    def _safe_iface(
        self, request: DiagnosticRequest
    ) -> tuple[DiagnosticCheck, InterfaceInfo | None]:
        try:
            return check_vpn_interface(
                request.snapshot,
                include_network=request.include_network,
                list_interfaces=self._deps.list_interfaces,
                run_command=self._deps.run_argv,
                which=self._deps.which,
            )
        except Exception as exc:
            return (
                DiagnosticCheck(
                    id="tunnel.interface",
                    label="VPN interface",
                    status=CheckStatus.FAIL,
                    summary="This check failed internally.",
                    detail=sanitize_diagnostic_text(str(exc)),
                    group=GROUP_TUNNEL,
                ),
                None,
            )
