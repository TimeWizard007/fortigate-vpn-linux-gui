# SPDX-License-Identifier: GPL-3.0-or-later
"""Individual diagnostic checks. Independent of Qt widgets."""

from __future__ import annotations

import ipaddress
import os
import re
import socket
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeout
from dataclasses import dataclass
from pathlib import Path

from fortigate_vpn_gui import __version__ as APP_VERSION
from fortigate_vpn_gui.diagnostics.model import (
    GROUP_NETWORK,
    GROUP_PROFILE,
    GROUP_SYSTEM,
    GROUP_TUNNEL,
    GROUP_VPN,
    CheckStatus,
    DiagnosticCheck,
)
from fortigate_vpn_gui.diagnostics.platform_info import (
    architecture,
    desktop_session_type,
    kernel_release,
    read_os_pretty_name,
)
from fortigate_vpn_gui.diagnostics.sanitization import sanitize_diagnostic_text
from fortigate_vpn_gui.diagnostics.subprocess_run import CommandResult, run_argv
from fortigate_vpn_gui.diagnostics.timeouts import (
    DNS_TIMEOUT_SECONDS,
    ROUTE_TIMEOUT_SECONDS,
    TCP_TIMEOUT_SECONDS,
    VERSION_TIMEOUT_SECONDS,
)
from fortigate_vpn_gui.helper.executables import (
    discover_approved_openfortivpn,
    resolve_approved_executable,
)
from fortigate_vpn_gui.helper.handshake import is_valid_helper_version, parse_helper_hello_output
from fortigate_vpn_gui.helper.protocol import (
    APPROVED_OPENFORTIVPN_PATHS,
    HELPER_VERSION,
    INSTALLED_HELPER_PATH,
    POLKIT_ACTION_ID,
)
from fortigate_vpn_gui.helper.validation import format_sha256_fingerprint
from fortigate_vpn_gui.profiles.model import ConnectionProfile, auth_mode_label
from fortigate_vpn_gui.system.polkit import POLKIT_POLICY_INSTALL_PATH
from fortigate_vpn_gui.vpn.capabilities import (
    OpenfortivpnCapabilities,
    VersionRunner,
    default_is_executable,
)
from fortigate_vpn_gui.vpn.models import ConnectionState, VpnSnapshot, state_label

Which = Callable[[str], str | None]
PathExists = Callable[[str], bool]
IsExecutable = Callable[[str], bool]
RunArgv = Callable[..., CommandResult]
ReadText = Callable[[str], str]


def _check(
    *,
    check_id: str,
    label: str,
    status: CheckStatus,
    summary: str,
    detail: str = "",
    hint: str = "",
    group: str,
) -> DiagnosticCheck:
    return DiagnosticCheck(
        id=check_id,
        label=label,
        status=status,
        summary=sanitize_diagnostic_text(summary),
        detail=sanitize_diagnostic_text(detail),
        hint=sanitize_diagnostic_text(hint),
        group=group,
    )


def check_platform(
    *,
    snapshot: VpnSnapshot,
    app_version: str = APP_VERSION,
    helper_protocol: str = HELPER_VERSION,
    os_name: str | None = None,
    kernel: str | None = None,
    arch: str | None = None,
    session_type: str | None = None,
) -> DiagnosticCheck:
    """Local application and OS facts. Never dumps environment variables."""
    pretty = os_name if os_name is not None else read_os_pretty_name()
    release = kernel if kernel is not None else kernel_release()
    machine = arch if arch is not None else architecture()
    session = session_type if session_type is not None else desktop_session_type()
    connection = state_label(snapshot.state)
    summary = f"{pretty}; kernel {release}; {machine}; session {session}; VPN {connection}"
    detail = (
        f"Application {app_version}; helper protocol {helper_protocol}. "
        f"Connection state: {connection}."
    )
    return _check(
        check_id="system.platform",
        label="Application / platform",
        status=CheckStatus.INFO,
        summary=summary,
        detail=detail,
        group=GROUP_SYSTEM,
    )


_SAML_UNAVAILABLE_HINT = (
    "Ubuntu 24.04's packaged openfortivpn 1.21.0 does not provide --saml-login. "
    "Reinstall FortiGate VPN Linux GUI so the package-owned SAML-capable "
    "openfortivpn is present, or install a build whose --help lists --saml-login."
)
_OPENFORTIVPN_MISSING_HINT = (
    "Reinstall FortiGate VPN Linux GUI. The package includes a SAML-capable "
    "openfortivpn at /usr/libexec/fortigate-vpn-linux-gui/openfortivpn."
)


def check_openfortivpn(
    *,
    which: Which | None = None,
    is_executable: IsExecutable = default_is_executable,
    extra_paths: Sequence[str] = APPROVED_OPENFORTIVPN_PATHS,
    run_command: RunArgv | None = None,
    probe_version: bool = True,
    detect: Callable[..., object] | None = None,
    profile: ConnectionProfile | None = None,
) -> DiagnosticCheck:
    """Report the effective helper openfortivpn and whether SAML is available."""
    del which
    if detect is not None:
        detection = detect(include_version=False, include_capabilities=False)
        if not getattr(detection, "available", False):
            return _check(
                check_id="vpn.openfortivpn",
                label="openfortivpn",
                status=CheckStatus.FAIL,
                summary="openfortivpn was not found.",
                hint=_OPENFORTIVPN_MISSING_HINT,
                group=GROUP_VPN,
            )

    discovered = discover_approved_openfortivpn(
        is_executable=is_executable,
        extra_paths=extra_paths,
    )
    if not discovered:
        return _check(
            check_id="vpn.openfortivpn",
            label="openfortivpn",
            status=CheckStatus.FAIL,
            summary="openfortivpn was not found.",
            hint=_OPENFORTIVPN_MISSING_HINT,
            group=GROUP_VPN,
        )

    require_saml = bool(profile is not None and profile.use_sso)
    runner: VersionRunner | None = None
    if probe_version and run_command is not None:
        first_path = discovered[0][0]
        preview = run_command([first_path, "--version"], timeout=VERSION_TIMEOUT_SECONDS)
        if preview.timed_out:
            return _check(
                check_id="vpn.openfortivpn",
                label="openfortivpn",
                status=CheckStatus.WARNING,
                summary="Version check timed out.",
                detail=first_path,
                hint="Retry diagnostics. The binary was found but did not respond in time.",
                group=GROUP_VPN,
            )
        runner = _version_runner_from_command(run_command)

    selected: OpenfortivpnCapabilities | None
    fallback: OpenfortivpnCapabilities | None = None
    if runner is not None:
        selected = resolve_approved_executable(
            require_saml=require_saml,
            runner=runner,
            is_executable=is_executable,
            extra_paths=extra_paths,
        )
        if selected is None:
            fallback = resolve_approved_executable(
                require_saml=False,
                runner=runner,
                is_executable=is_executable,
                extra_paths=extra_paths,
            )
    else:
        path, source = discovered[0]
        selected = OpenfortivpnCapabilities(
            executable_path=path,
            version=None,
            supports_saml=False,
            supports_cookie_stdin=False,
            source=source,
        )

    effective = selected if selected is not None else fallback
    if effective is None:
        return _check(
            check_id="vpn.openfortivpn",
            label="openfortivpn",
            status=CheckStatus.FAIL,
            summary="openfortivpn was not found.",
            hint=_OPENFORTIVPN_MISSING_HINT,
            group=GROUP_VPN,
        )

    version = effective.version or "unknown"
    detail = f"Effective VPN binary: {effective.executable_path}"
    if not probe_version or run_command is None:
        return _check(
            check_id="vpn.openfortivpn",
            label="openfortivpn",
            status=CheckStatus.WARNING,
            summary=f"openfortivpn {version} — SAML support not probed",
            detail=detail,
            hint="Run diagnostics to query --help for --saml-login.",
            group=GROUP_VPN,
        )

    if effective.supports_saml:
        return _check(
            check_id="vpn.openfortivpn",
            label="openfortivpn",
            status=CheckStatus.PASS,
            summary=f"openfortivpn {version} — SAML supported",
            detail=detail,
            group=GROUP_VPN,
        )

    status = CheckStatus.FAIL if require_saml else CheckStatus.WARNING
    return _check(
        check_id="vpn.openfortivpn",
        label="openfortivpn",
        status=status,
        summary=f"openfortivpn {version} — SAML support unavailable",
        detail=detail,
        hint=_SAML_UNAVAILABLE_HINT,
        group=GROUP_VPN,
    )


def _version_runner_from_command(run_command: RunArgv) -> VersionRunner:
    """Adapt diagnostics CommandResult to a capabilities VersionRunner."""
    import subprocess

    def runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
        result = run_command(argv, timeout=VERSION_TIMEOUT_SECONDS)
        if result.timed_out:
            raise subprocess.TimeoutExpired(argv, VERSION_TIMEOUT_SECONDS)
        if result.missing:
            raise FileNotFoundError(argv[0])
        return subprocess.CompletedProcess(
            argv,
            0 if result.returncode is None else result.returncode,
            result.stdout or "",
            result.stderr or "",
        )

    return runner


def check_helper(
    *,
    helper_path: str = INSTALLED_HELPER_PATH,
    path_exists: PathExists | None = None,
    is_executable: IsExecutable | None = None,
    run_command: RunArgv | None = None,
    expected_version: str = HELPER_VERSION,
    probe_version: bool = True,
) -> DiagnosticCheck:
    """Inspect the installed helper without pkexec or starting a VPN."""
    exists = path_exists or os.path.exists
    executable = is_executable or default_is_executable
    if not exists(helper_path):
        return _check(
            check_id="vpn.helper",
            label="VPN helper",
            status=CheckStatus.FAIL,
            summary="VPN helper is not installed.",
            detail=helper_path,
            hint="Install the FortiGate VPN Linux GUI helper and retry.",
            group=GROUP_VPN,
        )
    if not executable(helper_path):
        return _check(
            check_id="vpn.helper",
            label="VPN helper",
            status=CheckStatus.FAIL,
            summary="VPN helper is installed but not executable.",
            detail=helper_path,
            hint="Reinstall the helper package so the binary is executable.",
            group=GROUP_VPN,
        )
    if not probe_version or run_command is None:
        return _check(
            check_id="vpn.helper",
            label="VPN helper",
            status=CheckStatus.PASS,
            summary="Helper installed.",
            detail=helper_path,
            group=GROUP_VPN,
        )
    result = run_command([helper_path, "--version"], timeout=VERSION_TIMEOUT_SECONDS)
    if result.timed_out:
        return _check(
            check_id="vpn.helper",
            label="VPN helper",
            status=CheckStatus.WARNING,
            summary="Helper version check timed out.",
            detail=helper_path,
            group=GROUP_VPN,
        )
    hello = parse_helper_hello_output(
        stdout=result.stdout,
        stderr=result.stderr,
        returncode=result.returncode or 0,
    )
    version = hello.helper_version
    if is_valid_helper_version(version) and version == expected_version:
        return _check(
            check_id="vpn.helper",
            label="VPN helper",
            status=CheckStatus.PASS,
            summary="Helper installed and compatible.",
            detail=f"{helper_path}; protocol {version}",
            group=GROUP_VPN,
        )
    if is_valid_helper_version(version):
        return _check(
            check_id="vpn.helper",
            label="VPN helper",
            status=CheckStatus.FAIL,
            summary=f"Helper protocol {version} does not match GUI {expected_version}.",
            detail=helper_path,
            hint="Reinstall a helper that matches this application.",
            group=GROUP_VPN,
        )
    return _check(
        check_id="vpn.helper",
        label="VPN helper",
        status=CheckStatus.WARNING,
        summary="Helper is installed but its protocol version could not be read.",
        detail=helper_path,
        hint="The helper file is present. Interactive authorization is not tested here.",
        group=GROUP_VPN,
    )


def check_polkit_policy(
    *,
    policy_path: str = POLKIT_POLICY_INSTALL_PATH,
    action_id: str = POLKIT_ACTION_ID,
    path_exists: PathExists | None = None,
    read_text: ReadText | None = None,
) -> DiagnosticCheck:
    """Check that the polkit policy file exists. Does not invoke pkexec."""
    exists = path_exists or os.path.exists
    reader = read_text or (lambda path: Path(path).read_text(encoding="utf-8"))
    if not exists(policy_path):
        return _check(
            check_id="vpn.polkit",
            label="polkit policy",
            status=CheckStatus.FAIL,
            summary="polkit policy is not installed.",
            detail=policy_path,
            hint=f"Install the polkit policy that defines {action_id}.",
            group=GROUP_VPN,
        )
    try:
        text = reader(policy_path)
    except OSError:
        return _check(
            check_id="vpn.polkit",
            label="polkit policy",
            status=CheckStatus.WARNING,
            summary="polkit policy file could not be read.",
            detail=policy_path,
            group=GROUP_VPN,
        )
    if action_id not in text:
        return _check(
            check_id="vpn.polkit",
            label="polkit policy",
            status=CheckStatus.FAIL,
            summary=f"polkit action {action_id} was not found in the policy file.",
            detail=policy_path,
            hint="Reinstall the helper package that ships the polkit policy.",
            group=GROUP_VPN,
        )
    return _check(
        check_id="vpn.polkit",
        label="polkit policy",
        status=CheckStatus.PASS,
        summary="Policy installed.",
        detail=f"Action {action_id} is present.",
        group=GROUP_VPN,
    )


def check_polkit_authorization() -> DiagnosticCheck:
    """Interactive polkit auth is not performed by Diagnostics."""
    return _check(
        check_id="vpn.polkit_auth",
        label="polkit prompt",
        status=CheckStatus.INFO,
        summary="Interactive authorization is requested when a VPN is started.",
        detail="Diagnostics does not prompt for a password or launch pkexec.",
        group=GROUP_VPN,
    )


def check_profile_context(profile: ConnectionProfile | None) -> DiagnosticCheck:
    """Non-secret profile/gateway context."""
    if profile is None:
        return _check(
            check_id="profile.context",
            label="Selected profile",
            status=CheckStatus.INFO,
            summary="No profile selected.",
            hint="Create or select a profile, then run diagnostics.",
            group=GROUP_PROFILE,
        )
    mode = auth_mode_label(profile.use_sso)
    return _check(
        check_id="profile.context",
        label="Selected profile",
        status=CheckStatus.INFO,
        summary=f"{profile.name} → {profile.gateway}:{profile.port} ({mode})",
        detail=f"Authentication: {mode}",
        group=GROUP_PROFILE,
    )


def check_certificate_pin(profile: ConnectionProfile | None) -> DiagnosticCheck:
    """Show stored gateway certificate pin metadata. Does not trust anything."""
    if profile is None:
        return _check(
            check_id="profile.certificate",
            label="Gateway certificate pin",
            status=CheckStatus.NOT_TESTED,
            summary="No profile selected.",
            group=GROUP_PROFILE,
        )
    fingerprint = profile.trusted_cert_sha256
    if not fingerprint:
        return _check(
            check_id="profile.certificate",
            label="Gateway certificate pin",
            status=CheckStatus.INFO,
            summary="No trusted certificate fingerprint stored.",
            detail="Diagnostics does not change certificate trust.",
            group=GROUP_PROFILE,
        )
    shown = format_sha256_fingerprint(fingerprint)
    return _check(
        check_id="profile.certificate",
        label="Gateway certificate pin",
        status=CheckStatus.PASS,
        summary="Trusted certificate fingerprint stored.",
        detail=shown,
        group=GROUP_PROFILE,
    )


def check_connection_state(snapshot: VpnSnapshot) -> DiagnosticCheck:
    """Application VPN state, including a sanitized last error when failed."""
    label = state_label(snapshot.state)
    detail = ""
    hint = ""
    status = CheckStatus.INFO
    if snapshot.state is ConnectionState.CONNECTED:
        status = CheckStatus.PASS
    elif snapshot.state is ConnectionState.FAILED:
        status = CheckStatus.FAIL
        reason = snapshot.last_failure_reason or snapshot.failure_reason or ""
        detail = sanitize_diagnostic_text(reason)
        hint = "See Logs for redacted connection details."
    elif snapshot.state is ConnectionState.DISCONNECTED:
        status = CheckStatus.INFO
    summary = label
    if snapshot.state is ConnectionState.FAILED and detail:
        summary = f"{label}: {detail}"
    return _check(
        check_id="tunnel.connection",
        label="Connection state",
        status=status,
        summary=summary,
        detail=detail,
        hint=hint,
        group=GROUP_TUNNEL,
    )


def parse_ip_literal(value: str) -> str | None:
    """Return a canonical IP string, or None if *value* is a hostname."""
    text = value.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


@dataclass(frozen=True)
class DnsResult:
    """Outcome of a hostname lookup."""

    addresses: tuple[str, ...] = ()
    timed_out: bool = False
    error: str = ""


def default_resolve_host(host: str, timeout: float = DNS_TIMEOUT_SECONDS) -> DnsResult:
    """Resolve *host* with a bounded wait. Does not shell out to dig/nslookup."""

    def _lookup() -> tuple[str, ...]:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        addresses: list[str] = []
        seen: set[str] = set()
        for info in infos:
            addr = info[4][0]
            if addr in seen:
                continue
            seen.add(addr)
            addresses.append(addr)
        return tuple(addresses)

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(_lookup)
        try:
            addresses = future.result(timeout=timeout)
        except FuturesTimeout:
            return DnsResult(timed_out=True, error="timed out")
        except socket.gaierror as exc:
            return DnsResult(error=str(exc))
        except OSError as exc:
            return DnsResult(error=str(exc))
        finally:
            pool.shutdown(wait=False, cancel_futures=True)
    return DnsResult(addresses=addresses)


ResolveHost = Callable[..., DnsResult]


def check_dns(
    profile: ConnectionProfile | None,
    *,
    resolve: ResolveHost = default_resolve_host,
    include_network: bool = True,
) -> tuple[DiagnosticCheck, tuple[str, ...]]:
    """Resolve the selected gateway. Returns the check and resolved addresses."""
    if not include_network:
        return (
            _check(
                check_id="network.dns",
                label="DNS resolution",
                status=CheckStatus.NOT_TESTED,
                summary="Run diagnostics to resolve the gateway.",
                group=GROUP_NETWORK,
            ),
            (),
        )
    if profile is None:
        return (
            _check(
                check_id="network.dns",
                label="DNS resolution",
                status=CheckStatus.NOT_TESTED,
                summary="No profile selected.",
                group=GROUP_NETWORK,
            ),
            (),
        )
    literal = parse_ip_literal(profile.gateway)
    if literal is not None:
        return (
            _check(
                check_id="network.dns",
                label="DNS resolution",
                status=CheckStatus.INFO,
                summary="Not required (gateway is an IP address).",
                detail=literal,
                group=GROUP_NETWORK,
            ),
            (literal,),
        )
    result = resolve(profile.gateway, timeout=DNS_TIMEOUT_SECONDS)
    if result.timed_out:
        return (
            _check(
                check_id="network.dns",
                label="DNS resolution",
                status=CheckStatus.FAIL,
                summary=f"DNS lookup for {profile.gateway} timed out.",
                hint="Check local DNS configuration and retry.",
                group=GROUP_NETWORK,
            ),
            (),
        )
    if not result.addresses:
        return (
            _check(
                check_id="network.dns",
                label="DNS resolution",
                status=CheckStatus.FAIL,
                summary=f"DNS lookup for {profile.gateway} failed.",
                detail=result.error,
                hint="Verify the gateway hostname and DNS servers.",
                group=GROUP_NETWORK,
            ),
            (),
        )
    shown = ", ".join(result.addresses[:3])
    if len(result.addresses) > 3:
        shown = f"{shown}, …"
    return (
        _check(
            check_id="network.dns",
            label="DNS resolution",
            status=CheckStatus.PASS,
            summary=f"{profile.gateway} → {shown}",
            group=GROUP_NETWORK,
        ),
        result.addresses,
    )


@dataclass(frozen=True)
class RouteInfo:
    """Parsed ``ip route get`` fields."""

    destination: str
    via: str | None = None
    device: str | None = None
    source: str | None = None


_VIA_RE = re.compile(r"\bvia\s+(\S+)")
_DEV_RE = re.compile(r"\bdev\s+(\S+)")
_SRC_RE = re.compile(r"\bsrc\s+(\S+)")


def parse_ip_route_get(text: str) -> RouteInfo | None:
    """Extract destination/via/dev/src from ``ip route get`` output."""
    if not text or not text.strip():
        return None
    first = text.strip().splitlines()[0].strip()
    lowered = first.lower()
    if "unreachable" in lowered or "rtnetlink" in lowered or "network is unreachable" in lowered:
        return None
    parts = first.split()
    if not parts:
        return None
    destination = parts[0]
    via = match.group(1) if (match := _VIA_RE.search(first)) else None
    device = match.group(1) if (match := _DEV_RE.search(first)) else None
    source = match.group(1) if (match := _SRC_RE.search(first)) else None
    if device is None and via is None:
        return None
    return RouteInfo(destination=destination, via=via, device=device, source=source)


def format_route_summary(info: RouteInfo) -> str:
    """Return a concise route description."""
    bits: list[str] = []
    if info.via:
        bits.append(f"via {info.via}")
    if info.device:
        bits.append(f"dev {info.device}")
    if info.source:
        bits.append(f"src {info.source}")
    return " ".join(bits) if bits else info.destination


def check_route(
    profile: ConnectionProfile | None,
    addresses: Sequence[str],
    *,
    dns_failed: bool,
    include_network: bool,
    which: Which | None = None,
    run_command: RunArgv = run_argv,
) -> DiagnosticCheck:
    """Look up a unicast route toward the resolved gateway."""
    import shutil

    if not include_network:
        return _check(
            check_id="network.route",
            label="Route to gateway",
            status=CheckStatus.NOT_TESTED,
            summary="Run diagnostics to check the route.",
            group=GROUP_NETWORK,
        )
    if profile is None:
        return _check(
            check_id="network.route",
            label="Route to gateway",
            status=CheckStatus.NOT_TESTED,
            summary="No profile selected.",
            group=GROUP_NETWORK,
        )
    if dns_failed:
        return _check(
            check_id="network.route",
            label="Route to gateway",
            status=CheckStatus.NOT_TESTED,
            summary="DNS resolution failed.",
            group=GROUP_NETWORK,
        )
    if not addresses:
        return _check(
            check_id="network.route",
            label="Route to gateway",
            status=CheckStatus.NOT_TESTED,
            summary="No gateway address to look up.",
            group=GROUP_NETWORK,
        )
    locator = which or shutil.which
    ip_bin = locator("ip")
    if not ip_bin:
        return _check(
            check_id="network.route",
            label="Route to gateway",
            status=CheckStatus.WARNING,
            summary="The ip command was not found.",
            hint="Install iproute2 to inspect routes from Diagnostics.",
            group=GROUP_NETWORK,
        )
    target = addresses[0]
    if ":" in target:
        argv = [ip_bin, "-6", "route", "get", target]
    else:
        argv = [ip_bin, "route", "get", target]
    result = run_command(argv, timeout=ROUTE_TIMEOUT_SECONDS)
    if result.timed_out:
        return _check(
            check_id="network.route",
            label="Route to gateway",
            status=CheckStatus.WARNING,
            summary="Route lookup timed out.",
            group=GROUP_NETWORK,
        )
    if result.missing:
        return _check(
            check_id="network.route",
            label="Route to gateway",
            status=CheckStatus.WARNING,
            summary="The ip command was not found.",
            group=GROUP_NETWORK,
        )
    parsed = parse_ip_route_get(result.stdout or result.stderr)
    if parsed is None or (result.returncode not in {0, None}):
        return _check(
            check_id="network.route",
            label="Route to gateway",
            status=CheckStatus.FAIL,
            summary=f"No route to {target}.",
            hint="Check local network connectivity and default route.",
            group=GROUP_NETWORK,
        )
    return _check(
        check_id="network.route",
        label="Route to gateway",
        status=CheckStatus.PASS,
        summary=format_route_summary(parsed),
        detail=f"destination {parsed.destination}",
        group=GROUP_NETWORK,
    )


@dataclass(frozen=True)
class TcpResult:
    """Outcome of a TCP connect attempt."""

    ok: bool = False
    elapsed_ms: int | None = None
    kind: str = ""
    error: str = ""


def default_tcp_connect(host: str, port: int, timeout: float = TCP_TIMEOUT_SECONDS) -> TcpResult:
    """Bounded TCP connect. Success does not prove VPN authentication."""
    import time

    started = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            elapsed_ms = int((time.monotonic() - started) * 1000)
            return TcpResult(ok=True, elapsed_ms=elapsed_ms, kind="ok")
    except TimeoutError:
        return TcpResult(kind="timeout", error="timed out")
    except ConnectionRefusedError:
        return TcpResult(kind="refused", error="connection refused")
    except OSError as exc:
        err = exc.errno
        if err in {getattr(os, "ENETUNREACH", 101), getattr(os, "EHOSTUNREACH", 113)}:
            return TcpResult(kind="unreachable", error="network unreachable")
        if err == getattr(os, "ECONNREFUSED", 111):
            return TcpResult(kind="refused", error="connection refused")
        if err in {getattr(os, "ETIMEDOUT", 110), getattr(os, "EAGAIN", 11)}:
            return TcpResult(kind="timeout", error="timed out")
        return TcpResult(kind="error", error=str(exc.strerror or exc))


TcpConnect = Callable[..., TcpResult]


def check_tcp(
    profile: ConnectionProfile | None,
    addresses: Sequence[str],
    *,
    dns_failed: bool,
    include_network: bool,
    connect: TcpConnect = default_tcp_connect,
) -> DiagnosticCheck:
    """TCP connect to gateway:port. Not a SAML or TLS proof."""
    if not include_network:
        return _check(
            check_id="network.tcp",
            label="Gateway TCP",
            status=CheckStatus.NOT_TESTED,
            summary="Run diagnostics to test gateway reachability.",
            group=GROUP_NETWORK,
        )
    if profile is None:
        return _check(
            check_id="network.tcp",
            label="Gateway TCP",
            status=CheckStatus.NOT_TESTED,
            summary="No profile selected.",
            group=GROUP_NETWORK,
        )
    if dns_failed:
        return _check(
            check_id="network.tcp",
            label="Gateway TCP",
            status=CheckStatus.NOT_TESTED,
            summary="DNS resolution failed.",
            group=GROUP_NETWORK,
        )
    host = addresses[0] if addresses else profile.gateway
    port = profile.port
    result = connect(host, port, timeout=TCP_TIMEOUT_SECONDS)
    target = f"{profile.gateway}:{port}"
    if result.ok:
        elapsed = result.elapsed_ms if result.elapsed_ms is not None else 0
        return _check(
            check_id="network.tcp",
            label="Gateway TCP",
            status=CheckStatus.PASS,
            summary=f"{target} reachable in {elapsed} ms",
            detail=(
                "TCP connect succeeded. This does not prove SAML or VPN "
                "authentication will succeed."
            ),
            group=GROUP_NETWORK,
        )
    if result.kind == "timeout":
        summary = f"{target} timed out"
        hint = "The port did not accept a TCP connection in time."
    elif result.kind == "refused":
        summary = f"{target} connection refused"
        hint = "A host responded but the VPN port is closed."
    elif result.kind == "unreachable":
        summary = f"{target} network unreachable"
        hint = "Check routing and local network connectivity."
    else:
        summary = f"{target} could not be reached"
        hint = "Check DNS, routing, and firewall policy."
    return _check(
        check_id="network.tcp",
        label="Gateway TCP",
        status=CheckStatus.FAIL,
        summary=summary,
        detail=result.error,
        hint=hint,
        group=GROUP_NETWORK,
    )


@dataclass(frozen=True)
class InterfaceInfo:
    """One network interface discovered for diagnostics."""

    name: str
    address: str | None = None
    state: str = ""


_VPN_PREFIXES = ("ppp", "tun", "tap", "wg")
_BRIEF_ADDR_RE = re.compile(r"^(\S+)\s+(\S+)\s*(.*)$")


def is_likely_vpn_interface(name: str) -> bool:
    """Return True for common tunnel interface name prefixes. Not ppp0-only."""
    lowered = name.lower()
    return lowered.startswith(_VPN_PREFIXES)


def parse_ip_brief_addr(text: str) -> tuple[InterfaceInfo, ...]:
    """Parse ``ip -brief addr`` output."""
    items: list[InterfaceInfo] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        match = _BRIEF_ADDR_RE.match(line)
        if not match:
            continue
        name, state, rest = match.group(1), match.group(2), match.group(3).strip()
        address = None
        if rest and rest != "-":
            token = rest.split()[0]
            address = token.split("/")[0]
        items.append(InterfaceInfo(name=name, address=address, state=state))
    return tuple(items)


def default_list_interfaces(
    run_command: RunArgv = run_argv,
    which: Which | None = None,
) -> tuple[InterfaceInfo, ...]:
    """List interfaces using ``ip`` when available, else sysfs names."""
    import shutil

    locator = which or shutil.which
    ip_bin = locator("ip")
    if ip_bin:
        result = run_command([ip_bin, "-brief", "addr"], timeout=ROUTE_TIMEOUT_SECONDS)
        if not result.timed_out and not result.missing and result.stdout:
            parsed = parse_ip_brief_addr(result.stdout)
            if parsed:
                return parsed
    return _list_interfaces_sysfs()


def _list_interfaces_sysfs() -> tuple[InterfaceInfo, ...]:
    root = Path("/sys/class/net")
    if not root.is_dir():
        return ()
    items: list[InterfaceInfo] = []
    try:
        entries = sorted(root.iterdir())
    except OSError:
        return ()
    for entry in entries:
        name = entry.name
        if name == "lo":
            continue
        state = ""
        try:
            state = (entry / "operstate").read_text(encoding="utf-8").strip()
        except OSError:
            state = ""
        items.append(InterfaceInfo(name=name, state=state))
    return tuple(items)


ListInterfaces = Callable[..., tuple[InterfaceInfo, ...]]


def check_vpn_interface(
    snapshot: VpnSnapshot,
    *,
    include_network: bool,
    list_interfaces: ListInterfaces | None = None,
    run_command: RunArgv = run_argv,
    which: Which | None = None,
) -> tuple[DiagnosticCheck, InterfaceInfo | None]:
    """Report a likely VPN interface when connected. Never assumes only ppp0."""
    if snapshot.state is not ConnectionState.CONNECTED:
        return (
            _check(
                check_id="tunnel.interface",
                label="VPN interface",
                status=CheckStatus.INFO,
                summary="No VPN interface detected.",
                detail="The application is not connected.",
                group=GROUP_TUNNEL,
            ),
            None,
        )

    def _enumerate() -> tuple[InterfaceInfo, ...]:
        if list_interfaces is not None:
            return list_interfaces()
        if include_network:
            return default_list_interfaces(run_command=run_command, which=which)
        return _list_interfaces_sysfs()

    try:
        interfaces = _enumerate()
    except OSError:
        interfaces = ()
    vpn_ifaces = [item for item in interfaces if is_likely_vpn_interface(item.name)]
    chosen = vpn_ifaces[0] if vpn_ifaces else None
    if chosen is None:
        return (
            _check(
                check_id="tunnel.interface",
                label="VPN interface",
                status=CheckStatus.WARNING,
                summary="Connected but no tunnel interface was identified.",
                detail="openfortivpn often uses a PPP or tun interface; none matched.",
                group=GROUP_TUNNEL,
            ),
            None,
        )
    address = chosen.address or "address unknown"
    state = chosen.state or "unknown"
    return (
        _check(
            check_id="tunnel.interface",
            label="VPN interface",
            status=CheckStatus.PASS,
            summary=f"{chosen.name} {address} ({state})",
            group=GROUP_TUNNEL,
        ),
        chosen,
    )


def check_vpn_routes(
    snapshot: VpnSnapshot,
    interface: InterfaceInfo | None,
    *,
    include_network: bool,
    which: Which | None = None,
    run_command: RunArgv = run_argv,
) -> DiagnosticCheck:
    """Describe tunnel routes as INFO. Does not fail split vs full tunnel."""
    import shutil

    if snapshot.state is not ConnectionState.CONNECTED:
        return _check(
            check_id="tunnel.routes",
            label="VPN routes",
            status=CheckStatus.INFO,
            summary="Not connected.",
            group=GROUP_TUNNEL,
        )
    if not include_network:
        return _check(
            check_id="tunnel.routes",
            label="VPN routes",
            status=CheckStatus.NOT_TESTED,
            summary="Run diagnostics to inspect tunnel routes.",
            group=GROUP_TUNNEL,
        )
    if interface is None:
        return _check(
            check_id="tunnel.routes",
            label="VPN routes",
            status=CheckStatus.INFO,
            summary="No tunnel interface available to inspect routes.",
            group=GROUP_TUNNEL,
        )
    locator = which or shutil.which
    ip_bin = locator("ip")
    if not ip_bin:
        return _check(
            check_id="tunnel.routes",
            label="VPN routes",
            status=CheckStatus.INFO,
            summary="The ip command was not found; tunnel routes were not listed.",
            group=GROUP_TUNNEL,
        )
    result = run_command(
        [ip_bin, "route", "show", "dev", interface.name],
        timeout=ROUTE_TIMEOUT_SECONDS,
    )
    if result.timed_out or result.missing:
        return _check(
            check_id="tunnel.routes",
            label="VPN routes",
            status=CheckStatus.INFO,
            summary="Tunnel routes could not be listed.",
            group=GROUP_TUNNEL,
        )
    lines = [line.strip() for line in (result.stdout or "").splitlines() if line.strip()]
    if not lines:
        return _check(
            check_id="tunnel.routes",
            label="VPN routes",
            status=CheckStatus.INFO,
            summary="No routes listed on the tunnel interface (split-tunnel is normal).",
            detail=interface.name,
            group=GROUP_TUNNEL,
        )
    preview = "; ".join(lines[:3])
    extra = f" ({len(lines)} routes)" if len(lines) > 3 else ""
    return _check(
        check_id="tunnel.routes",
        label="VPN routes",
        status=CheckStatus.INFO,
        summary=f"{preview}{extra}",
        detail=f"Routes on {interface.name}. Full-tunnel and split-tunnel layouts both occur.",
        group=GROUP_TUNNEL,
    )
