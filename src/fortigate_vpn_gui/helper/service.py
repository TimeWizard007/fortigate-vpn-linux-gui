# SPDX-License-Identifier: GPL-3.0-or-later
"""Privileged helper service: one owned openfortivpn process.

The GUI must not spawn openfortivpn. This service validates structured
requests, builds argv, and owns the child process group.
"""

from __future__ import annotations

import json
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from subprocess import TimeoutExpired

from fortigate_vpn_gui.helper.argv import build_helper_argv, is_approved_openfortivpn_path
from fortigate_vpn_gui.helper.certificate import (
    CertificateFailureParser,
    is_certificate_validation_failure,
)
from fortigate_vpn_gui.helper.executables import resolve_approved_executable
from fortigate_vpn_gui.helper.ipsec_dns import (
    apply_temporary_vpn_dns,
    lookup_interface_for_address,
    parse_dns_server_line,
    parse_virtual_ip_line,
    restore_from_state_path,
)
from fortigate_vpn_gui.helper.ipsec_runtime import (
    IpsecRuntimeFiles,
    create_runtime_dir,
    settings_from_request,
    wipe_ipsec_runtime,
    write_ipsec_runtime,
)
from fortigate_vpn_gui.helper.protocol import (
    BACKEND_IPSEC,
    HELPER_VERSION,
    PROTOCOL_VERSION,
    ConnectRequest,
    HelperError,
    HelperEvent,
    HelperEventKind,
    HelperProtocolError,
)
from fortigate_vpn_gui.helper.validation import parse_credentials_payload, parse_request_line
from fortigate_vpn_gui.vpn.capabilities import (
    OpenfortivpnCapabilities,
    format_saml_unsupported_message,
)
from fortigate_vpn_gui.vpn.classify import OutputHint, classify_output
from fortigate_vpn_gui.vpn.ipsec.commands import (
    build_charon_argv,
    build_charon_environment,
    build_swanctl_initiate_argv,
    build_swanctl_load_argv,
    build_swanctl_terminate_argv,
)
from fortigate_vpn_gui.vpn.ipsec.detect import (
    discover_ipsec_backend,
    is_approved_charon_path,
    is_approved_swanctl_path,
)
from fortigate_vpn_gui.vpn.ipsec.secrets import IpsecCredentials
from fortigate_vpn_gui.vpn.log_redaction import redact_log_line
from fortigate_vpn_gui.vpn.process import ProcessFactory, VpnProcess, default_process_factory
from fortigate_vpn_gui.vpn.saml_parse import SamlEventKind, parse_saml_output
from fortigate_vpn_gui.vpn.url_safety import InvalidAuthUrl, validate_auth_url

Selector = Callable[[bool], OpenfortivpnCapabilities | None]
HelperListener = Callable[[HelperEvent], None]
SwanctlRunner = Callable[[list[str], float], "SwanctlCommandResult"]
ViciWait = Callable[[Path, float], bool]
CHARON_VICI_WAIT_SECONDS = 5.0
CHARON_READY_POLL_SECONDS = 0.05
_IPSEC_STARTUP_LOG_LIMIT = 32


@dataclass(frozen=True)
class SwanctlCommandResult:
    """Captured swanctl output. Must never be logged unredacted."""

    returncode: int
    stdout: str = ""
    stderr: str = ""


class HelperService:
    """In-process helper used by the privileged main loop and by tests."""

    def __init__(
        self,
        *,
        process_factory: ProcessFactory = default_process_factory,
        selector: Selector | None = None,
        listener: HelperListener | None = None,
        grace_seconds: float = 5.0,
        ipsec_discover: Callable[[], object] | None = None,
        runtime_dir_factory: Callable[[], object] | None = None,
        swanctl_runner: SwanctlRunner | None = None,
        vici_wait: ViciWait | None = None,
    ) -> None:
        self._factory = process_factory
        self._selector = selector if selector is not None else _default_selector
        self._listener = listener
        self._grace_seconds = grace_seconds
        self._ipsec_discover = ipsec_discover or discover_ipsec_backend
        self._runtime_dir_factory = runtime_dir_factory or create_runtime_dir
        self._swanctl_runner = swanctl_runner or default_swanctl_runner
        self._vici_wait = vici_wait or wait_for_unix_socket
        self._lock = threading.Lock()
        self._process: VpnProcess | None = None
        self._argv: tuple[str, ...] = ()
        self._capabilities: OpenfortivpnCapabilities | None = None
        self._cert_parser = CertificateFailureParser()
        self._saml = False
        self._emitted_cert_sha: str | None = None
        self._connected_emitted = False
        self._saml_url_emitted = False
        self._pending_ipsec: ConnectRequest | None = None
        self._ipsec_runtime: Path | None = None
        self._ipsec_files: IpsecRuntimeFiles | None = None
        self._ipsec_swanctl: str | None = None
        self._ipsec_cancel = threading.Event()
        self._ipsec_worker: threading.Thread | None = None
        self._ipsec_startup_logs: list[str] = []
        self._ipsec_start_error_emitted = False
        self._swanctl_cli_error_logged = False
        self._ipsec_dns_servers: list[str] = []
        self._ipsec_vip: str | None = None
        self._ipsec_dns_applied = False

    def set_listener(self, listener: HelperListener | None) -> None:
        self._listener = listener

    @property
    def process(self) -> VpnProcess | None:
        return self._process

    def is_running(self) -> bool:
        with self._lock:
            return self._process is not None and self._process.poll() is None

    def pid(self) -> int | None:
        with self._lock:
            if self._process is None:
                return None
            return self._process.pid

    def argv(self) -> tuple[str, ...]:
        with self._lock:
            return self._argv

    def wait_for_ipsec_setup(self, timeout: float = 2.0) -> None:
        """Join the background swanctl load/initiate worker (tests)."""
        worker = self._ipsec_worker
        if worker is not None:
            worker.join(timeout=timeout)

    def handle_line(self, line: str) -> HelperEvent | None:
        """Handle one JSON-lines request. Returns an immediate event if any."""
        operation, request, request_id = parse_request_line(line)
        if operation == "hello":
            event = HelperEvent(
                kind=HelperEventKind.HELLO,
                request_id=request_id,
                helper_version=HELPER_VERSION,
                protocol_version=PROTOCOL_VERSION,
            )
            self._emit(event)
            return event
        if operation == "status":
            return self.status(request_id=request_id)
        if operation == "disconnect":
            self.disconnect()
            event = HelperEvent(
                kind=HelperEventKind.ACK,
                request_id=request_id,
                state="disconnecting",
            )
            self._emit(event)
            return event
        if operation == "connect":
            assert request is not None
            if request.backend == BACKEND_IPSEC:
                self._pending_ipsec = request
                event = HelperEvent(
                    kind=HelperEventKind.ACK,
                    request_id=request_id,
                    state="starting",
                    backend=BACKEND_IPSEC,
                )
                self._emit(event)
                return event
            self.connect(request)
            event = HelperEvent(kind=HelperEventKind.ACK, request_id=request_id, state="starting")
            self._emit(event)
            return event
        if operation == "credentials":
            pending = self._pending_ipsec
            self._pending_ipsec = None
            if pending is None:
                raise HelperProtocolError(
                    "INVALID_CREDENTIALS",
                    "Credentials were sent without an IPsec connect request.",
                )
            payload = json.loads(line)
            credentials = parse_credentials_payload(payload)
            self.connect(pending, credentials=credentials)
            event = HelperEvent(
                kind=HelperEventKind.ACK,
                request_id=request_id,
                state="starting",
                backend=BACKEND_IPSEC,
            )
            self._emit(event)
            return event
        raise HelperProtocolError("UNSUPPORTED_OPERATION", "Unsupported helper operation.")

    def connect(
        self,
        request: ConnectRequest,
        credentials: IpsecCredentials | None = None,
    ) -> None:
        """Start the selected VPN backend for a validated request."""
        with self._lock:
            if self._process is not None and self._process.poll() is None:
                raise HelperProtocolError(
                    "ALREADY_CONNECTED",
                    "A privileged VPN process is already running.",
                )
        if request.backend == BACKEND_IPSEC:
            self._connect_ipsec(request, credentials)
            return
        self._connect_openfortivpn(request)

    def _connect_openfortivpn(self, request: ConnectRequest) -> None:
        """Start openfortivpn for a validated SSL VPN request."""
        capabilities = self._selector(request.auth_mode == "saml")
        if capabilities is None:
            if request.auth_mode == "saml":
                fallback = self._selector(False)
                if fallback is not None:
                    raise HelperError(
                        "SSO_NOT_SUPPORTED",
                        format_saml_unsupported_message(fallback.version),
                    )
            raise HelperError("OPENFORTIVPN_MISSING", "openfortivpn executable was not found.")
        if not is_approved_openfortivpn_path(capabilities.executable_path):
            raise HelperProtocolError(
                "INVALID_EXECUTABLE",
                "Refusing to execute a binary that is not an approved openfortivpn path.",
            )
        argv = build_helper_argv(
            executable=capabilities.executable_path,
            gateway=request.gateway,
            port=request.port,
            auth_mode=request.auth_mode,
            trusted_certificate_fingerprint=request.trusted_certificate_fingerprint,
        )
        self._cert_parser.reset()
        self._saml = request.auth_mode == "saml"
        self._emitted_cert_sha = None
        self._connected_emitted = False
        self._saml_url_emitted = False
        with self._lock:
            self._argv = tuple(argv)
            self._capabilities = capabilities
        process = self._spawn_owned_process(argv)
        try:
            process.start()
        except OSError as exc:
            raise HelperError("FAILED_TO_START", "openfortivpn failed to start.") from exc
        with self._lock:
            self._process = process
        self._emit(
            HelperEvent(
                kind=HelperEventKind.STARTED,
                pid=process.pid,
                argv=tuple(argv),
                selected_executable=capabilities.executable_path,
                openfortivpn_version=capabilities.version,
                supports_saml=capabilities.supports_saml,
                state="starting",
                backend="openfortivpn",
            )
        )

    def _connect_ipsec(
        self,
        request: ConnectRequest,
        credentials: IpsecCredentials | None,
    ) -> None:
        """Start a private charon instance and load/initiate via swanctl."""
        if credentials is None:
            raise HelperProtocolError(
                "INVALID_CREDENTIALS",
                "IPsec connect requires a pre-shared key and XAuth credentials.",
            )
        settings = settings_from_request(request.ipsec)
        if not settings.is_supported():
            raise HelperError("UNSUPPORTED_IPSEC", settings.support_summary())
        capabilities = self._ipsec_discover()
        charon = getattr(capabilities, "charon_path", None)
        swanctl = getattr(capabilities, "swanctl_path", None)
        if not getattr(capabilities, "available", False) or not charon or not swanctl:
            raise HelperError(
                "IPSEC_BACKEND_MISSING",
                "strongSwan (charon/swanctl) was not found. Install the distribution "
                "strongSwan packages; they are not bundled with this application.",
            )
        if not is_approved_charon_path(str(charon)) or not is_approved_swanctl_path(str(swanctl)):
            raise HelperProtocolError(
                "INVALID_EXECUTABLE",
                "Refusing to execute a binary that is not an approved IPsec path.",
            )
        runtime_dir = Path(str(self._runtime_dir_factory()))
        files = write_ipsec_runtime(
            gateway=request.gateway,
            port=request.port,
            settings=settings,
            credentials=credentials,
            runtime_dir=runtime_dir,
        )
        credentials.wipe()
        try:
            argv = build_charon_argv(str(charon))
            env = build_charon_environment(str(files.strongswan_conf))
        except ValueError as exc:
            wipe_ipsec_runtime(files)
            raise HelperProtocolError("INVALID_EXECUTABLE", str(exc)) from exc
        self._cert_parser.reset()
        self._saml = False
        self._emitted_cert_sha = None
        self._connected_emitted = False
        self._saml_url_emitted = False
        self._ipsec_cancel.clear()
        with self._lock:
            self._argv = tuple(argv)
            self._ipsec_runtime = runtime_dir
            self._ipsec_files = files
            self._ipsec_swanctl = str(swanctl)
            self._ipsec_startup_logs = []
            self._ipsec_start_error_emitted = False
            self._swanctl_cli_error_logged = False
            self._ipsec_dns_servers = []
            self._ipsec_vip = None
            self._ipsec_dns_applied = False
        process = self._spawn_owned_process(argv, env=env)
        try:
            process.start()
        except OSError as exc:
            wipe_ipsec_runtime(files)
            with self._lock:
                self._ipsec_runtime = None
                self._ipsec_files = None
                self._ipsec_swanctl = None
            raise HelperError(
                "IPSEC_DAEMON_START_FAILED",
                "The IPsec daemon failed to start.",
            ) from exc
        with self._lock:
            self._process = process
        self._emit(
            HelperEvent(
                kind=HelperEventKind.STARTED,
                pid=process.pid,
                argv=tuple(argv),
                selected_executable=str(charon),
                state="starting",
                backend=BACKEND_IPSEC,
            )
        )
        worker = threading.Thread(
            target=self._ipsec_bring_up,
            args=(files, str(swanctl)),
            name="helper-ipsec-bringup",
            daemon=True,
        )
        self._ipsec_worker = worker
        worker.start()

    def disconnect(self, *, wait: bool = True, grace_seconds: float | None = None) -> None:
        """SIGTERM the process group, then SIGKILL if it does not exit."""
        grace = self._grace_seconds if grace_seconds is None else grace_seconds
        self._ipsec_cancel.set()
        self._ipsec_terminate_sa()
        self._restore_ipsec_dns()
        with self._lock:
            process = self._process
            files = self._ipsec_files
        if process is None:
            wipe_ipsec_runtime(files)
            with self._lock:
                self._ipsec_runtime = None
                self._ipsec_files = None
                self._ipsec_swanctl = None
            return
        process.terminate()
        if not wait:
            worker = threading.Thread(
                target=self._await_stop,
                args=(process, grace),
                name="helper-stop",
                daemon=True,
            )
            worker.start()
            return
        self._await_stop(process, grace)

    def status(self, request_id: str | None = None) -> HelperEvent:
        event = HelperEvent(
            kind=HelperEventKind.STATUS,
            request_id=request_id,
            running=self.is_running(),
            pid=self.pid(),
            argv=self.argv(),
            helper_version=HELPER_VERSION,
            protocol_version=PROTOCOL_VERSION,
        )
        self._emit(event)
        return event

    def _await_stop(self, process: VpnProcess, grace: float) -> None:
        try:
            process.wait(timeout=grace)
            return
        except TimeoutExpired:
            pass
        except Exception:
            pass
        process.kill()
        try:
            process.wait(timeout=2)
        except (TimeoutExpired, Exception):
            pass

    def _on_output(self, line: str) -> None:
        redacted = redact_log_line(line)
        with self._lock:
            if self._ipsec_files is not None and not self._connected_emitted:
                self._ipsec_startup_logs.append(redacted)
                overflow = len(self._ipsec_startup_logs) - _IPSEC_STARTUP_LOG_LIMIT
                if overflow > 0:
                    del self._ipsec_startup_logs[:overflow]
        self._emit(HelperEvent(kind=HelperEventKind.LOG, line=redacted))
        self._note_ipsec_dns_line(redacted)
        cert = self._cert_parser.feed(line)
        if is_certificate_validation_failure(line) or cert is not None:
            info = cert or self._cert_parser.snapshot()
            if info is not None and info.sha256 != self._emitted_cert_sha:
                self._emitted_cert_sha = info.sha256
                self._emit(
                    HelperEvent(
                        kind=HelperEventKind.CERTIFICATE,
                        certificate=info,
                        line=redacted,
                    )
                )
        if classify_output(redacted) is OutputHint.CONNECTED and not self._connected_emitted:
            self._connected_emitted = True
            self._apply_ipsec_dns()
            self._emit(HelperEvent(kind=HelperEventKind.CONNECTED, line=redacted))
        if not self._saml:
            return
        parsed = parse_saml_output(line)
        if parsed.kind is SamlEventKind.AUTH_URL and parsed.url:
            try:
                url = str(validate_auth_url(parsed.url))
            except InvalidAuthUrl:
                self._emit(
                    HelperEvent(
                        kind=HelperEventKind.ERROR,
                        code="INVALID_AUTH_URL",
                        message="openfortivpn produced a sign-in URL that is not safe to open.",
                    )
                )
                return
            if self._saml_url_emitted:
                return
            self._saml_url_emitted = True
            self._emit(HelperEvent(kind=HelperEventKind.SAML_URL, url=url))
            return
        if parsed.kind is SamlEventKind.LISTENER_READY:
            self._emit(HelperEvent(kind=HelperEventKind.SAML_LISTENER))
            return
        if parsed.kind is SamlEventKind.WAITING:
            self._emit(HelperEvent(kind=HelperEventKind.SAML_WAITING))
            return
        if parsed.kind is SamlEventKind.SUCCESS:
            self._emit(HelperEvent(kind=HelperEventKind.SAML_SUCCESS))
            return
        if parsed.kind is SamlEventKind.FAILURE:
            self._emit(HelperEvent(kind=HelperEventKind.SAML_FAILURE))

    def _on_exit(self, code: int) -> None:
        with self._lock:
            self._process = None
            argv = self._argv
            self._argv = ()
            runtime = self._ipsec_runtime
            files = self._ipsec_files
            was_ipsec = runtime is not None or files is not None
            connected = self._connected_emitted
            cancelled = self._ipsec_cancel.is_set()
            startup_logs = list(self._ipsec_startup_logs)
            self._ipsec_runtime = None
            self._ipsec_files = None
            self._ipsec_swanctl = None
            self._ipsec_startup_logs = []
            self._ipsec_dns_servers = []
            self._ipsec_vip = None
            self._ipsec_dns_applied = False
        self._restore_ipsec_dns(files)
        wipe_ipsec_runtime(files)
        if was_ipsec and not connected and not cancelled:
            self._emit_ipsec_daemon_start_failed(_charon_exit_message(code, startup_logs))
        self._emit(HelperEvent(kind=HelperEventKind.EXIT, exit_code=code, argv=argv))

    def _ipsec_bring_up(self, files: IpsecRuntimeFiles, swanctl: str) -> None:
        """Load swanctl.conf and initiate the CHILD SA without blocking JSON-lines."""
        if self._ipsec_cancel.is_set():
            return
        with self._lock:
            owned = self._process

        def poll_exit() -> int | None:
            if owned is not None:
                return owned.poll()
            with self._lock:
                current = self._process
            if current is None:
                return 1
            return current.poll()

        outcome = wait_for_charon_ready(
            files.vici_socket,
            CHARON_VICI_WAIT_SECONDS,
            poll_exit=poll_exit,
            socket_wait=self._vici_wait,
            cancelled=self._ipsec_cancel.is_set,
        )
        if outcome == "cancelled":
            return
        if outcome == "exited":
            code = poll_exit()
            with self._lock:
                logs = list(self._ipsec_startup_logs)
            self._emit_ipsec_daemon_start_failed(
                _charon_exit_message(1 if code is None else code, logs)
            )
            self.disconnect(wait=False)
            return
        if outcome == "timeout":
            self._emit_ipsec_daemon_start_failed(
                "The IPsec daemon did not open its control socket."
            )
            self.disconnect(wait=False)
            return
        if self._ipsec_cancel.is_set():
            return
        try:
            load_argv = build_swanctl_load_argv(swanctl, str(files.swanctl_conf))
            initiate_argv = build_swanctl_initiate_argv(swanctl)
        except ValueError as exc:
            self._emit(
                HelperEvent(kind=HelperEventKind.ERROR, code="INVALID_EXECUTABLE", message=str(exc))
            )
            self.disconnect(wait=False)
            return
        load = self._run_swanctl(load_argv, timeout=10.0)
        if load.returncode != 0:
            self._emit(
                HelperEvent(
                    kind=HelperEventKind.ERROR,
                    code="FAILED_TO_START",
                    message="IPsec configuration could not be loaded.",
                )
            )
            self.disconnect(wait=False)
            return
        if self._ipsec_cancel.is_set():
            return
        initiate = self._run_swanctl(initiate_argv, timeout=60.0)
        if initiate.returncode != 0:
            self._emit(
                HelperEvent(
                    kind=HelperEventKind.ERROR,
                    code="VPN_PROCESS_FAILED",
                    message="IPsec initiation failed. See Logs for non-secret details.",
                )
            )
            self.disconnect(wait=False)
            return
        if not self._connected_emitted:
            self._connected_emitted = True
            self._apply_ipsec_dns()
            self._emit(
                HelperEvent(
                    kind=HelperEventKind.CONNECTED,
                    line="IPsec CHILD SA established",
                )
            )

    def _ipsec_terminate_sa(self) -> None:
        with self._lock:
            files = self._ipsec_files
            swanctl = self._ipsec_swanctl
        if files is None or not swanctl:
            return
        try:
            argv = build_swanctl_terminate_argv(swanctl)
        except ValueError:
            return
        self._run_swanctl(argv, timeout=5.0)

    def _run_swanctl(self, argv: list[str], *, timeout: float) -> SwanctlCommandResult:
        result = self._swanctl_runner(argv, timeout)
        useful = [
            line
            for stream in (result.stdout, result.stderr)
            for line in stream.splitlines()
            if line and not _is_swanctl_usage_line(line)
        ]
        cli_error = any(_is_swanctl_cli_parse_line(line) for line in useful)
        with self._lock:
            skip_repeat = cli_error and self._swanctl_cli_error_logged
            if cli_error:
                self._swanctl_cli_error_logged = True
        if skip_repeat:
            return result
        for line in useful:
            self._on_output(line)
        return result

    def _note_ipsec_dns_line(self, line: str) -> None:
        dns = parse_dns_server_line(line)
        vip = parse_virtual_ip_line(line)
        if dns is None and vip is None:
            return
        with self._lock:
            if dns is not None and dns not in self._ipsec_dns_servers:
                self._ipsec_dns_servers.append(dns)
            if vip is not None:
                self._ipsec_vip = vip
            connected = self._connected_emitted
        if connected:
            self._apply_ipsec_dns()

    def _apply_ipsec_dns(self) -> None:
        with self._lock:
            if self._ipsec_dns_applied:
                return
            servers = tuple(self._ipsec_dns_servers)
            vip = self._ipsec_vip
            files = self._ipsec_files
        if not servers or files is None:
            return
        interface = lookup_interface_for_address(vip) if vip else None
        if not interface:
            return
        try:
            state = apply_temporary_vpn_dns(interface, servers, files.dns_state)
        except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
            self._on_output(f"VPN DNS could not be applied via resolvectl: {exc}")
            return
        with self._lock:
            self._ipsec_dns_applied = True
        pre = state.pre_vpn
        if pre is not None:
            pre_servers = ", ".join(pre.servers) if pre.servers else "(none)"
            pre_domains = ", ".join(pre.domains) if pre.domains else "(none)"
            nm = "yes" if state.nm_managed else "no"
            self._on_output(
                "preserved pre-VPN DNS on "
                f"{interface}: servers={pre_servers} domains={pre_domains} nm-managed={nm}"
            )
        joined = ", ".join(servers)
        self._on_output(f"applied VPN DNS {joined} on {interface}")

    def _restore_ipsec_dns(self, files: IpsecRuntimeFiles | None = None) -> None:
        with self._lock:
            target = files if files is not None else self._ipsec_files
            self._ipsec_dns_applied = False
        if target is None:
            return
        result = restore_from_state_path(target.dns_state)
        if result is None:
            return
        status = "verified" if result.verified else "unverified"
        self._on_output(f"IPsec DNS cleanup {status}: {result.detail}")
        summary = " | ".join(
            line.strip() for line in (result.status_text or "").splitlines()[:12] if line.strip()
        )
        if summary:
            self._on_output(f"resolvectl status after DNS cleanup: {summary}")

    def _spawn_owned_process(
        self, argv: list[str], *, env: dict[str, str] | None = None
    ) -> VpnProcess:
        try:
            return self._factory(argv, self._on_output, self._on_exit, env=env)
        except TypeError:
            return self._factory(argv, self._on_output, self._on_exit)

    def _emit_ipsec_daemon_start_failed(self, message: str) -> None:
        with self._lock:
            if self._ipsec_start_error_emitted:
                return
            self._ipsec_start_error_emitted = True
        self._emit(
            HelperEvent(
                kind=HelperEventKind.ERROR,
                code="IPSEC_DAEMON_START_FAILED",
                message=message,
            )
        )

    def _emit(self, event: HelperEvent) -> None:
        listener = self._listener
        if listener is not None:
            listener(event)


def _default_selector(require_saml: bool) -> OpenfortivpnCapabilities | None:
    return resolve_approved_executable(require_saml=require_saml)


def default_swanctl_runner(argv: list[str], timeout: float) -> SwanctlCommandResult:
    """Run allowlisted swanctl with a list argv. Never uses a shell."""
    try:
        completed = subprocess.run(  # noqa: S603 — list argv, shell=False
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            check=False,
        )
    except FileNotFoundError:
        return SwanctlCommandResult(returncode=127, stderr="swanctl executable was not found.")
    except subprocess.TimeoutExpired:
        return SwanctlCommandResult(returncode=124, stderr="swanctl timed out.")
    return SwanctlCommandResult(
        completed.returncode,
        completed.stdout or "",
        completed.stderr or "",
    )


def _is_swanctl_usage_line(line: str) -> bool:
    """Return True for swanctl usage-banner lines that flood the GUI log."""
    stripped = line.strip()
    if not stripped:
        return False
    lowered = stripped.lower()
    if lowered == "usage:" or lowered.startswith("usage:"):
        return True
    if stripped.startswith("swanctl --"):
        return True
    if stripped.startswith("--") and " (-" in stripped:
        return True
    if lowered.startswith("strongswan ") and "swanctl" in lowered:
        return True
    return lowered.startswith("loaded plugins:")


def _is_swanctl_cli_parse_line(line: str) -> bool:
    """Return True for a swanctl getopt/operation rejection line."""
    lowered = line.lower()
    if "unrecognized option" in lowered:
        return True
    if "invalid operation" in lowered:
        return True
    return "invalid --" in lowered and "option" in lowered


def wait_for_unix_socket(path: Path, timeout: float) -> bool:
    """Return True when *path* exists before *timeout* seconds elapse."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return True
        time.sleep(CHARON_READY_POLL_SECONDS)
    return False


def wait_for_charon_ready(
    path: Path,
    timeout: float,
    *,
    poll_exit: Callable[[], int | None],
    socket_wait: ViciWait,
    cancelled: Callable[[], bool] | None = None,
) -> str:
    """Wait for the private VICI socket, or return as soon as charon exits.

    Returns ``ready``, ``exited``, ``cancelled``, or ``timeout``.
    """
    deadline = time.monotonic() + timeout
    while True:
        if cancelled is not None and cancelled():
            return "cancelled"
        if poll_exit() is not None:
            return "exited"
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        slice_timeout = min(CHARON_READY_POLL_SECONDS, remaining)
        if socket_wait(path, slice_timeout):
            if poll_exit() is not None:
                return "exited"
            return "ready"
    if cancelled is not None and cancelled():
        return "cancelled"
    if poll_exit() is not None:
        return "exited"
    return "timeout"


def _charon_exit_message(code: int, logs: list[str]) -> str:
    """Describe an early charon exit using already-redacted startup output."""
    message = (
        f"The IPsec daemon exited before opening its control socket (status {code})."
    )
    detail = ""
    for line in reversed(logs):
        text = line.strip()
        if not text:
            continue
        if text.lower().startswith("usage:"):
            continue
        detail = text
        break
    if detail:
        return f"{message} Last output: {detail}"
    return message
