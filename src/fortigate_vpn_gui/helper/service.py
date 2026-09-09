# SPDX-License-Identifier: GPL-3.0-or-later
"""Privileged helper service: one owned openfortivpn process.

The GUI must not spawn openfortivpn. This service validates structured
requests, builds argv, and owns the child process group.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from subprocess import TimeoutExpired

from fortigate_vpn_gui.helper.argv import build_helper_argv, is_approved_openfortivpn_path
from fortigate_vpn_gui.helper.certificate import (
    CertificateFailureParser,
    is_certificate_validation_failure,
)
from fortigate_vpn_gui.helper.executables import resolve_approved_executable
from fortigate_vpn_gui.helper.protocol import (
    HELPER_VERSION,
    PROTOCOL_VERSION,
    ConnectRequest,
    HelperError,
    HelperEvent,
    HelperEventKind,
    HelperProtocolError,
)
from fortigate_vpn_gui.helper.validation import parse_request_line
from fortigate_vpn_gui.vpn.capabilities import OpenfortivpnCapabilities
from fortigate_vpn_gui.vpn.classify import OutputHint, classify_output
from fortigate_vpn_gui.vpn.log_redaction import redact_log_line
from fortigate_vpn_gui.vpn.process import ProcessFactory, VpnProcess, default_process_factory
from fortigate_vpn_gui.vpn.saml_parse import SamlEventKind, parse_saml_output
from fortigate_vpn_gui.vpn.url_safety import InvalidAuthUrl, validate_auth_url

Selector = Callable[[bool], OpenfortivpnCapabilities | None]
HelperListener = Callable[[HelperEvent], None]


class HelperService:
    """In-process helper used by the privileged main loop and by tests."""

    def __init__(
        self,
        *,
        process_factory: ProcessFactory = default_process_factory,
        selector: Selector | None = None,
        listener: HelperListener | None = None,
        grace_seconds: float = 5.0,
    ) -> None:
        self._factory = process_factory
        self._selector = selector if selector is not None else _default_selector
        self._listener = listener
        self._grace_seconds = grace_seconds
        self._lock = threading.Lock()
        self._process: VpnProcess | None = None
        self._argv: tuple[str, ...] = ()
        self._capabilities: OpenfortivpnCapabilities | None = None
        self._cert_parser = CertificateFailureParser()
        self._saml = False

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
            self.connect(request)
            event = HelperEvent(kind=HelperEventKind.ACK, request_id=request_id, state="starting")
            self._emit(event)
            return event
        raise HelperProtocolError("UNSUPPORTED_OPERATION", "Unsupported helper operation.")

    def connect(self, request: ConnectRequest) -> None:
        """Start openfortivpn for a validated request. Rejects duplicates."""
        with self._lock:
            if self._process is not None and self._process.poll() is None:
                raise HelperProtocolError(
                    "ALREADY_CONNECTED",
                    "A privileged VPN process is already running.",
                )
        capabilities = self._selector(request.auth_mode == "saml")
        if capabilities is None:
            if request.auth_mode == "saml" and self._selector(False) is not None:
                raise HelperError(
                    "SSO_NOT_SUPPORTED",
                    "SAML/SSO requires openfortivpn with --saml-login support.",
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
        with self._lock:
            self._argv = tuple(argv)
            self._capabilities = capabilities
        process = self._factory(argv, self._on_output, self._on_exit)
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
            )
        )

    def disconnect(self, *, wait: bool = True, grace_seconds: float | None = None) -> None:
        """SIGTERM the process group, then SIGKILL if it does not exit."""
        grace = self._grace_seconds if grace_seconds is None else grace_seconds
        with self._lock:
            process = self._process
        if process is None:
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
        self._emit(HelperEvent(kind=HelperEventKind.LOG, line=redacted))
        cert = self._cert_parser.feed(line)
        if is_certificate_validation_failure(line) or cert is not None:
            info = cert or self._cert_parser.snapshot()
            if info is not None:
                self._emit(
                    HelperEvent(
                        kind=HelperEventKind.CERTIFICATE,
                        certificate=info,
                        line=redacted,
                    )
                )
        if classify_output(redacted) is OutputHint.CONNECTED:
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
        self._emit(HelperEvent(kind=HelperEventKind.EXIT, exit_code=code, argv=argv))

    def _emit(self, event: HelperEvent) -> None:
        listener = self._listener
        if listener is not None:
            listener(event)


def _default_selector(require_saml: bool) -> OpenfortivpnCapabilities | None:
    return resolve_approved_executable(require_saml=require_saml)
