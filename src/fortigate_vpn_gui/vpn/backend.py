# SPDX-License-Identifier: GPL-3.0-or-later
"""VPN backend service: helper-backed connect, SAML/SSO, and status.

This module does not import Qt. The GUI process stays unprivileged. Tunnel
setup is performed by the privileged helper through a structured protocol.
"""

from __future__ import annotations

import threading
from collections.abc import Callable

from fortigate_vpn_gui.helper.protocol import (
    CertificateInfo,
    ConnectRequest,
    HelperError,
    HelperEvent,
    HelperEventKind,
    HelperProbe,
)
from fortigate_vpn_gui.helper.validation import (
    connect_request_from_fields,
    format_sha256_fingerprint,
)
from fortigate_vpn_gui.profiles.model import ConnectionProfile
from fortigate_vpn_gui.system.dependencies import ubuntu_install_command
from fortigate_vpn_gui.system.helper_client import (
    HelperClient,
    InProcessHelperClient,
    default_helper_client,
)
from fortigate_vpn_gui.vpn.browser import BrowserLauncher, BrowserLaunchError, SystemBrowserLauncher
from fortigate_vpn_gui.vpn.capabilities import OpenfortivpnCapabilities, resolve_executable
from fortigate_vpn_gui.vpn.classify import OutputHint, classify_output
from fortigate_vpn_gui.vpn.detect import locate_openfortivpn
from fortigate_vpn_gui.vpn.log_buffer import LogBuffer, LogLevel
from fortigate_vpn_gui.vpn.log_redaction import redact_log_line
from fortigate_vpn_gui.vpn.models import (
    ALLOWED_TRANSITIONS,
    CONNECTABLE_STATES,
    ConnectionState,
    ProcessInfo,
    VpnErrorCode,
    VpnSnapshot,
    WaitReason,
    wait_reason_for,
)
from fortigate_vpn_gui.vpn.timeout import TimeoutScheduler, threaded_timeout_scheduler
from fortigate_vpn_gui.vpn.url_safety import InvalidAuthUrl, safe_url_for_display, validate_auth_url

Locator = Callable[[], str | None]
Selector = Callable[[bool], OpenfortivpnCapabilities | None]
VpnListener = Callable[["VpnEvent"], None]

DEFAULT_SAML_TIMEOUT_SECONDS = 120.0
DEFAULT_RECONNECT_DELAY_SECONDS = 5.0
DEFAULT_RECONNECT_ATTEMPTS = 3

_SAML_REQUIRED_MESSAGE = "SAML/SSO requires openfortivpn with --saml-login support."
_MISSING_MESSAGE = (
    "VPN connectivity is unavailable because openfortivpn is not installed.\n\n"
    "Recommended Ubuntu command:\n"
    f"{ubuntu_install_command(('openfortivpn',))}\n\n"
    "This application does not install packages automatically."
)
_PERMISSION_MESSAGE = (
    "openfortivpn could not configure the VPN tunnel (PPP, routes, or DNS). "
    "Confirm the polkit privileged helper is installed and authorized."
)
_AUTH_MESSAGE = "Authentication failed. Passwords and SAML cookies are not stored."
_SAML_AUTH_MESSAGE = (
    "SAML sign-in did not complete. Finish authentication in the system browser "
    "or try connecting again."
)
_START_MESSAGE = "openfortivpn failed to start. See Logs for details."
_EXIT_MESSAGE = "The VPN process ended unexpectedly. See Logs for details."
_INVALID_PROFILE_MESSAGE = "Select a valid connection profile before connecting."
_BUSY_MESSAGE = "A VPN operation is already in progress."
_TIMEOUT_MESSAGE = (
    "SAML sign-in timed out. Complete authentication in the browser within "
    "two minutes, then try again."
)
_INVALID_URL_MESSAGE = "openfortivpn produced a sign-in URL that is not safe to open."
_HELPER_MISSING_MESSAGE = (
    "The privileged VPN helper is not installed. Install the helper and polkit "
    "policy (see packaging/README.md). The GUI will not start openfortivpn as "
    "root and will not fall back to sudo."
)
_POLKIT_MISSING_MESSAGE = (
    "polkit (pkexec) is not available. Privileged VPN operations require polkit. "
    "The GUI will not use sudo."
)
_PRIVILEGE_DENIED_MESSAGE = (
    "Authorization for privileged VPN access was denied. The tunnel was not started."
)
_HELPER_VERSION_MESSAGE = (
    "The privileged helper version does not match this application. Reinstall "
    "the helper from this version of FortiGate VPN Linux GUI."
)
_HELPER_STARTUP_MESSAGE = (
    "The privileged VPN helper failed to start. See Logs or Diagnostics for "
    "details. The GUI will not fall back to sudo."
)
_CERT_UNTRUSTED_MESSAGE = (
    "The FortiGate gateway certificate could not be validated automatically. "
    "Trust it only if you expected this fingerprint for this VPN profile."
)
_CERT_CHANGED_MESSAGE = (
    "The gateway certificate has changed. The previously trusted fingerprint "
    "was not replaced automatically."
)
_CONNECTION_LOST_MESSAGE = "VPN connection was lost."
_PPP_MESSAGE = "The VPN tunnel could not configure PPP. See Logs for details."
_ROUTE_MESSAGE = "The VPN tunnel could not update routes. See Logs for details."
_DNS_MESSAGE = "The VPN tunnel could not update DNS. See Logs for details."


class VpnEvent:
    """Notification posted to subscribers (possibly from a worker thread)."""

    __slots__ = ("certificate", "error_code", "error_message", "kind", "snapshot")

    def __init__(
        self,
        kind: str,
        snapshot: VpnSnapshot,
        *,
        error_code: VpnErrorCode | None = None,
        error_message: str | None = None,
        certificate: CertificateInfo | None = None,
    ) -> None:
        self.kind = kind
        self.snapshot = snapshot
        self.error_code = error_code
        self.error_message = error_message
        self.certificate = certificate


class VpnBackend:
    """Supervise one helper-owned openfortivpn process, including SAML/SSO."""

    def __init__(
        self,
        *,
        log_buffer: LogBuffer | None = None,
        helper: HelperClient | None = None,
        process_factory=None,
        locator: Locator = locate_openfortivpn,
        selector: Selector | None = None,
        browser: BrowserLauncher | None = None,
        schedule_timeout: TimeoutScheduler = threaded_timeout_scheduler,
        grace_seconds: float = 5.0,
        saml_timeout_seconds: float = DEFAULT_SAML_TIMEOUT_SECONDS,
        auto_reconnect: bool = False,
        reconnect_delay_seconds: float = DEFAULT_RECONNECT_DELAY_SECONDS,
        reconnect_max_attempts: int = DEFAULT_RECONNECT_ATTEMPTS,
    ) -> None:
        self._log = log_buffer if log_buffer is not None else LogBuffer()
        self._locator = locator
        self._selector = selector if selector is not None else _default_selector
        self._browser = browser if browser is not None else SystemBrowserLauncher()
        self._schedule_timeout = schedule_timeout
        self._grace_seconds = grace_seconds
        self._saml_timeout_seconds = saml_timeout_seconds
        if helper is not None:
            self._helper = helper
        elif process_factory is not None:
            self._helper = InProcessHelperClient(
                process_factory=process_factory,
                selector=self._selector,
                grace_seconds=grace_seconds,
            )
        else:
            self._helper = default_helper_client()
        self._lock = threading.Lock()
        self._listeners: list[VpnListener] = []
        self._state = ConnectionState.DISCONNECTED
        self._profile: ConnectionProfile | None = None
        self._error_code: VpnErrorCode | None = None
        self._error_message: str | None = None
        self._output_hint = OutputHint.NONE
        self._argv: tuple[str, ...] = ()
        self._use_sso = False
        self._capabilities: OpenfortivpnCapabilities | None = None
        self._browser_status = "idle"
        self._safe_auth_url: str | None = None
        self._browser_opened = False
        self._cancel_timeout: Callable[[], None] | None = None
        self._helper_probe: HelperProbe | None = None
        self._presented_certificate: CertificateInfo | None = None
        self._certificate_subject: str | None = None
        self._certificate_issuer: str | None = None
        self._attempt_id = 0
        self._retry_count = 0
        self._cert_logged_sha: str | None = None
        self._cert_error_emitted = False
        self._tunnel_established_logged = False
        self._gateway_connected_logged = False
        self._listener_logged = False
        self._disconnect_logged = False
        self._last_disconnect_reason: str | None = None
        self._last_failure_reason: str | None = None
        self._failing = False
        self._saml_waiting_logged = False
        self._last_profile: ConnectionProfile | None = None
        self._shutting_down = False
        self._shutdown_finished = False
        self._shutdown_complete_callback: Callable[[], None] | None = None
        self._closing_logged = False
        self._auto_reconnect_enabled = bool(auto_reconnect)
        self._reconnect_delay_seconds = float(reconnect_delay_seconds)
        self._reconnect_max_attempts = int(reconnect_max_attempts)
        self._reconnect_attempt = 0
        self._reconnect_pending = False
        self._reconnect_cancel: Callable[[], None] | None = None
        self._user_disconnect = False
        self._was_reconnect = False
        self._manual_reconnect = False
        self._manual_reconnect_profile: ConnectionProfile | None = None
        self._skip_start_connection_log = False
        self._shutdown_cancel: Callable[[], None] | None = None

    def subscribe(self, callback: VpnListener) -> None:
        self._listeners.append(callback)

    @property
    def log_buffer(self) -> LogBuffer:
        return self._log

    @property
    def helper(self) -> HelperClient:
        return self._helper

    def current_state(self) -> ConnectionState:
        with self._lock:
            return self._state

    def is_running(self) -> bool:
        return self._helper.is_running()

    def process_info(self) -> ProcessInfo | None:
        with self._lock:
            return self._process_info_locked()

    def snapshot(self) -> VpnSnapshot:
        with self._lock:
            return self._snapshot_locked()

    def connect(self, profile: ConnectionProfile | None, *, after_trust: bool = False) -> None:
        """Ask the privileged helper to start openfortivpn for *profile*."""
        if profile is None:
            self._fail_without_process(VpnErrorCode.INVALID_PROFILE, _INVALID_PROFILE_MESSAGE)
            return
        with self._lock:
            if self._shutting_down or self._state is ConnectionState.CLOSING:
                self._log.append("vpn", "Ignoring connect; application is closing.")
                return
            if after_trust:
                allowed = self._state in {
                    ConnectionState.WAITING_FOR_CERTIFICATE_TRUST,
                    ConnectionState.FAILED,
                }
            else:
                allowed = self._state in CONNECTABLE_STATES
            if not allowed:
                self._log.append("vpn", "Ignoring repeated connect; session is busy.")
                return

        self._wait_helper_idle()

        probe = self._helper.probe()
        with self._lock:
            self._helper_probe = probe
        if probe.status == "missing":
            self._log.append("vpn", "Privileged helper is not installed.")
            self._fail_without_process(VpnErrorCode.HELPER_NOT_AVAILABLE, _HELPER_MISSING_MESSAGE)
            return
        if probe.status == "polkit_unavailable":
            self._log.append("vpn", "polkit (pkexec) is not available.")
            self._fail_without_process(VpnErrorCode.POLKIT_UNAVAILABLE, _POLKIT_MISSING_MESSAGE)
            return
        if probe.version_mismatch:
            self._log.append("vpn", "Privileged helper version mismatch.")
            self._fail_without_process(
                VpnErrorCode.HELPER_VERSION_MISMATCH, _HELPER_VERSION_MESSAGE
            )
            return

        capabilities = self._resolve_executable(profile)
        if capabilities is None:
            return

        try:
            request = connect_request_from_fields(
                gateway=profile.gateway,
                port=profile.port,
                auth_mode="saml" if profile.use_sso else "standard",
                trusted_certificate_fingerprint=profile.trusted_cert_sha256,
            )
        except HelperError as exc:
            self._log.append("vpn", f"Rejected connect request: {exc.message}")
            self._fail_without_process(VpnErrorCode.INVALID_PROFILE, _INVALID_PROFILE_MESSAGE)
            return

        self._begin_session(profile, capabilities, request, after_trust=after_trust)

    def disconnect(
        self,
        *,
        wait: bool = False,
        grace_seconds: float | None = None,
        for_reconnect: bool = False,
    ) -> None:
        """Ask the helper to stop the owned process. No-op when already idle."""
        self._cancel_saml_timeout()
        self._cancel_reconnect(user_cancel=True)
        if not for_reconnect:
            cancelled = False
            with self._lock:
                cancelled = self._manual_reconnect
                self._clear_manual_reconnect_locked()
            if cancelled:
                self._app_log("Reconnect cancelled.")
        grace = self._grace_seconds if grace_seconds is None else grace_seconds
        with self._lock:
            self._user_disconnect = True
            if self._state is ConnectionState.DISCONNECTED:
                snapshot = None
                running = False
            elif self._state is ConnectionState.CLOSING:
                snapshot = None
                running = self._helper.is_running()
            elif self._state is ConnectionState.FAILED:
                self._transition(ConnectionState.DISCONNECTED)
                snapshot = self._snapshot_locked()
                running = self._helper.is_running()
            elif self._state is ConnectionState.WAITING_FOR_CERTIFICATE_TRUST and (
                not self._helper.is_running()
            ):
                self._last_disconnect_reason = "certificate_trust_cancelled"
                if self._error_code is None:
                    self._error_code = VpnErrorCode.CERTIFICATE_UNTRUSTED
                    self._error_message = _CERT_UNTRUSTED_MESSAGE
                self._transition(ConnectionState.FAILED)
                snapshot = self._snapshot_locked()
                running = False
            elif not self._helper.is_running():
                if self._state is ConnectionState.CONNECTED:
                    self._last_disconnect_reason = "connection_lost"
                    self._error_code = VpnErrorCode.CONNECTION_LOST
                    self._error_message = _CONNECTION_LOST_MESSAGE
                    self._last_failure_reason = VpnErrorCode.CONNECTION_LOST.value
                    self._transition(ConnectionState.FAILED)
                else:
                    self._last_disconnect_reason = "user_disconnect"
                    self._transition(ConnectionState.DISCONNECTED)
                snapshot = self._snapshot_locked()
                running = False
            else:
                self._last_disconnect_reason = "user_disconnect"
                self._transition(ConnectionState.DISCONNECTING)
                snapshot = self._snapshot_locked()
                running = True
        if snapshot is not None:
            self._notify(VpnEvent("state", snapshot))
        if not running:
            return
        if for_reconnect:
            self._log.append(
                "vpn",
                "Helper disconnect started for reconnect.",
                severity=LogLevel.DEBUG,
            )
        elif not self._disconnect_logged:
            self._disconnect_logged = True
            self._app_log("Disconnect requested.")
        self._helper.disconnect(wait=wait, grace_seconds=grace)

    def set_auto_reconnect(self, enabled: bool) -> None:
        """Enable or disable automatic reconnect after unexpected tunnel loss."""
        pending = False
        with self._lock:
            self._auto_reconnect_enabled = bool(enabled)
            if not self._auto_reconnect_enabled:
                pending = self._reconnect_pending
                self._cancel_reconnect_locked()
        if pending:
            self._app_log("Automatic reconnect cancelled.")

    def reconnect(self, profile: ConnectionProfile | None = None) -> None:
        """Disconnect if needed, then start the normal Connect workflow once."""
        target = profile if profile is not None else self._last_profile
        if target is None:
            self._fail_without_process(VpnErrorCode.INVALID_PROFILE, _INVALID_PROFILE_MESSAGE)
            return
        with self._lock:
            if self._shutting_down or self._state is ConnectionState.CLOSING:
                self._log.append(
                    "vpn",
                    "Ignoring reconnect; application is closing.",
                    severity=LogLevel.DEBUG,
                )
                return
            if self._manual_reconnect or (
                self._was_reconnect
                and self._state
                in {
                    ConnectionState.STARTING,
                    ConnectionState.CONNECTING,
                    ConnectionState.WAITING_FOR_AUTH,
                    ConnectionState.DISCONNECTING,
                }
            ):
                self._log.append(
                    "vpn",
                    "Ignoring repeated reconnect; reconnection is already in progress.",
                    severity=LogLevel.DEBUG,
                )
                return
            self._cancel_reconnect_locked()
            self._manual_reconnect = True
            self._manual_reconnect_profile = target
            self._was_reconnect = True
            snapshot = self._snapshot_locked()
            running = self._helper.is_running()
            state = self._state
        self._notify(VpnEvent("state", snapshot))
        self._app_log("Reconnect requested.")
        needs_stop = running or state in {
            ConnectionState.STARTING,
            ConnectionState.CONNECTING,
            ConnectionState.CONNECTED,
            ConnectionState.WAITING_FOR_AUTH,
            ConnectionState.WAITING_FOR_CERTIFICATE_TRUST,
            ConnectionState.DISCONNECTING,
        }
        if needs_stop:
            self._app_log("Disconnecting current VPN session for reconnect.")
            self.disconnect(wait=False, for_reconnect=True)
            if self.is_running():
                self._log.append(
                    "vpn",
                    "Waiting for previous VPN session to stop.",
                    severity=LogLevel.DEBUG,
                )
                return
            self._log.append(
                "vpn",
                "Previous session already stopped after disconnect.",
                severity=LogLevel.DEBUG,
            )
        self._start_pending_reconnect(previous_stopped=needs_stop)

    def begin_shutdown(
        self,
        *,
        timeout: float | None = None,
        on_complete: Callable[[], None] | None = None,
    ) -> None:
        """Start non-blocking cleanup. Idempotent. Calls *on_complete* when idle."""
        grace = self._grace_seconds if timeout is None else timeout
        with self._lock:
            if not self._shutting_down:
                self._shutting_down = True
                if on_complete is not None:
                    self._shutdown_complete_callback = on_complete
                self._cancel_reconnect_locked()
                self._clear_manual_reconnect_locked()
                self._user_disconnect = True
                if self._state is not ConnectionState.CLOSING:
                    self._transition(ConnectionState.CLOSING)
                snapshot = self._snapshot_locked()
                running = self._helper.is_running()
                already = False
                callback = None
            else:
                already = True
                if self._shutdown_finished:
                    callback = None
                elif not self._helper.is_running():
                    callback = self._shutdown_complete_callback
                    self._shutdown_complete_callback = None
                else:
                    callback = None
        if already:
            if callback is not None:
                callback()
            return
        self._notify(VpnEvent("state", snapshot))
        if not self._closing_logged:
            self._closing_logged = True
            self._app_log("Application closing.")
        if not running:
            self._finish_shutdown()
            return
        self._app_log("Waiting for VPN cleanup before exit.")
        self._helper.disconnect(wait=False, grace_seconds=grace)
        self._arm_shutdown_timeout(grace)

    def _arm_shutdown_timeout(self, grace: float) -> None:
        with self._lock:
            if self._shutdown_finished:
                return
        cancel = self._schedule_timeout(grace, self._on_shutdown_timeout)
        with self._lock:
            if self._shutdown_finished:
                try:
                    cancel()
                except Exception:
                    pass
                return
            self._shutdown_cancel = cancel

    def _on_shutdown_timeout(self) -> None:
        with self._lock:
            if self._shutdown_finished or not self._shutting_down:
                return
        if not self._helper.is_running():
            self._finish_shutdown()
            return
        # Timer thread: blocking wait is acceptable here; the Qt loop stays free.
        self._helper.disconnect(wait=True, grace_seconds=2.0)
        self._finish_shutdown()

    def _finish_shutdown(self) -> None:
        with self._lock:
            cancel = self._shutdown_cancel
            self._shutdown_cancel = None
            callback = self._shutdown_complete_callback
            self._shutdown_complete_callback = None
            already = self._shutdown_finished
            self._shutdown_finished = True
            snapshot = self._snapshot_locked()
        if cancel is not None:
            try:
                cancel()
            except Exception:
                pass
        if already:
            return
        self._notify(VpnEvent("state", snapshot))
        if callback is not None:
            # May run on the GUI thread (idle shutdown) or on a helper/timeout
            # worker thread (process EXIT / shutdown timer). Callers must marshal
            # to the Qt main thread; do not assume Qt affinity here.
            callback()

    def shutdown(self, timeout: float = 5.0) -> None:
        """Stop any helper-owned process before the application exits."""
        self.begin_shutdown(timeout=timeout)
        if self._helper.is_running():
            self._helper.disconnect(wait=True, grace_seconds=timeout)
        self._helper.close()
        with self._lock:
            self._shutting_down = True
            if self._state is ConnectionState.CLOSING:
                self._transition(ConnectionState.DISCONNECTED)
            elif self._state not in {ConnectionState.DISCONNECTED, ConnectionState.FAILED}:
                self._transition(ConnectionState.DISCONNECTED)

    def _resolve_executable(self, profile: ConnectionProfile) -> OpenfortivpnCapabilities | None:
        if profile.use_sso:
            capabilities = self._selector(True)
            if capabilities is not None:
                return capabilities
            if self._locator() or self._selector(False):
                self._log.append("vpn", "No SAML-capable openfortivpn (--saml-login) was found.")
                self._fail_without_process(VpnErrorCode.SSO_NOT_SUPPORTED, _SAML_REQUIRED_MESSAGE)
                return None
            self._log.append("vpn", "openfortivpn executable was not found.")
            self._fail_without_process(VpnErrorCode.OPENFORTIVPN_MISSING, _MISSING_MESSAGE)
            return None

        path = self._locator()
        if path:
            return OpenfortivpnCapabilities(
                executable_path=path,
                version=None,
                supports_saml=False,
                supports_cookie_stdin=False,
                source="locator",
            )
        capabilities = self._selector(False)
        if capabilities is None:
            self._log.append("vpn", "openfortivpn executable was not found on PATH.")
            self._fail_without_process(VpnErrorCode.OPENFORTIVPN_MISSING, _MISSING_MESSAGE)
            return None
        return capabilities

    def _begin_session(
        self,
        profile: ConnectionProfile,
        capabilities: OpenfortivpnCapabilities,
        request: ConnectRequest,
        *,
        after_trust: bool = False,
    ) -> None:
        with self._lock:
            if after_trust:
                allowed = self._state in {
                    ConnectionState.WAITING_FOR_CERTIFICATE_TRUST,
                    ConnectionState.FAILED,
                }
            else:
                allowed = self._state in CONNECTABLE_STATES
            if not allowed:
                self._log.append("vpn", "Ignoring connect after cleanup; session is busy.")
                return
            self._attempt_id += 1
            if after_trust:
                self._retry_count += 1
                name = profile.name
            else:
                self._retry_count = 0
                name = None
            self._profile = profile
            self._last_profile = profile
            self._user_disconnect = False
            self._capabilities = capabilities
            self._use_sso = profile.use_sso
            self._error_code = None
            self._error_message = None
            self._output_hint = OutputHint.NONE
            self._presented_certificate = None
            self._certificate_subject = None
            self._certificate_issuer = None
            self._cert_logged_sha = None
            self._cert_error_emitted = False
            self._tunnel_established_logged = False
            self._gateway_connected_logged = False
            self._listener_logged = False
            self._disconnect_logged = False
            self._failing = False
            self._saml_waiting_logged = False
            self._browser_status = "not_required" if not profile.use_sso else "idle"
            self._safe_auth_url = None
            self._browser_opened = False
            self._argv = ()
            self._transition(ConnectionState.STARTING)
            snapshot = self._snapshot_locked()
        self._notify(VpnEvent("state", snapshot))
        if after_trust and name is not None:
            self._app_log(f'Certificate trusted for profile "{name}".')
            self._app_log("Retrying VPN connection.")
        skip_start_log = False
        with self._lock:
            skip_start_log = self._skip_start_connection_log
            self._skip_start_connection_log = False
        if not skip_start_log:
            self._app_log("Starting VPN connection.")
        mode = "SAML/SSO" if profile.use_sso else "standard"
        self._log.append(
            "vpn",
            f"Starting privileged openfortivpn for {profile.name} "
            f"({profile.gateway}:{profile.port}) mode={mode}.",
            severity=LogLevel.DEBUG,
        )
        try:
            self._helper.connect(request, self._on_helper_event)
        except HelperError as exc:
            code, message = _helper_error_to_vpn(exc)
            self._log.append("vpn", exc.message, severity=LogLevel.ERROR)
            self._fail_and_clear(code, message)
            return
        self._app_log("Privileged helper authorized.")
        with self._lock:
            if not profile.use_sso and self._state is ConnectionState.STARTING:
                self._transition(ConnectionState.CONNECTING)
            snapshot = self._snapshot_locked()
        self._notify(VpnEvent("state", snapshot))

    def _on_helper_event(self, event: HelperEvent) -> None:
        if event.kind is HelperEventKind.LOG and event.line:
            self._handle_log_line(event.line)
            return
        if event.kind is HelperEventKind.STARTED:
            with self._lock:
                self._argv = event.argv
                if event.selected_executable and self._capabilities is not None:
                    self._capabilities = OpenfortivpnCapabilities(
                        executable_path=event.selected_executable,
                        version=event.openfortivpn_version or self._capabilities.version,
                        supports_saml=(
                            event.supports_saml
                            if event.supports_saml is not None
                            else self._capabilities.supports_saml
                        ),
                        supports_cookie_stdin=self._capabilities.supports_cookie_stdin,
                        source=self._capabilities.source,
                    )
            return
        if event.kind is HelperEventKind.SAML_URL and event.url:
            self._maybe_open_browser(event.url)
            return
        if event.kind is HelperEventKind.SAML_LISTENER:
            if not self._listener_logged:
                self._listener_logged = True
                self._app_log("SAML callback listener ready.")
            return
        if event.kind is HelperEventKind.SAML_WAITING:
            self._enter_waiting_for_auth()
            return
        if event.kind is HelperEventKind.SAML_SUCCESS:
            self._handle_saml_success()
            return
        if event.kind is HelperEventKind.SAML_FAILURE:
            self._fail_saml_session(VpnErrorCode.SAML_FAILED, _SAML_AUTH_MESSAGE)
            return
        if event.kind is HelperEventKind.CERTIFICATE and event.certificate is not None:
            self._handle_certificate(event.certificate)
            return
        if event.kind is HelperEventKind.CONNECTED:
            snapshots: list[VpnSnapshot] = []
            with self._lock:
                snapshots.extend(self._mark_connected_locked())
            for item in snapshots:
                self._notify(VpnEvent("state", item))
            return
        if event.kind is HelperEventKind.EXIT:
            self._on_exit(event.exit_code if event.exit_code is not None else 1)
            return
        if event.kind is HelperEventKind.ERROR:
            self._handle_helper_error(event)

    def _handle_log_line(self, line: str) -> None:
        text = redact_log_line(line)
        self._log.append("openfortivpn", text)
        hint = classify_output(text)
        snapshots: list[VpnSnapshot] = []
        log_gateway = False
        with self._lock:
            if hint is not OutputHint.NONE:
                self._output_hint = hint
            if hint is OutputHint.GATEWAY_CONNECTED and not self._gateway_connected_logged:
                self._gateway_connected_logged = True
                log_gateway = True
            if hint is OutputHint.CONNECTED:
                snapshots.extend(self._mark_connected_locked())
        if log_gateway:
            self._app_log("Connected to gateway.")
        for item in snapshots:
            self._notify(VpnEvent("state", item))

    def _handle_certificate(self, info: CertificateInfo) -> None:
        events: list[VpnEvent] = []
        with self._lock:
            self._presented_certificate = info
            self._certificate_subject = info.subject
            self._certificate_issuer = info.issuer
            self._output_hint = OutputHint.CERTIFICATE
            pinned = None if self._profile is None else self._profile.trusted_cert_sha256
            duplicate = self._cert_logged_sha == info.sha256
            if not duplicate:
                self._cert_logged_sha = info.sha256
                self._cancel_timeout_locked()
                if self._state in {
                    ConnectionState.STARTING,
                    ConnectionState.WAITING_FOR_AUTH,
                    ConnectionState.CONNECTING,
                }:
                    self._transition(ConnectionState.WAITING_FOR_CERTIFICATE_TRUST)
                snapshot = self._snapshot_locked()
                events.append(VpnEvent("state", snapshot, certificate=info))
                if pinned and pinned != info.sha256:
                    code = VpnErrorCode.CERTIFICATE_CHANGED
                    message = _CERT_CHANGED_MESSAGE
                else:
                    code = VpnErrorCode.CERTIFICATE_UNTRUSTED
                    message = _CERT_UNTRUSTED_MESSAGE
                self._error_code = code
                self._error_message = message
                self._last_failure_reason = code.value
                if not self._cert_error_emitted:
                    self._cert_error_emitted = True
                    events.append(
                        VpnEvent(
                            "error",
                            snapshot,
                            error_code=code,
                            error_message=message,
                            certificate=info,
                        )
                    )
            else:
                snapshot = None
        if duplicate:
            return
        self._app_log(
            "Gateway certificate requires explicit trust.",
            severity=LogLevel.ERROR,
        )
        self._app_log("Waiting for certificate trust decision.")
        self._app_log(f"Certificate fingerprint: {format_sha256_fingerprint(info.sha256)}")
        if pinned and pinned != info.sha256:
            self._app_log(
                "The gateway certificate has changed.",
                severity=LogLevel.WARNING,
            )
        for event in events:
            self._notify(event)

    def _enter_waiting_for_auth(self) -> None:
        with self._lock:
            if self._state is ConnectionState.STARTING:
                self._transition(ConnectionState.WAITING_FOR_AUTH)
                snapshot = self._snapshot_locked()
            else:
                snapshot = None
        if snapshot is not None:
            if not self._saml_waiting_logged:
                self._saml_waiting_logged = True
                self._app_log("Waiting for SAML authentication.")
            self._notify(VpnEvent("state", snapshot))
            self._arm_saml_timeout()

    def _handle_saml_success(self) -> None:
        with self._lock:
            self._cancel_timeout_locked()
            if self._state is ConnectionState.WAITING_FOR_AUTH:
                self._transition(ConnectionState.CONNECTING)
                snapshot = self._snapshot_locked()
            else:
                snapshot = None
        if snapshot is not None:
            self._app_log("Authenticated.")
            self._notify(VpnEvent("state", snapshot))

    def _handle_helper_error(self, event: HelperEvent) -> None:
        code = event.code or "VPN_PROCESS_FAILED"
        mapped = _CODE_MAP.get(code)
        if mapped is None:
            mapped = VpnErrorCode.VPN_PROCESS_FAILED
        message = event.message or _EXIT_MESSAGE
        if mapped is VpnErrorCode.INVALID_AUTH_URL:
            self._fail_saml_session(mapped, _INVALID_URL_MESSAGE)
            return
        self._fail_saml_session(mapped, message)

    def _mark_connected_locked(self) -> list[VpnSnapshot]:
        snapshots: list[VpnSnapshot] = []
        if self._state is ConnectionState.WAITING_FOR_AUTH:
            self._cancel_timeout_locked()
            self._transition(ConnectionState.CONNECTING)
            snapshots.append(self._snapshot_locked())
        if self._state is ConnectionState.CONNECTING:
            self._transition(ConnectionState.CONNECTED)
            snapshots.append(self._snapshot_locked())
            if not self._tunnel_established_logged:
                self._tunnel_established_logged = True
                self._app_log("VPN tunnel established.")
                reconnected = self._reconnect_attempt > 0 or self._was_reconnect
                self._reconnect_attempt = 0
                self._reconnect_pending = False
                self._was_reconnect = False
                if reconnected:
                    self._app_log("VPN reconnected successfully.")
        return snapshots

    def _maybe_open_browser(self, raw_url: str) -> None:
        with self._lock:
            if self._browser_opened:
                self._log.append("vpn", "Ignoring repeated SAML sign-in URL.")
                return
            self._browser_opened = True
        try:
            validated = validate_auth_url(raw_url)
        except InvalidAuthUrl:
            self._log.append("vpn", "Rejected unsafe SAML sign-in URL.", severity=LogLevel.ERROR)
            self._fail_saml_session(VpnErrorCode.INVALID_AUTH_URL, _INVALID_URL_MESSAGE)
            return
        safe = safe_url_for_display(validated)
        with self._lock:
            self._safe_auth_url = safe
            self._browser_status = "opening"
            if self._state is ConnectionState.STARTING:
                self._transition(ConnectionState.WAITING_FOR_AUTH)
            snapshot = self._snapshot_locked()
        self._notify(VpnEvent("state", snapshot))
        if not self._saml_waiting_logged:
            self._saml_waiting_logged = True
            self._app_log("Waiting for SAML authentication.")
        self._arm_saml_timeout()
        self._app_log("Opening browser for SAML sign-in.")
        self._log.append(
            "vpn",
            f"Opening system browser for SAML sign-in at {safe}.",
            severity=LogLevel.DEBUG,
        )
        try:
            self._browser.open(validated)
        except BrowserLaunchError as exc:
            self._log.append("vpn", str(exc), severity=LogLevel.ERROR)
            with self._lock:
                self._browser_status = "failed"
            self._fail_saml_session(VpnErrorCode.BROWSER_FAILED, str(exc))
            return
        with self._lock:
            self._browser_status = "opened"
            snapshot = self._snapshot_locked()
        self._notify(VpnEvent("state", snapshot))

    def _arm_saml_timeout(self) -> None:
        self._cancel_saml_timeout()
        self._cancel_timeout = self._schedule_timeout(
            self._saml_timeout_seconds, self._on_saml_timeout
        )

    def _cancel_saml_timeout(self) -> None:
        with self._lock:
            self._cancel_timeout_locked()

    def _cancel_timeout_locked(self) -> None:
        cancel = self._cancel_timeout
        self._cancel_timeout = None
        if cancel is not None:
            try:
                cancel()
            except Exception:
                pass

    def _cancel_reconnect(self, *, user_cancel: bool) -> None:
        pending = False
        with self._lock:
            pending = self._reconnect_pending
            self._cancel_reconnect_locked()
        if user_cancel and pending:
            self._app_log("Automatic reconnect cancelled.")

    def _cancel_reconnect_locked(self) -> None:
        cancel = self._reconnect_cancel
        self._reconnect_cancel = None
        self._reconnect_pending = False
        if cancel is not None:
            try:
                cancel()
            except Exception:
                pass

    def _clear_manual_reconnect_locked(self) -> None:
        self._manual_reconnect = False
        self._manual_reconnect_profile = None

    def _start_pending_reconnect(self, *, previous_stopped: bool) -> None:
        with self._lock:
            if self._shutting_down or not self._manual_reconnect:
                return
            if self._helper.is_running():
                self._log.append(
                    "vpn",
                    "Reconnect is waiting for the previous VPN session to stop.",
                    severity=LogLevel.DEBUG,
                )
                return
            profile = self._manual_reconnect_profile or self._last_profile
            state = self._state
        if profile is None:
            with self._lock:
                self._clear_manual_reconnect_locked()
                snapshot = self._snapshot_locked()
            self._notify(VpnEvent("state", snapshot))
            self._app_log("Reconnect failed: no profile is selected.", severity=LogLevel.ERROR)
            return
        if state not in CONNECTABLE_STATES:
            self._log.append(
                "vpn",
                f"Reconnect deferred until idle; state is {state.value}.",
                severity=LogLevel.DEBUG,
            )
            return
        if previous_stopped:
            self._app_log("Previous VPN session stopped.")
        self._app_log("Starting VPN reconnection.")
        with self._lock:
            self._manual_reconnect = False
            self._was_reconnect = True
            self._skip_start_connection_log = True
        self.connect(profile)
        if self.current_state() not in {
            ConnectionState.STARTING,
            ConnectionState.CONNECTING,
            ConnectionState.WAITING_FOR_AUTH,
            ConnectionState.WAITING_FOR_CERTIFICATE_TRUST,
            ConnectionState.CONNECTED,
        }:
            with self._lock:
                self._clear_manual_reconnect_locked()
                self._was_reconnect = False
                snapshot = self._snapshot_locked()
            self._notify(VpnEvent("state", snapshot))
            self._app_log(
                "Reconnect failed to start a new VPN session.",
                severity=LogLevel.ERROR,
            )

    def _maybe_schedule_reconnect(self) -> None:
        with self._lock:
            if (
                self._shutting_down
                or self._user_disconnect
                or not self._auto_reconnect_enabled
                or self._last_profile is None
                or self._reconnect_pending
                or self._state is not ConnectionState.FAILED
            ):
                return
            if self._error_code is not VpnErrorCode.CONNECTION_LOST:
                return
            if self._reconnect_attempt >= self._reconnect_max_attempts:
                limit = self._reconnect_max_attempts
                stop = True
            else:
                self._reconnect_attempt += 1
                attempt = self._reconnect_attempt
                limit = self._reconnect_max_attempts
                delay = self._reconnect_delay_seconds
                self._reconnect_pending = True
                stop = False
        if stop:
            self._app_log(f"Automatic reconnect stopped after {limit} attempts.")
            return
        delay_display = int(delay) if delay == int(delay) else delay
        self._app_log(f"Automatic reconnect scheduled in {delay_display} seconds.")
        self._app_log(f"Reconnect attempt {attempt} of {limit}.")
        with self._lock:
            snapshot = self._snapshot_locked()
        self._notify(VpnEvent("state", snapshot))
        self._reconnect_cancel = self._schedule_timeout(delay, self._on_reconnect_timer)

    def _on_reconnect_timer(self) -> None:
        with self._lock:
            if (
                self._shutting_down
                or not self._auto_reconnect_enabled
                or not self._reconnect_pending
            ):
                return
            self._reconnect_pending = False
            profile = self._last_profile
            self._was_reconnect = True
        if profile is None:
            return
        self.connect(profile)

    def _on_saml_timeout(self) -> None:
        with self._lock:
            if self._state is not ConnectionState.WAITING_FOR_AUTH:
                return
        self._log.append("vpn", "SAML authentication timed out.", severity=LogLevel.ERROR)
        self._fail_saml_session(VpnErrorCode.SAML_TIMEOUT, _TIMEOUT_MESSAGE)

    def _fail_saml_session(self, code: VpnErrorCode, message: str) -> None:
        self._cancel_saml_timeout()
        running = False
        with self._lock:
            if self._failing:
                return
            if self._state in {
                ConnectionState.DISCONNECTED,
                ConnectionState.DISCONNECTING,
                ConnectionState.WAITING_FOR_CERTIFICATE_TRUST,
                ConnectionState.CLOSING,
            }:
                return
            self._failing = True
            self._error_code = code
            self._error_message = message
            self._last_failure_reason = code.value
            if self._state is not ConnectionState.FAILED:
                self._transition(ConnectionState.FAILED)
            running = self._helper.is_running()
            snapshot = self._snapshot_locked()
        self._notify(VpnEvent("state", snapshot, certificate=snapshot.presented_certificate))
        self._notify(
            VpnEvent(
                "error",
                snapshot,
                error_code=code,
                error_message=message,
                certificate=snapshot.presented_certificate,
            )
        )
        if running:
            self._helper.disconnect(wait=False)

    def _on_exit(self, code: int) -> None:
        self._cancel_saml_timeout()
        self._log.append("openfortivpn", f"Process exited with status {code}.")
        with self._lock:
            previous = self._state
            hint = self._output_hint
            presented = self._presented_certificate
            pinned = None if self._profile is None else self._profile.trusted_cert_sha256
            self._argv = ()
            if previous is ConnectionState.DISCONNECTING:
                self._error_code = None
                self._error_message = None
                self._last_disconnect_reason = self._last_disconnect_reason or "user_disconnect"
                self._transition(ConnectionState.DISCONNECTED)
                error = None
                disconnected = True
                lost = False
                closing = False
            elif previous is ConnectionState.CLOSING:
                error = None
                disconnected = False
                lost = False
                closing = True
            elif previous is ConnectionState.WAITING_FOR_CERTIFICATE_TRUST:
                error = None
                disconnected = False
                lost = False
                closing = False
            elif previous is ConnectionState.FAILED:
                error = None
                disconnected = False
                lost = False
                closing = False
            elif previous is ConnectionState.CONNECTED:
                error_code, message = (
                    VpnErrorCode.CONNECTION_LOST,
                    _CONNECTION_LOST_MESSAGE,
                )
                self._error_code = error_code
                self._error_message = message
                self._last_failure_reason = error_code.value
                self._last_disconnect_reason = "connection_lost"
                self._transition(ConnectionState.FAILED)
                error = (error_code, message)
                disconnected = False
                lost = not self._user_disconnect and not self._shutting_down
                closing = False
            elif previous in {
                ConnectionState.STARTING,
                ConnectionState.CONNECTING,
                ConnectionState.WAITING_FOR_AUTH,
            }:
                error_code, message = self._exit_error(hint, code, previous, presented, pinned)
                self._error_code = error_code
                self._error_message = message
                self._last_failure_reason = error_code.value
                if error_code in {
                    VpnErrorCode.CERTIFICATE_UNTRUSTED,
                    VpnErrorCode.CERTIFICATE_CHANGED,
                }:
                    self._transition(ConnectionState.WAITING_FOR_CERTIFICATE_TRUST)
                    if not self._cert_error_emitted and presented is not None:
                        self._cert_error_emitted = True
                        error = (error_code, message)
                    else:
                        error = None
                else:
                    self._transition(ConnectionState.FAILED)
                    error = (error_code, message)
                disconnected = False
                lost = False
                closing = False
            else:
                error = None
                disconnected = False
                lost = False
                closing = False
            reconnecting = self._manual_reconnect
            snapshot = self._snapshot_locked()
        if disconnected and not reconnecting:
            self._app_log("VPN disconnected.")
        if lost:
            self._app_log("VPN connection lost.", severity=LogLevel.ERROR)
        self._notify(VpnEvent("state", snapshot, certificate=snapshot.presented_certificate))
        if error is not None:
            self._notify(
                VpnEvent(
                    "error",
                    snapshot,
                    error_code=error[0],
                    error_message=error[1],
                    certificate=snapshot.presented_certificate,
                )
            )
        if closing:
            self._finish_shutdown()
            return
        if lost:
            self._maybe_schedule_reconnect()
            return
        if disconnected:
            self._start_pending_reconnect(previous_stopped=True)

    def _exit_error(
        self,
        hint: OutputHint,
        code: int,
        previous: ConnectionState,
        presented: CertificateInfo | None,
        pinned: str | None,
    ) -> tuple[VpnErrorCode, str]:
        if hint is OutputHint.CERTIFICATE or presented is not None:
            if pinned and presented is not None and pinned != presented.sha256:
                return VpnErrorCode.CERTIFICATE_CHANGED, _CERT_CHANGED_MESSAGE
            return VpnErrorCode.CERTIFICATE_UNTRUSTED, _CERT_UNTRUSTED_MESSAGE
        if hint is OutputHint.PERMISSION:
            return VpnErrorCode.PERMISSION_DENIED, _PERMISSION_MESSAGE
        if hint is OutputHint.PPP_FAILURE:
            return VpnErrorCode.PPP_FAILED, _PPP_MESSAGE
        if hint is OutputHint.ROUTE_FAILURE:
            return VpnErrorCode.ROUTE_FAILED, _ROUTE_MESSAGE
        if hint is OutputHint.DNS_FAILURE:
            return VpnErrorCode.DNS_FAILED, _DNS_MESSAGE
        if hint is OutputHint.AUTH_FAILURE or previous is ConnectionState.WAITING_FOR_AUTH:
            if previous is ConnectionState.WAITING_FOR_AUTH:
                return VpnErrorCode.SAML_FAILED, _SAML_AUTH_MESSAGE
            return VpnErrorCode.AUTH_FAILURE, _AUTH_MESSAGE
        if code != 0:
            return VpnErrorCode.VPN_PROCESS_FAILED, _EXIT_MESSAGE
        return VpnErrorCode.UNEXPECTED_EXIT, _EXIT_MESSAGE

    def _fail_without_process(self, code: VpnErrorCode, message: str) -> None:
        with self._lock:
            self._error_code = code
            self._error_message = message
            self._last_failure_reason = code.value
            snapshot = self._snapshot_locked()
        self._notify(VpnEvent("error", snapshot, error_code=code, error_message=message))

    def _fail_and_clear(self, code: VpnErrorCode, message: str) -> None:
        self._cancel_saml_timeout()
        with self._lock:
            self._argv = ()
            self._error_code = code
            self._error_message = message
            self._last_failure_reason = code.value
            self._transition(ConnectionState.FAILED)
            failed = self._snapshot_locked()
            self._transition(ConnectionState.DISCONNECTED)
            idle = self._snapshot_locked()
        self._notify(VpnEvent("state", failed))
        self._notify(VpnEvent("error", failed, error_code=code, error_message=message))
        self._notify(VpnEvent("state", idle))

    def _emit_error(self, code: VpnErrorCode, message: str) -> None:
        with self._lock:
            snapshot = self._snapshot_locked()
        self._notify(VpnEvent("error", snapshot, error_code=code, error_message=message))

    def _transition(self, new_state: ConnectionState) -> None:
        if new_state is self._state:
            return
        allowed = ALLOWED_TRANSITIONS.get(self._state, frozenset())
        if new_state not in allowed:
            self._log.append(
                "vpn",
                f"Illegal transition {self._state.value} -> {new_state.value}; forcing.",
                severity=LogLevel.WARNING,
            )
        self._state = new_state
        if new_state is ConnectionState.DISCONNECTED:
            self._profile = None
            self._use_sso = False
            self._capabilities = None
            self._browser_status = "idle"
            self._safe_auth_url = None
            self._browser_opened = False
            self._presented_certificate = None
            self._certificate_subject = None
            self._certificate_issuer = None

    def _process_info_locked(self) -> ProcessInfo | None:
        pid = self._helper.pid()
        argv = self._helper.argv() or self._argv
        if pid is None and not argv and not self._helper.is_running():
            return None
        executable = argv[0] if argv else None
        return ProcessInfo(pid=pid, executable=executable, argv=argv)

    def _snapshot_locked(self) -> VpnSnapshot:
        process = self._process_info_locked()
        profile = self._profile if self._profile is not None else self._last_profile
        capabilities = self._capabilities
        auth_mode = None
        if profile is not None:
            auth_mode = "SAML/SSO" if profile.use_sso else "non-SSO"
        elif self._use_sso:
            auth_mode = "SAML/SSO"
        selected = None
        version = None
        supports_saml = None
        supports_cookie = None
        if capabilities is not None:
            selected = capabilities.executable_path
            version = capabilities.version
            if capabilities.source != "locator":
                supports_saml = capabilities.supports_saml
                supports_cookie = capabilities.supports_cookie_stdin
        elif process is not None:
            selected = process.executable
        probe = self._helper_probe
        pinned = None if profile is None else bool(profile.trusted_cert_sha256)
        fingerprint = None if profile is None else profile.trusted_cert_sha256
        presented = self._presented_certificate
        failure = None if self._error_code is None else self._error_code.value
        wait = wait_reason_for(self._state)
        if self._reconnect_pending or self._manual_reconnect:
            wait = WaitReason.RECONNECTING
        return VpnSnapshot(
            state=self._state,
            profile_id=None if profile is None else profile.id,
            profile_name=None if profile is None else profile.name,
            error_code=self._error_code,
            error_message=self._error_message,
            process=process,
            auth_mode=auth_mode,
            browser_status=self._browser_status,
            safe_auth_url=self._safe_auth_url,
            selected_executable=selected,
            openfortivpn_version=version,
            supports_saml=supports_saml,
            supports_cookie_stdin=supports_cookie,
            use_sso=None if profile is None else profile.use_sso,
            failure_reason=failure,
            helper_installed=None if probe is None else probe.installed,
            helper_version=None if probe is None else probe.helper_version,
            helper_status=None if probe is None else probe.status,
            authorization_mechanism="polkit",
            privileged_pid=self._helper.pid(),
            certificate_pinned=pinned,
            certificate_fingerprint=fingerprint,
            certificate_subject=(
                self._certificate_subject
                if self._certificate_subject is not None
                else (None if presented is None else presented.subject)
            ),
            certificate_issuer=(
                self._certificate_issuer
                if self._certificate_issuer is not None
                else (None if presented is None else presented.issuer)
            ),
            presented_certificate=presented,
            helper_probe=probe,
            wait_reason=wait.value,
            attempt_id=self._attempt_id,
            retry_count=self._retry_count,
            last_disconnect_reason=self._last_disconnect_reason,
            last_failure_reason=self._last_failure_reason or failure,
            shutdown_in_progress=self._shutting_down,
            auto_reconnect_enabled=self._auto_reconnect_enabled,
            reconnect_pending=self._reconnect_pending,
            reconnect_attempt=self._reconnect_attempt,
            reconnect_limit=self._reconnect_max_attempts,
            reconnect_delay_seconds=self._reconnect_delay_seconds,
            manual_reconnect=self._manual_reconnect,
        )

    def _notify(self, event: VpnEvent) -> None:
        for listener in list(self._listeners):
            listener(event)

    def _wait_helper_idle(self) -> None:
        """Block until any previous privileged process has exited."""
        if not self._helper.is_running():
            return
        self._helper.disconnect(wait=True, grace_seconds=self._grace_seconds)

    def _app_log(self, message: str, *, severity: LogLevel = LogLevel.INFO) -> None:
        self._log.append("vpn", message, severity=severity)


_CODE_MAP = {
    "HELPER_NOT_AVAILABLE": VpnErrorCode.HELPER_NOT_AVAILABLE,
    "POLKIT_UNAVAILABLE": VpnErrorCode.POLKIT_UNAVAILABLE,
    "HELPER_VERSION_MISMATCH": VpnErrorCode.HELPER_VERSION_MISMATCH,
    "HELPER_STARTUP_FAILED": VpnErrorCode.HELPER_STARTUP_FAILED,
    "PRIVILEGE_DENIED": VpnErrorCode.PRIVILEGE_DENIED,
    "SSO_NOT_SUPPORTED": VpnErrorCode.SSO_NOT_SUPPORTED,
    "OPENFORTIVPN_MISSING": VpnErrorCode.OPENFORTIVPN_MISSING,
    "FAILED_TO_START": VpnErrorCode.FAILED_TO_START,
    "ALREADY_CONNECTED": VpnErrorCode.ALREADY_BUSY,
    "INVALID_AUTH_URL": VpnErrorCode.INVALID_AUTH_URL,
    "SAML_FAILED": VpnErrorCode.SAML_FAILED,
    "VPN_PROCESS_FAILED": VpnErrorCode.VPN_PROCESS_FAILED,
}


def _helper_error_to_vpn(exc: HelperError) -> tuple[VpnErrorCode, str]:
    mapped = _CODE_MAP.get(exc.code, VpnErrorCode.VPN_PROCESS_FAILED)
    messages = {
        VpnErrorCode.HELPER_NOT_AVAILABLE: _HELPER_MISSING_MESSAGE,
        VpnErrorCode.POLKIT_UNAVAILABLE: _POLKIT_MISSING_MESSAGE,
        VpnErrorCode.HELPER_VERSION_MISMATCH: _HELPER_VERSION_MESSAGE,
        VpnErrorCode.HELPER_STARTUP_FAILED: _HELPER_STARTUP_MESSAGE,
        VpnErrorCode.PRIVILEGE_DENIED: _PRIVILEGE_DENIED_MESSAGE,
        VpnErrorCode.SSO_NOT_SUPPORTED: _SAML_REQUIRED_MESSAGE,
        VpnErrorCode.OPENFORTIVPN_MISSING: _MISSING_MESSAGE,
        VpnErrorCode.FAILED_TO_START: _START_MESSAGE,
        VpnErrorCode.ALREADY_BUSY: _BUSY_MESSAGE,
    }
    return mapped, messages.get(mapped, exc.message)


def _default_selector(require_saml: bool) -> OpenfortivpnCapabilities | None:
    return resolve_executable(require_saml=require_saml)


__all__ = ["DEFAULT_SAML_TIMEOUT_SECONDS", "VpnBackend", "VpnEvent"]
