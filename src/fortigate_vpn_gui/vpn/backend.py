# SPDX-License-Identifier: GPL-3.0-or-later
"""VPN backend service: connect, disconnect, and status.

This module does not import Qt. The GUI calls these methods and subscribes to
events. Privileged helpers, SAML, and password storage are out of scope.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from subprocess import TimeoutExpired

from fortigate_vpn_gui.profiles.model import ConnectionProfile
from fortigate_vpn_gui.system.dependencies import ubuntu_install_command
from fortigate_vpn_gui.vpn.classify import OutputHint, classify_output
from fortigate_vpn_gui.vpn.command import CommandConstructionError, build_connect_argv
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
)
from fortigate_vpn_gui.vpn.process import ProcessFactory, VpnProcess, default_process_factory

Locator = Callable[[], str | None]
VpnListener = Callable[["VpnEvent"], None]


class VpnEvent:
    """Notification posted to subscribers (possibly from a worker thread)."""

    __slots__ = ("error_code", "error_message", "kind", "snapshot")

    def __init__(
        self,
        kind: str,
        snapshot: VpnSnapshot,
        *,
        error_code: VpnErrorCode | None = None,
        error_message: str | None = None,
    ) -> None:
        self.kind = kind
        self.snapshot = snapshot
        self.error_code = error_code
        self.error_message = error_message


_SSO_MESSAGE = "SAML/SSO connection support is planned for v0.4.0."
_MISSING_MESSAGE = (
    "VPN connectivity is unavailable because openfortivpn is not installed.\n\n"
    "Recommended Ubuntu command:\n"
    f"{ubuntu_install_command(('openfortivpn',))}\n\n"
    "This application does not install packages automatically."
)
_PERMISSION_MESSAGE = (
    "openfortivpn needs extra privileges to configure the VPN tunnel "
    "(PPP, routes, or DNS). A privileged helper/polkit design is planned "
    "for a later release. The GUI will never run as root."
)
_AUTH_MESSAGE = (
    "Authentication failed. v0.3.0 does not store passwords or SAML cookies, "
    "so the tunnel process may stop at the login prompt."
)
_START_MESSAGE = "openfortivpn failed to start. See Logs for details."
_EXIT_MESSAGE = "The VPN process ended unexpectedly. See Logs for details."
_INVALID_PROFILE_MESSAGE = "Select a valid connection profile before connecting."
_BUSY_MESSAGE = "A VPN operation is already in progress."


class VpnBackend:
    """Supervise a single openfortivpn child process."""

    def __init__(
        self,
        *,
        log_buffer: LogBuffer | None = None,
        process_factory: ProcessFactory = default_process_factory,
        locator: Locator = locate_openfortivpn,
        grace_seconds: float = 5.0,
    ) -> None:
        self._log = log_buffer if log_buffer is not None else LogBuffer()
        self._factory = process_factory
        self._locator = locator
        self._grace_seconds = grace_seconds
        self._lock = threading.Lock()
        self._listeners: list[VpnListener] = []
        self._state = ConnectionState.DISCONNECTED
        self._process: VpnProcess | None = None
        self._profile: ConnectionProfile | None = None
        self._error_code: VpnErrorCode | None = None
        self._error_message: str | None = None
        self._output_hint = OutputHint.NONE
        self._argv: tuple[str, ...] = ()

    def subscribe(self, callback: VpnListener) -> None:
        self._listeners.append(callback)

    @property
    def log_buffer(self) -> LogBuffer:
        return self._log

    def current_state(self) -> ConnectionState:
        with self._lock:
            return self._state

    def is_running(self) -> bool:
        with self._lock:
            return self._process is not None and self._process.poll() is None

    def process_info(self) -> ProcessInfo | None:
        with self._lock:
            if self._process is None:
                return None
            executable = self._argv[0] if self._argv else None
            return ProcessInfo(pid=self._process.pid, executable=executable, argv=self._argv)

    def snapshot(self) -> VpnSnapshot:
        with self._lock:
            return self._snapshot_locked()

    def connect(self, profile: ConnectionProfile | None) -> None:
        """Start openfortivpn for *profile*. No-op if a session is already busy."""
        if profile is None:
            self._fail_without_process(VpnErrorCode.INVALID_PROFILE, _INVALID_PROFILE_MESSAGE)
            return
        if profile.use_sso:
            self._log.append("vpn", "Refusing SSO profile: SAML is not implemented in v0.3.0.")
            self._emit_error(VpnErrorCode.SSO_NOT_SUPPORTED, _SSO_MESSAGE)
            return
        with self._lock:
            if self._state not in CONNECTABLE_STATES:
                self._log.append("vpn", "Ignoring repeated connect; session is busy.")
                error = (VpnErrorCode.ALREADY_BUSY, _BUSY_MESSAGE)
            else:
                error = None
        if error is not None:
            self._emit_error(*error)
            return

        executable = self._locator()
        if not executable:
            self._log.append("vpn", "openfortivpn executable was not found on PATH.")
            self._fail_without_process(VpnErrorCode.OPENFORTIVPN_MISSING, _MISSING_MESSAGE)
            return

        try:
            argv = build_connect_argv(profile, executable)
        except CommandConstructionError as exc:
            self._log.append("vpn", f"Rejected connect argv: {exc}")
            self._fail_without_process(VpnErrorCode.INVALID_PROFILE, _INVALID_PROFILE_MESSAGE)
            return

        self._begin_session(profile, argv)

    def disconnect(self, *, wait: bool = False, grace_seconds: float | None = None) -> None:
        """Ask the child process to exit. No-op when already idle."""
        grace = self._grace_seconds if grace_seconds is None else grace_seconds
        with self._lock:
            if self._state in {ConnectionState.DISCONNECTED, ConnectionState.FAILED}:
                if self._state is ConnectionState.FAILED:
                    self._transition(ConnectionState.DISCONNECTED)
                    snapshot = self._snapshot_locked()
                else:
                    snapshot = None
                process = None
            elif self._process is None:
                self._transition(ConnectionState.DISCONNECTED)
                snapshot = self._snapshot_locked()
                process = None
            else:
                self._transition(ConnectionState.DISCONNECTING)
                process = self._process
                snapshot = self._snapshot_locked()
        if snapshot is not None:
            self._notify(VpnEvent("state", snapshot))
        if process is None:
            return
        self._log.append("vpn", "Disconnect requested.")
        process.terminate()
        if wait:
            self._await_stop(process, grace)
        else:
            worker = threading.Thread(
                target=self._await_stop,
                args=(process, grace),
                name="openfortivpn-stop",
                daemon=True,
            )
            worker.start()

    def shutdown(self, timeout: float = 5.0) -> None:
        """Stop any child process before the application exits."""
        self.disconnect(wait=True, grace_seconds=timeout)

    def _begin_session(self, profile: ConnectionProfile, argv: list[str]) -> None:
        with self._lock:
            self._profile = profile
            self._argv = tuple(argv)
            self._error_code = None
            self._error_message = None
            self._output_hint = OutputHint.NONE
            self._transition(ConnectionState.STARTING)
            snapshot = self._snapshot_locked()
        self._notify(VpnEvent("state", snapshot))
        self._log.append("vpn", f"Starting openfortivpn for {profile.name} ({argv[1]}).")
        try:
            process = self._factory(argv, self._on_output, self._on_exit)
            process.start()
        except OSError as exc:
            self._log.append("vpn", f"Failed to start openfortivpn: {exc}", severity=LogLevel.ERROR)
            self._fail_and_clear(VpnErrorCode.FAILED_TO_START, _START_MESSAGE)
            return
        with self._lock:
            self._process = process
            self._transition(ConnectionState.CONNECTING)
            snapshot = self._snapshot_locked()
        self._notify(VpnEvent("state", snapshot))

    def _await_stop(self, process: VpnProcess, grace: float) -> None:
        try:
            process.wait(timeout=grace)
            return
        except TimeoutExpired:
            self._log.append("vpn", "Graceful stop timed out; sending SIGKILL.")
        except Exception:
            self._log.append("vpn", "Graceful stop timed out; sending SIGKILL.")
        process.kill()
        try:
            process.wait(timeout=2)
        except (TimeoutExpired, Exception):
            self._log.append("vpn", "Forced kill did not reap the process immediately.")

    def _on_output(self, line: str) -> None:
        text = redact_log_line(line)
        self._log.append("openfortivpn", text)
        hint = classify_output(text)
        with self._lock:
            if hint is not OutputHint.NONE:
                self._output_hint = hint
            if hint is OutputHint.CONNECTED and self._state is ConnectionState.CONNECTING:
                self._transition(ConnectionState.CONNECTED)
                snapshot = self._snapshot_locked()
            else:
                snapshot = None
        if snapshot is not None:
            self._notify(VpnEvent("state", snapshot))

    def _on_exit(self, code: int) -> None:
        self._log.append("openfortivpn", f"Process exited with status {code}.")
        with self._lock:
            previous = self._state
            hint = self._output_hint
            self._process = None
            self._argv = ()
            if previous is ConnectionState.DISCONNECTING:
                self._error_code = None
                self._error_message = None
                self._transition(ConnectionState.DISCONNECTED)
                error = None
            elif previous in {
                ConnectionState.STARTING,
                ConnectionState.CONNECTING,
                ConnectionState.CONNECTED,
                ConnectionState.WAITING_FOR_AUTH,
            }:
                error_code, message = self._exit_error(hint, code)
                self._error_code = error_code
                self._error_message = message
                self._transition(ConnectionState.FAILED)
                error = (error_code, message)
            else:
                error = None
            snapshot = self._snapshot_locked()
        self._notify(VpnEvent("state", snapshot))
        if error is not None:
            self._notify(VpnEvent("error", snapshot, error_code=error[0], error_message=error[1]))

    def _exit_error(self, hint: OutputHint, code: int) -> tuple[VpnErrorCode, str]:
        if hint is OutputHint.PERMISSION:
            return VpnErrorCode.PERMISSION_DENIED, _PERMISSION_MESSAGE
        if hint is OutputHint.AUTH_FAILURE:
            return VpnErrorCode.AUTH_FAILURE, _AUTH_MESSAGE
        if code != 0:
            return VpnErrorCode.UNEXPECTED_EXIT, _EXIT_MESSAGE
        return VpnErrorCode.UNEXPECTED_EXIT, _EXIT_MESSAGE

    def _fail_without_process(self, code: VpnErrorCode, message: str) -> None:
        with self._lock:
            self._error_code = code
            self._error_message = message
            snapshot = self._snapshot_locked()
        self._notify(VpnEvent("error", snapshot, error_code=code, error_message=message))

    def _fail_and_clear(self, code: VpnErrorCode, message: str) -> None:
        with self._lock:
            self._process = None
            self._argv = ()
            self._error_code = code
            self._error_message = message
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

    def _snapshot_locked(self) -> VpnSnapshot:
        process = None
        if self._process is not None:
            executable = self._argv[0] if self._argv else None
            process = ProcessInfo(pid=self._process.pid, executable=executable, argv=self._argv)
        profile = self._profile
        return VpnSnapshot(
            state=self._state,
            profile_id=None if profile is None else profile.id,
            profile_name=None if profile is None else profile.name,
            error_code=self._error_code,
            error_message=self._error_message,
            process=process,
        )

    def _notify(self, event: VpnEvent) -> None:
        for listener in list(self._listeners):
            listener(event)


__all__ = ["VpnBackend", "VpnEvent"]
