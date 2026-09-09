# SPDX-License-Identifier: GPL-3.0-or-later
"""GUI-side helper client: in-process (tests) and polkit-backed (production)."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from fortigate_vpn_gui.helper.handshake import is_valid_helper_version, parse_helper_hello_output
from fortigate_vpn_gui.helper.protocol import (
    HELPER_VERSION,
    INSTALLED_HELPER_PATH,
    PROTOCOL_VERSION,
    ConnectRequest,
    HelperError,
    HelperEvent,
    HelperEventKind,
    HelperProbe,
    event_from_payload,
)
from fortigate_vpn_gui.helper.service import HelperService
from fortigate_vpn_gui.helper.validation import connect_request_from_fields
from fortigate_vpn_gui.vpn.capabilities import OpenfortivpnCapabilities
from fortigate_vpn_gui.vpn.log_redaction import redact_log_line
from fortigate_vpn_gui.vpn.process import ProcessFactory, default_process_factory

HelperListener = Callable[[HelperEvent], None]
Selector = Callable[[bool], OpenfortivpnCapabilities | None]
Which = Callable[[str], str | None]
PathExists = Callable[[str], bool]
PopenFactory = Callable[..., subprocess.Popen[str]]
_DENIED = "Authorization for privileged VPN access was denied."
_VERSION_MISMATCH = "Privileged helper version does not match the GUI."
_STARTUP_FAILED = "The privileged VPN helper failed to start."
_DETAIL_LIMIT = 400


class HelperClient(Protocol):
    """Unprivileged client used by VpnBackend."""

    def probe(self) -> HelperProbe: ...

    def connect(self, request: ConnectRequest, listener: HelperListener) -> None: ...

    def disconnect(self, *, wait: bool = True, grace_seconds: float | None = None) -> None: ...

    def close(self) -> None: ...

    def is_running(self) -> bool: ...

    def pid(self) -> int | None: ...

    def argv(self) -> tuple[str, ...]: ...

    @property
    def process(self) -> object | None: ...


class InProcessHelperClient:
    """Test/dev client that uses HelperService in-process. Never calls pkexec."""

    def __init__(
        self,
        *,
        process_factory: ProcessFactory = default_process_factory,
        selector: Selector | None = None,
        installed: bool = True,
        helper_version: str = HELPER_VERSION,
        polkit_available: bool = True,
        denied: bool = False,
        version_mismatch: bool = False,
        grace_seconds: float = 5.0,
    ) -> None:
        self._probe_installed = installed
        self._probe_version = helper_version
        self._polkit_available = polkit_available
        self._denied = denied
        self._version_mismatch = version_mismatch
        self._service = HelperService(
            process_factory=process_factory,
            selector=selector,
            grace_seconds=grace_seconds,
        )
        self._listener: HelperListener | None = None

    @property
    def process(self) -> object | None:
        return self._service.process

    def probe(self) -> HelperProbe:
        if not self._probe_installed:
            return HelperProbe(
                installed=False,
                helper_path=None,
                helper_version=None,
                polkit_available=self._polkit_available,
                authorization_mechanism="polkit",
                status="missing",
            )
        if not self._polkit_available:
            return HelperProbe(
                installed=True,
                helper_path=INSTALLED_HELPER_PATH,
                helper_version=self._probe_version,
                polkit_available=False,
                authorization_mechanism="polkit",
                status="polkit_unavailable",
            )
        if self._version_mismatch:
            return HelperProbe(
                installed=True,
                helper_path=INSTALLED_HELPER_PATH,
                helper_version=self._probe_version,
                polkit_available=True,
                authorization_mechanism="polkit",
                status="version_mismatch",
                version_mismatch=True,
            )
        return HelperProbe(
            installed=True,
            helper_path=INSTALLED_HELPER_PATH,
            helper_version=self._probe_version,
            polkit_available=True,
            authorization_mechanism="polkit",
            status="ready",
        )

    def connect(self, request: ConnectRequest, listener: HelperListener) -> None:
        probe = self.probe()
        if probe.status == "missing":
            raise HelperError("HELPER_NOT_AVAILABLE", "The privileged VPN helper is not installed.")
        if probe.status == "polkit_unavailable":
            raise HelperError("POLKIT_UNAVAILABLE", "polkit (pkexec) is not available.")
        if probe.version_mismatch:
            raise HelperError("HELPER_VERSION_MISMATCH", _VERSION_MISMATCH)
        if probe.status == "startup_failed":
            raise HelperError("HELPER_STARTUP_FAILED", _STARTUP_FAILED)
        if self._denied:
            raise HelperError("PRIVILEGE_DENIED", _DENIED)
        validated = connect_request_from_fields(
            gateway=request.gateway,
            port=request.port,
            auth_mode=request.auth_mode,
            trusted_certificate_fingerprint=request.trusted_certificate_fingerprint,
            request_id=request.request_id,
        )
        self._listener = listener
        self._service.set_listener(listener)
        self._service.connect(validated)

    def disconnect(self, *, wait: bool = True, grace_seconds: float | None = None) -> None:
        self._service.disconnect(wait=wait, grace_seconds=grace_seconds)

    def close(self) -> None:
        self.disconnect(wait=True)

    def is_running(self) -> bool:
        return self._service.is_running()

    def pid(self) -> int | None:
        return self._service.pid()

    def argv(self) -> tuple[str, ...]:
        return self._service.argv()


class PolkitHelperClient:
    """Launch the installed helper through pkexec. Never uses sudo."""

    def __init__(
        self,
        *,
        helper_path: str | None = None,
        pkexec_name: str = "pkexec",
        which: Which = shutil.which,
        path_exists: PathExists = os.path.exists,
        popen: PopenFactory = subprocess.Popen,
        expected_version: str = HELPER_VERSION,
        expected_protocol: int = PROTOCOL_VERSION,
        version_runner: Callable[[list[str]], subprocess.CompletedProcess[str]] | None = None,
    ) -> None:
        self._helper_path = (
            helper_path or os.environ.get("FORTIGATE_VPN_HELPER") or INSTALLED_HELPER_PATH
        )
        self._pkexec_name = pkexec_name
        self._which = which
        self._path_exists = path_exists
        self._popen = popen
        self._expected_version = expected_version
        self._expected_protocol = expected_protocol
        self._version_runner = version_runner or _run_version
        self._proc: subprocess.Popen[str] | None = None
        self._reader: threading.Thread | None = None
        self._listener: HelperListener | None = None
        self._lock = threading.Lock()
        self._running = False
        self._pid: int | None = None
        self._argv: tuple[str, ...] = ()
        self._hello_version: str | None = None

    @property
    def process(self) -> object | None:
        return None

    def probe(self) -> HelperProbe:
        installed = bool(self._helper_path) and self._path_exists(self._helper_path)
        pkexec = self._which(self._pkexec_name)
        version = None
        mismatch = False
        handshake_failed = False
        detail: str | None = None
        if installed:
            hello = self._read_helper_hello()
            detail = _safe_startup_detail(hello.detail)
            if hello.status == "ok" and hello.helper_version:
                version = hello.helper_version
                mismatch = version != self._expected_version
            else:
                handshake_failed = True
        if not installed:
            status = "missing"
        elif handshake_failed:
            status = "startup_failed"
        elif pkexec is None:
            status = "polkit_unavailable"
        elif mismatch:
            status = "version_mismatch"
        else:
            status = "ready"
        return HelperProbe(
            installed=installed,
            helper_path=self._helper_path if installed else None,
            helper_version=version,
            polkit_available=pkexec is not None,
            authorization_mechanism="polkit",
            status=status,
            version_mismatch=mismatch,
            startup_detail=detail,
        )

    def connect(self, request: ConnectRequest, listener: HelperListener) -> None:
        probe = self.probe()
        if probe.status == "missing":
            raise HelperError("HELPER_NOT_AVAILABLE", "The privileged VPN helper is not installed.")
        if probe.status == "polkit_unavailable":
            raise HelperError(
                "POLKIT_UNAVAILABLE",
                "polkit (pkexec) is not available. Install polkit and retry.",
            )
        if probe.version_mismatch:
            raise HelperError("HELPER_VERSION_MISMATCH", _VERSION_MISMATCH)
        if probe.status == "startup_failed":
            raise HelperError("HELPER_STARTUP_FAILED", _STARTUP_FAILED)
        validated = connect_request_from_fields(
            gateway=request.gateway,
            port=request.port,
            auth_mode=request.auth_mode,
            trusted_certificate_fingerprint=request.trusted_certificate_fingerprint,
            request_id=request.request_id,
        )
        self._listener = listener
        self._ensure_session()
        self._send(
            {
                "id": validated.request_id or "connect",
                "operation": "connect",
                "gateway": validated.gateway,
                "port": validated.port,
                "auth_mode": validated.auth_mode,
                "trusted_certificate_fingerprint": validated.trusted_certificate_fingerprint,
            }
        )

    def disconnect(self, *, wait: bool = True, grace_seconds: float | None = None) -> None:
        del grace_seconds
        proc = self._proc
        if proc is None or proc.poll() is not None:
            self._running = False
            return
        try:
            self._send({"operation": "disconnect"})
        except Exception:
            pass
        if wait:
            try:
                proc.wait(timeout=8)
            except Exception:
                proc.kill()
        self._running = False

    def close(self) -> None:
        self.disconnect(wait=True)
        proc = self._proc
        if proc is not None and proc.poll() is None:
            proc.terminate()

    def is_running(self) -> bool:
        return self._running and self._proc is not None and self._proc.poll() is None

    def pid(self) -> int | None:
        return self._pid

    def argv(self) -> tuple[str, ...]:
        return self._argv

    def _read_helper_hello(self):
        try:
            completed = self._version_runner([self._helper_path, "--version"])
        except (OSError, subprocess.TimeoutExpired):
            return parse_helper_hello_output(stdout="", stderr="", returncode=1)
        stdout = getattr(completed, "stdout", "") or ""
        stderr = getattr(completed, "stderr", "") or ""
        returncode = getattr(completed, "returncode", 0)
        if returncode is None:
            returncode = 0
        return parse_helper_hello_output(stdout=stdout, stderr=stderr, returncode=returncode)

    def _ensure_session(self) -> None:
        if self._proc is not None and self._proc.poll() is None:
            return
        pkexec = self._which(self._pkexec_name)
        if pkexec is None:
            raise HelperError("POLKIT_UNAVAILABLE", "polkit (pkexec) is not available.")
        helper = self._helper_path
        if not helper or not self._path_exists(helper):
            raise HelperError("HELPER_NOT_AVAILABLE", "The privileged VPN helper is not installed.")
        try:
            proc = self._popen(
                [pkexec, helper],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                shell=False,
            )
        except OSError as exc:
            raise HelperError(
                "HELPER_NOT_AVAILABLE",
                "The privileged VPN helper could not be started.",
            ) from exc
        self._proc = proc
        self._reader = threading.Thread(
            target=self._read_stdout, name="vpn-helper-ipc", daemon=True
        )
        self._reader.start()
        if proc.poll() is not None:
            self._raise_spawn_failure(proc)
        # The helper emits HELLO immediately. Version is confirmed from that event.

    def _raise_spawn_failure(self, proc: subprocess.Popen[str]) -> None:
        code = proc.returncode
        stderr = ""
        if proc.stderr is not None:
            try:
                stderr = proc.stderr.read() or ""
            except Exception:
                stderr = ""
        lowered = stderr.lower()
        if code in {126, 127} or "not authorized" in lowered or "authorization" in lowered:
            raise HelperError("PRIVILEGE_DENIED", _DENIED)
        if "traceback" in lowered:
            raise HelperError("HELPER_STARTUP_FAILED", _STARTUP_FAILED)
        raise HelperError("HELPER_NOT_AVAILABLE", "The privileged VPN helper could not be started.")

    def _send(self, payload: dict[object, object]) -> None:
        proc = self._proc
        if proc is None or proc.stdin is None:
            raise HelperError("HELPER_NOT_AVAILABLE", "The privileged VPN helper is not running.")
        if proc.poll() is not None:
            self._raise_spawn_failure(proc)
        proc.stdin.write(json.dumps(payload) + "\n")
        proc.stdin.flush()

    def _read_stdout(self) -> None:
        proc = self._proc
        if proc is None or proc.stdout is None:
            return
        try:
            for raw in proc.stdout:
                line = raw.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(payload, dict):
                    continue
                try:
                    event = event_from_payload(payload)
                except HelperError:
                    continue
                self._apply_event(event)
                listener = self._listener
                if listener is not None:
                    listener(event)
        finally:
            if proc.poll() is not None and proc.returncode not in {None, 0}:
                try:
                    self._raise_spawn_failure(proc)
                except HelperError as exc:
                    listener = self._listener
                    if listener is not None:
                        listener(
                            HelperEvent(
                                kind=HelperEventKind.ERROR,
                                code=exc.code,
                                message=exc.message,
                            )
                        )

    def _apply_event(self, event: HelperEvent) -> None:
        if event.kind is HelperEventKind.HELLO:
            version = event.helper_version
            if not is_valid_helper_version(version):
                return
            self._hello_version = version
            if version != self._expected_version:
                listener = self._listener
                if listener is not None:
                    listener(
                        HelperEvent(
                            kind=HelperEventKind.ERROR,
                            code="HELPER_VERSION_MISMATCH",
                            message="Privileged helper version does not match the GUI.",
                        )
                    )
        if event.kind is HelperEventKind.STARTED:
            self._running = True
            self._pid = event.pid
            self._argv = event.argv
        if event.kind is HelperEventKind.EXIT:
            self._running = False
            self._pid = None
            self._argv = ()


def _safe_startup_detail(text: str) -> str | None:
    if not text:
        return None
    redacted = redact_log_line(text)
    if len(redacted) > _DETAIL_LIMIT:
        redacted = redacted[:_DETAIL_LIMIT].rstrip() + "…"
    return redacted


def _run_version(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 — list argv, shell=False
        argv,
        check=False,
        capture_output=True,
        text=True,
        timeout=3,
        shell=False,
    )


def default_helper_client() -> PolkitHelperClient:
    """Production client: pkexec + installed helper path."""
    return PolkitHelperClient()


def helper_path_from_source_tree() -> str | None:
    """Return a source-tree helper path for documented development installs."""
    here = Path(__file__).resolve()
    candidate = here.parents[3] / "packaging" / "libexec" / "vpn-helper"
    if candidate.is_file():
        return str(candidate)
    return None


__all__ = [
    "HelperClient",
    "InProcessHelperClient",
    "PolkitHelperClient",
    "default_helper_client",
]
