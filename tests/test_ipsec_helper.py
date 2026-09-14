# SPDX-License-Identifier: GPL-3.0-or-later
"""IPsec helper protocol, backend selection, and lifecycle tests."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from fortigate_vpn_gui.helper.protocol import BACKEND_IPSEC, HelperEventKind, HelperProtocolError
from fortigate_vpn_gui.helper.service import (
    HelperService,
    SwanctlCommandResult,
    wait_for_charon_ready,
    wait_for_unix_socket,
)
from fortigate_vpn_gui.helper.validation import (
    connect_request_from_fields,
    parse_request_payload,
)
from fortigate_vpn_gui.profiles.ipsec import default_ipsec_settings
from fortigate_vpn_gui.profiles.model import build_profile
from fortigate_vpn_gui.vpn.ipsec.detect import IpsecBackendCapabilities
from fortigate_vpn_gui.vpn.ipsec.secrets import IpsecCredentials
from fortigate_vpn_gui.vpn.models import ConnectionState, VpnErrorCode
from tests.vpn_fakes import FakeVpnProcess, VpnHarness


def _ipsec_request():
    return connect_request_from_fields(
        gateway="vpn.example.com",
        port=500,
        auth_mode="standard",
        backend=BACKEND_IPSEC,
        ipsec=default_ipsec_settings().to_json(),
    )


def _available_ipsec():
    return IpsecBackendCapabilities(
        charon_path="/usr/lib/ipsec/charon",
        swanctl_path="/usr/sbin/swanctl",
        available=True,
        source="test",
    )


def test_ssl_connect_json_still_accepted() -> None:
    operation, request = parse_request_payload(
        {
            "operation": "connect",
            "gateway": "vpn.example.com",
            "port": 443,
            "auth_mode": "saml",
        }
    )
    assert operation == "connect"
    assert request is not None
    assert request.backend == "openfortivpn"


def test_password_still_rejected_on_ssl_connect() -> None:
    with pytest.raises(HelperProtocolError, match="UNSUPPORTED_FIELD"):
        parse_request_payload(
            {
                "operation": "connect",
                "gateway": "vpn.example.com",
                "port": 443,
                "auth_mode": "standard",
                "password": "nope",
            }
        )


def test_ipsec_connect_request_is_secret_free() -> None:
    request = connect_request_from_fields(
        gateway="vpn.example.com",
        port=500,
        auth_mode="standard",
        backend=BACKEND_IPSEC,
        ipsec=default_ipsec_settings().to_json(),
    )
    assert request.ipsec is not None
    assert "psk" not in request.ipsec
    assert "password" not in request.ipsec


def test_unsupported_ipsec_combo_rejected_by_helper() -> None:
    with pytest.raises(HelperProtocolError, match="UNSUPPORTED_IPSEC"):
        connect_request_from_fields(
            gateway="vpn.example.com",
            port=500,
            auth_mode="standard",
            backend=BACKEND_IPSEC,
            ipsec={**default_ipsec_settings().to_json(), "ike_version": "ikev2"},
        )


def test_backend_refuses_ipsec_without_credentials() -> None:
    harness = VpnHarness()
    profile = build_profile(
        name="IPsec",
        gateway="vpn.example.com",
        port=500,
        vpn_type="ipsec",
        ipsec=default_ipsec_settings().to_json(),
    )
    harness.backend.connect(profile)
    snapshot = harness.backend.snapshot()
    assert snapshot.error_code is VpnErrorCode.IPSEC_CREDENTIALS_REQUIRED


def test_backend_selects_ipsec_vs_ssl() -> None:
    ssl = build_profile(name="SSL", gateway="vpn.example.com", port=443)
    ipsec = build_profile(
        name="IPsec",
        gateway="vpn.example.com",
        port=500,
        vpn_type="ipsec",
        ipsec=default_ipsec_settings().to_json(),
    )
    harness = VpnHarness()
    harness.backend.connect(ssl)
    assert harness.backend.snapshot().vpn_backend == "openfortivpn"
    harness.backend.disconnect(wait=True)
    harness.backend.connect(
        ipsec,
        credentials=IpsecCredentials(psk="super-psk", username="ada", password="hunter2"),
    )
    snapshot = harness.backend.snapshot()
    assert snapshot.vpn_backend == "ipsec"
    assert snapshot.error_code is VpnErrorCode.IPSEC_BACKEND_MISSING


def test_helper_ipsec_argv_has_no_secrets(tmp_path: Path) -> None:
    held: dict[str, FakeVpnProcess] = {}
    swanctl_calls: list[list[str]] = []

    def factory(argv, on_output, on_exit, env=None):
        proc = FakeVpnProcess(argv, on_output, on_exit, env=env)
        held["proc"] = proc
        return proc

    def swanctl_runner(argv: list[str], timeout: float) -> SwanctlCommandResult:
        del timeout
        swanctl_calls.append(list(argv))
        return SwanctlCommandResult(returncode=0)

    events: list[object] = []
    service = HelperService(
        process_factory=factory,
        ipsec_discover=lambda: IpsecBackendCapabilities(
            charon_path="/usr/lib/ipsec/charon",
            swanctl_path="/usr/sbin/swanctl",
            available=True,
            source="test",
        ),
        runtime_dir_factory=lambda: tmp_path / "run",
        swanctl_runner=swanctl_runner,
        vici_wait=lambda path, timeout: True,
        listener=events.append,
    )
    (tmp_path / "run").mkdir()
    request = connect_request_from_fields(
        gateway="vpn.example.com",
        port=500,
        auth_mode="standard",
        backend=BACKEND_IPSEC,
        ipsec=default_ipsec_settings().to_json(),
    )
    credentials = IpsecCredentials(psk="super-psk", username="ada", password="hunter2")
    service.connect(request, credentials=credentials)
    service.wait_for_ipsec_setup(timeout=2.0)
    proc = held["proc"]
    assert proc.argv == ["/usr/lib/ipsec/charon"]
    assert "--conf" not in proc.argv
    assert proc.env is not None
    assert proc.env["STRONGSWAN_CONF"] == str(tmp_path / "run" / "strongswan.conf")
    joined = " ".join(proc.argv)
    assert "super-psk" not in joined
    assert "hunter2" not in joined
    assert all("super-psk" not in value for value in proc.env.values())
    assert all("hunter2" not in value for value in proc.env.values())
    conf = (tmp_path / "run" / "swanctl.conf").read_text(encoding="utf-8")
    strongswan = (tmp_path / "run" / "strongswan.conf").read_text(encoding="utf-8")
    assert "super-psk" not in conf
    assert "remote_ts = 0.0.0.0/0" in conf
    assert "remote_ts = dynamic" not in conf
    assert "cisco_unity = yes" in strongswan
    assert "unix://" in strongswan
    assert "charon.vici" in strongswan
    assert any("--load-all" in call for call in swanctl_calls)
    assert any("--initiate" in call for call in swanctl_calls)
    conf_path = str(tmp_path / "run" / "swanctl.conf")
    assert any(
        call == ["/usr/sbin/swanctl", "--load-all", "--file", conf_path]
        for call in swanctl_calls
    )
    assert any(
        call == ["/usr/sbin/swanctl", "--initiate", "--child", "fortigate"]
        for call in swanctl_calls
    )
    for call in swanctl_calls:
        assert "super-psk" not in call
        assert "hunter2" not in call
        assert "--unix" not in call
        assert "--uri" not in call
        assert call[0] == "/usr/sbin/swanctl"
        assert call[1] in {"--load-all", "--initiate", "--terminate"}
        assert "--file" not in call or call[1] == "--load-all"
    kinds = [getattr(event, "kind", None) for event in events]
    assert HelperEventKind.CONNECTED in kinds
    service.disconnect()
    assert not (tmp_path / "run").exists()


def test_helper_emits_connected_from_charon_child_sa(tmp_path: Path) -> None:
    held: dict[str, FakeVpnProcess] = {}

    def factory(argv, on_output, on_exit, env=None):
        proc = FakeVpnProcess(argv, on_output, on_exit, env=env)
        held["proc"] = proc
        return proc

    events: list[object] = []
    service = HelperService(
        process_factory=factory,
        ipsec_discover=lambda: IpsecBackendCapabilities(
            charon_path="/usr/lib/ipsec/charon",
            swanctl_path="/usr/sbin/swanctl",
            available=True,
            source="test",
        ),
        runtime_dir_factory=lambda: tmp_path / "run",
        swanctl_runner=lambda argv, timeout: SwanctlCommandResult(returncode=0),
        vici_wait=lambda path, timeout: True,
        listener=events.append,
    )
    (tmp_path / "run").mkdir()
    request = connect_request_from_fields(
        gateway="vpn.example.com",
        port=500,
        auth_mode="standard",
        backend=BACKEND_IPSEC,
        ipsec=default_ipsec_settings().to_json(),
    )
    service.connect(
        request,
        credentials=IpsecCredentials(psk="super-psk", username="ada", password="hunter2"),
    )
    held["proc"].emit("13[IKE] CHILD_SA fortigate{1} established with SPIs c1-c2")
    kinds = [getattr(event, "kind", None) for event in events]
    assert HelperEventKind.CONNECTED in kinds
    service.disconnect()


def test_wait_for_charon_ready_detects_exit_without_full_timeout(tmp_path: Path) -> None:
    waits: list[float] = []

    def socket_wait(path: Path, timeout: float) -> bool:
        waits.append(timeout)
        time.sleep(timeout)
        return False

    started = time.monotonic()
    outcome = wait_for_charon_ready(
        tmp_path / "charon.vici",
        5.0,
        poll_exit=lambda: 1,
        socket_wait=socket_wait,
    )
    elapsed = time.monotonic() - started
    assert outcome == "exited"
    assert elapsed < 0.5
    assert waits == []


def test_wait_for_charon_ready_times_out_only_while_running(tmp_path: Path) -> None:
    started = time.monotonic()
    outcome = wait_for_charon_ready(
        tmp_path / "missing.vici",
        0.2,
        poll_exit=lambda: None,
        socket_wait=wait_for_unix_socket,
    )
    elapsed = time.monotonic() - started
    assert outcome == "timeout"
    assert elapsed >= 0.2
    assert elapsed < 1.0


def test_early_charon_exit_is_daemon_start_failed_not_backend_missing(
    tmp_path: Path,
) -> None:
    held: dict[str, FakeVpnProcess] = {}
    events: list[object] = []

    def factory(argv, on_output, on_exit, env=None):
        proc = FakeVpnProcess(argv, on_output, on_exit, env=env)
        held["proc"] = proc
        return proc

    service = HelperService(
        process_factory=factory,
        ipsec_discover=_available_ipsec,
        runtime_dir_factory=lambda: tmp_path / "run",
        swanctl_runner=lambda argv, timeout: SwanctlCommandResult(returncode=0),
        listener=events.append,
    )
    (tmp_path / "run").mkdir()
    service.connect(
        _ipsec_request(),
        credentials=IpsecCredentials(psk="super-psk", username="ada", password="hunter2"),
    )
    proc = held["proc"]
    proc.emit("/usr/lib/ipsec/charon: unrecognized option '--conf'")
    proc.emit("Usage: charon")
    started = time.monotonic()
    proc.finish(1)
    service.wait_for_ipsec_setup(timeout=2.0)
    elapsed = time.monotonic() - started
    assert elapsed < 1.0
    errors = [
        event
        for event in events
        if getattr(event, "kind", None) is HelperEventKind.ERROR
    ]
    assert errors
    assert all(getattr(event, "code", None) != "IPSEC_BACKEND_MISSING" for event in errors)
    assert any(getattr(event, "code", None) == "IPSEC_DAEMON_START_FAILED" for event in errors)
    message = " ".join(getattr(event, "message", "") or "" for event in errors)
    assert "unrecognized option '--conf'" in message
    assert "super-psk" not in message
    assert "hunter2" not in message
    logs = [
        getattr(event, "line", "") or ""
        for event in events
        if getattr(event, "kind", None) is HelperEventKind.LOG
    ]
    assert any("unrecognized option '--conf'" in line for line in logs)
    assert all("super-psk" not in line for line in logs)
    assert not (tmp_path / "run").exists()


def test_ipsec_process_exit_is_not_logged_as_openfortivpn(tmp_path: Path) -> None:
    (tmp_path / "run").mkdir()
    harness = VpnHarness(
        ipsec_available=True,
        runtime_dir_factory=lambda: tmp_path / "run",
        vici_wait=lambda path, timeout: False,
    )
    profile = build_profile(
        name="IPsec",
        gateway="vpn.example.com",
        port=500,
        vpn_type="ipsec",
        ipsec=default_ipsec_settings().to_json(),
    )
    harness.backend.connect(
        profile,
        credentials=IpsecCredentials(psk="super-psk", username="ada", password="hunter2"),
    )
    assert harness.process is not None
    harness.process.emit("/usr/lib/ipsec/charon: unrecognized option '--conf'")
    harness.process.finish(1)
    harness.helper.wait_for_ipsec_setup(timeout=2.0)
    snapshot = harness.backend.snapshot()
    assert snapshot.error_code is VpnErrorCode.IPSEC_DAEMON_START_FAILED
    assert snapshot.last_failure_reason == "ipsec_daemon_start_failed"
    assert snapshot.state is ConnectionState.FAILED
    exits = [record for record in harness.log.records() if "Process exited" in record.message]
    assert exits
    assert all(record.source == "ipsec" for record in exits)
    joined = " ".join(record.format_line() for record in harness.log.records())
    assert "[openfortivpn] Process exited" not in joined
    assert "super-psk" not in joined
    assert "hunter2" not in joined


def test_ssl_process_exit_is_still_logged_as_openfortivpn() -> None:
    harness = VpnHarness()
    profile = build_profile(name="SSL", gateway="vpn.example.com", port=443)
    harness.backend.connect(profile)
    assert harness.process is not None
    harness.process.finish(1)
    exits = [record for record in harness.log.records() if "Process exited" in record.message]
    assert exits
    assert all(record.source == "openfortivpn" for record in exits)
    assert harness.backend.snapshot().error_code is VpnErrorCode.VPN_PROCESS_FAILED


_SWANCTL_USAGE_DUMP = """\
/usr/sbin/swanctl: unrecognized option '--unix'
Error: invalid operation
strongSwan 5.9.13 swanctl
usage:
 swanctl --initiate       (-i) initiate a connection
 swanctl --terminate      (-t) terminate a connection
 swanctl --load-all       (-q) load credentials, authorities, pools and connections
 --unix            (-u) connect to vici socket
 --file            (-f) custom path to swanctl.conf
"""


def test_repeated_swanctl_usage_dump_is_logged_once(tmp_path: Path) -> None:
    swanctl_calls: list[list[str]] = []

    def factory(argv, on_output, on_exit, env=None):
        return FakeVpnProcess(argv, on_output, on_exit, env=env)

    def swanctl_runner(argv: list[str], timeout: float) -> SwanctlCommandResult:
        del timeout
        swanctl_calls.append(list(argv))
        return SwanctlCommandResult(returncode=1, stderr=_SWANCTL_USAGE_DUMP)

    events: list[object] = []
    service = HelperService(
        process_factory=factory,
        ipsec_discover=_available_ipsec,
        runtime_dir_factory=lambda: tmp_path / "run",
        swanctl_runner=swanctl_runner,
        vici_wait=lambda path, timeout: True,
        listener=events.append,
    )
    (tmp_path / "run").mkdir()
    service.connect(
        _ipsec_request(),
        credentials=IpsecCredentials(psk="super-psk", username="ada", password="hunter2"),
    )
    service.wait_for_ipsec_setup(timeout=2.0)
    logs = [
        getattr(event, "line", "") or ""
        for event in events
        if getattr(event, "kind", None) is HelperEventKind.LOG
    ]
    assert swanctl_calls
    assert all("--unix" not in call for call in swanctl_calls)
    unix_mentions = [line for line in logs if "unrecognized option '--unix'" in line]
    assert len(unix_mentions) == 1
    assert all(line.strip() != "usage:" for line in logs)
    assert all(not line.strip().startswith("swanctl --") for line in logs)
    assert all("super-psk" not in line for line in logs)
    assert all("hunter2" not in line for line in logs)
