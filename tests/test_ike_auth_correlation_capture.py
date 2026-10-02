# SPDX-License-Identifier: GPL-3.0-or-later
"""Research IKE_AUTH correlation capture tests. No live VPN, SSH, or tcpdump."""

from __future__ import annotations

import importlib.util
import json
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "research" / "linux" / "capture-ike-auth-correlation.sh"
CORRELATOR = ROOT / "tools" / "research" / "linux" / "correlate_ike_auth_capture.py"
PLUGIN = ROOT / "native" / "fvl-forticlient-vid" / "fvl_forticlient_vid_plugin.c"

PEER = "91.149.212.169"
CLIENT = "10.91.124.189"


def load_correlator():
    spec = importlib.util.spec_from_file_location("correlate_ike_auth_capture", CORRELATOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _eth(payload: bytes) -> bytes:
    return (b"\x00" * 6) + (b"\x11" * 6) + b"\x08\x00" + payload


def _ipv4_udp(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    udp_len = 8 + len(payload)
    udp = struct.pack("!HHHH", sport, dport, udp_len, 0) + payload
    total = 20 + len(udp)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total,
        0,
        0,
        64,
        17,
        0,
        socket.inet_aton(src),
        socket.inet_aton(dst),
    )
    return ip + udp


def _ike(*, exchange: int, msgid: int, next_payload: int, body: bytes, response: bool) -> bytes:
    flags = 0x08
    if response:
        flags |= 0x20
    spi_i = b"\x01" * 8
    spi_r = (b"\x02" * 8) if response else (b"\x00" * 8)
    header = (
        spi_i
        + spi_r
        + struct.pack("!BBBBII", next_payload, 0x20, exchange, flags, msgid, 28 + len(body))
    )
    return header + body


def _sa_body() -> bytes:
    return struct.pack("!BBH", 0, 0, 8) + b"\x00\x00\x00\x00"


def _pcap(frames: list[tuple[int, bytes]]) -> bytes:
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    out = [header]
    for ts, frame in frames:
        out.append(struct.pack("<IIII", ts, 0, len(frame), len(frame)))
        out.append(frame)
    return b"".join(out)


def test_capture_script_is_diagnostics_only() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    collector = (ROOT / "tools" / "research" / "linux" / "fortigate_debug_collector.py").read_text(
        encoding="utf-8"
    )
    assert "diagnose debug reset" not in text
    assert "diagnose debug reset" not in collector
    assert "diagnose debug disable" in collector
    assert "diagnose debug console timestamp enable" in collector
    assert "diagnose debug application ike -1" in collector
    assert "diagnose debug application fnbamd -1" in collector
    assert "diagnose debug enable" in collector
    assert "udp port 500" in text
    assert "udp port 4500" in text
    assert "get system status" in text
    assert "tokenid" not in text.lower()
    assert "fct_uid" not in text.lower()
    assert "pre-shared" not in text.lower()
    assert "IdentityFile" not in text
    assert "BEGIN OPENSSH PRIVATE KEY" not in text
    assert "fortigate_debug_collector.py" in text
    assert "RequestTTY=force" in (
        ROOT / "tools" / "research" / "linux" / "fortigate_debug_collector.py"
    ).read_text(encoding="utf-8")
    assert "-tt" in (
        ROOT / "tools" / "research" / "linux" / "fortigate_debug_collector.py"
    ).read_text(encoding="utf-8")
    assert "assert_ready" in text
    assert "FortiGate debug collector: ACTIVE" in text
    assert "READY: perform exactly one GUI connection attempt now." in text
    assert text.index("assert_ready") < text.index("wait_for_attempt")
    assert "exec {FG_IN_FD}>" not in text
    assert "fg-cli.in" not in text


def test_capture_script_does_not_touch_plugin_or_auth() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    plugin = PLUGIN.read_text(encoding="utf-8")
    assert "fvl_forticlient_vid_plugin.c" not in text
    assert "reposition_license_notify" not in text
    assert "omit_initiator_auth" not in text
    assert "PLV2_AUTH" in plugin
    assert "omit_initiator_auth" in plugin


def test_gitignore_excludes_research_captures() -> None:
    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "docs/research/captures/" in gitignore
    assert "*.pcap" in gitignore


def test_route_verification_accepts_lab_layout() -> None:
    mod = load_correlator()
    code, text = mod.verify_routes(
        mgmt_text="10.10.10.1 via 10.10.30.1 dev eno1 src 10.10.30.102 uid 1000",
        vpn_text="91.149.212.169 via 10.91.124.1 dev wlp5s0 src 10.91.124.189 uid 1000",
        mgmt_host="10.10.10.1",
        mgmt_dev="eno1",
        vpn_host="91.149.212.169",
        vpn_dev="wlp5s0",
    )
    assert code == 0
    assert "dev eno1" in text
    assert "dev wlp5s0" in text


def test_route_verification_rejects_wrong_device() -> None:
    mod = load_correlator()
    code, text = mod.verify_routes(
        mgmt_text="10.10.10.1 via 10.10.30.1 dev wlp5s0 src 10.91.124.189",
        vpn_text="91.149.212.169 via 10.10.30.1 dev eno1 src 10.10.30.102",
        mgmt_host="10.10.10.1",
        mgmt_dev="eno1",
        vpn_host="91.149.212.169",
        vpn_dev="wlp5s0",
    )
    assert code == 1
    assert "expected dev eno1" in text
    assert "expected dev wlp5s0" in text


def test_redact_research_text_strips_secrets_not_ike_structure() -> None:
    mod = load_correlator()
    uid = "0123456789abcdef0123456789abcdef"
    token = "TEST_ONLY_TOKEN_DO_NOT_USE"
    blob = "aa" * 120
    text = (
        f"FCT_UID={uid}\n"
        f"tokenid={token}\n"
        "password=supersecret\n"
        f"notify 0xF100 data={blob}\n"
        "FortiClient compatibility: repositioned Notify 0xF100 before CFG_REQUEST\n"
        "Serial-Number: FGT60FTK12345678\n"
    )
    redacted = mod.redact_research_text(text)
    assert uid not in redacted
    assert token not in redacted
    assert "supersecret" not in redacted
    assert blob not in redacted
    assert "[redacted hex]" in redacted
    assert "repositioned Notify 0xF100 before CFG_REQUEST" in redacted
    assert "FGT60FTK12345678" not in redacted


def test_fnbamd_ocsp_is_not_homevpn_evidence() -> None:
    mod = load_correlator()
    auth_ts = 1_000.0
    ocsp = "2026-10-01 10:00:01 fnbamd ocsp request for certificate"
    ike = "2026-10-01 10:00:01 fnbamd eap identity for vpn"
    assert mod.classify_fnbamd_line(ocsp, ike_auth_ts=auth_ts, line_ts=auth_ts) == "uncorrelated"
    assert mod.classify_fnbamd_line(ike, ike_auth_ts=auth_ts, line_ts=auth_ts) == "correlated"
    assert (
        mod.classify_fnbamd_line(ike, ike_auth_ts=auth_ts, line_ts=auth_ts + 30) == "uncorrelated"
    )


def test_pcap_parses_init_and_encrypted_ike_auth() -> None:
    mod = load_correlator()
    init_req = _eth(
        _ipv4_udp(
            CLIENT,
            PEER,
            500,
            500,
            _ike(exchange=34, msgid=0, next_payload=33, body=_sa_body(), response=False),
        )
    )
    init_resp = _eth(
        _ipv4_udp(
            PEER,
            CLIENT,
            500,
            500,
            _ike(exchange=34, msgid=0, next_payload=33, body=_sa_body(), response=True),
        )
    )
    auth = b"\x00\x00\x00\x00" + _ike(
        exchange=35, msgid=1, next_payload=46, body=b"\x00" * 32, response=False
    )
    auth_frame = _eth(_ipv4_udp(CLIENT, PEER, 4500, 4500, auth))
    retransmit = _eth(_ipv4_udp(CLIENT, PEER, 4500, 4500, auth))
    pcap = _pcap([(10, init_req), (11, init_resp), (12, auth_frame), (16, retransmit)])
    packets = mod.parse_pcap_ike_packets(pcap, peer=PEER)
    assert [p.exchange for p in packets] == ["IKE_SA_INIT", "IKE_SA_INIT", "IKE_AUTH", "IKE_AUTH"]
    assert packets[0].direction == "to-peer"
    assert packets[1].direction == "from-peer"
    assert packets[2].udp_payload_len == len(auth)
    assert packets[2].message_id == 1
    assert packets[2].next_payload == "SK"
    assert packets[2].dport == 4500
    first_auth = mod.first_matching(
        packets, exchange="IKE_AUTH", direction="to-peer", response=False, message_id=1
    )
    assert first_auth is not None
    retr = mod.ike_auth_retransmits(packets, first_auth)
    assert len(retr) == 1
    assert retr[0].timestamp == 16


def test_report_answers_questions_without_secrets_or_auth_mutation(tmp_path: Path) -> None:
    mod = load_correlator()
    auth = b"\x00\x00\x00\x00" + _ike(
        exchange=35, msgid=1, next_payload=46, body=b"\x11" * 64, response=False
    )
    frames = [
        (
            20,
            _eth(
                _ipv4_udp(
                    CLIENT,
                    PEER,
                    500,
                    500,
                    _ike(exchange=34, msgid=0, next_payload=33, body=_sa_body(), response=False),
                )
            ),
        ),
        (
            21,
            _eth(
                _ipv4_udp(
                    PEER,
                    CLIENT,
                    500,
                    500,
                    _ike(exchange=34, msgid=0, next_payload=33, body=_sa_body(), response=True),
                )
            ),
        ),
        (22, _eth(_ipv4_udp(CLIENT, PEER, 4500, 4500, auth))),
        (26, _eth(_ipv4_udp(CLIENT, PEER, 4500, 4500, auth))),
    ]
    capture = tmp_path / "cap"
    capture.mkdir()
    (capture / "ike.pcap").write_bytes(_pcap(frames))
    (capture / "meta.json").write_text(
        json.dumps(
            {
                "started_at": "2026-10-01T10:00:00Z",
                "ended_at": "2026-10-01T10:02:00Z",
                "peer": PEER,
                "capture_dev": "wlp5s0",
                "ssh_alias": "fvl-fortigate",
            }
        ),
        encoding="utf-8",
    )
    uid = "0123456789abcdef0123456789abcdef"
    (capture / "fortigate-debug.log").write_text(
        "\n".join(
            [
                "2026-10-01 10:00:19 diagnose debug disable",
                "2026-10-01 10:00:19 diagnose debug console timestamp enable",
                "2026-10-01 10:00:19 diagnose debug application ike -1",
                "2026-10-01 10:00:19 diagnose debug application fnbamd -1",
                "2026-10-01 10:00:19 diagnose debug enable",
                "2026-10-01 10:00:20 ike 0: comes 10.91.124.189:500",
                "2026-10-01 10:00:21 ike 0: IKE_SA_INIT response",
                "2026-10-01 10:00:22 fnbamd ocsp request for certificate",
                "2026-10-01 10:00:22 ike 0: parse error in IKE_AUTH",
                f"2026-10-01 10:00:22 ike 0: invalid AUTH for FCT_UID={uid}",
                "2026-10-01 10:00:22 ike 0: drop IKE_AUTH",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (capture / "gui-logs.txt").write_text(
        "FortiClient compatibility: repositioned Notify 0xF100 before CFG_REQUEST\n"
        f"tokenid=TEST_ONLY_TOKEN_DO_NOT_USE FCT_UID={uid}\n",
        encoding="utf-8",
    )
    (capture / "routing-summary.txt").write_text(
        "FortiGate management: 10.10.10.1 via 10.10.30.1 dev eno1 src 10.10.30.102\n",
        encoding="utf-8",
    )
    path = mod.write_report(capture)
    report = path.read_text(encoding="utf-8")
    assert "Diagnostics only" in report
    assert "does not authorize stacking another protocol mutation" in report
    assert "Notify 0xF100" in report
    assert "CFG_REQUEST (CP16)" in report
    assert "A. Does FortiGate receive" in report
    assert "parse error" in report
    assert "invalid AUTH" in report
    assert uid not in report
    assert "TEST_ONLY_TOKEN_DO_NOT_USE" not in report
    assert "Uncorrelated fnbamd" in report
    assert "Retransmission timestamps" in report
    assert "00:00:26" in report
    assert "INVALID" not in report
    assert "FortiGate IKE debug lines were present" in report


def test_missing_fortigate_debug_marks_report_invalid(tmp_path: Path) -> None:
    mod = load_correlator()
    capture = tmp_path / "cap"
    capture.mkdir()
    (capture / "meta.json").write_text("{}", encoding="utf-8")
    (capture / "routing-summary.txt").write_text("dev eno1\n", encoding="utf-8")
    path = mod.write_report(capture)
    report = path.read_text(encoding="utf-8")
    assert "INVALID" in report
    assert "FortiGate debug collector was unavailable/failed" in report
    assert "silent discard" in report
    assert "possible silent discard before IKE_AUTH processing" not in report


def test_active_collector_without_ike_lines_is_not_invalid(tmp_path: Path) -> None:
    mod = load_correlator()
    capture = tmp_path / "cap"
    capture.mkdir()
    handshake = "\n".join(
        [
            "diagnose debug disable",
            "diagnose debug console timestamp enable",
            "diagnose debug application ike -1",
            "diagnose debug application fnbamd -1",
            "diagnose debug enable",
        ]
    )
    (capture / "fortigate-debug.log").write_text(handshake + "\n", encoding="utf-8")
    (capture / "fortigate-debug-status.json").write_text(
        json.dumps({"state": "active"}), encoding="utf-8"
    )
    (capture / "meta.json").write_text("{}", encoding="utf-8")
    report = mod.write_report(capture).read_text(encoding="utf-8")
    assert "INVALID" not in report
    assert "FortiGate debug collector captured no relevant IKE lines" in report


def test_collector_starts_and_persists_raw_debug(tmp_path: Path) -> None:
    collector = ROOT / "tools" / "research" / "linux" / "fortigate_debug_collector.py"
    log = tmp_path / "fortigate-debug.log"
    status = tmp_path / "fortigate-debug-status.json"
    control = tmp_path / "fg-control"
    proc = subprocess.Popen(
        [
            sys.executable,
            str(collector),
            "--log",
            str(log),
            "--status",
            str(status),
            "--control",
            str(control),
            "--ready-timeout",
            "8",
            "--fake-remote",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        state = ""
        deadline = time.time() + 10
        while time.time() < deadline:
            if status.is_file():
                try:
                    state = json.loads(status.read_text(encoding="utf-8")).get("state", "")
                except json.JSONDecodeError:
                    state = ""
                if state == "active":
                    break
            if proc.poll() is not None:
                break
            time.sleep(0.1)
        assert state == "active"
        assert proc.poll() is None
        text = log.read_text(encoding="utf-8", errors="replace")
        assert "diagnose debug enable" in text
        assert "diagnose debug application ike -1" in text
        os_write = control.write_bytes(b"shutdown\n")
        del os_write
        proc.wait(timeout=8)
        stopped = json.loads(status.read_text(encoding="utf-8"))
        assert stopped.get("state") in {"stopped", "active"}
        final = log.read_text(encoding="utf-8", errors="replace")
        assert "diagnose debug disable" in final
    finally:
        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=5)


def test_collector_death_before_ready_is_failed(tmp_path: Path) -> None:
    collector = ROOT / "tools" / "research" / "linux" / "fortigate_debug_collector.py"
    log = tmp_path / "fortigate-debug.log"
    status = tmp_path / "fortigate-debug-status.json"
    control = tmp_path / "fg-control"
    completed = subprocess.run(
        [
            sys.executable,
            str(collector),
            "--log",
            str(log),
            "--status",
            str(status),
            "--control",
            str(control),
            "--ready-timeout",
            "4",
            "--fake-remote-die",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.returncode != 0
    payload = json.loads(status.read_text(encoding="utf-8"))
    assert payload["state"] == "failed"
    assert "READY: perform exactly one GUI connection attempt now." not in completed.stdout
    text = log.read_text(encoding="utf-8", errors="replace")
    assert "diagnose debug enable" not in text or payload["state"] == "failed"


def test_script_prints_ready_only_after_collector_self_test() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert "FortiGate debug collector died before READY" in text
    assert "diagnose debug enable" in text
    ready_at = text.index("READY: perform exactly one GUI connection attempt now.")
    die_at = text.index("FortiGate CLI session did not accept debug commands")
    assert die_at < ready_at
    assert "printf 'shutdown" in text or "shutdown\\n" in text
    collector = (ROOT / "tools" / "research" / "linux" / "fortigate_debug_collector.py").read_text(
        encoding="utf-8"
    )
    assert "diagnose debug disable" in collector
    assert "IdentityFile" not in collector
    assert "diagnose debug reset" not in collector
