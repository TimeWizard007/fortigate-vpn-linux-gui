#!/usr/bin/env python3.12
# SPDX-License-Identifier: GPL-3.0-or-later
"""Build a redacted IKE_AUTH correlation report from a research capture directory.

Diagnostics / evidence only. Does not start a VPN, talk to FortiGate, or change
IKE behavior. Raw pcaps and FortiGate logs stay in the capture directory;
this writes a redacted human-readable report beside them.
"""

from __future__ import annotations

import argparse
import json
import re
import struct
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from fortigate_vpn_gui.diagnostics.checks import parse_ip_route_get  # noqa: E402
from fortigate_vpn_gui.vpn.log_redaction import redact_log_line  # noqa: E402

IKE_SA_INIT = 34
IKE_AUTH = 35
UDP_IKE = 500
UDP_NATT = 4500
NON_ESP_MARKER = b"\x00\x00\x00\x00"
NATT_KEEPALIVE = b"\xff"

PAYLOAD_NAMES = {
    0: "NONE",
    33: "SA",
    34: "KE",
    35: "IDi",
    36: "IDr",
    37: "CERT",
    38: "CERTREQ",
    39: "AUTH",
    40: "Ni/Nr",
    41: "N",
    42: "D",
    43: "V",
    44: "TSi",
    45: "TSr",
    46: "SK",
    47: "CP",
    48: "EAP",
}

EXCHANGE_NAMES = {
    IKE_SA_INIT: "IKE_SA_INIT",
    IKE_AUTH: "IKE_AUTH",
}

FNBAMD_UNRELATED = re.compile(
    r"\b(ocsp|crl|certificate|cert |untrusted ca|ca cert)\b",
    re.IGNORECASE,
)
FNBAMD_IKE_HINT = re.compile(
    r"\b(ike|eap|saml|mschap|xauth|vpn|tokenid|fct_uid)\b",
    re.IGNORECASE,
)
LEADING_TS = re.compile(
    r"^((?:\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?)|"
    r"(?:\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}))"
)
LONG_HEX = re.compile(r"(?i)(?<![0-9a-f])[0-9a-f]{80,}(?![0-9a-f])")
SERIAL = re.compile(r"(?i)(serial[- ]number\s*[:=]\s*)\S+")
PRIVATE_KEY_HEADER = re.compile(r"BEGIN [A-Z ]*PRIVATE KEY")

HANDSHAKE_MARKERS = (
    "diagnose debug application ike -1",
    "diagnose debug application fnbamd -1",
    "diagnose debug enable",
)
FROZEN_ORDER = (
    "IDi",
    "INITIAL_CONTACT",
    "Notify 0xF100",
    "CFG_REQUEST (CP16)",
    "SA",
    "TSi",
    "TSr",
)


@dataclass(frozen=True)
class RouteExpectation:
    destination: str
    device: str
    label: str


@dataclass(frozen=True)
class RouteCheck:
    ok: bool
    summary: str
    device: str | None


@dataclass(frozen=True)
class IkePacket:
    timestamp: float
    src: str
    dst: str
    sport: int
    dport: int
    ip_len: int
    udp_len: int
    udp_payload_len: int
    direction: str
    exchange: str
    message_id: int | None
    initiator: bool
    response: bool
    ike_len: int | None
    next_payload: str
    payloads: tuple[str, ...]
    note: str = ""


def format_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + "Z"


def redact_research_text(text: str) -> str:
    """Redact secrets for the human-readable report. Per-line; no 400-char cap."""
    out: list[str] = []
    for raw in text.splitlines(keepends=True):
        newline = ""
        line = raw
        if raw.endswith("\n"):
            newline = "\n"
            line = raw[:-1]
        if PRIVATE_KEY_HEADER.search(line):
            out.append("[redacted private key]" + newline)
            continue
        redacted = redact_log_line(line)
        redacted = SERIAL.sub(r"\1***", redacted)
        redacted = LONG_HEX.sub("[redacted hex]", redacted)
        out.append(redacted + newline)
    return "".join(out)


def check_route(text: str, expected: RouteExpectation) -> RouteCheck:
    parsed = parse_ip_route_get(text)
    if parsed is None:
        return RouteCheck(
            False,
            f"{expected.label}: no parseable route to {expected.destination}",
            None,
        )
    device = parsed.device
    summary = (
        f"{expected.label}: {expected.destination} via {parsed.via or '?'} "
        f"dev {device or '?'} src {parsed.source or '?'}"
    )
    if device != expected.device:
        return RouteCheck(
            False,
            f"{summary} (expected dev {expected.device})",
            device,
        )
    return RouteCheck(True, summary, device)


def classify_fnbamd_line(line: str, *, ike_auth_ts: float | None, line_ts: float | None) -> str:
    """Return correlated, uncorrelated, or ignore for a fnbamd debug line."""
    lowered = line.lower()
    if "fnbamd" not in lowered:
        return "ignore"
    if FNBAMD_UNRELATED.search(line) and not FNBAMD_IKE_HINT.search(line):
        return "uncorrelated"
    if ike_auth_ts is None or line_ts is None:
        return "uncorrelated"
    if abs(line_ts - ike_auth_ts) <= 3.0 and FNBAMD_IKE_HINT.search(line):
        return "correlated"
    return "uncorrelated"


def parse_leading_timestamp(line: str, *, default_date: str | None = None) -> float | None:
    match = LEADING_TS.search(line.strip())
    if match is None:
        return None
    stamp = match.group(1)
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
        try:
            return datetime.strptime(stamp, fmt).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    if default_date and re.match(r"^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}$", stamp):
        try:
            parsed = datetime.strptime(f"{default_date} {stamp}", "%Y %b %d %H:%M:%S")
            return parsed.replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            return None
    return None


def _payload_name(code: int) -> str:
    return PAYLOAD_NAMES.get(code, f"type-{code}")


def walk_unencrypted_payloads(body: bytes, next_payload: int) -> tuple[str, ...]:
    names: list[str] = []
    current = next_payload
    offset = 0
    while current and offset + 4 <= len(body):
        nxt, _critical, length = struct.unpack("!BBH", body[offset : offset + 4])
        if length < 4 or offset + length > len(body):
            names.append(_payload_name(current) + "(truncated)")
            break
        names.append(_payload_name(current))
        if current == 46:  # SK — remainder is ciphertext
            break
        offset += length
        current = nxt
    return tuple(names)


def parse_ike_header(
    payload: bytes, *, sport: int, dport: int
) -> tuple[int, int, int, int, int, int, bytes] | None:
    data = payload
    if sport == UDP_NATT or dport == UDP_NATT:
        if data == NATT_KEEPALIVE:
            return None
        if data.startswith(NON_ESP_MARKER):
            data = data[4:]
        elif len(data) >= 4 and data[:4] != NON_ESP_MARKER:
            return None
    if len(data) < 28:
        return None
    next_payload, version, exchange, flags, message_id, length = struct.unpack(
        "!BBBBII", data[16:28]
    )
    if version >> 4 != 2:
        return None
    return next_payload, version, exchange, flags, message_id, length, data[28:]


def parse_pcap_ike_packets(data: bytes, *, peer: str) -> tuple[IkePacket, ...]:
    if len(data) < 24:
        return ()
    magic, _vmaj, _vmin, _zone, _sigfigs, _snaplen, network = struct.unpack("<IHHIIII", data[:24])
    if magic != 0xA1B2C3D4:
        return ()
    offset = 24
    packets: list[IkePacket] = []
    while offset + 16 <= len(data):
        ts_sec, ts_usec, incl_len, _orig_len = struct.unpack("<IIII", data[offset : offset + 16])
        offset += 16
        frame = data[offset : offset + incl_len]
        offset += incl_len
        parsed = _parse_frame(frame, network)
        if parsed is None:
            continue
        src, dst, sport, dport, ip_len, udp_len, udp_payload = parsed
        if peer not in {src, dst}:
            continue
        if sport not in {UDP_IKE, UDP_NATT} and dport not in {UDP_IKE, UDP_NATT}:
            continue
        ts = ts_sec + ts_usec / 1_000_000
        direction = "to-peer" if dst == peer else "from-peer"
        header = parse_ike_header(udp_payload, sport=sport, dport=dport)
        if header is None:
            note = "NAT-T keepalive" if udp_payload == NATT_KEEPALIVE else "non-IKE UDP"
            packets.append(
                IkePacket(
                    timestamp=ts,
                    src=src,
                    dst=dst,
                    sport=sport,
                    dport=dport,
                    ip_len=ip_len,
                    udp_len=udp_len,
                    udp_payload_len=len(udp_payload),
                    direction=direction,
                    exchange=note,
                    message_id=None,
                    initiator=False,
                    response=False,
                    ike_len=None,
                    next_payload="—",
                    payloads=(),
                    note=note,
                )
            )
            continue
        next_payload, _version, exchange, flags, message_id, length, body = header
        names = walk_unencrypted_payloads(body, next_payload)
        packets.append(
            IkePacket(
                timestamp=ts,
                src=src,
                dst=dst,
                sport=sport,
                dport=dport,
                ip_len=ip_len,
                udp_len=udp_len,
                udp_payload_len=len(udp_payload),
                direction=direction,
                exchange=EXCHANGE_NAMES.get(exchange, f"exchange-{exchange}"),
                message_id=message_id,
                initiator=bool(flags & 0x08),
                response=bool(flags & 0x20),
                ike_len=length,
                next_payload=_payload_name(next_payload),
                payloads=names,
            )
        )
    return tuple(packets)


def _parse_frame(frame: bytes, network: int) -> tuple[str, str, int, int, int, int, bytes] | None:
    if network == 1:
        if len(frame) < 14:
            return None
        ethertype = struct.unpack("!H", frame[12:14])[0]
        l3 = 14
        if ethertype == 0x8100 and len(frame) >= 18:
            ethertype = struct.unpack("!H", frame[16:18])[0]
            l3 = 18
        if ethertype != 0x0800:
            return None
        return _parse_ipv4_udp(frame[l3:])
    if network == 113:
        if len(frame) < 16:
            return None
        ethertype = struct.unpack("!H", frame[14:16])[0]
        if ethertype != 0x0800:
            return None
        return _parse_ipv4_udp(frame[16:])
    return None


def _parse_ipv4_udp(packet: bytes) -> tuple[str, str, int, int, int, int, bytes] | None:
    if len(packet) < 20:
        return None
    ver_ihl, _, total_len, _, _, _, proto, _, src_b, dst_b = struct.unpack(
        "!BBHHHBBH4s4s", packet[:20]
    )
    if ver_ihl >> 4 != 4 or proto != 17:
        return None
    ihl = (ver_ihl & 0x0F) * 4
    if ihl < 20 or len(packet) < ihl + 8:
        return None
    udp = packet[ihl:]
    sport, dport, udp_len, _ = struct.unpack("!HHHH", udp[:8])
    payload = udp[8 : 8 + max(0, udp_len - 8)]
    src = ".".join(str(b) for b in src_b)
    dst = ".".join(str(b) for b in dst_b)
    return src, dst, sport, dport, total_len, udp_len, payload


def first_matching(packets: tuple[IkePacket, ...], **kwargs) -> IkePacket | None:
    for packet in packets:
        if all(getattr(packet, key) == value for key, value in kwargs.items()):
            return packet
    return None


def ike_auth_retransmits(packets: tuple[IkePacket, ...], first: IkePacket) -> tuple[IkePacket, ...]:
    found: list[IkePacket] = []
    for packet in packets:
        if packet is first:
            continue
        if (
            packet.exchange == "IKE_AUTH"
            and packet.direction == first.direction
            and packet.message_id == first.message_id
            and not packet.response
        ):
            found.append(packet)
    return tuple(found)


def extract_fortigate_highlights(text: str, *, ike_auth_ts: float | None) -> dict[str, list[str]]:
    buckets: dict[str, list[str]] = {
        "ike_sa_init": [],
        "ike_auth": [],
        "parse_decrypt": [],
        "auth_error": [],
        "eap": [],
        "last_ike": [],
        "fnbamd_correlated": [],
        "fnbamd_uncorrelated": [],
    }
    ike_lines: list[str] = []
    for raw in text.splitlines():
        line = raw.rstrip("\n")
        if not line.strip():
            continue
        if "diagnose debug" in line.lower():
            continue
        lowered = line.lower()
        line_ts = parse_leading_timestamp(line)
        fnbamd = classify_fnbamd_line(line, ike_auth_ts=ike_auth_ts, line_ts=line_ts)
        if fnbamd == "correlated":
            buckets["fnbamd_correlated"].append(line)
            continue
        if fnbamd == "uncorrelated":
            buckets["fnbamd_uncorrelated"].append(line)
            continue
        if "ike" in lowered:
            ike_lines.append(line)
            if "ike_sa_init" in lowered or "information-sa" in lowered:
                buckets["ike_sa_init"].append(line)
            if "ike_auth" in lowered:
                buckets["ike_auth"].append(line)
            if any(
                token in lowered
                for token in ("decrypt", "decapsulate", "parse error", "parse fail")
            ):
                buckets["parse_decrypt"].append(line)
            if re.search(r"\bauth\b", lowered) and any(
                token in lowered for token in ("fail", "invalid", "error", "reject", "mismatch")
            ):
                buckets["auth_error"].append(line)
            if "eap" in lowered:
                buckets["eap"].append(line)
    if ike_lines:
        buckets["last_ike"] = ike_lines[-8:]
    return buckets


def handshake_accepted(log_text: str) -> bool:
    text = (log_text or "").replace("\r", "")
    return all(marker in text for marker in HANDSHAKE_MARKERS)


def load_collector_status(capture_dir: Path) -> dict[str, str]:
    status_path = capture_dir / "fortigate-debug-status.json"
    if status_path.is_file():
        try:
            loaded = json.loads(status_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {"state": "failed", "reason": "status json unreadable"}
        return {str(k): str(v) if v is not None else "" for k, v in loaded.items()}
    log_path = capture_dir / "fortigate-debug.log"
    if not log_path.is_file():
        return {"state": "failed", "reason": "raw FortiGate debug file missing"}
    if handshake_accepted(load_text(log_path)):
        return {"state": "stopped", "reason": ""}
    if not load_text(log_path).strip():
        return {"state": "failed", "reason": "raw FortiGate debug file empty"}
    return {"state": "failed", "reason": "debug handshake not present"}


def collector_evidence_state(log_text: str, status: dict[str, str]) -> str:
    """Return failed, active_no_ike, or active_with_ike."""
    state = str(status.get("state") or "").lower()
    if state in {"failed", "missing", "unreadable", "unavailable"}:
        return "failed"
    if not handshake_accepted(log_text):
        return "failed"
    fg = extract_fortigate_highlights(log_text, ike_auth_ts=None)
    if fg["ike_sa_init"] or fg["ike_auth"] or fg["last_ike"] or fg["parse_decrypt"]:
        return "active_with_ike"
    return "active_no_ike"


def _bullet(lines: list[str], *, empty: str = "none in this capture") -> str:
    if not lines:
        return f"- {empty}"
    return "\n".join(f"- `{redact_research_text(line)}`" for line in lines[:40])


def build_report(
    *,
    meta: dict[str, str],
    packets: tuple[IkePacket, ...],
    fortigate_text: str,
    local_text: str,
    route_lines: tuple[str, ...],
    collector_status: dict[str, str] | None = None,
) -> str:
    peer = meta.get("peer", "91.149.212.169")
    status = collector_status or {}
    evidence = collector_evidence_state(fortigate_text, status)
    collector_reason = status.get("reason") or ""
    init_req = first_matching(
        packets, exchange="IKE_SA_INIT", direction="to-peer", response=False, message_id=0
    ) or first_matching(packets, exchange="IKE_SA_INIT", direction="to-peer", response=False)
    init_resp = first_matching(
        packets, exchange="IKE_SA_INIT", direction="from-peer", response=True
    )
    first_auth = first_matching(
        packets, exchange="IKE_AUTH", direction="to-peer", response=False, message_id=1
    ) or first_matching(packets, exchange="IKE_AUTH", direction="to-peer", response=False)
    auth_reply = None
    if first_auth is not None:
        auth_reply = first_matching(
            packets,
            exchange="IKE_AUTH",
            direction="from-peer",
            response=True,
            message_id=first_auth.message_id,
        )
    retrans = ike_auth_retransmits(packets, first_auth) if first_auth else ()
    ike_auth_ts = first_auth.timestamp if first_auth else None
    fg = extract_fortigate_highlights(fortigate_text, ike_auth_ts=ike_auth_ts)
    local_redacted = redact_research_text(local_text)
    local_hits = [
        line
        for line in local_redacted.splitlines()
        if re.search(r"ike_auth|ike_sa_init|forticlient compatibility|retransmit", line, re.I)
    ]

    received = "UNKNOWN"
    parsed = "UNKNOWN"
    auth_reject = "UNKNOWN — no AUTH-specific FortiGate error extracted"
    eap = "NO EAP transition extracted from FortiGate debug"
    last_event = "UNKNOWN"
    silence = "UNKNOWN"
    ike_empty = "none in this capture"
    if evidence == "failed":
        invalid = (
            "INVALID — FortiGate debug collector was unavailable/failed. "
            "Do not treat missing FortiGate IKE lines as a silent discard."
        )
        received = invalid
        parsed = invalid
        auth_reject = invalid
        eap = invalid
        last_event = invalid
        silence = invalid
        ike_empty = "FortiGate debug collector was unavailable/failed"
    elif evidence == "active_no_ike":
        received = (
            "PACKET reached the wire toward the peer; FortiGate debug collector "
            "captured no relevant IKE lines"
            if first_auth is not None
            else "NO Linux IKE_AUTH seen in the pcap"
        )
        parsed = "FortiGate debug collector captured no relevant IKE lines"
        silence = (
            "No IKE_AUTH response from peer in the pcap. FortiGate debug collector "
            "captured no relevant IKE lines."
            if first_auth is not None and auth_reply is None
            else silence
        )
        ike_empty = "FortiGate debug collector captured no relevant IKE lines"
    else:
        if first_auth is not None and fg["ike_auth"]:
            received = "YES — FortiGate IKE debug mentioned IKE_AUTH near this attempt"
        elif first_auth is not None and not fg["ike_auth"]:
            received = (
                "PACKET reached the wire toward the peer; FortiGate IKE debug did not "
                "mention IKE_AUTH (possible silent discard before IKE_AUTH processing)"
            )
        elif first_auth is None:
            received = "NO Linux IKE_AUTH seen in the pcap"
        if fg["parse_decrypt"]:
            parsed = "FortiGate logged parse/decrypt-related lines (see below)"
        elif fg["ike_auth"]:
            parsed = "FortiGate mentioned IKE_AUTH; no explicit parse/decrypt error extracted"
        elif first_auth is not None and not fg["ike_auth"]:
            parsed = "No FortiGate IKE_AUTH parse line; decryption/parse not evidenced"
        if fg["auth_error"]:
            auth_reject = "FortiGate logged AUTH-related error text (redacted lines below)"
        if fg["eap"]:
            eap = "FortiGate logged EAP-related lines"
        if fg["last_ike"]:
            last_event = redact_research_text(fg["last_ike"][-1])
        if first_auth is not None and auth_reply is None:
            silence = (
                "No IKE_AUTH response from peer in the pcap. Last FortiGate IKE line "
                "before capture end is listed below."
            )
        elif auth_reply is not None:
            silence = "Peer sent an IKE_AUTH response — not a silent drop on this attempt."

    lines = [
        "# IKE_AUTH correlation report",
        "",
        "**Diagnostics only.** AUTH omission is LIVE POSITIVE. EAP-only local auth is CODE, live pending.",
        "This report does not authorize stacking another protocol mutation.",
        "",
        "Frozen initiator first `IKE_AUTH` order:",
        "",
        *[f"- {item}" for item in FROZEN_ORDER],
        "",
        "## Capture window",
        "",
        f"- Start: {meta.get('started_at', 'UNKNOWN')}",
        f"- End: {meta.get('ended_at', 'UNKNOWN')}",
        f"- Peer: `{peer}` UDP/500 and UDP/4500",
        f"- Capture interface: `{meta.get('capture_dev', 'UNKNOWN')}`",
        f"- SSH alias: `{meta.get('ssh_alias', 'fvl-fortigate')}`",
        "",
        "## Routing (preflight)",
        "",
    ]
    if route_lines:
        lines.extend(f"- {item}" for item in route_lines)
    else:
        lines.append("- (no routing files)")
    if evidence == "failed":
        collector_lines = [
            "- Status: FAILED/UNAVAILABLE",
            "- This report is **INVALID** for responder-side conclusions (questions A–G).",
        ]
        if collector_reason:
            collector_lines.append(f"- Reason: {redact_research_text(collector_reason)}")
    elif evidence == "active_no_ike":
        collector_lines = [
            "- Status: ACTIVE",
            "- FortiGate debug collector captured no relevant IKE lines",
        ]
    else:
        collector_lines = [
            "- Status: ACTIVE",
            "- FortiGate IKE debug lines were present in the raw debug file",
        ]
    lines.extend(
        [
            "",
            "## FortiGate debug collector",
            "",
            *collector_lines,
            "",
            "## Packet timeline",
            "",
        ]
    )
    if not packets:
        lines.append("- No IKE UDP packets for the peer were parsed from the pcap.")
    else:
        lines.append("| Time (UTC) | Direction | Ports | UDP payload | Exchange | MID | Note |")
        lines.append("| --- | --- | --- | ---: | --- | ---: | --- |")
        for packet in packets:
            mid = "" if packet.message_id is None else str(packet.message_id)
            note = packet.next_payload if packet.payloads else packet.note or packet.next_payload
            lines.append(
                f"| {format_ts(packet.timestamp)} | {packet.direction} | "
                f"{packet.sport}→{packet.dport} | {packet.udp_payload_len} | "
                f"{packet.exchange} | {mid} | {note} |"
            )

    def _pkt(label: str, packet: IkePacket | None) -> list[str]:
        if packet is None:
            return [f"- {label}: not found"]
        payloads = ", ".join(packet.payloads) if packet.payloads else packet.next_payload
        return [
            f"- {label}: {format_ts(packet.timestamp)}",
            f"  - {packet.direction} {packet.src}:{packet.sport} → {packet.dst}:{packet.dport}",
            f"  - UDP payload {packet.udp_payload_len} bytes; IKE length {packet.ike_len}",
            (
                f"  - MID={packet.message_id}; initiator={packet.initiator}; "
                f"response={packet.response}"
            ),
            f"  - payloads/next: {payloads}",
        ]

    lines.extend(
        [
            "",
            "## Key messages",
            "",
            *_pkt("IKE_SA_INIT client request", init_req),
            *_pkt("FortiGate IKE_SA_INIT response", init_resp),
            *_pkt("First Linux IKE_AUTH", first_auth),
            *_pkt("FortiGate IKE_AUTH response", auth_reply),
            "",
            "Retransmission timestamps (same MID, initiator, no response bit):",
        ]
    )
    if not retrans:
        lines.append("- none")
    else:
        for packet in retrans:
            lines.append(
                f"- {format_ts(packet.timestamp)} UDP payload {packet.udp_payload_len} bytes"
            )

    lines.extend(
        [
            "",
            "## Questions",
            "",
            f"**A. Does FortiGate receive the first ~512-byte IKE_AUTH?** {received}",
            "",
            f"**B. Does FortiGate decrypt/parse it?** {parsed}",
            "",
            "**C. Which payloads does FortiGate report?** Inner SK payloads are not visible "
            "in the pcap. FortiGate IKE_AUTH lines:",
            _bullet(fg["ike_auth"], empty=ike_empty),
            "",
            f"**D. Does FortiGate reject AUTH specifically?** {auth_reject}",
            _bullet(fg["auth_error"], empty="no AUTH-specific error line extracted"),
            "",
            "**E. Other payload / state-transition reject?** See parse/decrypt and last IKE lines.",
            _bullet(fg["parse_decrypt"], empty="no parse/decrypt line extracted"),
            "",
            f"**F. Silent discard before normal IKE_AUTH processing?** {silence}",
            "",
            f"**G. Last responder-side event before silence:** `{last_event}`",
            "",
            f"EAP: {eap}",
            _bullet(fg["eap"], empty="no EAP line extracted"),
            "",
            "## FortiGate IKE lines around INIT",
            "",
            _bullet(fg["ike_sa_init"], empty=ike_empty),
            "",
            "## Last FortiGate IKE lines",
            "",
            _bullet(fg["last_ike"], empty=ike_empty),
            "",
            "## fnbamd (HomeVPN only if time-correlated)",
            "",
            "Unrelated certificate/OCSP fnbamd traffic is expected. Those lines are not "
            "HomeVPN evidence.",
            "",
            "Time-correlated fnbamd (±3s of first IKE_AUTH, IKE/EAP/SAML hint):",
            _bullet(fg["fnbamd_correlated"], empty="none"),
            "",
            "Uncorrelated fnbamd (do not treat as HomeVPN evidence):",
            f"- {len(fg['fnbamd_uncorrelated'])} line(s) stored in the raw FortiGate debug file",
            "",
            "## Local application / helper / journal highlights",
            "",
            "Charon `filelog` is stderr into the helper, then the GUI log buffer. "
            "It is not a disk file. This section uses journald plus any `gui-logs.txt` "
            "copied into the capture directory.",
            "",
            _bullet(local_hits, empty="no IKE/FortiClient compatibility lines in local logs"),
            "",
            "## What this does not decide",
            "",
            "- AUTH omission on first `IKE_AUTH` is LIVE POSITIVE; keep it.",
            "- EAP-only local authentication is CODE, live pending; not a proven fix.",
            "- Notify `0xF100` presence, CP16, VIDs, EAP_ONLY, MSG_ID_SYN_SUP, "
            "INITIAL_CONTACT, and `0xF100` ordering remain previously recorded "
            "valid negatives as in the research doc.",
            "- Do not stack another protocol mutation from this report alone.",
            "",
        ]
    )
    return "\n".join(lines) + "\n"


def load_text(path: Path) -> str:
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def write_report(capture_dir: Path) -> Path:
    meta_path = capture_dir / "meta.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.is_file() else {}
    peer = str(meta.get("peer") or "91.149.212.169")
    pcap = (capture_dir / "ike.pcap").read_bytes() if (capture_dir / "ike.pcap").is_file() else b""
    packets = parse_pcap_ike_packets(pcap, peer=peer)
    fortigate = load_text(capture_dir / "fortigate-debug.log")
    local = "\n".join(
        [
            load_text(capture_dir / "local-journal.log"),
            load_text(capture_dir / "local-journal-system.log"),
            load_text(capture_dir / "gui-logs.txt"),
        ]
    )
    route_lines = tuple(
        line for line in (load_text(capture_dir / "routing-summary.txt").strip(),) if line
    )
    if not route_lines:
        route_lines = (
            load_text(capture_dir / "routing-mgmt.txt").strip(),
            load_text(capture_dir / "routing-vpn.txt").strip(),
        )
    status = load_collector_status(capture_dir)
    report = build_report(
        meta={str(k): str(v) for k, v in meta.items()},
        packets=packets,
        fortigate_text=fortigate,
        local_text=local,
        route_lines=tuple(item for item in route_lines if item),
        collector_status=status,
    )
    report_path = capture_dir / "correlation-report.md"
    report_path.write_text(report, encoding="utf-8")
    return report_path


def verify_routes(
    *,
    mgmt_text: str,
    vpn_text: str,
    mgmt_host: str,
    mgmt_dev: str,
    vpn_host: str,
    vpn_dev: str,
) -> tuple[int, str]:
    mgmt = check_route(mgmt_text, RouteExpectation(mgmt_host, mgmt_dev, "FortiGate management"))
    vpn = check_route(vpn_text, RouteExpectation(vpn_host, vpn_dev, "HomeVPN endpoint"))
    text = "\n".join((mgmt.summary, vpn.summary)) + "\n"
    if mgmt.ok and vpn.ok:
        return 0, text
    return 1, text


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dir", type=Path, help="Capture directory")
    parser.add_argument("--verify-routes", action="store_true")
    parser.add_argument("--mgmt-route-file", type=Path)
    parser.add_argument("--vpn-route-file", type=Path)
    parser.add_argument("--mgmt-host", default="10.10.10.1")
    parser.add_argument("--mgmt-dev", default="eno1")
    parser.add_argument("--vpn-host", default="91.149.212.169")
    parser.add_argument("--vpn-dev", default="wlp5s0")
    args = parser.parse_args(argv)
    if args.verify_routes:
        mgmt_text = args.mgmt_route_file.read_text(encoding="utf-8") if args.mgmt_route_file else ""
        vpn_text = args.vpn_route_file.read_text(encoding="utf-8") if args.vpn_route_file else ""
        code, text = verify_routes(
            mgmt_text=mgmt_text,
            vpn_text=vpn_text,
            mgmt_host=args.mgmt_host,
            mgmt_dev=args.mgmt_dev,
            vpn_host=args.vpn_host,
            vpn_dev=args.vpn_dev,
        )
        sys.stdout.write(text)
        return code
    if args.dir is None:
        parser.error("--dir is required unless --verify-routes is set")
    capture_dir = args.dir.expanduser().resolve()
    if not capture_dir.is_dir():
        print(f"error: capture directory not found: {capture_dir}", file=sys.stderr)
        return 2
    path = write_report(capture_dir)
    print(str(path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
