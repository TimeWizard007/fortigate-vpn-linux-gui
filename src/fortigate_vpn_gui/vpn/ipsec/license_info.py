# SPDX-License-Identifier: GPL-3.0-or-later
"""Linux equivalent of FortiClient GenRawLicenseInfo2 plaintext (research §12.9).

Wire framing matches official FortiClient 7.4.8.2066: ASCII KEY=value lines,
LF (0x0A) after every field including the last, then one NUL (0x00) that
ipsec.exe includes in Notify 0xF100 data (strlen+1).

FCTVER=7.4.8.2066 is a compatibility value for this Notify A/B. It does not
claim that this Linux client is FortiClient.

The complete blob is sensitive inventory. Callers must write it mode 0600
and must not log field values, the blob, FCT_UID, MAC, IP, hostname, or
username.
"""

from __future__ import annotations

import os
import pwd
import socket
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from fortigate_vpn_gui.system.ipsec_saml_uid import validate_ipsec_saml_uid

FCTVER_COMPAT = "7.4.8.2066"
LICENSE_NOTIFY_TYPE = 61696  # 0xF100
LICENSE_NOTIFY_TYPE_HEX = "0xF100"
LICENSE_INFO_KEYS = (
    "VER",
    "FCTVER",
    "UID",
    "IP",
    "MAC",
    "HOST",
    "USER",
    "OSVER",
    "REG_STATUS",
)
EMS_KEYS = ("EMSSN", "EMSID", "FCTTAGS", "REG_PASSWD")
SKIP_DESCRIPTION_PREFIXES = ("VMware", "VirtualBox", "fortissl")
SKIP_NAME_PREFIXES = ("vmnet", "vboxnet", "vbox", "fortissl")
SKIP_MACS = (
    bytes.fromhex("00090f090001"),
    bytes.fromhex("00090ffe0001"),
)
LICENSE_INFO_FILENAME = "forticlient-license-info"
MAX_LICENSE_INFO_BYTES = 4096


@dataclass(frozen=True)
class NetAdapter:
    """One local interface considered for the MAC= list."""

    name: str
    mac: bytes
    description: str = ""


@dataclass(frozen=True)
class LicenseInfoFields:
    """Non-secret-typed inventory used to build the Notify payload.

    ``uid`` is the existing FCT_UID (EAP Identity). Do not log instances.
    """

    uid: str
    ip: str = ""
    mac: str = ""
    host: str = ""
    user: str = ""
    osver: str = ""
    fctver: str = FCTVER_COMPAT


def format_mac(mac: bytes) -> str:
    """Return official ``%.2x-%.2x-%.2x-%.2x-%.2x-%.2x;`` for six bytes."""
    if len(mac) < 6:
        raise ValueError("MAC must be six bytes")
    return f"{mac[0]:02x}-{mac[1]:02x}-{mac[2]:02x}-{mac[3]:02x}-{mac[4]:02x}-{mac[5]:02x};"


def should_skip_adapter(adapter: NetAdapter) -> bool:
    """Return True for official virtual adapters and the all-zero MAC."""
    mac = adapter.mac
    if len(mac) != 6 or mac == bytes(6):
        return True
    if mac in SKIP_MACS:
        return True
    description = adapter.description or ""
    for prefix in SKIP_DESCRIPTION_PREFIXES:
        if description.startswith(prefix):
            return True
    name = adapter.name.lower()
    if name == "lo":
        return True
    return any(name.startswith(prefix) for prefix in SKIP_NAME_PREFIXES)


def format_mac_list(adapters: Sequence[NetAdapter]) -> str:
    """Concatenate official MAC strings for adapters that pass the filter."""
    parts: list[str] = []
    for adapter in adapters:
        if should_skip_adapter(adapter):
            continue
        parts.append(format_mac(adapter.mac))
    return "".join(parts)


def ascii_field(value: str) -> str:
    """Strip CR/LF/NUL and drop non-ASCII so framing stays KEY=value LF."""
    cleaned = (
        value.replace("\r", " ").replace("\n", " ").replace("\0", "").strip()
    )
    return cleaned.encode("ascii", "ignore").decode("ascii")


def build_license_info(fields: LicenseInfoFields) -> bytes:
    """Return official-format plaintext plus the trailing NUL.

    Does not emit EMS fields. ``uid`` must be the same 32-hex FCT_UID used
    for SAML pre-auth and EAP Identity.
    """
    uid = validate_ipsec_saml_uid(fields.uid)
    fctver = ascii_field(fields.fctver) or FCTVER_COMPAT
    lines = (
        "VER=1",
        f"FCTVER={fctver}",
        f"UID={uid}",
        f"IP={ascii_field(fields.ip)}",
        f"MAC={ascii_field(fields.mac)}",
        f"HOST={ascii_field(fields.host)}",
        f"USER={ascii_field(fields.user)}",
        f"OSVER={ascii_field(fields.osver)}",
        "REG_STATUS=0",
    )
    body = "\n".join(lines) + "\n"
    blob = body.encode("ascii") + b"\x00"
    if len(blob) > MAX_LICENSE_INFO_BYTES:
        raise ValueError("license-info exceeds the private Notify size cap")
    return blob


def license_info_keys(blob: bytes) -> tuple[str, ...]:
    """Return KEY names from a blob. Values are not returned."""
    text = blob.split(b"\x00", 1)[0].decode("ascii")
    keys: list[str] = []
    for raw in text.split("\n"):
        if not raw:
            continue
        key, sep, _value = raw.partition("=")
        if sep:
            keys.append(key)
    return tuple(keys)


def discover_source_ipv4(gateway: str, port: int) -> str:
    """Return the local IPv4 that would be used to reach *gateway*."""
    if not gateway:
        return ""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(1.0)
        sock.connect((gateway, port or 500))
        ip = sock.getsockname()[0]
    except OSError:
        return ""
    finally:
        sock.close()
    if ip.startswith("127."):
        return ""
    return ip


def collect_adapters(*, sys_class_net: Path | None = None) -> tuple[NetAdapter, ...]:
    """Read MAC addresses from sysfs. Missing sysfs yields an empty list."""
    base = Path("/sys/class/net") if sys_class_net is None else sys_class_net
    adapters: list[NetAdapter] = []
    try:
        entries = sorted(base.iterdir(), key=lambda item: item.name)
    except OSError:
        return ()
    for iface in entries:
        try:
            raw = (iface / "address").read_text(encoding="ascii").strip()
        except OSError:
            continue
        hex_digits = raw.replace(":", "").replace("-", "")
        if len(hex_digits) != 12:
            continue
        try:
            mac = bytes.fromhex(hex_digits)
        except ValueError:
            continue
        adapters.append(NetAdapter(name=iface.name, mac=mac, description=iface.name))
    return tuple(adapters)


def linux_hostname() -> str:
    try:
        return socket.gethostname().split(".", 1)[0]
    except OSError:
        return ""


def linux_session_username(*, environ: dict[str, str] | None = None) -> str:
    """Return the pkexec/sudo caller name. Helper uid 0 is not a session user."""
    env = os.environ if environ is None else environ
    for key in ("PKEXEC_UID", "SUDO_UID"):
        raw = env.get(key, "")
        if not raw.isdigit():
            continue
        try:
            return pwd.getpwuid(int(raw)).pw_name
        except KeyError:
            continue
        except OSError:
            continue
    return ""


def linux_osver(*, os_release: Path | None = None) -> str:
    path = Path("/etc/os-release") if os_release is None else os_release
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return "Linux"
    for line in text.splitlines():
        if line.startswith("PRETTY_NAME="):
            value = line.split("=", 1)[1].strip().strip('"')
            return value or "Linux"
    return "Linux"


def collect_license_info_fields(
    *,
    uid: str,
    gateway: str,
    port: int,
    adapters: Sequence[NetAdapter] | None = None,
    ip: str | None = None,
    host: str | None = None,
    user: str | None = None,
    osver: str | None = None,
    environ: dict[str, str] | None = None,
) -> LicenseInfoFields:
    """Build Linux inventory around the existing FCT_UID. Do not log the result."""
    mac_list = format_mac_list(adapters if adapters is not None else collect_adapters())
    return LicenseInfoFields(
        uid=validate_ipsec_saml_uid(uid),
        ip=ip if ip is not None else discover_source_ipv4(gateway, port),
        mac=mac_list,
        host=host if host is not None else linux_hostname(),
        user=user if user is not None else linux_session_username(environ=environ),
        osver=osver if osver is not None else linux_osver(),
        fctver=FCTVER_COMPAT,
    )


def write_license_info_file(path: Path, blob: bytes) -> None:
    """Write *blob* mode 0600. Parent directory must already exist."""
    if not blob.endswith(b"\x00"):
        raise ValueError("license-info blob must include the trailing NUL")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(str(path), flags, 0o600)
    try:
        os.write(fd, blob)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(path, 0o600)


def iter_forbidden_ems_keys(blob: bytes) -> Iterable[str]:
    keys = license_info_keys(blob)
    for key in EMS_KEYS:
        if key in keys:
            yield key


__all__ = [
    "EMS_KEYS",
    "FCTVER_COMPAT",
    "LICENSE_INFO_FILENAME",
    "LICENSE_INFO_KEYS",
    "LICENSE_NOTIFY_TYPE",
    "LICENSE_NOTIFY_TYPE_HEX",
    "LicenseInfoFields",
    "MAX_LICENSE_INFO_BYTES",
    "NetAdapter",
    "build_license_info",
    "collect_license_info_fields",
    "format_mac",
    "format_mac_list",
    "license_info_keys",
    "should_skip_adapter",
    "write_license_info_file",
]
