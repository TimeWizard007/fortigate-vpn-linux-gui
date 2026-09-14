# SPDX-License-Identifier: GPL-3.0-or-later
"""Generic FortiGate IPsec profile settings.

These fields are non-secret connection parameters. The IPsec pre-shared
key authenticates the IKE peer and is never stored here. The XAuth user
password is a separate credential and is also never stored here. The
XAuth username may be kept as the profile ``username_hint``. v1.1.0
implements and tests only IKEv1 Aggressive + PSK + XAuth + Mode Config;
other combinations may be stored for later work but are not presented as
supported.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

VPN_TYPE_SSL = "ssl"
VPN_TYPE_IPSEC = "ipsec"
VPN_TYPES = frozenset({VPN_TYPE_SSL, VPN_TYPE_IPSEC})

IKE_V1 = "ikev1"
IKE_V2 = "ikev2"
IKE_VERSIONS = frozenset({IKE_V1, IKE_V2})

IKE_MODE_AGGRESSIVE = "aggressive"
IKE_MODE_MAIN = "main"
IKE_MODES = frozenset({IKE_MODE_AGGRESSIVE, IKE_MODE_MAIN})

AUTH_PSK_XAUTH = "psk_xauth"
AUTH_PSK = "psk"
AUTH_CERTIFICATE = "certificate"
AUTH_EAP = "eap"
AUTH_METHODS = frozenset({AUTH_PSK_XAUTH, AUTH_PSK, AUTH_CERTIFICATE, AUTH_EAP})

ADDR_MODECONFIG = "modeconfig"
ADDR_MANUAL = "manual"
ADDRESS_ASSIGNMENTS = frozenset({ADDR_MODECONFIG, ADDR_MANUAL})

ENCRYPTION_ALGORITHMS = ("aes128", "aes192", "aes256")
INTEGRITY_ALGORITHMS = ("sha1", "sha256", "sha384", "sha512")
DH_GROUPS = (2, 5, 14, 15, 16, 19, 20)

DH_GROUP_TO_MODP = {
    2: "modp1024",
    5: "modp1536",
    14: "modp2048",
    15: "modp3072",
    16: "modp4096",
    19: "ecp256",
    20: "ecp384",
}

# Only this combination is implemented/tested in v1.1.0.
SUPPORTED_IPSEC_COMBOS = frozenset(
    {
        (IKE_V1, IKE_MODE_AGGRESSIVE, AUTH_PSK_XAUTH, ADDR_MODECONFIG),
    }
)

IPSEC_STORED_FIELDS = (
    "ike_version",
    "ike_mode",
    "auth_method",
    "address_assignment",
    "local_id",
    "peer_id",
    "phase1_encryption",
    "phase1_integrity",
    "dh_group",
    "phase1_lifetime",
    "phase2_encryption",
    "phase2_integrity",
    "pfs",
    "pfs_dh_group",
    "phase2_lifetime",
    "nat_traversal",
    "dpd",
    "dpd_interval",
    "replay_detection",
    "local_lan_access",
)

_MAX_ID_LENGTH = 253
_DEFAULT_PHASE1_LIFETIME = 86400
_DEFAULT_PHASE2_LIFETIME = 43200
_DEFAULT_DPD_INTERVAL = 60
_MAX_LIFETIME = 604800


@dataclass(frozen=True)
class IpsecSettings:
    """Non-secret IPsec parameters for a connection profile."""

    ike_version: str = IKE_V1
    ike_mode: str = IKE_MODE_AGGRESSIVE
    auth_method: str = AUTH_PSK_XAUTH
    address_assignment: str = ADDR_MODECONFIG
    local_id: str = ""
    peer_id: str = ""
    phase1_encryption: str = "aes256"
    phase1_integrity: str = "sha256"
    dh_group: int = 14
    phase1_lifetime: int = _DEFAULT_PHASE1_LIFETIME
    phase2_encryption: str = "aes256"
    phase2_integrity: str = "sha256"
    pfs: bool = True
    pfs_dh_group: int = 14
    phase2_lifetime: int = _DEFAULT_PHASE2_LIFETIME
    nat_traversal: bool = True
    dpd: bool = True
    dpd_interval: int = _DEFAULT_DPD_INTERVAL
    replay_detection: bool = True
    local_lan_access: bool = False

    def to_json(self) -> dict[str, object]:
        """Return JSON-serialisable non-secret fields."""
        return {key: asdict(self)[key] for key in IPSEC_STORED_FIELDS}

    def combo(self) -> tuple[str, str, str, str]:
        return (self.ike_version, self.ike_mode, self.auth_method, self.address_assignment)

    def is_supported(self) -> bool:
        """Return True when this combination is implemented in this release."""
        return self.combo() in SUPPORTED_IPSEC_COMBOS

    def support_summary(self) -> str:
        if self.is_supported():
            return "IKEv1 Aggressive Mode, PSK + XAuth, Mode Config"
        return (
            "This IPsec combination is stored but not implemented yet. "
            "v1.1.0 supports IKEv1 Aggressive + PSK + XAuth + Mode Config."
        )

    def phase1_proposal(self) -> str:
        return _proposal(self.phase1_encryption, self.phase1_integrity, self.dh_group)

    def phase2_proposal(self) -> str:
        dh = self.pfs_dh_group if self.pfs else None
        return _proposal(self.phase2_encryption, self.phase2_integrity, dh)

    def auth_label(self) -> str:
        labels = {
            AUTH_PSK_XAUTH: "IPsec PSK + XAuth",
            AUTH_PSK: "IPsec pre-shared key",
            AUTH_CERTIFICATE: "IPsec certificate",
            AUTH_EAP: "IPsec EAP",
        }
        return labels.get(self.auth_method, "IPsec")


def default_ipsec_settings() -> IpsecSettings:
    """Return FortiGate remote-access reference defaults (not site-specific)."""
    return IpsecSettings()


def parse_ipsec_settings(payload: object) -> IpsecSettings:
    """Parse an ``ipsec`` JSON object. Raises ``ValueError`` with a message."""
    if payload is None:
        return default_ipsec_settings()
    if not isinstance(payload, dict):
        raise ValueError("IPsec settings must be an object.")
    data = {str(key): value for key, value in payload.items()}
    return IpsecSettings(
        ike_version=_one_of(data.get("ike_version", IKE_V1), IKE_VERSIONS, "IKE version"),
        ike_mode=_one_of(data.get("ike_mode", IKE_MODE_AGGRESSIVE), IKE_MODES, "IKE mode"),
        auth_method=_one_of(
            data.get("auth_method", AUTH_PSK_XAUTH), AUTH_METHODS, "IPsec authentication method"
        ),
        address_assignment=_one_of(
            data.get("address_assignment", ADDR_MODECONFIG),
            ADDRESS_ASSIGNMENTS,
            "Address assignment",
        ),
        local_id=_optional_id(data.get("local_id", ""), "Local ID"),
        peer_id=_optional_id(data.get("peer_id", ""), "Peer ID"),
        phase1_encryption=_one_of(
            data.get("phase1_encryption", "aes256"), ENCRYPTION_ALGORITHMS, "Phase 1 encryption"
        ),
        phase1_integrity=_one_of(
            data.get("phase1_integrity", "sha256"), INTEGRITY_ALGORITHMS, "Phase 1 integrity"
        ),
        dh_group=_dh_group(data.get("dh_group", 14), "DH group"),
        phase1_lifetime=_lifetime(
            data.get("phase1_lifetime", _DEFAULT_PHASE1_LIFETIME), "Phase 1 lifetime"
        ),
        phase2_encryption=_one_of(
            data.get("phase2_encryption", "aes256"), ENCRYPTION_ALGORITHMS, "Phase 2 encryption"
        ),
        phase2_integrity=_one_of(
            data.get("phase2_integrity", "sha256"), INTEGRITY_ALGORITHMS, "Phase 2 integrity"
        ),
        pfs=_as_bool(data.get("pfs", True), "PFS"),
        pfs_dh_group=_dh_group(data.get("pfs_dh_group", 14), "PFS DH group"),
        phase2_lifetime=_lifetime(
            data.get("phase2_lifetime", _DEFAULT_PHASE2_LIFETIME), "Phase 2 lifetime"
        ),
        nat_traversal=_as_bool(data.get("nat_traversal", True), "NAT traversal"),
        dpd=_as_bool(data.get("dpd", True), "DPD"),
        dpd_interval=_lifetime(
            data.get("dpd_interval", _DEFAULT_DPD_INTERVAL), "DPD interval", minimum=1
        ),
        replay_detection=_as_bool(data.get("replay_detection", True), "Replay detection"),
        local_lan_access=_as_bool(data.get("local_lan_access", False), "Local LAN access"),
    )


def _proposal(encryption: str, integrity: str, dh_group: int | None) -> str:
    parts = [encryption, integrity]
    if dh_group is not None:
        parts.append(DH_GROUP_TO_MODP[dh_group])
    return "-".join(parts)


def _one_of(value: object, allowed: tuple[str, ...] | frozenset[str], label: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise ValueError(f"{label} is not supported.")
    return value


def _optional_id(value: object, label: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValueError(f"{label} must be text.")
    text = value.strip()
    if len(text) > _MAX_ID_LENGTH:
        raise ValueError(f"{label} must be at most {_MAX_ID_LENGTH} characters.")
    if any(ord(char) < 32 or ord(char) == 127 for char in text):
        raise ValueError(f"{label} must not contain control characters.")
    return text


def _dh_group(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        if isinstance(value, str) and value.strip().isdigit():
            number = int(value.strip())
        else:
            raise ValueError(f"{label} is not supported.")
    else:
        number = value
    if number not in DH_GROUPS:
        raise ValueError(f"{label} is not supported.")
    return number


def _lifetime(value: object, label: str, *, minimum: int = 60) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        if isinstance(value, str) and value.strip().isdigit():
            number = int(value.strip())
        else:
            raise ValueError(f"{label} must be a number of seconds.")
    else:
        number = value
    if number < minimum or number > _MAX_LIFETIME:
        raise ValueError(f"{label} must be between {minimum} and {_MAX_LIFETIME} seconds.")
    return number


def _as_bool(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be true or false.")
    return value
