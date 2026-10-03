# SPDX-License-Identifier: GPL-3.0-or-later
"""Generic FortiGate IPsec profile settings.

These fields are non-secret connection parameters. The IPsec pre-shared
key authenticates the IKE peer and is never stored here. The XAuth user
password is a separate credential and is also never stored here. The
XAuth username may be kept as the profile ``username_hint``. This release
implements IKEv1 Aggressive + PSK + XAuth + Mode Config and IKEv2 + PSK +
EAP-MSCHAPv2 after SAML pre-auth. Other combinations may be stored for
later work but are not presented as supported.

Proposal lists vs legacy singular fields
----------------------------------------
Canonical representation:

- ``ike_proposals`` / ``ike_dh_groups``
- ``child_proposals`` / ``pfs_dh_groups``

Legacy singular fields (``phase1_encryption``, ``phase1_integrity``,
``dh_group``, ``phase2_encryption``, ``phase2_integrity``,
``pfs_dh_group``) are dual-written on save as the first item of each
list so older readers keep working.

Load precedence: if a list field is present and non-empty, it is
canonical and the matching singular field is ignored for constructing
the list. Otherwise the singular field is migrated to a one-item list.
Loading never rewrites the on-disk profile.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import NamedTuple, TypeVar

from fortigate_vpn_gui.helper.protocol import (
    CAPABILITY_IPSEC_IKEV1_PSK_XAUTH,
    CAPABILITY_IPSEC_IKEV2_EAP,
)

_T = TypeVar("_T")

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

USER_AUTH_PSK_XAUTH = "psk_xauth"
USER_AUTH_SAML = "saml"
USER_AUTH_MODES = frozenset({USER_AUTH_PSK_XAUTH, USER_AUTH_SAML})

USER_AUTH_PSK_XAUTH_LABEL = "Username / Password"
USER_AUTH_SAML_LABEL = "SAML / SSO"

ADDR_MODECONFIG = "modeconfig"
ADDR_MANUAL = "manual"
ADDRESS_ASSIGNMENTS = frozenset({ADDR_MODECONFIG, ADDR_MANUAL})

DEFAULT_SAML_PORT = 1001

ENCRYPTION_ALGORITHMS = ("aes128", "aes192", "aes256")
INTEGRITY_ALGORITHMS = ("sha1", "sha256", "sha384", "sha512")
DH_GROUPS = (2, 5, 14, 15, 16, 19, 20, 21)

DH_GROUP_TO_MODP = {
    2: "modp1024",
    5: "modp1536",
    14: "modp2048",
    15: "modp3072",
    16: "modp4096",
    19: "ecp256",
    20: "ecp384",
    21: "ecp521",
}

# UI catalogs. The stored model accepts any encryption/integrity pair from
# ENCRYPTION_ALGORITHMS × INTEGRITY_ALGORITHMS, not only these rows.
IKE_PROPOSAL_CHOICES = (
    ("aes128", "sha256"),
    ("aes256", "sha256"),
    ("aes128", "sha1"),
    ("aes256", "sha1"),
    ("aes192", "sha256"),
    ("aes256", "sha384"),
    ("aes128", "sha384"),
    ("aes256", "sha512"),
)
CHILD_PROPOSAL_CHOICES = (
    ("aes128", "sha1"),
    ("aes256", "sha256"),
    ("aes128", "sha256"),
    ("aes256", "sha1"),
    ("aes192", "sha256"),
    ("aes256", "sha384"),
    ("aes128", "sha384"),
    ("aes256", "sha512"),
)

# IKEv1 Aggressive PSK+XAuth remains the legacy helper combo. IKEv2 + EAP +
# Mode Config is accepted by is_supported() for the SAML-then-IKE path.
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
    "ike_proposals",
    "ike_dh_groups",
    "phase1_lifetime",
    "phase2_encryption",
    "phase2_integrity",
    "child_proposals",
    "pfs",
    "pfs_dh_group",
    "pfs_dh_groups",
    "phase2_lifetime",
    "nat_traversal",
    "dpd",
    "dpd_interval",
    "replay_detection",
    "local_lan_access",
    "saml_port",
)

_MAX_ID_LENGTH = 253
_DEFAULT_PHASE1_LIFETIME = 86400
_DEFAULT_PHASE2_LIFETIME = 43200
_DEFAULT_DPD_INTERVAL = 60
_MAX_LIFETIME = 604800

_SAML_IKE_PROPOSALS = (("aes128", "sha256"), ("aes256", "sha256"))
_SAML_IKE_DH_GROUPS = (20, 21)
_SAML_CHILD_PROPOSALS = (("aes128", "sha1"), ("aes256", "sha256"))
_SAML_PFS_DH_GROUPS = (20,)


class CryptoProposal(NamedTuple):
    """One encryption + integrity pair. Not a display string."""

    encryption: str
    integrity: str

    def label(self) -> str:
        return f"{self.encryption.upper()} / {self.integrity.upper()}"

    def to_json(self) -> dict[str, str]:
        return {"encryption": self.encryption, "integrity": self.integrity}


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
    ike_proposals: tuple[CryptoProposal, ...] = (CryptoProposal("aes256", "sha256"),)
    ike_dh_groups: tuple[int, ...] = (14,)
    phase1_lifetime: int = _DEFAULT_PHASE1_LIFETIME
    phase2_encryption: str = "aes256"
    phase2_integrity: str = "sha256"
    child_proposals: tuple[CryptoProposal, ...] = (CryptoProposal("aes256", "sha256"),)
    pfs: bool = True
    pfs_dh_group: int = 14
    pfs_dh_groups: tuple[int, ...] = (14,)
    phase2_lifetime: int = _DEFAULT_PHASE2_LIFETIME
    nat_traversal: bool = True
    dpd: bool = True
    dpd_interval: int = _DEFAULT_DPD_INTERVAL
    replay_detection: bool = True
    local_lan_access: bool = False
    saml_port: int = DEFAULT_SAML_PORT

    def to_json(self) -> dict[str, object]:
        """Return JSON-serialisable non-secret fields, dual-writing lists + singular."""
        ike = self.ike_proposals or (CryptoProposal(self.phase1_encryption, self.phase1_integrity),)
        child = self.child_proposals or (
            CryptoProposal(self.phase2_encryption, self.phase2_integrity),
        )
        dh_groups = self.ike_dh_groups or (self.dh_group,)
        pfs_groups = self.pfs_dh_groups or (self.pfs_dh_group,)
        return {
            "ike_version": self.ike_version,
            "ike_mode": self.ike_mode,
            "auth_method": self.auth_method,
            "address_assignment": self.address_assignment,
            "local_id": self.local_id,
            "peer_id": self.peer_id,
            "phase1_encryption": ike[0].encryption,
            "phase1_integrity": ike[0].integrity,
            "dh_group": dh_groups[0],
            "ike_proposals": [item.to_json() for item in ike],
            "ike_dh_groups": list(dh_groups),
            "phase1_lifetime": self.phase1_lifetime,
            "phase2_encryption": child[0].encryption,
            "phase2_integrity": child[0].integrity,
            "child_proposals": [item.to_json() for item in child],
            "pfs": self.pfs,
            "pfs_dh_group": pfs_groups[0],
            "pfs_dh_groups": list(pfs_groups),
            "phase2_lifetime": self.phase2_lifetime,
            "nat_traversal": self.nat_traversal,
            "dpd": self.dpd,
            "dpd_interval": self.dpd_interval,
            "replay_detection": self.replay_detection,
            "local_lan_access": self.local_lan_access,
            "saml_port": self.saml_port,
        }

    def combo(self) -> tuple[str, str, str, str]:
        return (self.ike_version, self.ike_mode, self.auth_method, self.address_assignment)

    def is_supported(self) -> bool:
        """Return True when helper/charon can start this combination."""
        if self.combo() in SUPPORTED_IPSEC_COMBOS:
            return True
        return (
            self.ike_version == IKE_V2
            and self.auth_method == AUTH_EAP
            and self.address_assignment == ADDR_MODECONFIG
        )

    def required_helper_capabilities(self) -> frozenset[str]:
        """Return helper hello capabilities required to start this combination."""
        if self.combo() in SUPPORTED_IPSEC_COMBOS:
            return frozenset({CAPABILITY_IPSEC_IKEV1_PSK_XAUTH})
        if (
            self.ike_version == IKE_V2
            and self.auth_method == AUTH_EAP
            and self.address_assignment == ADDR_MODECONFIG
        ):
            return frozenset({CAPABILITY_IPSEC_IKEV2_EAP})
        return frozenset()

    def support_summary(self) -> str:
        if self.combo() in SUPPORTED_IPSEC_COMBOS:
            return "IKEv1 Aggressive Mode, PSK + XAuth, Mode Config"
        if self.allows_saml_preauth() and self.address_assignment == ADDR_MODECONFIG:
            return "IKEv2 PSK + EAP-MSCHAPv2, Mode Config (SAML pre-auth)"
        return (
            "This IPsec combination is stored but not implemented yet. "
            "This release supports IKEv1 Aggressive + PSK + XAuth + Mode Config "
            "and IKEv2 PSK + EAP-MSCHAPv2 with SAML pre-auth."
        )

    def phase1_proposal(self) -> str:
        proposals = self.ike_proposals or (
            CryptoProposal(self.phase1_encryption, self.phase1_integrity),
        )
        groups = self.ike_dh_groups or (self.dh_group,)
        parts: list[str] = []
        for proposal in proposals:
            for group in groups:
                parts.append(_proposal(proposal.encryption, proposal.integrity, group))
        return ",".join(parts)

    def phase2_proposal(self) -> str:
        proposals = self.child_proposals or (
            CryptoProposal(self.phase2_encryption, self.phase2_integrity),
        )
        groups = self.pfs_dh_groups or (self.pfs_dh_group,)
        dh_values: tuple[int | None, ...] = groups if self.pfs else (None,)
        parts: list[str] = []
        for proposal in proposals:
            for dh in dh_values:
                parts.append(_proposal(proposal.encryption, proposal.integrity, dh))
        return ",".join(parts)

    def allows_saml_preauth(self) -> bool:
        """Return True for the stored IKEv2 + EAP combo used by IPsec SAML pre-auth."""
        return self.ike_version == IKE_V2 and self.auth_method == AUTH_EAP

    def user_auth_mode(self) -> str:
        """Return the structured user-authentication workflow (not a display string)."""
        if self.allows_saml_preauth():
            return USER_AUTH_SAML
        return USER_AUTH_PSK_XAUTH

    def auth_label(self) -> str:
        if self.allows_saml_preauth():
            return USER_AUTH_SAML_LABEL
        labels = {
            AUTH_PSK_XAUTH: USER_AUTH_PSK_XAUTH_LABEL,
            AUTH_PSK: "IPsec pre-shared key",
            AUTH_CERTIFICATE: "IPsec certificate",
            AUTH_EAP: "IPsec EAP-MSCHAPv2",
        }
        return labels.get(self.auth_method, "IPsec")


def default_ipsec_settings() -> IpsecSettings:
    """Return IKEv1 Aggressive + PSK + XAuth defaults (not IKEv2 SSO)."""
    return IpsecSettings()


def default_ikev2_saml_settings() -> IpsecSettings:
    """Return known-good FortiClient-matching defaults for a new IKEv2 SSO profile."""
    ike = tuple(CryptoProposal(enc, integ) for enc, integ in _SAML_IKE_PROPOSALS)
    child = tuple(CryptoProposal(enc, integ) for enc, integ in _SAML_CHILD_PROPOSALS)
    return IpsecSettings(
        ike_version=IKE_V2,
        ike_mode=IKE_MODE_MAIN,
        auth_method=AUTH_EAP,
        address_assignment=ADDR_MODECONFIG,
        phase1_encryption=ike[0].encryption,
        phase1_integrity=ike[0].integrity,
        dh_group=_SAML_IKE_DH_GROUPS[0],
        ike_proposals=ike,
        ike_dh_groups=_SAML_IKE_DH_GROUPS,
        phase1_lifetime=_DEFAULT_PHASE1_LIFETIME,
        phase2_encryption=child[0].encryption,
        phase2_integrity=child[0].integrity,
        child_proposals=child,
        pfs=True,
        pfs_dh_group=_SAML_PFS_DH_GROUPS[0],
        pfs_dh_groups=_SAML_PFS_DH_GROUPS,
        phase2_lifetime=_DEFAULT_PHASE2_LIFETIME,
        nat_traversal=True,
        dpd=True,
        replay_detection=True,
        saml_port=DEFAULT_SAML_PORT,
    )


def parse_ipsec_settings(payload: object) -> IpsecSettings:
    """Parse an ``ipsec`` JSON object. Raises ``ValueError`` with a message."""
    if payload is None:
        return default_ipsec_settings()
    if not isinstance(payload, dict):
        raise ValueError("IPsec settings must be an object.")
    data = {str(key): value for key, value in payload.items()}
    ike_proposals = _parse_proposals(
        data,
        list_key="ike_proposals",
        encryption_key="phase1_encryption",
        integrity_key="phase1_integrity",
        encryption_default="aes256",
        integrity_default="sha256",
        label="IKE proposal",
    )
    child_proposals = _parse_proposals(
        data,
        list_key="child_proposals",
        encryption_key="phase2_encryption",
        integrity_key="phase2_integrity",
        encryption_default="aes256",
        integrity_default="sha256",
        label="CHILD_SA proposal",
    )
    ike_dh_groups = _parse_dh_groups(
        data,
        list_key="ike_dh_groups",
        singular_key="dh_group",
        default=14,
        label="DH group",
    )
    pfs_dh_groups = _parse_dh_groups(
        data,
        list_key="pfs_dh_groups",
        singular_key="pfs_dh_group",
        default=14,
        label="PFS DH group",
    )
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
        phase1_encryption=ike_proposals[0].encryption,
        phase1_integrity=ike_proposals[0].integrity,
        dh_group=ike_dh_groups[0],
        ike_proposals=ike_proposals,
        ike_dh_groups=ike_dh_groups,
        phase1_lifetime=_lifetime(
            data.get("phase1_lifetime", _DEFAULT_PHASE1_LIFETIME), "Phase 1 lifetime"
        ),
        phase2_encryption=child_proposals[0].encryption,
        phase2_integrity=child_proposals[0].integrity,
        child_proposals=child_proposals,
        pfs=_as_bool(data.get("pfs", True), "PFS"),
        pfs_dh_group=pfs_dh_groups[0],
        pfs_dh_groups=pfs_dh_groups,
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
        saml_port=_port(data.get("saml_port", DEFAULT_SAML_PORT), "IPsec SAML port"),
    )


def _proposal(encryption: str, integrity: str, dh_group: int | None) -> str:
    parts = [encryption, integrity]
    if dh_group is not None:
        parts.append(DH_GROUP_TO_MODP[dh_group])
    return "-".join(parts)


def _parse_proposals(
    data: dict[str, object],
    *,
    list_key: str,
    encryption_key: str,
    integrity_key: str,
    encryption_default: str,
    integrity_default: str,
    label: str,
) -> tuple[CryptoProposal, ...]:
    raw = data.get(list_key)
    if raw is not None:
        if not isinstance(raw, list) or not raw:
            raise ValueError(f"{label}s must be a non-empty list.")
        parsed = tuple(_parse_one_proposal(item, label) for item in raw)
        return _dedupe(parsed)
    encryption = _one_of(
        data.get(encryption_key, encryption_default), ENCRYPTION_ALGORITHMS, f"{label} encryption"
    )
    integrity = _one_of(
        data.get(integrity_key, integrity_default), INTEGRITY_ALGORITHMS, f"{label} integrity"
    )
    return (CryptoProposal(encryption, integrity),)


def _parse_one_proposal(value: object, label: str) -> CryptoProposal:
    if isinstance(value, dict):
        encryption = _one_of(value.get("encryption"), ENCRYPTION_ALGORITHMS, f"{label} encryption")
        integrity = _one_of(value.get("integrity"), INTEGRITY_ALGORITHMS, f"{label} integrity")
        return CryptoProposal(encryption, integrity)
    raise ValueError(f"{label}s must be objects with encryption and integrity.")


def _parse_dh_groups(
    data: dict[str, object],
    *,
    list_key: str,
    singular_key: str,
    default: int,
    label: str,
) -> tuple[int, ...]:
    raw = data.get(list_key)
    if raw is not None:
        if not isinstance(raw, list) or not raw:
            raise ValueError(f"{label}s must be a non-empty list.")
        parsed = tuple(_dh_group(item, label) for item in raw)
        return _dedupe(parsed)
    return (_dh_group(data.get(singular_key, default), label),)


def _dedupe(values: tuple[_T, ...]) -> tuple[_T, ...]:
    seen: set[_T] = set()
    ordered: list[_T] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return tuple(ordered)


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


def _port(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        if isinstance(value, str) and value.strip().isdigit():
            number = int(value.strip())
        else:
            raise ValueError(f"{label} must be between 1 and 65535.")
    else:
        number = value
    if number < 1 or number > 65535:
        raise ValueError(f"{label} must be between 1 and 65535.")
    return number
