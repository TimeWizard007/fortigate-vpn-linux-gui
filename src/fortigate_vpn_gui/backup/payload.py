# SPDX-License-Identifier: GPL-3.0-or-later
"""Backup payload schema, independent of the encryption container.

This module never reads Secret Service and never talks to the helper.
It is not the secret-free Export/Import path.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fortigate_vpn_gui import __version__
from fortigate_vpn_gui.backup.format import PAYLOAD_VERSION, BackupFormatError
from fortigate_vpn_gui.profiles.ipsec import IPSEC_STORED_FIELDS, VPN_TYPE_IPSEC, VPN_TYPES
from fortigate_vpn_gui.profiles.model import (
    FORBIDDEN_SECRET_KEYS,
    STORED_FIELDS,
    ConnectionProfile,
    ProfileValidationError,
    build_profile,
    unique_suffixed_name,
)

PAYLOAD_FORMAT = "fortigate-vpn-linux-gui-backup"
ALLOWED_SECRET_KEYS = frozenset({"psk", "xauth_password"})
ALLOWED_PAYLOAD_KEYS = frozenset(
    {
        "format",
        "payload_version",
        "created_app_version",
        "default_profile_id",
        "profiles",
    }
)
ALLOWED_PROFILE_KEYS = frozenset(STORED_FIELDS) | frozenset({"ipsec", "secrets"})
FORBIDDEN_PAYLOAD_KEYS = FORBIDDEN_SECRET_KEYS | frozenset(
    {
        "password",
        "passwd",
        "ssl_password",
        "tokenid",
        "fct_uid",
        "fct_token_id",
        "eap_identity",
        "eap_password",
        "cookie",
        "cookies",
        "saml_token",
        "saml_session",
        "auth_cache",
    }
)


@dataclass
class BackupSecrets:
    """Optional persisted IPsec secrets for one profile. Wipe after use."""

    psk: str | None = None
    xauth_password: str | None = None

    def wipe(self) -> None:
        self.psk = "" if self.psk is not None else None
        self.xauth_password = "" if self.xauth_password is not None else None

    def has_any(self) -> bool:
        return bool(self.psk) or bool(self.xauth_password)


@dataclass
class BackupProfile:
    """One validated backup profile plus optional secrets."""

    profile: ConnectionProfile
    secrets: BackupSecrets


@dataclass(frozen=True)
class RestoreSummaryRow:
    """Safe-to-display restore row. Never includes secret values."""

    profile_id: str
    name: str
    family: str
    has_psk: bool
    has_xauth: bool
    action: str


@dataclass
class RestorePlan:
    """Preflight result. Secrets stay in memory until commit or wipe."""

    profiles: list[BackupProfile]
    default_profile_id: str | None
    rows: tuple[RestoreSummaryRow, ...]
    replace_ids: frozenset[str]
    has_secrets: bool

    def wipe(self) -> None:
        for item in self.profiles:
            item.secrets.wipe()


def build_payload_document(
    profiles: list[ConnectionProfile],
    *,
    default_profile_id: str | None,
    secrets_by_id: dict[str, BackupSecrets],
    created_app_version: str | None = None,
) -> dict[str, Any]:
    """Return a payload dict ready for JSON serialization."""
    records: list[dict[str, Any]] = []
    for profile in profiles:
        record = _profile_fields(profile)
        secret = secrets_by_id.get(profile.id)
        packed = _secrets_to_json(secret)
        if packed:
            record["secrets"] = packed
        records.append(record)
    known = {profile.id for profile in profiles}
    default_id = default_profile_id if default_profile_id in known else None
    return {
        "format": PAYLOAD_FORMAT,
        "payload_version": PAYLOAD_VERSION,
        "created_app_version": created_app_version or __version__,
        "default_profile_id": default_id,
        "profiles": records,
    }


def parse_payload_document(raw: object) -> tuple[list[BackupProfile], str | None]:
    """Validate payload JSON. Fail closed on unknown or forbidden keys."""
    if not isinstance(raw, dict):
        raise BackupFormatError("The backup payload is not valid.")
    _reject_forbidden(raw)
    extra = set(raw) - ALLOWED_PAYLOAD_KEYS
    if extra:
        raise BackupFormatError("The backup payload contains unsupported fields.")
    if raw.get("format") != PAYLOAD_FORMAT:
        raise BackupFormatError("This file is not a FortiGate VPN Linux GUI backup.")
    if raw.get("payload_version") != PAYLOAD_VERSION:
        raise BackupFormatError("This backup payload version is not supported.")
    created = raw.get("created_app_version")
    if created is not None and not isinstance(created, str):
        raise BackupFormatError("The backup payload is not valid.")
    records = raw.get("profiles")
    if not isinstance(records, list):
        raise BackupFormatError("The backup payload is not valid.")
    items: list[BackupProfile] = []
    seen: set[str] = set()
    for record in records:
        item = _parse_profile_record(record)
        if item.profile.id in seen:
            raise BackupFormatError("The backup contains duplicate profile identifiers.")
        seen.add(item.profile.id)
        items.append(item)
    default_raw = raw.get("default_profile_id")
    if default_raw in (None, ""):
        default_id = None
    elif isinstance(default_raw, str) and default_raw.strip():
        default_id = default_raw.strip()
        if default_id not in seen:
            default_id = None
    else:
        raise BackupFormatError("The backup payload is not valid.")
    return items, default_id


def plan_restore(
    items: list[BackupProfile],
    *,
    existing: list[ConnectionProfile],
    default_profile_id: str | None,
) -> tuple[list[BackupProfile], str | None, tuple[RestoreSummaryRow, ...], frozenset[str]]:
    """Resolve id replacements and name collisions. Does not write."""
    existing_by_id = {profile.id: profile for profile in existing}
    backup_ids = {item.profile.id for item in items}
    kept = [profile for profile in existing if profile.id not in backup_ids]
    taken_names = {profile.name for profile in kept}
    resolved: list[BackupProfile] = []
    rows: list[RestoreSummaryRow] = []
    replace_ids: set[str] = set()
    for item in items:
        incoming = item.profile
        action = "add"
        if incoming.id in existing_by_id:
            action = "replace"
            replace_ids.add(incoming.id)
        name = incoming.name
        if name.casefold() in {taken.casefold() for taken in taken_names}:
            name = unique_suffixed_name(name, taken_names, stem="restored")
            action = "replace" if action == "replace" else "rename"
            incoming = _with_name(incoming, name)
        taken_names.add(incoming.name)
        resolved.append(BackupProfile(profile=incoming, secrets=item.secrets))
        rows.append(
            RestoreSummaryRow(
                profile_id=incoming.id,
                name=incoming.name,
                family=incoming.profile_family(),
                has_psk=bool(item.secrets.psk),
                has_xauth=bool(item.secrets.xauth_password),
                action=action,
            )
        )
    known_ids = {item.profile.id for item in resolved} | {profile.id for profile in kept}
    default_id = default_profile_id if default_profile_id in known_ids else None
    return resolved, default_id, tuple(rows), frozenset(replace_ids)


def merged_profiles(
    existing: list[ConnectionProfile],
    incoming: list[BackupProfile],
) -> list[ConnectionProfile]:
    """Return kept existing profiles plus incoming backup profiles."""
    backup_ids = {item.profile.id for item in incoming}
    kept = [profile for profile in existing if profile.id not in backup_ids]
    return kept + [item.profile for item in incoming]


def payload_has_secrets(items: list[BackupProfile]) -> bool:
    return any(item.secrets.has_any() for item in items)


def format_restore_summary(plan: RestorePlan, *, source: Path | str | None = None) -> str:
    """Return confirmation text. Never includes secret values."""
    psk_count = sum(1 for row in plan.rows if row.has_psk)
    xauth_count = sum(1 for row in plan.rows if row.has_xauth)
    added = [row for row in plan.rows if row.action == "add"]
    replaces = [row for row in plan.rows if row.action == "replace"]
    renames = [row for row in plan.rows if row.action == "rename"]
    lines: list[str] = []
    if source is not None:
        lines.append(f"Backup file: {source}")
    lines.extend(
        [
            f"Profiles in this backup: {len(plan.rows)}",
            f"Will add: {len(added)}",
            f"Will replace: {len(replaces)}",
            f"Will rename: {len(renames)}",
            f"PSK restored for {psk_count} profile(s)."
            if psk_count
            else "No saved PSK in this backup.",
            f"XAuth password restored for {xauth_count} profile(s)."
            if xauth_count
            else "No saved XAuth password in this backup.",
            "SSL passwords are never included in backups.",
            "SAML sessions, cookies, and tokens are never included.",
        ]
    )
    if plan.rows:
        lines.append("")
        lines.append("Profiles:")
        for row in plan.rows:
            extra = []
            if row.has_psk:
                extra.append("PSK saved")
            if row.has_xauth:
                extra.append("XAuth saved")
            suffix = f" ({', '.join(extra)})" if extra else ""
            lines.append(f"- {row.name} — {row.family}{suffix}")
    if added:
        lines.append("")
        lines.append("These profiles will be added:")
        for row in added:
            lines.append(f"- {row.name}")
    if replaces:
        lines.append("")
        lines.append("These existing profiles will be replaced:")
        for row in replaces:
            lines.append(f"- {row.name}")
    if renames:
        lines.append("")
        lines.append("These names collide with existing profiles and will be renamed:")
        for row in renames:
            lines.append(f"- {row.name}")
    lines.append("")
    lines.append("This cannot be undone except by restoring another backup.")
    return "\n".join(lines)


def _profile_fields(profile: ConnectionProfile) -> dict[str, Any]:
    record: dict[str, Any] = {key: getattr(profile, key) for key in STORED_FIELDS}
    if not record.get("trusted_cert_sha256"):
        record["trusted_cert_sha256"] = None
    if profile.is_ipsec():
        payload = profile.ipsec_payload() or {}
        record["ipsec"] = {key: payload[key] for key in IPSEC_STORED_FIELDS if key in payload}
    return record


def _secrets_to_json(secret: BackupSecrets | None) -> dict[str, str]:
    packed: dict[str, str] = {}
    if secret is None:
        return packed
    if secret.psk:
        packed["psk"] = secret.psk
    if secret.xauth_password:
        packed["xauth_password"] = secret.xauth_password
    return packed


def _parse_profile_record(record: object) -> BackupProfile:
    if not isinstance(record, dict):
        raise BackupFormatError("The backup payload is not valid.")
    _reject_forbidden(record)
    extra = set(record) - ALLOWED_PROFILE_KEYS
    if extra:
        raise BackupFormatError("The backup payload contains unsupported fields.")
    vpn_type = record.get("vpn_type", "ssl")
    if vpn_type not in VPN_TYPES:
        raise BackupFormatError("This VPN type is not supported.")
    ipsec_value: object | None = None
    if vpn_type == VPN_TYPE_IPSEC:
        ipsec_raw = record.get("ipsec")
        if ipsec_raw is None:
            ipsec_value = None
        elif not isinstance(ipsec_raw, dict):
            raise BackupFormatError("IPsec settings in the backup are not valid.")
        else:
            _reject_forbidden(ipsec_raw)
            extra_ipsec = set(ipsec_raw) - set(IPSEC_STORED_FIELDS)
            if extra_ipsec:
                raise BackupFormatError("The backup payload contains unsupported fields.")
            ipsec_value = {key: ipsec_raw[key] for key in IPSEC_STORED_FIELDS if key in ipsec_raw}
    elif "ipsec" in record and record.get("ipsec") not in (None, {}):
        raise BackupFormatError("SSL VPN backups must not include IPsec settings.")
    secrets = _parse_secrets(record.get("secrets"))
    try:
        profile = build_profile(
            profile_id=record.get("id"),
            name=record.get("name"),
            gateway=record.get("gateway"),
            port=record.get("port", 443),
            description=record.get("description", ""),
            username_hint=record.get("username_hint", ""),
            use_sso=record.get("use_sso", True),
            trusted_cert_sha256=record.get("trusted_cert_sha256"),
            vpn_type=vpn_type,
            ipsec=ipsec_value,
        )
    except ProfileValidationError as exc:
        raise BackupFormatError("; ".join(exc.errors)) from exc
    return BackupProfile(profile=profile, secrets=secrets)


def _parse_secrets(raw: object) -> BackupSecrets:
    if raw in (None, {}):
        return BackupSecrets()
    if not isinstance(raw, dict):
        raise BackupFormatError("The backup payload is not valid.")
    _reject_forbidden(raw)
    extra = set(raw) - ALLOWED_SECRET_KEYS
    if extra:
        raise BackupFormatError("The backup payload contains unsupported fields.")
    psk = raw.get("psk")
    xauth = raw.get("xauth_password")
    if psk is not None and (not isinstance(psk, str) or not psk):
        raise BackupFormatError("The backup payload is not valid.")
    if xauth is not None and (not isinstance(xauth, str) or not xauth):
        raise BackupFormatError("The backup payload is not valid.")
    return BackupSecrets(psk=psk, xauth_password=xauth)


def _reject_forbidden(value: object) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            folded = str(key).casefold()
            if folded in FORBIDDEN_PAYLOAD_KEYS and folded not in ALLOWED_SECRET_KEYS:
                raise BackupFormatError("Backup files must not contain unsupported secrets.")
            if folded in FORBIDDEN_PAYLOAD_KEYS and folded in ALLOWED_SECRET_KEYS:
                # Allowed only inside the secrets object; nested misuse still walks.
                pass
            _reject_forbidden(item)
        return
    if isinstance(value, list):
        for item in value:
            _reject_forbidden(item)


def _with_name(profile: ConnectionProfile, name: str) -> ConnectionProfile:
    return ConnectionProfile(
        id=profile.id,
        name=name,
        gateway=profile.gateway,
        port=profile.port,
        description=profile.description,
        username_hint=profile.username_hint,
        use_sso=profile.use_sso,
        trusted_cert_sha256=profile.trusted_cert_sha256,
        vpn_type=profile.vpn_type,
        ipsec=profile.ipsec,
    )
