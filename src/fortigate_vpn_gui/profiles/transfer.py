# SPDX-License-Identifier: GPL-3.0-or-later
"""Versioned profile import/export without secrets.

The application-owned format is JSON:

    {"format": "fortigate-vpn-linux-gui-profile", "version": 1, "profile": {...}}

Exports never include passwords, PSKs, tokens, cookies, FCT UID, tokenid,
keyring values, or filesystem/config fragments. Import never writes those
fields and never treats plaintext credentials as a supported feature.
"""

from __future__ import annotations

import json
from pathlib import Path

from fortigate_vpn_gui.profiles.ipsec import (
    IPSEC_STORED_FIELDS,
    VPN_TYPE_IPSEC,
    VPN_TYPE_SSL,
    VPN_TYPES,
    parse_ipsec_settings,
)
from fortigate_vpn_gui.profiles.model import (
    FORBIDDEN_SECRET_KEYS,
    ConnectionProfile,
    ProfileError,
    ProfileValidationError,
    build_profile,
)

EXPORT_FORMAT = "fortigate-vpn-linux-gui-profile"
EXPORT_VERSION = 1

EXPORT_PROFILE_KEYS = (
    "name",
    "gateway",
    "port",
    "description",
    "username_hint",
    "use_sso",
    "vpn_type",
    "trusted_cert_sha256",
)

# Keys that must never appear in an import document (secrets or injection).
FORBIDDEN_IMPORT_KEYS = FORBIDDEN_SECRET_KEYS | frozenset(
    {
        "path",
        "config_path",
        "config",
        "swanctl",
        "charon",
        "plugin",
        "plugin_path",
        "plugindir",
        "script",
        "argv",
        "command",
        "helper_path",
        "vici",
        "secrets_file",
        "ca_file",
        "cert_file",
        "key_file",
        "include",
        "load",
        "plugins",
        "strongswan_conf",
        "exec",
        "cwd",
        "env",
        "environment",
        "private_key_path",
        "license_info",
        "notify_data",
        "vendor_id",
        "vendor_ids",
        "cp16",
        "auth_omit",
        "initial_contact",
    }
)

_SECRET_HINTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "cookie",
    "psk",
    "keyring",
)


class ProfileTransferError(ProfileError):
    """The import file is malformed, unsupported, or unsafe."""


def export_profile_document(profile: ConnectionProfile) -> dict[str, object]:
    """Return a versioned export document with non-secret fields only."""
    record: dict[str, object] = {
        "name": profile.name,
        "gateway": profile.gateway,
        "port": profile.port,
        "description": profile.description,
        "username_hint": profile.username_hint,
        "use_sso": profile.use_sso,
        "vpn_type": profile.vpn_type,
        "trusted_cert_sha256": profile.trusted_cert_sha256,
    }
    if profile.is_ipsec():
        settings = profile.ipsec_payload() or {}
        record["ipsec"] = {key: settings[key] for key in IPSEC_STORED_FIELDS if key in settings}
    return {
        "format": EXPORT_FORMAT,
        "version": EXPORT_VERSION,
        "profile": record,
    }


def export_profile_json(profile: ConnectionProfile) -> str:
    """Return pretty-printed UTF-8 JSON for *profile*."""
    document = export_profile_document(profile)
    return json.dumps(document, indent=2, ensure_ascii=False, sort_keys=True) + "\n"


def write_exported_profile(profile: ConnectionProfile, path: Path) -> Path:
    """Write a secret-free export to *path*."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(export_profile_json(profile), encoding="utf-8")
    return path


def parse_exported_profile(payload: object) -> dict[str, object]:
    """Validate an export document and return fields for ``ProfileManager.add``.

    Raises ``ProfileTransferError`` for malformed, secret-bearing, or
    unsupported files. Does not persist anything.
    """
    if not isinstance(payload, dict):
        raise ProfileTransferError("The file is not a valid profile export.")
    _reject_forbidden_keys(payload)
    if payload.get("format") != EXPORT_FORMAT:
        raise ProfileTransferError("This file is not a FortiGate VPN Linux GUI profile export.")
    if payload.get("version") != EXPORT_VERSION:
        raise ProfileTransferError("This profile export version is not supported.")
    raw = payload.get("profile")
    if not isinstance(raw, dict):
        raise ProfileTransferError("The export does not contain a profile object.")
    _reject_forbidden_keys(raw)

    vpn_type = raw.get("vpn_type", VPN_TYPE_SSL)
    if vpn_type not in VPN_TYPES:
        raise ProfileTransferError("This VPN type is not supported.")

    ipsec_value: object | None = None
    if vpn_type == VPN_TYPE_IPSEC:
        ipsec_raw = raw.get("ipsec")
        if ipsec_raw is None:
            ipsec_value = None
        elif not isinstance(ipsec_raw, dict):
            raise ProfileTransferError("IPsec settings in the export are not valid.")
        else:
            _reject_forbidden_keys(ipsec_raw)
            allowed = {key: ipsec_raw[key] for key in IPSEC_STORED_FIELDS if key in ipsec_raw}
            try:
                parse_ipsec_settings(allowed)
            except ValueError as exc:
                raise ProfileTransferError(str(exc)) from exc
            ipsec_value = allowed
    elif "ipsec" in raw and raw.get("ipsec") not in (None, {}):
        raise ProfileTransferError("SSL VPN exports must not include IPsec settings.")

    try:
        preview = build_profile(
            name=raw.get("name"),
            gateway=raw.get("gateway"),
            port=raw.get("port", 443),
            description=raw.get("description", ""),
            username_hint=raw.get("username_hint", ""),
            use_sso=raw.get("use_sso", True),
            trusted_cert_sha256=raw.get("trusted_cert_sha256"),
            vpn_type=vpn_type,
            ipsec=ipsec_value,
        )
    except ProfileValidationError as exc:
        raise ProfileTransferError("; ".join(exc.errors)) from exc

    return {
        "name": preview.name,
        "gateway": preview.gateway,
        "port": preview.port,
        "description": preview.description,
        "username_hint": preview.username_hint,
        "use_sso": preview.use_sso,
        "trusted_cert_sha256": preview.trusted_cert_sha256,
        "vpn_type": preview.vpn_type,
        "ipsec": preview.ipsec_payload(),
    }


def load_exported_profile_file(path: Path) -> dict[str, object]:
    """Read and validate a profile export file."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ProfileTransferError("The profile file could not be read.") from exc
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ProfileTransferError("The profile file is not valid JSON.") from exc
    _reject_secret_text(text)
    return parse_exported_profile(payload)


def _reject_forbidden_keys(value: object) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            name = str(key)
            folded = name.casefold()
            if folded in FORBIDDEN_IMPORT_KEYS or folded in FORBIDDEN_SECRET_KEYS:
                if folded in FORBIDDEN_SECRET_KEYS or any(hint in folded for hint in _SECRET_HINTS):
                    raise ProfileTransferError(
                        "Import files must not contain credentials or secrets."
                    )
                raise ProfileTransferError(
                    "The profile file contains unsupported configuration fields."
                )
            if any(hint in folded for hint in _SECRET_HINTS):
                raise ProfileTransferError("Import files must not contain credentials or secrets.")
            _reject_forbidden_keys(item)
        return
    if isinstance(value, list):
        for item in value:
            _reject_forbidden_keys(item)


def _reject_secret_text(text: str) -> None:
    """Fail closed if the raw file looks like it embeds credentials."""
    folded = text.casefold()
    for key in FORBIDDEN_SECRET_KEYS:
        needle = f'"{key}"'
        if needle in folded:
            raise ProfileTransferError("Import files must not contain credentials or secrets.")
