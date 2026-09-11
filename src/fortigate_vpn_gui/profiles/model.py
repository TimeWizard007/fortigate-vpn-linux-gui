# SPDX-License-Identifier: GPL-3.0-or-later
"""Connection profile data model and validation.

Profiles never include passwords, SAML tokens, cookies, client secrets, or
MFA material. Those keys are rejected if they appear in stored JSON.
``trusted_cert_sha256`` is an optional certificate pin, not a secret.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from dataclasses import asdict, dataclass

from fortigate_vpn_gui.helper.protocol import HelperProtocolError
from fortigate_vpn_gui.helper.validation import (
    normalize_sha256_fingerprint,
    validate_gateway,
)

SCHEMA_VERSION = 1

AUTH_SAML_LABEL = "SAML / SSO"
AUTH_PASSWORD_LABEL = "Username / Password"

# Keys that must never be persisted or round-tripped from disk.
FORBIDDEN_SECRET_KEYS = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "client_secret",
        "token",
        "saml_token",
        "access_token",
        "refresh_token",
        "cookie",
        "cookies",
        "mfa",
        "otp",
        "totp",
        "pin",
    }
)

STORED_FIELDS = (
    "id",
    "name",
    "gateway",
    "port",
    "description",
    "username_hint",
    "use_sso",
    "trusted_cert_sha256",
)

_MAX_NAME_LENGTH = 200
_MAX_GATEWAY_LENGTH = 253
_MAX_TEXT_LENGTH = 1000


class ProfileError(Exception):
    """Base error for profile operations."""


class ProfileValidationError(ProfileError):
    """One or more field validation failures."""

    def __init__(
        self,
        errors: list[str],
        field_errors: dict[str, str] | None = None,
    ) -> None:
        self.errors = errors
        self.field_errors = dict(field_errors or {})
        super().__init__("; ".join(errors))


class ProfileNotFoundError(ProfileError):
    """The requested profile id does not exist."""


@dataclass(frozen=True)
class ConnectionProfile:
    """A saved FortiGate connection profile (non-secret fields only)."""

    id: str
    name: str
    gateway: str
    port: int = 443
    description: str = ""
    username_hint: str = ""
    use_sso: bool = True
    trusted_cert_sha256: str | None = None

    def to_json(self) -> dict[str, object]:
        """Return the JSON-serialisable record. Secret keys are never included."""
        payload = {key: asdict(self)[key] for key in STORED_FIELDS}
        if not payload.get("trusted_cert_sha256"):
            payload["trusted_cert_sha256"] = None
        return payload

    def auth_label(self) -> str:
        """Return the human-readable authentication mode."""
        return auth_mode_label(self.use_sso)


def auth_mode_label(use_sso: bool) -> str:
    """Return the authentication label used in Profiles and Connection."""
    return AUTH_SAML_LABEL if use_sso else AUTH_PASSWORD_LABEL


def new_profile_id() -> str:
    """Return a stable unique identifier."""
    return uuid.uuid4().hex


def unique_copy_name(base: str, existing_names: Iterable[str]) -> str:
    """Return a deterministic unique name for a duplicated profile."""
    taken = {name.casefold() for name in existing_names}
    suffix = " (copy)"
    candidate = _with_copy_suffix(base, suffix)
    if candidate.casefold() not in taken:
        return candidate
    index = 2
    while True:
        suffix = f" (copy {index})"
        candidate = _with_copy_suffix(base, suffix)
        if candidate.casefold() not in taken:
            return candidate
        index += 1


def build_profile(
    *,
    profile_id: str | None = None,
    name: object,
    gateway: object,
    port: object = 443,
    description: object = "",
    username_hint: object = "",
    use_sso: object = True,
    trusted_cert_sha256: object = None,
) -> ConnectionProfile:
    """Validate and construct a profile. Raises ``ProfileValidationError``."""
    errors: list[str] = []
    field_errors: dict[str, str] = {}

    ident = str(profile_id).strip() if profile_id is not None else new_profile_id()
    if not ident:
        _add_error(errors, field_errors, "id", "Profile id cannot be empty.")

    name_text = _as_text(name)
    if name_text is None or not name_text.strip():
        _add_error(errors, field_errors, "name", "Profile name is required.")
        name_text = None
    elif len(name_text.strip()) > _MAX_NAME_LENGTH:
        _add_error(
            errors,
            field_errors,
            "name",
            f"Profile name must be at most {_MAX_NAME_LENGTH} characters.",
        )
        name_text = None
    else:
        name_text = name_text.strip()

    gateway_text = _normalize_gateway(gateway, errors, field_errors)

    port_value = _as_port(port)
    if port_value is None:
        _add_error(
            errors,
            field_errors,
            "port",
            "Port must be between 1 and 65535.",
        )

    description_text = _as_optional_text(description, "Description", _MAX_TEXT_LENGTH, errors)
    hint_text = _as_optional_text(username_hint, "Username hint", _MAX_TEXT_LENGTH, errors)

    sso_value = _as_bool(use_sso)
    if sso_value is None:
        _add_error(errors, field_errors, "use_sso", "Authentication mode must be true or false.")

    pin_value: str | None = None
    if trusted_cert_sha256 not in (None, ""):
        pin_value = normalize_sha256_fingerprint(trusted_cert_sha256)
        if pin_value is None:
            _add_error(
                errors,
                field_errors,
                "trusted_cert_sha256",
                "Trusted certificate fingerprint must be a SHA-256 hex digest.",
            )

    if errors:
        raise ProfileValidationError(errors, field_errors=field_errors)

    assert name_text is not None
    assert gateway_text is not None
    assert port_value is not None
    assert description_text is not None
    assert hint_text is not None
    assert sso_value is not None

    return ConnectionProfile(
        id=ident,
        name=name_text,
        gateway=gateway_text,
        port=port_value,
        description=description_text,
        username_hint=hint_text,
        use_sso=sso_value,
        trusted_cert_sha256=pin_value,
    )


def _with_copy_suffix(base: str, suffix: str) -> str:
    budget = _MAX_NAME_LENGTH - len(suffix)
    trimmed = base.strip()
    if budget < 1:
        return suffix.strip()[:_MAX_NAME_LENGTH]
    if len(trimmed) > budget:
        trimmed = trimmed[:budget].rstrip()
    if not trimmed:
        trimmed = "Profile"[:budget]
    return trimmed + suffix


def _add_error(
    errors: list[str],
    field_errors: dict[str, str],
    field: str,
    message: str,
) -> None:
    errors.append(message)
    field_errors.setdefault(field, message)


def _normalize_gateway(
    value: object,
    errors: list[str],
    field_errors: dict[str, str],
) -> str | None:
    gateway_text = _as_text(value)
    if gateway_text is None:
        _add_error(errors, field_errors, "gateway", "Gateway is required.")
        return None
    stripped = gateway_text.strip()
    if not stripped:
        _add_error(errors, field_errors, "gateway", "Gateway is required.")
        return None
    if len(stripped) > _MAX_GATEWAY_LENGTH:
        _add_error(
            errors,
            field_errors,
            "gateway",
            f"Gateway must be at most {_MAX_GATEWAY_LENGTH} characters.",
        )
        return None
    try:
        return validate_gateway(stripped)
    except HelperProtocolError:
        _add_error(errors, field_errors, "gateway", "Enter a valid gateway.")
        return None


def _as_text(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool) or isinstance(value, (int, float)):
        return None
    if not isinstance(value, str):
        return None
    return value


def _as_optional_text(
    value: object,
    label: str,
    max_length: int,
    errors: list[str],
) -> str | None:
    if value is None:
        return ""
    if isinstance(value, bool) or isinstance(value, (int, float)):
        errors.append(f"{label} must be text.")
        return None
    if not isinstance(value, str):
        errors.append(f"{label} must be text.")
        return None
    text = value.strip()
    if len(text) > max_length:
        errors.append(f"{label} must be at most {max_length} characters.")
        return None
    return text


def _as_port(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        number = value
    elif isinstance(value, str) and value.strip().isdigit():
        number = int(value.strip())
    else:
        return None
    if 1 <= number <= 65535:
        return number
    return None


def _as_bool(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    return None
