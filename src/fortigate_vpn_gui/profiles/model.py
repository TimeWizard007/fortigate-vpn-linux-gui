# SPDX-License-Identifier: GPL-3.0-or-later
"""Connection profile data model and validation.

Profiles never include passwords, SAML tokens, cookies, client secrets, or
MFA material. Those keys are rejected if they appear in stored JSON.
``trusted_cert_sha256`` is an optional certificate pin, not a secret.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass

from fortigate_vpn_gui.helper.validation import normalize_sha256_fingerprint

SCHEMA_VERSION = 1

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

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
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


def new_profile_id() -> str:
    """Return a stable unique identifier."""
    return uuid.uuid4().hex


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

    ident = str(profile_id).strip() if profile_id is not None else new_profile_id()
    if not ident:
        errors.append("Profile id cannot be empty.")

    name_text = _as_text(name)
    if name_text is None:
        errors.append("Profile name cannot be empty.")
    elif not name_text.strip():
        errors.append("Profile name cannot be empty.")
    elif len(name_text.strip()) > _MAX_NAME_LENGTH:
        errors.append(f"Profile name must be at most {_MAX_NAME_LENGTH} characters.")
    else:
        name_text = name_text.strip()

    gateway_text = _as_text(gateway)
    if gateway_text is None:
        errors.append("Gateway cannot be empty.")
    elif not gateway_text.strip():
        errors.append("Gateway cannot be empty.")
    elif any(ch.isspace() for ch in gateway_text.strip()):
        errors.append("Gateway must be a hostname or IP address without spaces.")
    elif len(gateway_text.strip()) > _MAX_GATEWAY_LENGTH:
        errors.append(f"Gateway must be at most {_MAX_GATEWAY_LENGTH} characters.")
    else:
        gateway_text = gateway_text.strip()

    port_value = _as_port(port)
    if port_value is None:
        errors.append("Port must be an integer between 1 and 65535.")

    description_text = _as_optional_text(description, "Description", _MAX_TEXT_LENGTH, errors)
    hint_text = _as_optional_text(username_hint, "Username hint", _MAX_TEXT_LENGTH, errors)

    sso_value = _as_bool(use_sso)
    if sso_value is None:
        errors.append("Use SSO must be true or false.")

    pin_value: str | None = None
    if trusted_cert_sha256 not in (None, ""):
        pin_value = normalize_sha256_fingerprint(trusted_cert_sha256)
        if pin_value is None:
            errors.append("Trusted certificate fingerprint must be a SHA-256 hex digest.")

    if errors:
        raise ProfileValidationError(errors)

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
