# SPDX-License-Identifier: GPL-3.0-or-later
"""Persistent FortiClient-style IPsec SAML identity (FCT_UID).

This value is an install-stable identity, not a password. It is never stored
in Secret Service, profile JSON, logs, or diagnostics. The file holds exactly
32 lowercase hexadecimal characters.
"""

from __future__ import annotations

import os
import re
import secrets
import tempfile
from collections.abc import Mapping
from pathlib import Path

from fortigate_vpn_gui.profiles.storage import default_config_dir

UID_LENGTH = 32
UID_PATTERN = re.compile(rf"^[0-9a-f]{{{UID_LENGTH}}}$")
UID_FILENAME = "ipsec-saml-uid"
_FILE_MODE = 0o600
_DIR_MODE = 0o700


class IpsecSamlUidError(RuntimeError):
    """The on-disk IPsec SAML identity is missing or invalid."""


def ipsec_saml_uid_path(
    environ: Mapping[str, str] | None = None,
    *,
    home: Path | None = None,
    path: Path | None = None,
) -> Path:
    """Return the identity file path. *path* overrides XDG when provided."""
    if path is not None:
        return path
    return default_config_dir(environ, home=home) / UID_FILENAME


def validate_ipsec_saml_uid(value: object) -> str:
    """Return *value* if it is exactly 32 lowercase hex characters."""
    if not isinstance(value, str) or UID_PATTERN.fullmatch(value) is None:
        raise IpsecSamlUidError("IPsec SAML identity is invalid.")
    return value


def get_or_create_ipsec_saml_uid(
    *,
    path: Path | None = None,
    environ: Mapping[str, str] | None = None,
    home: Path | None = None,
) -> str:
    """Load the persisted identity or create one if the file is absent.

    A corrupt existing file is rejected. It is not overwritten silently.
    """
    target = ipsec_saml_uid_path(environ, home=home, path=path)
    if target.is_file():
        try:
            raw = target.read_text(encoding="ascii")
        except OSError as exc:
            raise IpsecSamlUidError("IPsec SAML identity could not be read.") from exc
        return validate_ipsec_saml_uid(raw.strip())
    uid = secrets.token_hex(UID_LENGTH // 2)
    _atomic_write_uid(target, uid)
    return uid


def _atomic_write_uid(path: Path, uid: str) -> None:
    validate_ipsec_saml_uid(uid)
    created_dir = not path.parent.exists()
    path.parent.mkdir(parents=True, exist_ok=True)
    if created_dir:
        try:
            os.chmod(path.parent, _DIR_MODE)
        except OSError:
            pass
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{UID_FILENAME}.",
        suffix=".tmp",
        dir=str(path.parent),
    )
    try:
        os.fchmod(fd, _FILE_MODE)
        with os.fdopen(fd, "w", encoding="ascii") as handle:
            handle.write(uid)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
        os.chmod(path, _FILE_MODE)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


__all__ = [
    "UID_FILENAME",
    "UID_LENGTH",
    "IpsecSamlUidError",
    "get_or_create_ipsec_saml_uid",
    "ipsec_saml_uid_path",
    "validate_ipsec_saml_uid",
]
