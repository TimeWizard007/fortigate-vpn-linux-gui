# SPDX-License-Identifier: GPL-3.0-or-later
"""XDG-compatible JSON storage for connection profiles.

This module never stores secrets. Unknown JSON fields are ignored. Malformed
files yield an empty profile list instead of crashing the application.
v0.7.1 documents without ``default_profile_id`` load with no default.
"""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from fortigate_vpn_gui.profiles.model import (
    FORBIDDEN_SECRET_KEYS,
    SCHEMA_VERSION,
    ConnectionProfile,
    ProfileValidationError,
    build_profile,
)

APP_CONFIG_DIRNAME = "fortigate-vpn-linux-gui"
PROFILES_FILENAME = "profiles.json"


@dataclass(frozen=True)
class ProfilesDocument:
    """Loaded profiles.json contents, including the optional default marker."""

    profiles: list[ConnectionProfile]
    default_profile_id: str | None = None


def default_config_dir(
    environ: Mapping[str, str] | None = None,
    *,
    home: Path | None = None,
) -> Path:
    """Return the per-user config directory (XDG_CONFIG_HOME or ``~/.config``)."""
    env = os.environ if environ is None else environ
    xdg = str(env.get("XDG_CONFIG_HOME", "")).strip()
    if xdg:
        return Path(xdg) / APP_CONFIG_DIRNAME
    base = home if home is not None else Path.home()
    return base / ".config" / APP_CONFIG_DIRNAME


def default_profiles_path(
    environ: Mapping[str, str] | None = None,
    *,
    home: Path | None = None,
) -> Path:
    """Return the default ``profiles.json`` path."""
    return default_config_dir(environ, home=home) / PROFILES_FILENAME


def display_path(path: Path, *, home: Path | None = None) -> str:
    """Return a compact path, using ``~`` when the file is under the home directory."""
    home_path = home if home is not None else Path.home()
    try:
        return "~/" + path.resolve().relative_to(home_path.resolve()).as_posix()
    except (OSError, ValueError):
        return str(path)


class ProfileStore:
    """Load and save ``profiles.json`` without touching the GUI."""

    def __init__(self, path: Path | None = None, *, config_dir: Path | None = None) -> None:
        if path is not None:
            self._path = path
        elif config_dir is not None:
            self._path = config_dir / PROFILES_FILENAME
        else:
            self._path = default_profiles_path()

    @property
    def path(self) -> Path:
        return self._path

    def load(self) -> ProfilesDocument:
        """Read profiles. Missing or invalid files return an empty document."""
        try:
            text = self._path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return ProfilesDocument(profiles=[])
        except OSError:
            return ProfilesDocument(profiles=[])
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return ProfilesDocument(profiles=[])
        return parse_profiles_document(payload)

    def save(
        self,
        profiles: list[ConnectionProfile],
        *,
        default_profile_id: str | None = None,
    ) -> None:
        """Atomically write profiles as UTF-8 JSON. Creates the directory if needed."""
        known_ids = {profile.id for profile in profiles}
        default_id = default_profile_id if default_profile_id in known_ids else None
        document = {
            "version": SCHEMA_VERSION,
            "default_profile_id": default_id,
            "profiles": [profile.to_json() for profile in profiles],
        }
        text = json.dumps(document, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
        atomic_write_text(self._path, text)


def parse_profiles_document(payload: object) -> ProfilesDocument:
    """Parse a JSON document into profiles, skipping invalid or duplicate ids."""
    records, default_profile_id = _extract_document(payload)
    profiles: list[ConnectionProfile] = []
    seen_ids: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            continue
        profile = _record_to_profile(record)
        if profile is None:
            continue
        if profile.id in seen_ids:
            continue
        seen_ids.add(profile.id)
        profiles.append(profile)
    if default_profile_id not in seen_ids:
        default_profile_id = None
    return ProfilesDocument(profiles=profiles, default_profile_id=default_profile_id)


def _extract_document(payload: object) -> tuple[list[object], str | None]:
    if isinstance(payload, list):
        return payload, None
    if isinstance(payload, dict):
        records = payload.get("profiles", [])
        if not isinstance(records, list):
            records = []
        raw_default = payload.get("default_profile_id")
        default_id = raw_default.strip() if isinstance(raw_default, str) else None
        if not default_id:
            default_id = None
        return records, default_id
    return [], None


def _record_to_profile(record: dict[object, object]) -> ConnectionProfile | None:
    # Secret keys are dropped, not loaded. Unknown fields are ignored.
    cleaned = {
        str(key): value for key, value in record.items() if str(key) not in FORBIDDEN_SECRET_KEYS
    }
    profile_id = cleaned.get("id")
    if not isinstance(profile_id, str) or not profile_id.strip():
        return None
    pin = cleaned.get("trusted_cert_sha256")
    try:
        return build_profile(
            profile_id=profile_id,
            name=cleaned.get("name"),
            gateway=cleaned.get("gateway"),
            port=cleaned.get("port", 443),
            description=cleaned.get("description", ""),
            username_hint=cleaned.get("username_hint", ""),
            use_sso=cleaned.get("use_sso", True),
            trusted_cert_sha256=pin,
        )
    except ProfileValidationError:
        try:
            return build_profile(
                profile_id=profile_id,
                name=cleaned.get("name"),
                gateway=cleaned.get("gateway"),
                port=cleaned.get("port", 443),
                description=cleaned.get("description", ""),
                username_hint=cleaned.get("username_hint", ""),
                use_sso=cleaned.get("use_sso", True),
                trusted_cert_sha256=None,
            )
        except ProfileValidationError:
            return None


def atomic_write_text(path: Path, text: str) -> None:
    """Write *text* to *path* via a temporary file in the same directory."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=".profiles.",
        suffix=".tmp",
        dir=str(path.parent),
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
