# SPDX-License-Identifier: GPL-3.0-or-later
"""In-memory profile CRUD with persistence.

This module belongs to the application layer. Qt widgets must call it rather
than reading or writing JSON themselves.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from fortigate_vpn_gui.profiles.model import (
    ConnectionProfile,
    ProfileNotFoundError,
    ProfileValidationError,
    build_profile,
    new_profile_id,
)
from fortigate_vpn_gui.profiles.storage import ProfileStore

_UNSET = object()


class ProfileManager:
    """List, add, update, and delete connection profiles."""

    def __init__(
        self,
        store: ProfileStore | None = None,
        *,
        config_dir: Path | None = None,
        path: Path | None = None,
    ) -> None:
        if store is not None:
            self._store = store
        else:
            self._store = ProfileStore(path=path, config_dir=config_dir)
        self._profiles: list[ConnectionProfile] = []
        self._listeners: list[Callable[[], None]] = []
        self.load()

    @property
    def storage_path(self) -> Path:
        """Filesystem path of ``profiles.json``."""
        return self._store.path

    def add_change_listener(self, callback: Callable[[], None]) -> None:
        """Register a callback invoked after any successful mutating save."""
        self._listeners.append(callback)

    def list_profiles(self) -> tuple[ConnectionProfile, ...]:
        return tuple(self._profiles)

    def get(self, profile_id: str) -> ConnectionProfile | None:
        for profile in self._profiles:
            if profile.id == profile_id:
                return profile
        return None

    def load(self) -> None:
        """Reload from disk. Invalid files become an empty list."""
        self._profiles = list(self._store.load())

    def save(self) -> None:
        """Persist the current list. Creates the config directory if needed."""
        self._store.save(self._profiles)

    def add(
        self,
        *,
        name: object,
        gateway: object,
        port: object = 443,
        description: object = "",
        username_hint: object = "",
        use_sso: object = True,
        trusted_cert_sha256: object = None,
    ) -> ConnectionProfile:
        profile = build_profile(
            profile_id=new_profile_id(),
            name=name,
            gateway=gateway,
            port=port,
            description=description,
            username_hint=username_hint,
            use_sso=use_sso,
            trusted_cert_sha256=trusted_cert_sha256,
        )
        self._ensure_unique_name(profile.name)
        self._profiles.append(profile)
        self._persist_and_notify()
        return profile

    def update(
        self,
        profile_id: str,
        *,
        name: object,
        gateway: object,
        port: object = 443,
        description: object = "",
        username_hint: object = "",
        use_sso: object = True,
        trusted_cert_sha256: object = _UNSET,
    ) -> ConnectionProfile:
        existing = self.get(profile_id)
        if existing is None:
            raise ProfileNotFoundError(profile_id)
        pin = existing.trusted_cert_sha256 if trusted_cert_sha256 is _UNSET else trusted_cert_sha256
        profile = build_profile(
            profile_id=profile_id,
            name=name,
            gateway=gateway,
            port=port,
            description=description,
            username_hint=username_hint,
            use_sso=use_sso,
            trusted_cert_sha256=pin,
        )
        self._ensure_unique_name(profile.name, ignore_id=profile_id)
        self._profiles = [profile if item.id == profile_id else item for item in self._profiles]
        self._persist_and_notify()
        return profile

    def set_trusted_certificate(self, profile_id: str, fingerprint: object) -> ConnectionProfile:
        """Pin a SHA-256 fingerprint on an existing profile."""
        existing = self.get(profile_id)
        if existing is None:
            raise ProfileNotFoundError(profile_id)
        return self.update(
            profile_id,
            name=existing.name,
            gateway=existing.gateway,
            port=existing.port,
            description=existing.description,
            username_hint=existing.username_hint,
            use_sso=existing.use_sso,
            trusted_cert_sha256=fingerprint,
        )

    def clear_trusted_certificate(self, profile_id: str) -> ConnectionProfile:
        """Remove a stored certificate pin."""
        return self.set_trusted_certificate(profile_id, None)

    def delete(self, profile_id: str) -> bool:
        """Remove a profile. Returns False if the id was not present."""
        remaining = [item for item in self._profiles if item.id != profile_id]
        if len(remaining) == len(self._profiles):
            return False
        self._profiles = remaining
        self._persist_and_notify()
        return True

    def _ensure_unique_name(self, name: str, *, ignore_id: str | None = None) -> None:
        needle = name.casefold()
        for item in self._profiles:
            if ignore_id is not None and item.id == ignore_id:
                continue
            if item.name.casefold() == needle:
                raise ProfileValidationError([f'A profile named "{item.name}" already exists.'])

    def _persist_and_notify(self) -> None:
        self.save()
        for listener in list(self._listeners):
            listener()
