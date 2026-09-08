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
    ) -> ConnectionProfile:
        profile = build_profile(
            profile_id=new_profile_id(),
            name=name,
            gateway=gateway,
            port=port,
            description=description,
            username_hint=username_hint,
            use_sso=use_sso,
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
    ) -> ConnectionProfile:
        if self.get(profile_id) is None:
            raise ProfileNotFoundError(profile_id)
        profile = build_profile(
            profile_id=profile_id,
            name=name,
            gateway=gateway,
            port=port,
            description=description,
            username_hint=username_hint,
            use_sso=use_sso,
        )
        self._ensure_unique_name(profile.name, ignore_id=profile_id)
        self._profiles = [profile if item.id == profile_id else item for item in self._profiles]
        self._persist_and_notify()
        return profile

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
