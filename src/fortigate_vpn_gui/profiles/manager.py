# SPDX-License-Identifier: GPL-3.0-or-later
"""In-memory profile CRUD with persistence.

This module belongs to the application layer. Qt widgets must call it rather
than reading or writing JSON themselves.

There is exactly one optional default profile. Deleting it clears the default
instead of silently choosing another profile. Duplicate copies safe metadata
(including the certificate pin) and never copies passwords, tokens,
IPsec pre-shared keys, or stored XAuth passwords.
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
    unique_copy_name,
)
from fortigate_vpn_gui.profiles.storage import ProfileStore
from fortigate_vpn_gui.system.psk_store import PskStore, default_psk_store

_UNSET = object()


class ProfileManager:
    """List, add, update, duplicate, and delete connection profiles."""

    def __init__(
        self,
        store: ProfileStore | None = None,
        *,
        config_dir: Path | None = None,
        path: Path | None = None,
        psk_store: PskStore | None = None,
    ) -> None:
        if store is not None:
            self._store = store
        else:
            self._store = ProfileStore(path=path, config_dir=config_dir)
        self._psk_store = psk_store if psk_store is not None else default_psk_store()
        self._profiles: list[ConnectionProfile] = []
        self._default_profile_id: str | None = None
        self._listeners: list[Callable[[], None]] = []
        self.load()

    @property
    def psk_store(self) -> PskStore:
        """Secret Service (or test) store for IPsec pre-shared keys."""
        return self._psk_store

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

    def default_profile_id(self) -> str | None:
        """Return the id of the explicit default profile, if any."""
        return self._default_profile_id

    def default_profile(self) -> ConnectionProfile | None:
        if self._default_profile_id is None:
            return None
        return self.get(self._default_profile_id)

    def is_default(self, profile_id: str) -> bool:
        return self._default_profile_id == profile_id

    def load(self) -> None:
        """Reload from disk. Invalid files become an empty list."""
        document = self._store.load()
        self._profiles = list(document.profiles)
        default_id = document.default_profile_id
        if default_id is not None and self.get(default_id) is None:
            default_id = None
        self._default_profile_id = default_id

    def save(self) -> None:
        """Persist the current list. Creates the config directory if needed."""
        self._store.save(self._profiles, default_profile_id=self._default_profile_id)

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
        vpn_type: object = "ssl",
        ipsec: object = None,
    ) -> ConnectionProfile:
        profile = self._validated_profile(
            name=name,
            gateway=gateway,
            port=port,
            description=description,
            username_hint=username_hint,
            use_sso=use_sso,
            trusted_cert_sha256=trusted_cert_sha256,
            vpn_type=vpn_type,
            ipsec=ipsec,
        )
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
        vpn_type: object = _UNSET,
        ipsec: object = _UNSET,
    ) -> ConnectionProfile:
        existing = self.get(profile_id)
        if existing is None:
            raise ProfileNotFoundError(profile_id)
        pin = existing.trusted_cert_sha256 if trusted_cert_sha256 is _UNSET else trusted_cert_sha256
        type_value = existing.vpn_type if vpn_type is _UNSET else vpn_type
        ipsec_value = existing.ipsec_payload() if ipsec is _UNSET else ipsec
        profile = self._validated_profile(
            profile_id=profile_id,
            name=name,
            gateway=gateway,
            port=port,
            description=description,
            username_hint=username_hint,
            use_sso=use_sso,
            trusted_cert_sha256=pin,
            vpn_type=type_value,
            ipsec=ipsec_value,
            ignore_id=profile_id,
        )
        self._profiles = [profile if item.id == profile_id else item for item in self._profiles]
        self._persist_and_notify()
        return profile

    def duplicate(self, profile_id: str) -> ConnectionProfile:
        """Copy safe non-secret metadata into a new profile with a unique name.

        The certificate pin is copied because it is a public fingerprint, not a
        credential. Passwords, tokens, and IPsec pre-shared keys are not copied.
        Default status is not copied.
        """
        existing = self.get(profile_id)
        if existing is None:
            raise ProfileNotFoundError(profile_id)
        name = unique_copy_name(existing.name, (item.name for item in self._profiles))
        return self.add(
            name=name,
            gateway=existing.gateway,
            port=existing.port,
            description=existing.description,
            username_hint=existing.username_hint,
            use_sso=existing.use_sso,
            trusted_cert_sha256=existing.trusted_cert_sha256,
            vpn_type=existing.vpn_type,
            ipsec=existing.ipsec_payload(),
        )

    def set_default(self, profile_id: str) -> ConnectionProfile:
        """Mark *profile_id* as the only default profile."""
        existing = self.get(profile_id)
        if existing is None:
            raise ProfileNotFoundError(profile_id)
        if self._default_profile_id == profile_id:
            return existing
        self._default_profile_id = profile_id
        self._persist_and_notify()
        return existing

    def clear_default(self) -> None:
        """Clear the default selection without choosing a replacement."""
        if self._default_profile_id is None:
            return
        self._default_profile_id = None
        self._persist_and_notify()

    def set_username_hint(self, profile_id: str, username_hint: object) -> ConnectionProfile:
        """Update the non-secret username reminder without touching other fields."""
        existing = self.get(profile_id)
        if existing is None:
            raise ProfileNotFoundError(profile_id)
        return self.update(
            profile_id,
            name=existing.name,
            gateway=existing.gateway,
            port=existing.port,
            description=existing.description,
            username_hint=username_hint,
            use_sso=existing.use_sso,
            vpn_type=existing.vpn_type,
            ipsec=existing.ipsec_payload(),
        )

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
        """Remove a profile. Returns False if the id was not present.

        Deleting the default profile clears the default. An active VPN session
        is not disconnected by this method.
        """
        remaining = [item for item in self._profiles if item.id != profile_id]
        if len(remaining) == len(self._profiles):
            return False
        self._profiles = remaining
        if self._default_profile_id == profile_id:
            self._default_profile_id = None
        self._persist_and_notify()
        self._psk_store.delete_all(profile_id)
        return True

    def _validated_profile(
        self,
        *,
        profile_id: str | None = None,
        name: object,
        gateway: object,
        port: object = 443,
        description: object = "",
        username_hint: object = "",
        use_sso: object = True,
        trusted_cert_sha256: object = None,
        vpn_type: object = "ssl",
        ipsec: object = None,
        ignore_id: str | None = None,
    ) -> ConnectionProfile:
        errors: list[str] = []
        field_errors: dict[str, str] = {}
        profile: ConnectionProfile | None = None
        try:
            profile = build_profile(
                profile_id=profile_id if profile_id is not None else new_profile_id(),
                name=name,
                gateway=gateway,
                port=port,
                description=description,
                username_hint=username_hint,
                use_sso=use_sso,
                trusted_cert_sha256=trusted_cert_sha256,
                vpn_type=vpn_type,
                ipsec=ipsec,
            )
        except ProfileValidationError as exc:
            errors.extend(exc.errors)
            field_errors.update(exc.field_errors)
        candidate_name = profile.name if profile is not None else str(name or "").strip()
        if candidate_name:
            try:
                self._ensure_unique_name(candidate_name, ignore_id=ignore_id)
            except ProfileValidationError as exc:
                errors.extend(exc.errors)
                field_errors.update(exc.field_errors)
        if errors or profile is None:
            raise ProfileValidationError(errors, field_errors=field_errors)
        return profile

    def _ensure_unique_name(self, name: str, *, ignore_id: str | None = None) -> None:
        needle = name.casefold()
        for item in self._profiles:
            if ignore_id is not None and item.id == ignore_id:
                continue
            if item.name.casefold() == needle:
                message = "A profile with this name already exists."
                raise ProfileValidationError([message], field_errors={"name": message})

    def _persist_and_notify(self) -> None:
        self.save()
        for listener in list(self._listeners):
            listener()
