# SPDX-License-Identifier: GPL-3.0-or-later
"""IPsec PSK Secret Service storage. Never writes profiles.json or argv."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fortigate_vpn_gui.profiles.ipsec import default_ipsec_settings
from fortigate_vpn_gui.profiles.manager import ProfileManager
from fortigate_vpn_gui.system.psk_store import (
    MISSING_LIBRARY_MESSAGE,
    PSK_SERVICE_NAME,
    UNAVAILABLE_MESSAGE,
    UNSUPPORTED_BACKEND_MESSAGE,
    XAUTH_PASSWORD_SERVICE_NAME,
    PskStoreError,
    SecretServicePskStore,
    UnavailablePskStore,
    build_psk_store,
)


class FakeSecretService:
    def __init__(self) -> None:
        self.data: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self.data.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.data[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        self.data.pop((service, username), None)


class _FileBackend:
    __module__ = "keyring.backends.file"


class _FailBackend:
    __module__ = "keyring.backends.fail"


class _SecretServiceBackend:
    __module__ = "keyring.backends.SecretService"


class _NullBackend:
    __module__ = "keyring.backends.null"


class _PlaintextBackend:
    __module__ = "keyring.backends.file.plaintext"


class _LibsecretBackend:
    __module__ = "keyring.backends.libsecret"


class FileKeyringApi(FakeSecretService):
    def get_keyring(self) -> object:
        return _FileBackend()


class FailKeyringApi(FakeSecretService):
    def get_keyring(self) -> object:
        return _FailBackend()


class NullKeyringApi(FakeSecretService):
    def get_keyring(self) -> object:
        return _NullBackend()


class PlaintextKeyringApi(FakeSecretService):
    def get_keyring(self) -> object:
        return _PlaintextBackend()


class SecretServiceKeyringApi(FakeSecretService):
    def get_keyring(self) -> object:
        return _SecretServiceBackend()


class LibsecretKeyringApi(FakeSecretService):
    def get_keyring(self) -> object:
        return _LibsecretBackend()


class KeyringLocked(Exception):
    """Stand-in for keyring.errors.KeyringLocked."""


class LockedSecretServiceApi(FakeSecretService):
    def get_keyring(self) -> object:
        return _SecretServiceBackend()

    def get_password(self, service: str, username: str) -> str | None:
        del service, username
        raise KeyringLocked("Failed to unlock the collection!")

    def set_password(self, service: str, username: str, password: str) -> None:
        del service, username, password
        raise KeyringLocked("Failed to unlock the collection!")


def _ipsec_manager(tmp_path: Path, psk_store=None) -> ProfileManager:
    return ProfileManager(config_dir=tmp_path / "cfg", psk_store=psk_store)


def _add_ipsec(manager: ProfileManager, *, name: str = "IPsec office"):
    return manager.add(
        name=name,
        gateway="vpn.example.com",
        port=500,
        vpn_type="ipsec",
        username_hint="mwi",
        ipsec=default_ipsec_settings().to_json(),
    )


def test_secret_service_stores_and_retrieves_by_profile_id() -> None:
    api = FakeSecretService()
    store = SecretServicePskStore(api)
    store.set("profile-stable-id", "tunnel-psk-secret")
    assert store.get("profile-stable-id") == "tunnel-psk-secret"
    assert store.contains("profile-stable-id")
    assert api.data[(PSK_SERVICE_NAME, "profile-stable-id")] == "tunnel-psk-secret"


def test_secret_service_delete_removes_psk() -> None:
    store = SecretServicePskStore(FakeSecretService())
    store.set("pid", "tunnel-psk-secret")
    store.delete("pid")
    assert store.get("pid") is None
    assert store.contains("pid") is False


def test_file_keyring_backend_is_refused() -> None:
    store = SecretServicePskStore(FileKeyringApi())
    assert store.is_available() is False
    with pytest.raises(PskStoreError, match="No supported Secret Service"):
        store.set("pid", "tunnel-psk-secret")
    assert store.get("pid") is None


def test_fail_keyring_backend_is_unavailable() -> None:
    store = SecretServicePskStore(FailKeyringApi())
    assert store.is_available() is False
    with pytest.raises(PskStoreError, match="No supported Secret Service"):
        store.set("pid", "tunnel-psk-secret")


def test_build_psk_store_does_not_fall_back_to_plaintext(monkeypatch) -> None:
    monkeypatch.setattr(
        "fortigate_vpn_gui.system.psk_store._load_secret_service_api",
        lambda: None,
    )
    store = build_psk_store()
    assert isinstance(store, UnavailablePskStore)
    assert store.is_available() is False
    assert store.unavailable_message() == MISSING_LIBRARY_MESSAGE
    assert "requested again at connect time" in store.unavailable_message()
    with pytest.raises(PskStoreError, match="keyring library is not installed"):
        store.set("pid", "tunnel-psk-secret")


def test_psk_never_written_to_profiles_json(tmp_path: Path, psk_store) -> None:
    manager = _ipsec_manager(tmp_path, psk_store)
    profile = _add_ipsec(manager)
    psk_store.set(profile.id, "tunnel-psk-secret")
    raw = manager.storage_path.read_text(encoding="utf-8")
    payload = json.loads(raw)
    dumped = json.dumps(payload)
    assert "tunnel-psk-secret" not in raw
    assert "tunnel-psk-secret" not in dumped
    assert '"psk"' not in dumped
    assert payload["profiles"][0]["username_hint"] == "mwi"
    assert "password" not in payload["profiles"][0]


def test_stored_psk_retrieval_survives_reload(tmp_path: Path, psk_store) -> None:
    manager = _ipsec_manager(tmp_path, psk_store)
    profile = _add_ipsec(manager)
    psk_store.set(profile.id, "tunnel-psk-secret")
    reloaded = ProfileManager(config_dir=tmp_path / "cfg", psk_store=psk_store)
    found = reloaded.get(profile.id)
    assert found is not None
    assert reloaded.psk_store.get(found.id) == "tunnel-psk-secret"
    assert found.username_hint == "mwi"


def test_deleting_profile_removes_stored_psk(tmp_path: Path, psk_store) -> None:
    manager = _ipsec_manager(tmp_path, psk_store)
    profile = _add_ipsec(manager)
    psk_store.set(profile.id, "tunnel-psk-secret")
    assert manager.delete(profile.id) is True
    assert psk_store.get(profile.id) is None
    raw = manager.storage_path.read_text(encoding="utf-8")
    assert "tunnel-psk-secret" not in raw


def test_rename_preserves_psk_association(tmp_path: Path, psk_store) -> None:
    manager = _ipsec_manager(tmp_path, psk_store)
    profile = _add_ipsec(manager, name="Old name")
    psk_store.set(profile.id, "tunnel-psk-secret")
    updated = manager.update(
        profile.id,
        name="New visible name",
        gateway=profile.gateway,
        port=profile.port,
        vpn_type="ipsec",
        username_hint=profile.username_hint,
        ipsec=profile.ipsec_payload(),
    )
    assert updated.id == profile.id
    assert updated.name == "New visible name"
    assert psk_store.get(updated.id) == "tunnel-psk-secret"
    assert psk_store.get("New visible name") is None
    raw = manager.storage_path.read_text(encoding="utf-8")
    assert "tunnel-psk-secret" not in raw
    assert "New visible name" in raw


def test_duplicate_does_not_copy_psk(tmp_path: Path, psk_store) -> None:
    manager = _ipsec_manager(tmp_path, psk_store)
    original = _add_ipsec(manager)
    psk_store.set(original.id, "tunnel-psk-secret")
    copy = manager.duplicate(original.id)
    assert copy.id != original.id
    assert psk_store.get(original.id) == "tunnel-psk-secret"
    assert psk_store.get(copy.id) is None


def test_unavailable_store_does_not_write_plaintext(tmp_path: Path) -> None:
    store = UnavailablePskStore()
    manager = _ipsec_manager(tmp_path, store)
    profile = _add_ipsec(manager)
    with pytest.raises(PskStoreError, match="Secure keyring"):
        store.set(profile.id, "tunnel-psk-secret")
    raw = manager.storage_path.read_text(encoding="utf-8")
    assert "tunnel-psk-secret" not in raw
    assert store.get(profile.id) is None
    assert UNAVAILABLE_MESSAGE in store.unavailable_message()


def test_xauth_username_is_not_the_psk(tmp_path: Path, psk_store) -> None:
    manager = _ipsec_manager(tmp_path, psk_store)
    profile = _add_ipsec(manager)
    psk_store.set(profile.id, "tunnel-psk-secret")
    assert profile.username_hint == "mwi"
    assert profile.username_hint != psk_store.get(profile.id)
    raw = json.loads(manager.storage_path.read_text(encoding="utf-8"))
    assert raw["profiles"][0]["username_hint"] == "mwi"
    assert raw["profiles"][0].get("password") is None
    assert "tunnel-psk-secret" not in json.dumps(raw)


class _ChainerBackend:
    __module__ = "keyring.backends.chainer"

    def __init__(self) -> None:
        self.backends = [_SecretServiceBackend(), _FailBackend()]


class ChainerKeyringApi(FakeSecretService):
    def get_keyring(self) -> object:
        return _ChainerBackend()


def test_chainer_with_secret_service_is_allowed() -> None:
    store = SecretServicePskStore(ChainerKeyringApi())
    assert store.is_available() is True
    store.set("pid", "tunnel-psk-secret")
    assert store.get("pid") == "tunnel-psk-secret"


def test_xauth_password_lifecycle_and_delete_all(tmp_path: Path, psk_store) -> None:
    manager = _ipsec_manager(tmp_path, psk_store)
    profile = _add_ipsec(manager)
    psk_store.set(profile.id, "tunnel-psk-secret")
    psk_store.set_xauth_password(profile.id, "ad-directory-password")
    raw = manager.storage_path.read_text(encoding="utf-8")
    assert "ad-directory-password" not in raw
    manager.update(
        profile.id,
        name="Renamed tunnel",
        gateway=profile.gateway,
        port=profile.port,
        vpn_type="ipsec",
        username_hint=profile.username_hint,
        ipsec=profile.ipsec_payload(),
    )
    assert psk_store.get_xauth_password(profile.id) == "ad-directory-password"
    copy = manager.duplicate(profile.id)
    assert psk_store.get_xauth_password(copy.id) is None
    assert psk_store.get(copy.id) is None
    manager.delete(profile.id)
    assert psk_store.get(profile.id) is None
    assert psk_store.get_xauth_password(profile.id) is None


def test_direct_secret_service_backend_is_accepted() -> None:
    store = SecretServicePskStore(SecretServiceKeyringApi())
    assert store.is_available() is True
    store.set("pid", "tunnel-psk-secret")
    assert store.get("pid") == "tunnel-psk-secret"


def test_libsecret_backend_is_accepted() -> None:
    store = SecretServicePskStore(LibsecretKeyringApi())
    assert store.is_available() is True


def test_chainer_class_backends_property_is_inspected() -> None:
    class _ClassChainer:
        __module__ = "keyring.backends.chainer"
        backends = (_SecretServiceBackend(),)

    class Api(FakeSecretService):
        def get_keyring(self) -> object:
            return _ClassChainer()

    store = SecretServicePskStore(Api())
    assert store.is_available() is True
    store.set("pid", "tunnel-psk-secret")
    assert store.get("pid") == "tunnel-psk-secret"


def test_null_keyring_backend_is_rejected() -> None:
    store = build_psk_store(api=NullKeyringApi())
    assert isinstance(store, UnavailablePskStore)
    assert store.is_available() is False
    assert store.unavailable_message() == UNSUPPORTED_BACKEND_MESSAGE


def test_plaintext_keyring_backend_is_rejected() -> None:
    store = SecretServicePskStore(PlaintextKeyringApi())
    assert store.is_available() is False
    with pytest.raises(PskStoreError, match="No supported Secret Service"):
        store.set("pid", "tunnel-psk-secret")


def test_chainer_with_file_backend_is_rejected() -> None:
    class _InsecureChainer:
        __module__ = "keyring.backends.chainer"

        def __init__(self) -> None:
            self.backends = [_FileBackend(), _SecretServiceBackend()]

    class Api(FakeSecretService):
        def get_keyring(self) -> object:
            return _InsecureChainer()

    store = SecretServicePskStore(Api())
    assert store.is_available() is False


def test_locked_secret_service_keeps_secure_storage_enabled() -> None:
    store = SecretServicePskStore(LockedSecretServiceApi())
    assert store.is_available() is True
    assert store.get("pid") is None
    with pytest.raises(PskStoreError, match="locked"):
        store.set("pid", "tunnel-psk-secret")


def test_psk_and_xauth_use_separate_services() -> None:
    api = SecretServiceKeyringApi()
    store = SecretServicePskStore(api)
    store.set("pid", "tunnel-psk-secret")
    store.set_xauth_password("pid", "ad-directory-password")
    assert api.data[(PSK_SERVICE_NAME, "pid")] == "tunnel-psk-secret"
    assert api.data[(XAUTH_PASSWORD_SERVICE_NAME, "pid")] == "ad-directory-password"
    assert store.get("pid") != store.get_xauth_password("pid")
    store.delete("pid")
    assert store.get("pid") is None
    assert store.get_xauth_password("pid") == "ad-directory-password"
    store.delete_xauth_password("pid")
    assert store.get_xauth_password("pid") is None
