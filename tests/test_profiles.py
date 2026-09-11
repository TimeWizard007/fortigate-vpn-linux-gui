# SPDX-License-Identifier: GPL-3.0-or-later
"""Profile model, storage, and manager tests.

These tests use temporary directories only. They must not touch ~/.config,
the network, sudo, or VPN tools.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fortigate_vpn_gui.profiles.manager import ProfileManager
from fortigate_vpn_gui.profiles.model import (
    FORBIDDEN_SECRET_KEYS,
    STORED_FIELDS,
    ProfileNotFoundError,
    ProfileValidationError,
    build_profile,
    unique_copy_name,
)
from fortigate_vpn_gui.profiles.storage import (
    ProfileStore,
    default_config_dir,
    default_profiles_path,
)


def test_valid_profile() -> None:
    profile = build_profile(
        name="Office",
        gateway="vpn.example.com",
        port=443,
        description="HQ",
        username_hint="ada",
        use_sso=True,
    )
    assert profile.name == "Office"
    assert profile.gateway == "vpn.example.com"
    assert profile.port == 443
    assert profile.use_sso is True
    assert profile.id
    assert profile.auth_label() == "SAML / SSO"


def test_valid_ip_gateway() -> None:
    profile = build_profile(name="Lab", gateway="192.0.2.10")
    assert profile.gateway == "192.0.2.10"


def test_gateway_strips_whitespace() -> None:
    profile = build_profile(name="Office", gateway="  vpn.example.com  ")
    assert profile.gateway == "vpn.example.com"


def test_invalid_empty_name() -> None:
    with pytest.raises(ProfileValidationError, match="Profile name is required") as exc:
        build_profile(name="  ", gateway="vpn.example.com")
    assert exc.value.field_errors["name"] == "Profile name is required."
    assert any("name" in error.lower() for error in exc.value.errors)


def test_invalid_empty_gateway() -> None:
    with pytest.raises(ProfileValidationError, match="Gateway is required") as exc:
        build_profile(name="Office", gateway="")
    assert exc.value.field_errors["gateway"] == "Gateway is required."


def test_invalid_gateway_url() -> None:
    with pytest.raises(ProfileValidationError, match="Enter a valid gateway") as exc:
        build_profile(name="Office", gateway="https://vpn.example.com")
    assert exc.value.field_errors["gateway"] == "Enter a valid gateway."


def test_invalid_gateway_with_path() -> None:
    with pytest.raises(ProfileValidationError, match="Enter a valid gateway"):
        build_profile(name="Office", gateway="vpn.example.com/ssl")


def test_port_bounds() -> None:
    assert build_profile(name="Office", gateway="vpn.example.com", port=1).port == 1
    assert build_profile(name="Office", gateway="vpn.example.com", port=65535).port == 65535
    with pytest.raises(ProfileValidationError, match="Port must be between 1 and 65535") as exc:
        build_profile(name="Office", gateway="vpn.example.com", port=0)
    assert exc.value.field_errors["port"] == "Port must be between 1 and 65535."
    with pytest.raises(ProfileValidationError, match="Port must be between 1 and 65535"):
        build_profile(name="Office", gateway="vpn.example.com", port=65536)
    with pytest.raises(ProfileValidationError, match="Port must be between 1 and 65535"):
        build_profile(name="Office", gateway="vpn.example.com", port=True)


def test_save_and_load(tmp_path: Path) -> None:
    manager = ProfileManager(config_dir=tmp_path / "cfg")
    created = manager.add(name="Office", gateway="vpn.example.com", port=8443)
    reloaded = ProfileManager(config_dir=tmp_path / "cfg")
    loaded = reloaded.get(created.id)
    assert loaded is not None
    assert loaded.name == "Office"
    assert loaded.gateway == "vpn.example.com"
    assert loaded.port == 8443


def test_xdg_config_home(tmp_path: Path) -> None:
    environ = {"XDG_CONFIG_HOME": str(tmp_path / "custom-xdg")}
    config_dir = default_config_dir(environ)
    assert config_dir == tmp_path / "custom-xdg" / "fortigate-vpn-linux-gui"
    assert default_profiles_path(environ) == config_dir / "profiles.json"


def test_default_path_uses_home_when_xdg_unset(tmp_path: Path) -> None:
    path = default_profiles_path(environ={}, home=tmp_path)
    assert path == tmp_path / ".config" / "fortigate-vpn-linux-gui" / "profiles.json"


def test_malformed_json_does_not_crash(tmp_path: Path) -> None:
    path = tmp_path / "profiles.json"
    path.write_text("{not-json", encoding="utf-8")
    store = ProfileStore(path)
    assert store.load().profiles == []
    assert store.load().default_profile_id is None


def test_duplicate_ids_keep_first(tmp_path: Path) -> None:
    path = tmp_path / "profiles.json"
    document = {
        "version": 1,
        "profiles": [
            {
                "id": "dup",
                "name": "First",
                "gateway": "one.example",
                "port": 443,
                "use_sso": True,
            },
            {
                "id": "dup",
                "name": "Second",
                "gateway": "two.example",
                "port": 443,
                "use_sso": True,
            },
        ],
    }
    path.write_text(json.dumps(document), encoding="utf-8")
    profiles = ProfileStore(path).load().profiles
    assert len(profiles) == 1
    assert profiles[0].name == "First"


def test_unknown_fields_are_ignored(tmp_path: Path) -> None:
    path = tmp_path / "profiles.json"
    document = {
        "version": 1,
        "profiles": [
            {
                "id": "abc123",
                "name": "Office",
                "gateway": "vpn.example.com",
                "port": 443,
                "use_sso": True,
                "extra_widget": True,
                "password": "should-never-load",
            }
        ],
    }
    path.write_text(json.dumps(document), encoding="utf-8")
    profiles = ProfileStore(path).load().profiles
    assert len(profiles) == 1
    dumped = profiles[0].to_json()
    assert "password" not in dumped
    assert "extra_widget" not in dumped
    assert set(dumped) == set(STORED_FIELDS)


def test_add_update_delete(tmp_path: Path) -> None:
    manager = ProfileManager(config_dir=tmp_path / "cfg")
    profile = manager.add(name="Office", gateway="vpn.example.com")
    assert len(manager.list_profiles()) == 1
    manager.update(profile.id, name="Home", gateway="home.example", port=443)
    updated = manager.get(profile.id)
    assert updated is not None
    assert updated.name == "Home"
    assert manager.delete(profile.id) is True
    assert manager.list_profiles() == ()
    assert manager.delete(profile.id) is False


def test_duplicate_name_rejected(tmp_path: Path) -> None:
    manager = ProfileManager(config_dir=tmp_path / "cfg")
    manager.add(name="Office", gateway="vpn.example.com")
    with pytest.raises(ProfileValidationError, match="already exists") as exc:
        manager.add(name="office", gateway="other.example")
    assert exc.value.field_errors["name"] == "A profile with this name already exists."


def test_update_to_duplicate_name_rejected(tmp_path: Path) -> None:
    manager = ProfileManager(config_dir=tmp_path / "cfg")
    first = manager.add(name="Office", gateway="vpn.example.com")
    second = manager.add(name="Home", gateway="home.example")
    with pytest.raises(ProfileValidationError, match="already exists"):
        manager.update(second.id, name="office", gateway="home.example")
    still = manager.get(first.id)
    assert still is not None
    assert still.name == "Office"


def test_no_secret_fields_stored(tmp_path: Path) -> None:
    manager = ProfileManager(config_dir=tmp_path / "cfg")
    manager.add(name="Office", gateway="vpn.example.com", username_hint="ada")
    raw = json.loads(manager.storage_path.read_text(encoding="utf-8"))
    payload = json.dumps(raw)
    for secret in FORBIDDEN_SECRET_KEYS:
        assert secret not in raw["profiles"][0]
        assert f'"{secret}"' not in payload
    assert "password" not in payload
    assert "token" not in payload
    assert "cookie" not in payload


def test_old_schema_loads_without_trusted_cert(tmp_path: Path) -> None:
    path = tmp_path / "profiles.json"
    document = {
        "version": 1,
        "profiles": [
            {
                "id": "legacy",
                "name": "Office",
                "gateway": "vpn.example.com",
                "port": 443,
                "use_sso": True,
            }
        ],
    }
    path.write_text(json.dumps(document), encoding="utf-8")
    loaded = ProfileStore(path).load()
    assert len(loaded.profiles) == 1
    assert loaded.profiles[0].trusted_cert_sha256 is None
    assert loaded.default_profile_id is None


def test_v071_config_migration_preserves_profiles(tmp_path: Path) -> None:
    path = tmp_path / "cfg" / "profiles.json"
    path.parent.mkdir()
    document = {
        "version": 1,
        "profiles": [
            {
                "id": "legacy-office",
                "name": "Office",
                "gateway": "vpn.example.com",
                "port": 443,
                "description": "HQ",
                "username_hint": "ada",
                "use_sso": True,
            },
            {
                "id": "legacy-lab",
                "name": "Lab",
                "gateway": "192.0.2.10",
                "port": 10443,
                "use_sso": False,
            },
        ],
    }
    path.write_text(json.dumps(document), encoding="utf-8")
    manager = ProfileManager(path=path)
    assert [item.name for item in manager.list_profiles()] == ["Office", "Lab"]
    assert manager.default_profile_id() is None
    office = manager.get("legacy-office")
    assert office is not None
    manager.set_default(office.id)
    raw = json.loads(path.read_text(encoding="utf-8"))
    assert raw["version"] == 1
    assert raw["default_profile_id"] == "legacy-office"
    assert raw["profiles"][0]["name"] == "Office"
    assert raw["profiles"][1]["gateway"] == "192.0.2.10"
    assert "password" not in json.dumps(raw)


def test_default_profile_persistence(tmp_path: Path) -> None:
    manager = ProfileManager(config_dir=tmp_path / "cfg")
    first = manager.add(name="Office", gateway="vpn.example.com")
    second = manager.add(name="Home", gateway="home.example")
    manager.set_default(second.id)
    assert manager.default_profile_id() == second.id
    manager.set_default(first.id)
    assert manager.default_profile_id() == first.id
    reloaded = ProfileManager(config_dir=tmp_path / "cfg")
    assert reloaded.default_profile_id() == first.id
    assert reloaded.is_default(first.id) is True
    assert reloaded.is_default(second.id) is False


def test_deleting_default_clears_default(tmp_path: Path) -> None:
    manager = ProfileManager(config_dir=tmp_path / "cfg")
    first = manager.add(name="Office", gateway="vpn.example.com")
    second = manager.add(name="Home", gateway="home.example")
    manager.set_default(first.id)
    assert manager.delete(first.id) is True
    assert manager.default_profile_id() is None
    assert manager.get(second.id) is not None
    reloaded = ProfileManager(config_dir=tmp_path / "cfg")
    assert reloaded.default_profile_id() is None
    assert len(reloaded.list_profiles()) == 1


def test_set_default_unknown_id(tmp_path: Path) -> None:
    manager = ProfileManager(config_dir=tmp_path / "cfg")
    with pytest.raises(ProfileNotFoundError):
        manager.set_default("missing")


def test_unique_copy_name_collision() -> None:
    names = ["Office", "Office (copy)"]
    assert unique_copy_name("Office", names) == "Office (copy 2)"
    assert unique_copy_name("Office", ["Lab"]) == "Office (copy)"


def test_duplicate_copies_safe_metadata_only(tmp_path: Path) -> None:
    digest = "ab" * 32
    manager = ProfileManager(config_dir=tmp_path / "cfg")
    original = manager.add(
        name="Customer ABC",
        gateway="vpn.example.com",
        port=10443,
        description="Prod",
        username_hint="ada",
        use_sso=False,
        trusted_cert_sha256=digest,
    )
    manager.set_default(original.id)
    copy = manager.duplicate(original.id)
    assert copy.id != original.id
    assert copy.name == "Customer ABC (copy)"
    assert copy.gateway == original.gateway
    assert copy.port == original.port
    assert copy.description == original.description
    assert copy.username_hint == original.username_hint
    assert copy.use_sso is False
    assert copy.trusted_cert_sha256 == digest
    assert manager.is_default(copy.id) is False
    second = manager.duplicate(original.id)
    assert second.name == "Customer ABC (copy 2)"
    raw = json.loads(manager.storage_path.read_text(encoding="utf-8"))
    payload = json.dumps(raw)
    assert "password" not in payload
    assert "token" not in payload
    for record in raw["profiles"]:
        assert "password" not in record


def test_trusted_cert_round_trip(tmp_path: Path) -> None:
    digest = "ab" * 32
    manager = ProfileManager(config_dir=tmp_path / "cfg")
    profile = manager.add(
        name="Office",
        gateway="vpn.example.com",
        trusted_cert_sha256="AB:" * 31 + "AB",
    )
    assert profile.trusted_cert_sha256 == digest
    reloaded = ProfileManager(config_dir=tmp_path / "cfg").get(profile.id)
    assert reloaded is not None
    assert reloaded.trusted_cert_sha256 == digest
    manager.clear_trusted_certificate(profile.id)
    cleared = manager.get(profile.id)
    assert cleared is not None
    assert cleared.trusted_cert_sha256 is None


def test_malformed_fingerprint_rejected_on_build() -> None:
    with pytest.raises(ProfileValidationError, match="SHA-256"):
        build_profile(
            name="Office",
            gateway="vpn.example.com",
            trusted_cert_sha256="not-valid",
        )


def test_malformed_fingerprint_on_load_is_dropped(tmp_path: Path) -> None:
    path = tmp_path / "profiles.json"
    document = {
        "version": 1,
        "profiles": [
            {
                "id": "badpin",
                "name": "Office",
                "gateway": "vpn.example.com",
                "port": 443,
                "use_sso": True,
                "trusted_cert_sha256": "nope",
            }
        ],
    }
    path.write_text(json.dumps(document), encoding="utf-8")
    profiles = ProfileStore(path).load().profiles
    assert len(profiles) == 1
    assert profiles[0].trusted_cert_sha256 is None
