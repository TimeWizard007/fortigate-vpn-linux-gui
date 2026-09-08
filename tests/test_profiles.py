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
    ProfileValidationError,
    build_profile,
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


def test_invalid_empty_name() -> None:
    with pytest.raises(ProfileValidationError, match="name cannot be empty") as exc:
        build_profile(name="  ", gateway="vpn.example.com")
    assert any("name" in error.lower() for error in exc.value.errors)


def test_invalid_empty_gateway() -> None:
    with pytest.raises(ProfileValidationError, match="Gateway cannot be empty"):
        build_profile(name="Office", gateway="")


def test_invalid_port() -> None:
    with pytest.raises(ProfileValidationError, match="Port must be an integer"):
        build_profile(name="Office", gateway="vpn.example.com", port=0)
    with pytest.raises(ProfileValidationError, match="Port must be an integer"):
        build_profile(name="Office", gateway="vpn.example.com", port=65536)
    with pytest.raises(ProfileValidationError, match="Port must be an integer"):
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
    assert store.load() == []


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
    profiles = ProfileStore(path).load()
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
    profiles = ProfileStore(path).load()
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
    with pytest.raises(ProfileValidationError, match="already exists"):
        manager.add(name="office", gateway="other.example")


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
