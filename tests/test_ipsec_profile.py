# SPDX-License-Identifier: GPL-3.0-or-later
"""IPsec profile backward compatibility, validation, and serialization."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fortigate_vpn_gui.profiles.ipsec import AUTH_PSK_XAUTH, IKE_V2, default_ipsec_settings
from fortigate_vpn_gui.profiles.manager import ProfileManager
from fortigate_vpn_gui.profiles.model import FORBIDDEN_SECRET_KEYS, build_profile
from fortigate_vpn_gui.profiles.storage import ProfileStore


def test_missing_vpn_type_loads_as_ssl(tmp_path: Path) -> None:
    path = tmp_path / "profiles.json"
    path.write_text(
        json.dumps(
            {
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
        ),
        encoding="utf-8",
    )
    loaded = ProfileStore(path).load().profiles[0]
    assert loaded.is_ssl()
    assert loaded.vpn_type == "ssl"
    assert loaded.use_sso is True
    assert loaded.ipsec is None


def test_ipsec_profile_round_trip_excludes_secrets(tmp_path: Path) -> None:
    manager = ProfileManager(config_dir=tmp_path / "cfg")
    created = manager.add(
        name="IPsec office",
        gateway="vpn.example.com",
        port=500,
        vpn_type="ipsec",
        username_hint="ada",
        ipsec=default_ipsec_settings().to_json(),
    )
    assert created.is_ipsec()
    assert created.use_sso is False
    assert created.ipsec is not None
    assert created.ipsec.is_supported()
    raw = json.loads(manager.storage_path.read_text(encoding="utf-8"))
    payload = json.dumps(raw)
    for secret in FORBIDDEN_SECRET_KEYS:
        assert f'"{secret}"' not in payload
    assert raw["profiles"][0]["vpn_type"] == "ipsec"
    assert raw["profiles"][0]["ipsec"]["ike_version"] == "ikev1"
    reloaded = ProfileManager(config_dir=tmp_path / "cfg").get(created.id)
    assert reloaded is not None
    assert reloaded.ipsec is not None
    assert reloaded.ipsec.auth_method == AUTH_PSK_XAUTH


def test_ipsec_duplicate_copies_settings_not_secrets(tmp_path: Path) -> None:
    manager = ProfileManager(config_dir=tmp_path / "cfg")
    original = manager.add(
        name="Tunnel",
        gateway="vpn.example.com",
        port=500,
        vpn_type="ipsec",
        ipsec={**default_ipsec_settings().to_json(), "local_id": "client@example"},
    )
    copy = manager.duplicate(original.id)
    assert copy.is_ipsec()
    assert copy.ipsec is not None
    assert copy.ipsec.local_id == "client@example"
    raw = manager.storage_path.read_text(encoding="utf-8")
    assert '"psk"' not in raw


def test_unsupported_ikev2_can_be_stored_but_is_not_supported() -> None:
    profile = build_profile(
        name="Future",
        gateway="vpn.example.com",
        port=500,
        vpn_type="ipsec",
        ipsec={**default_ipsec_settings().to_json(), "ike_version": IKE_V2, "ike_mode": "main"},
    )
    assert profile.ipsec is not None
    assert profile.ipsec.is_supported() is False


def test_invalid_vpn_type_rejected() -> None:
    from fortigate_vpn_gui.profiles.model import ProfileValidationError

    with pytest.raises(ProfileValidationError, match="VPN type"):
        build_profile(name="Bad", gateway="vpn.example.com", vpn_type="wireguard")


def test_nested_psk_is_stripped_on_load(tmp_path: Path) -> None:
    path = tmp_path / "profiles.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "profiles": [
                    {
                        "id": "dirty",
                        "name": "Tunnel",
                        "gateway": "vpn.example.com",
                        "port": 500,
                        "vpn_type": "ipsec",
                        "psk": "should-not-load",
                        "ipsec": {
                            **default_ipsec_settings().to_json(),
                            "psk": "nested-secret",
                            "password": "hunter2",
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    loaded = ProfileStore(path).load().profiles[0]
    assert loaded.is_ipsec()
    assert loaded.ipsec is not None
    raw = json.dumps(loaded.to_json())
    assert "should-not-load" not in raw
    assert "nested-secret" not in raw
    assert "hunter2" not in raw
