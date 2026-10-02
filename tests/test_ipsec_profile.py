# SPDX-License-Identifier: GPL-3.0-or-later
"""IPsec profile backward compatibility, validation, and serialization."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fortigate_vpn_gui.profiles.ipsec import (
    AUTH_PSK_XAUTH,
    IKE_V2,
    CryptoProposal,
    default_ikev2_saml_settings,
    default_ipsec_settings,
    parse_ipsec_settings,
)
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
    assert created.ipsec.required_helper_capabilities() == {"ipsec_ikev1_psk_xauth"}
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


def test_ikev2_eap_sso_persists_without_tokenid(tmp_path: Path) -> None:
    manager = ProfileManager(config_dir=tmp_path / "cfg")
    created = manager.add(
        name="IPsec SAML",
        gateway="vpn.example.com",
        port=500,
        vpn_type="ipsec",
        use_sso=True,
        ipsec={
            **default_ipsec_settings().to_json(),
            "ike_version": IKE_V2,
            "ike_mode": "main",
            "auth_method": "eap",
            "saml_port": 1001,
        },
    )
    assert created.use_sso is True
    assert created.is_ipsec_saml_preauth() is True
    assert created.ipsec is not None
    assert created.ipsec.saml_port == 1001
    assert created.ipsec.is_supported() is True
    assert created.ipsec.required_helper_capabilities() == {"ipsec_ikev2_eap"}
    raw = manager.storage_path.read_text(encoding="utf-8")
    assert "tokenid" not in raw
    assert "cafebabe" not in raw
    reloaded = ProfileManager(config_dir=tmp_path / "cfg").get(created.id)
    assert reloaded is not None
    assert reloaded.use_sso is True
    assert reloaded.ipsec is not None
    assert reloaded.ipsec.saml_port == 1001


def test_legacy_ipsec_json_defaults_saml_port(tmp_path: Path) -> None:
    path = tmp_path / "profiles.json"
    payload = default_ipsec_settings().to_json()
    payload.pop("saml_port", None)
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "profiles": [
                    {
                        "id": "legacy-ipsec",
                        "name": "Tunnel",
                        "gateway": "vpn.example.com",
                        "port": 500,
                        "vpn_type": "ipsec",
                        "use_sso": False,
                        "ipsec": payload,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    loaded = ProfileStore(path).load().profiles[0]
    assert loaded.use_sso is False
    assert loaded.ipsec is not None
    assert loaded.ipsec.saml_port == 1001


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


def test_legacy_singular_phase_fields_migrate_to_one_item_lists() -> None:
    settings = parse_ipsec_settings(
        {
            "ike_version": "ikev1",
            "ike_mode": "aggressive",
            "auth_method": "psk_xauth",
            "address_assignment": "modeconfig",
            "phase1_encryption": "aes128",
            "phase1_integrity": "sha1",
            "dh_group": 5,
            "phase2_encryption": "aes256",
            "phase2_integrity": "sha512",
            "pfs_dh_group": 16,
        }
    )
    assert settings.ike_proposals == (CryptoProposal("aes128", "sha1"),)
    assert settings.ike_dh_groups == (5,)
    assert settings.child_proposals == (CryptoProposal("aes256", "sha512"),)
    assert settings.pfs_dh_groups == (16,)
    assert settings.phase1_encryption == "aes128"
    assert settings.phase1_integrity == "sha1"
    assert settings.dh_group == 5
    assert settings.phase2_encryption == "aes256"
    assert settings.phase2_integrity == "sha512"
    assert settings.pfs_dh_group == 16


def test_proposal_lists_take_precedence_over_singular_fields() -> None:
    settings = parse_ipsec_settings(
        {
            "phase1_encryption": "aes192",
            "phase1_integrity": "sha1",
            "dh_group": 2,
            "phase2_encryption": "aes192",
            "phase2_integrity": "sha1",
            "pfs_dh_group": 2,
            "ike_proposals": [
                {"encryption": "aes128", "integrity": "sha256"},
                {"encryption": "aes256", "integrity": "sha256"},
            ],
            "ike_dh_groups": [20, 21],
            "child_proposals": [
                {"encryption": "aes128", "integrity": "sha1"},
                {"encryption": "aes256", "integrity": "sha256"},
            ],
            "pfs_dh_groups": [20],
        }
    )
    assert settings.ike_proposals == (
        CryptoProposal("aes128", "sha256"),
        CryptoProposal("aes256", "sha256"),
    )
    assert settings.ike_dh_groups == (20, 21)
    assert settings.child_proposals == (
        CryptoProposal("aes128", "sha1"),
        CryptoProposal("aes256", "sha256"),
    )
    assert settings.pfs_dh_groups == (20,)
    dumped = settings.to_json()
    assert dumped["phase1_encryption"] == "aes128"
    assert dumped["dh_group"] == 20
    assert dumped["phase2_encryption"] == "aes128"
    assert dumped["pfs_dh_group"] == 20


def test_multiple_proposals_and_dh_groups_round_trip(tmp_path: Path) -> None:
    manager = ProfileManager(config_dir=tmp_path / "cfg")
    created = manager.add(
        name="Multi proposal",
        gateway="vpn.example.com",
        port=500,
        vpn_type="ipsec",
        ipsec={
            **default_ipsec_settings().to_json(),
            "ike_proposals": [
                {"encryption": "aes128", "integrity": "sha256"},
                {"encryption": "aes256", "integrity": "sha256"},
            ],
            "ike_dh_groups": [20, 21],
            "child_proposals": [
                {"encryption": "aes128", "integrity": "sha1"},
                {"encryption": "aes256", "integrity": "sha256"},
            ],
            "pfs": True,
            "pfs_dh_groups": [20],
        },
    )
    assert created.ipsec is not None
    assert "aes128-sha256-ecp384" in created.ipsec.phase1_proposal()
    assert "aes256-sha256-ecp521" in created.ipsec.phase1_proposal()
    assert "aes128-sha1-ecp384" in created.ipsec.phase2_proposal()
    assert "aes256-sha256-ecp384" in created.ipsec.phase2_proposal()
    raw = json.loads(manager.storage_path.read_text(encoding="utf-8"))
    ipsec = raw["profiles"][0]["ipsec"]
    assert ipsec["ike_dh_groups"] == [20, 21]
    assert ipsec["dh_group"] == 20
    reloaded = ProfileManager(config_dir=tmp_path / "cfg").get(created.id)
    assert reloaded is not None and reloaded.ipsec is not None
    assert reloaded.ipsec.ike_dh_groups == (20, 21)
    assert reloaded.ipsec.child_proposals[0] == CryptoProposal("aes128", "sha1")


def test_loading_legacy_profile_does_not_rewrite_file(tmp_path: Path) -> None:
    path = tmp_path / "profiles.json"
    ipsec = {
        "ike_version": "ikev1",
        "ike_mode": "aggressive",
        "auth_method": "psk_xauth",
        "address_assignment": "modeconfig",
        "local_id": "",
        "peer_id": "",
        "phase1_encryption": "aes256",
        "phase1_integrity": "sha256",
        "dh_group": 14,
        "phase1_lifetime": 86400,
        "phase2_encryption": "aes256",
        "phase2_integrity": "sha256",
        "pfs": True,
        "pfs_dh_group": 14,
        "phase2_lifetime": 43200,
        "nat_traversal": True,
        "dpd": True,
        "dpd_interval": 60,
        "replay_detection": True,
        "local_lan_access": False,
    }
    original = json.dumps(
        {
            "version": 1,
            "profiles": [
                {
                    "id": "legacy-ikev1",
                    "name": "Office IPsec",
                    "gateway": "vpn.example.com",
                    "port": 500,
                    "vpn_type": "ipsec",
                    "use_sso": False,
                    "ipsec": ipsec,
                }
            ],
        },
        indent=2,
        sort_keys=True,
    )
    path.write_text(original + "\n", encoding="utf-8")
    before = path.read_text(encoding="utf-8")
    loaded = ProfileStore(path).load().profiles[0]
    assert path.read_text(encoding="utf-8") == before
    assert "ike_proposals" not in json.loads(before)["profiles"][0]["ipsec"]
    assert loaded.ipsec is not None
    assert loaded.ipsec.ike_version == "ikev1"
    assert loaded.ipsec.ike_mode == "aggressive"
    assert loaded.ipsec.auth_method == AUTH_PSK_XAUTH
    assert loaded.ipsec.is_supported() is True
    assert loaded.ipsec.ike_proposals == (CryptoProposal("aes256", "sha256"),)
    assert loaded.requires_ipsec_connect_credentials() is True


def test_new_ikev2_saml_defaults_do_not_change_legacy_defaults() -> None:
    legacy = default_ipsec_settings()
    saml = default_ikev2_saml_settings()
    assert legacy.ike_version == "ikev1"
    assert legacy.ike_mode == "aggressive"
    assert legacy.auth_method == AUTH_PSK_XAUTH
    assert legacy.dh_group == 14
    assert legacy.ike_proposals == (CryptoProposal("aes256", "sha256"),)
    assert saml.ike_version == IKE_V2
    assert saml.auth_method == "eap"
    assert saml.ike_proposals == (
        CryptoProposal("aes128", "sha256"),
        CryptoProposal("aes256", "sha256"),
    )
    assert saml.ike_dh_groups == (20, 21)
    assert saml.child_proposals == (
        CryptoProposal("aes128", "sha1"),
        CryptoProposal("aes256", "sha256"),
    )
    assert saml.pfs is True
    assert saml.pfs_dh_groups == (20,)
    assert saml.phase1_lifetime == 86400
    assert saml.phase2_lifetime == 43200
    assert saml.nat_traversal is True
    assert saml.dpd is True
    assert saml.replay_detection is True
    assert saml.saml_port == 1001
    assert saml.allows_saml_preauth() is True
    assert legacy.allows_saml_preauth() is False
