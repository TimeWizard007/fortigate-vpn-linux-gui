# SPDX-License-Identifier: GPL-3.0-or-later
"""Profile import/export and family-label tests. No network or secrets on disk."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fortigate_vpn_gui.profiles.ipsec import default_ikev2_saml_settings, default_ipsec_settings
from fortigate_vpn_gui.profiles.manager import ProfileManager
from fortigate_vpn_gui.profiles.model import (
    PROFILE_FAMILY_IKEV1,
    PROFILE_FAMILY_IKEV2_SAML,
    PROFILE_FAMILY_SSL,
    VPN_TYPE_IKEV1_LABEL,
    VPN_TYPE_IKEV2_SAML_LABEL,
    VPN_TYPE_SSL_LABEL,
    build_profile,
    unique_imported_name,
)
from fortigate_vpn_gui.profiles.transfer import (
    EXPORT_FORMAT,
    EXPORT_VERSION,
    ProfileTransferError,
    export_profile_document,
    export_profile_json,
    parse_exported_profile,
)

_SYNTHETIC_PSK = "TEST_ONLY_PSK_DO_NOT_USE"
_SYNTHETIC_PASSWORD = "TEST_ONLY_XAUTH_DO_NOT_USE"


def test_profile_families_and_labels() -> None:
    ssl = build_profile(name="SSL", gateway="vpn.example.com", use_sso=True)
    ikev1 = build_profile(
        name="IKEv1",
        gateway="vpn.example.com",
        port=500,
        vpn_type="ipsec",
        ipsec=default_ipsec_settings().to_json(),
    )
    ikev2 = build_profile(
        name="IKEv2",
        gateway="vpn.example.com",
        port=500,
        use_sso=True,
        vpn_type="ipsec",
        ipsec=default_ikev2_saml_settings().to_json(),
    )
    assert ssl.profile_family() == PROFILE_FAMILY_SSL
    assert ssl.vpn_type_label() == VPN_TYPE_SSL_LABEL
    assert ssl.is_connectable() is True
    assert ikev1.profile_family() == PROFILE_FAMILY_IKEV1
    assert ikev1.vpn_type_label() == VPN_TYPE_IKEV1_LABEL
    assert ikev1.is_connectable() is True
    assert ikev2.profile_family() == PROFILE_FAMILY_IKEV2_SAML
    assert ikev2.vpn_type_label() == VPN_TYPE_IKEV2_SAML_LABEL
    assert ikev2.is_connectable() is True
    assert ikev2.auth_label() == "SAML / SSO"


def test_v13_ssl_and_ipsec_fixtures_still_load(tmp_path: Path) -> None:
    path = tmp_path / "profiles.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "profiles": [
                    {
                        "id": "ssl-legacy",
                        "name": "Office SSL",
                        "gateway": "vpn.example.com",
                        "port": 443,
                        "use_sso": True,
                    },
                    {
                        "id": "ikev1-legacy",
                        "name": "Office IKEv1",
                        "gateway": "vpn.example.com",
                        "port": 500,
                        "use_sso": False,
                        "vpn_type": "ipsec",
                        "ipsec": default_ipsec_settings().to_json(),
                    },
                    {
                        "id": "ikev2-legacy",
                        "name": "Office IKEv2",
                        "gateway": "vpn.example.com",
                        "port": 500,
                        "use_sso": True,
                        "vpn_type": "ipsec",
                        "ipsec": default_ikev2_saml_settings().to_json(),
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    manager = ProfileManager(path=path)
    ssl = manager.get("ssl-legacy")
    ikev1 = manager.get("ikev1-legacy")
    ikev2 = manager.get("ikev2-legacy")
    assert ssl is not None and ssl.is_ssl()
    assert ikev1 is not None and ikev1.profile_family() == PROFILE_FAMILY_IKEV1
    assert ikev2 is not None and ikev2.profile_family() == PROFILE_FAMILY_IKEV2_SAML
    raw = path.read_text(encoding="utf-8")
    assert _SYNTHETIC_PSK not in raw
    assert "password" not in json.dumps(json.loads(raw)["profiles"][0])


def test_export_contains_no_secrets(tmp_path: Path, psk_store) -> None:
    manager = ProfileManager(config_dir=tmp_path / "cfg", psk_store=psk_store)
    profile = manager.add(
        name="IPsec office",
        gateway="vpn.example.com",
        port=500,
        username_hint="ada",
        vpn_type="ipsec",
        ipsec=default_ipsec_settings().to_json(),
    )
    psk_store.set(profile.id, _SYNTHETIC_PSK)
    psk_store.set_xauth_password(profile.id, _SYNTHETIC_PASSWORD)
    document = manager.export_profile(profile.id)
    text = export_profile_json(profile)
    assert document["format"] == EXPORT_FORMAT
    assert document["version"] == EXPORT_VERSION
    assert "id" not in document["profile"]
    assert _SYNTHETIC_PSK not in text
    assert _SYNTHETIC_PASSWORD not in text
    folded = text.casefold()
    for needle in ("psk", "password", "tokenid", "fct_uid", "cookie"):
        assert f'"{needle}"' not in folded
    assert psk_store.get(profile.id) == _SYNTHETIC_PSK


def test_import_round_trip_without_secrets(tmp_path: Path, psk_store) -> None:
    manager = ProfileManager(config_dir=tmp_path / "cfg", psk_store=psk_store)
    original = manager.add(
        name="Office",
        gateway="vpn.example.com",
        port=500,
        vpn_type="ipsec",
        ipsec=default_ikev2_saml_settings().to_json(),
        use_sso=True,
    )
    psk_store.set(original.id, _SYNTHETIC_PSK)
    imported = manager.import_profile(export_profile_document(original))
    assert imported.id != original.id
    assert imported.name == "Office (imported)"
    assert imported.gateway == "vpn.example.com"
    assert imported.is_ipsec_saml_preauth() is True
    assert psk_store.get(imported.id) is None
    assert psk_store.get(original.id) == _SYNTHETIC_PSK


def test_import_rejects_plaintext_credentials() -> None:
    with pytest.raises(ProfileTransferError, match="credentials or secrets"):
        parse_exported_profile(
            {
                "format": EXPORT_FORMAT,
                "version": EXPORT_VERSION,
                "profile": {
                    "name": "Bad",
                    "gateway": "vpn.example.com",
                    "vpn_type": "ssl",
                    "password": _SYNTHETIC_PASSWORD,
                },
            }
        )


def test_import_rejects_path_injection() -> None:
    with pytest.raises(ProfileTransferError, match="unsupported configuration"):
        parse_exported_profile(
            {
                "format": EXPORT_FORMAT,
                "version": EXPORT_VERSION,
                "profile": {
                    "name": "Bad",
                    "gateway": "vpn.example.com",
                    "vpn_type": "ipsec",
                    "swanctl": "/etc/swanctl/conf.d/evil.conf",
                },
            }
        )


def test_import_rejects_malformed_and_unknown_type() -> None:
    with pytest.raises(ProfileTransferError, match="not a valid profile export"):
        parse_exported_profile(["not", "an", "object"])
    with pytest.raises(ProfileTransferError, match="not a FortiGate VPN Linux GUI"):
        parse_exported_profile({"format": "other", "version": 1, "profile": {}})
    with pytest.raises(ProfileTransferError, match="version is not supported"):
        parse_exported_profile({"format": EXPORT_FORMAT, "version": 99, "profile": {"name": "X"}})
    with pytest.raises(ProfileTransferError, match="VPN type is not supported"):
        parse_exported_profile(
            {
                "format": EXPORT_FORMAT,
                "version": EXPORT_VERSION,
                "profile": {
                    "name": "Bad",
                    "gateway": "vpn.example.com",
                    "vpn_type": "wireguard",
                },
            }
        )


def test_duplicate_does_not_clone_secrets(tmp_path: Path, psk_store) -> None:
    manager = ProfileManager(config_dir=tmp_path / "cfg", psk_store=psk_store)
    original = manager.add(
        name="Office",
        gateway="vpn.example.com",
        port=500,
        vpn_type="ipsec",
        ipsec=default_ipsec_settings().to_json(),
    )
    psk_store.set(original.id, _SYNTHETIC_PSK)
    copy = manager.duplicate(original.id)
    assert copy.id != original.id
    assert copy.name == "Office (copy)"
    assert psk_store.get(copy.id) is None
    assert psk_store.get_xauth_password(copy.id) is None
    assert psk_store.get(original.id) == _SYNTHETIC_PSK


def test_unique_imported_name_collision() -> None:
    assert unique_imported_name("Office", ["Lab"]) == "Office"
    assert unique_imported_name("Office", ["Office"]) == "Office (imported)"
    assert unique_imported_name("Office", ["Office", "Office (imported)"]) == "Office (imported 2)"
