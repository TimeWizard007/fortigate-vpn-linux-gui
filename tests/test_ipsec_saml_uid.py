# SPDX-License-Identifier: GPL-3.0-or-later
"""Persistent IPsec SAML identity (FCT_UID) tests. Synthetic values only."""

from __future__ import annotations

from pathlib import Path

import pytest

from fortigate_vpn_gui.system.ipsec_saml_uid import (
    UID_LENGTH,
    IpsecSamlUidError,
    get_or_create_ipsec_saml_uid,
    validate_ipsec_saml_uid,
)

_FIXTURE_UID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


def test_first_generation_is_32_lowercase_hex(tmp_path: Path) -> None:
    path = tmp_path / "ipsec-saml-uid"
    uid = get_or_create_ipsec_saml_uid(path=path)
    assert len(uid) == UID_LENGTH
    assert uid == uid.lower()
    validate_ipsec_saml_uid(uid)
    assert path.is_file()
    assert (path.stat().st_mode & 0o777) == 0o600


def test_uid_is_persisted_and_reused(tmp_path: Path) -> None:
    path = tmp_path / "ipsec-saml-uid"
    first = get_or_create_ipsec_saml_uid(path=path)
    second = get_or_create_ipsec_saml_uid(path=path)
    assert first == second
    assert path.read_text(encoding="ascii") == first


def test_invalid_uid_is_rejected_not_silently_replaced(tmp_path: Path) -> None:
    path = tmp_path / "ipsec-saml-uid"
    path.write_text("NOT-A-VALID-UID", encoding="ascii")
    with pytest.raises(IpsecSamlUidError, match="invalid"):
        get_or_create_ipsec_saml_uid(path=path)
    assert path.read_text(encoding="ascii") == "NOT-A-VALID-UID"
    path.unlink()
    recovered = get_or_create_ipsec_saml_uid(path=path)
    validate_ipsec_saml_uid(recovered)
    assert recovered != "NOT-A-VALID-UID"


def test_uppercase_hex_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "ipsec-saml-uid"
    path.write_text("A" * UID_LENGTH, encoding="ascii")
    with pytest.raises(IpsecSamlUidError):
        get_or_create_ipsec_saml_uid(path=path)


def test_validate_accepts_fixture_uid() -> None:
    assert validate_ipsec_saml_uid(_FIXTURE_UID) == _FIXTURE_UID


def test_validate_rejects_wrong_length() -> None:
    with pytest.raises(IpsecSamlUidError):
        validate_ipsec_saml_uid("aa")
