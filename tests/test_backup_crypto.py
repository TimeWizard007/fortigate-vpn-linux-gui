# SPDX-License-Identifier: GPL-3.0-or-later
"""Argon2id + AES-GCM backup crypto tests."""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from fortigate_vpn_gui.backup.crypto import decrypt_payload, derive_key, encrypt_payload
from fortigate_vpn_gui.backup.format import (
    CONTAINER_VERSION,
    PAYLOAD_VERSION,
    associated_data,
    canonical_header_bytes,
    pack_container,
    unpack_container,
)

_FAST = {"memory_kib": 8, "time_cost": 1, "parallelism": 1}
_PASSWORD = "backup-password-ok"


def test_round_trip() -> None:
    header, ciphertext = encrypt_payload(
        b"secret-payload",
        _PASSWORD,
        payload_version=PAYLOAD_VERSION,
        container_version=CONTAINER_VERSION,
        **_FAST,
    )
    assert decrypt_payload(header, ciphertext, _PASSWORD) == b"secret-payload"


def test_salt_and_nonce_are_random() -> None:
    first, _ct1 = encrypt_payload(
        b"a",
        _PASSWORD,
        payload_version=PAYLOAD_VERSION,
        container_version=CONTAINER_VERSION,
        **_FAST,
    )
    second, _ct2 = encrypt_payload(
        b"a",
        _PASSWORD,
        payload_version=PAYLOAD_VERSION,
        container_version=CONTAINER_VERSION,
        **_FAST,
    )
    assert first["salt"] != second["salt"]
    assert first["nonce"] != second["nonce"]


def test_header_aad_is_authenticated() -> None:
    header, ciphertext = encrypt_payload(
        b"payload",
        _PASSWORD,
        payload_version=PAYLOAD_VERSION,
        container_version=CONTAINER_VERSION,
        **_FAST,
    )
    key = derive_key(_PASSWORD, header)
    nonce = __import__("base64").b64decode(header["nonce"])
    aesgcm = AESGCM(key)
    aad = associated_data(header)
    assert aad.startswith(b"FVLBKP01")
    aesgcm.decrypt(nonce, ciphertext, aad)
    try:
        aesgcm.decrypt(nonce, ciphertext, canonical_header_bytes(header))
        header_only = True
    except Exception:
        header_only = False
    assert header_only is False
    try:
        aesgcm.decrypt(nonce, ciphertext, aad + b"x")
        raised = False
    except Exception:
        raised = True
    assert raised is True


def test_packed_container_round_trip() -> None:
    header, ciphertext = encrypt_payload(
        b"{}",
        _PASSWORD,
        payload_version=PAYLOAD_VERSION,
        container_version=CONTAINER_VERSION,
        **_FAST,
    )
    blob = pack_container(header, ciphertext)
    parsed, parsed_ct = unpack_container(blob)
    assert parsed == header
    assert parsed_ct == ciphertext
    assert decrypt_payload(parsed, parsed_ct, _PASSWORD) == b"{}"
