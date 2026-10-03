# SPDX-License-Identifier: GPL-3.0-or-later
"""Encrypted backup container tests. Fast KDF parameters only."""

from __future__ import annotations

import json
import struct

import pytest

from fortigate_vpn_gui.backup.crypto import decrypt_payload, encrypt_payload
from fortigate_vpn_gui.backup.format import (
    CONTAINER_VERSION,
    MAGIC,
    MAX_BACKUP_SIZE,
    PAYLOAD_VERSION,
    BackupAuthError,
    BackupFormatError,
    pack_container,
    unpack_container,
)

_FAST = {"memory_kib": 8, "time_cost": 1, "parallelism": 1}
_PASSWORD = "backup-password-ok"


def _pack(plaintext: bytes = b'{"format":"x"}') -> bytes:
    header, ciphertext = encrypt_payload(
        plaintext,
        _PASSWORD,
        payload_version=PAYLOAD_VERSION,
        container_version=CONTAINER_VERSION,
        **_FAST,
    )
    return pack_container(header, ciphertext)


def test_unpack_rejects_bad_magic() -> None:
    blob = _pack()
    damaged = b"XXXXXXXX" + blob[8:]
    with pytest.raises(BackupFormatError, match="not a FortiGate VPN Linux GUI backup"):
        unpack_container(damaged)


def test_unpack_rejects_truncated() -> None:
    with pytest.raises(BackupFormatError, match="truncated"):
        unpack_container(MAGIC + b"\x00")


def test_unpack_rejects_oversized() -> None:
    with pytest.raises(BackupFormatError, match="1 MiB"):
        unpack_container(b"\x00" * (MAX_BACKUP_SIZE + 1))


def test_unpack_rejects_malformed_header() -> None:
    header_bytes = b"{not-json"
    blob = MAGIC + struct.pack(">I", len(header_bytes)) + header_bytes + b"cipher"
    with pytest.raises(BackupFormatError, match="header"):
        unpack_container(blob)


def test_unpack_rejects_unsupported_container_version() -> None:
    header, ciphertext = encrypt_payload(
        b"{}",
        _PASSWORD,
        payload_version=PAYLOAD_VERSION,
        container_version=CONTAINER_VERSION,
        **_FAST,
    )
    header["container_version"] = 99
    blob = pack_container(header, ciphertext)
    with pytest.raises(BackupFormatError, match="format version"):
        unpack_container(blob)


def test_unpack_rejects_unsupported_payload_version() -> None:
    header, ciphertext = encrypt_payload(
        b"{}",
        _PASSWORD,
        payload_version=PAYLOAD_VERSION,
        container_version=CONTAINER_VERSION,
        **_FAST,
    )
    header["payload_version"] = 99
    blob = pack_container(header, ciphertext)
    with pytest.raises(BackupFormatError, match="payload version"):
        unpack_container(blob)


def test_header_has_no_profile_metadata() -> None:
    blob = _pack()
    header, _ciphertext = unpack_container(blob)
    dumped = json.dumps(header)
    for needle in ("vpn.example.com", "Office", "gateway", "psk"):
        assert needle not in dumped


def test_wrong_password_is_unspecific() -> None:
    blob = _pack()
    header, ciphertext = unpack_container(blob)
    with pytest.raises(BackupAuthError, match="Wrong password or the backup file is damaged"):
        decrypt_payload(header, ciphertext, "wrong-password-ok")


def test_corrupted_ciphertext() -> None:
    blob = bytearray(_pack())
    blob[-1] ^= 0x01
    header, ciphertext = unpack_container(bytes(blob))
    with pytest.raises(BackupAuthError, match="Wrong password or the backup file is damaged"):
        decrypt_payload(header, ciphertext, _PASSWORD)


def test_truncated_ciphertext() -> None:
    blob = _pack()
    header, ciphertext = unpack_container(blob)
    with pytest.raises(BackupAuthError):
        decrypt_payload(header, ciphertext[:8], _PASSWORD)
