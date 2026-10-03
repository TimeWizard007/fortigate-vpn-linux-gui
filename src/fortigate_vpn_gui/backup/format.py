# SPDX-License-Identifier: GPL-3.0-or-later
"""Binary ``*.fvbackup`` container: magic, header, ciphertext.

The unencrypted header holds only cryptographic parameters. Profile names,
gateways, and secrets never appear outside the authenticated ciphertext.
"""

from __future__ import annotations

import base64
import json
import struct
from typing import Any

MAGIC = b"FVLBKP01"
CONTAINER_VERSION = 1
PAYLOAD_VERSION = 1
MAX_BACKUP_SIZE = 1 * 1024 * 1024
MAX_HEADER_SIZE = 8 * 1024
SALT_LENGTH = 32
NONCE_LENGTH = 12
KEY_LENGTH = 32
KDF_NAME = "argon2id"
CIPHER_NAME = "aes-256-gcm"
DEFAULT_KDF_MEMORY_KIB = 65536
DEFAULT_KDF_TIME = 3
DEFAULT_KDF_PARALLELISM = 1
BACKUP_EXTENSION = ".fvbackup"

HEADER_CONTAINER_VERSION = "container_version"
HEADER_KDF = "kdf"
HEADER_KDF_M = "kdf_m"
HEADER_KDF_T = "kdf_t"
HEADER_KDF_P = "kdf_p"
HEADER_SALT = "salt"
HEADER_CIPHER = "cipher"
HEADER_NONCE = "nonce"
HEADER_PAYLOAD_VERSION = "payload_version"

ALLOWED_HEADER_KEYS = frozenset(
    {
        HEADER_CONTAINER_VERSION,
        HEADER_KDF,
        HEADER_KDF_M,
        HEADER_KDF_T,
        HEADER_KDF_P,
        HEADER_SALT,
        HEADER_CIPHER,
        HEADER_NONCE,
        HEADER_PAYLOAD_VERSION,
    }
)

AUTH_FAILURE_MESSAGE = "Wrong password or the backup file is damaged."
RESTORE_FAILED_MESSAGE = "Restore did not finish. Previous profiles were kept."
MIN_PASSWORD_LENGTH = 12
PASSWORD_TOO_SHORT_MESSAGE = (
    f"Choose a backup password of at least {MIN_PASSWORD_LENGTH} characters."
)
PASSWORD_MISMATCH_MESSAGE = "The password and confirmation do not match."


class BackupError(Exception):
    """User-safe backup or restore failure. Messages must not include secrets."""


class BackupAuthError(BackupError):
    """Wrong password or authenticated-data failure. Intentionally unspecific."""

    def __init__(self, message: str = AUTH_FAILURE_MESSAGE) -> None:
        super().__init__(message)


class BackupFormatError(BackupError):
    """Malformed, truncated, oversized, or unsupported backup container."""


def canonical_header_bytes(header: dict[str, Any]) -> bytes:
    """Return deterministic UTF-8 JSON for AAD. Key order is sorted."""
    return json.dumps(
        header,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def associated_data(header: dict[str, Any]) -> bytes:
    """AAD is magic || header-length || exact canonical header bytes."""
    header_bytes = canonical_header_bytes(header)
    if len(header_bytes) > MAX_HEADER_SIZE:
        raise BackupFormatError("Backup header is too large.")
    return MAGIC + struct.pack(">I", len(header_bytes)) + header_bytes


def pack_container(header: dict[str, Any], ciphertext: bytes) -> bytes:
    """Serialize magic + header length + header + ciphertext."""
    return associated_data(header) + ciphertext


def unpack_container(data: bytes) -> tuple[dict[str, Any], bytes]:
    """Parse a container. Rejects oversized or truncated files before KDF."""
    if len(data) > MAX_BACKUP_SIZE:
        raise BackupFormatError("The backup file is larger than the 1 MiB limit.")
    minimum = len(MAGIC) + 4 + 2
    if len(data) < minimum:
        raise BackupFormatError("The backup file is truncated or not a valid backup.")
    if data[: len(MAGIC)] != MAGIC:
        raise BackupFormatError("This file is not a FortiGate VPN Linux GUI backup.")
    (header_len,) = struct.unpack(">I", data[len(MAGIC) : len(MAGIC) + 4])
    if header_len < 2 or header_len > MAX_HEADER_SIZE:
        raise BackupFormatError("Backup header is not valid.")
    header_start = len(MAGIC) + 4
    header_end = header_start + header_len
    if header_end > len(data):
        raise BackupFormatError("The backup file is truncated or not a valid backup.")
    header_bytes = data[header_start:header_end]
    ciphertext = data[header_end:]
    if not ciphertext:
        raise BackupFormatError("The backup file is truncated or not a valid backup.")
    try:
        raw = json.loads(header_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BackupFormatError("Backup header is not valid.") from exc
    header = decode_header_object(raw)
    expected = canonical_header_bytes(header)
    if header_bytes != expected:
        raise BackupFormatError("Backup header is not valid.")
    return header, ciphertext


def decode_header_object(raw: object) -> dict[str, Any]:
    """Validate header JSON. Profile metadata must not appear here."""
    if not isinstance(raw, dict):
        raise BackupFormatError("Backup header is not valid.")
    extra = set(raw) - ALLOWED_HEADER_KEYS
    if extra:
        raise BackupFormatError("Backup header is not valid.")
    missing = ALLOWED_HEADER_KEYS - set(raw)
    if missing:
        raise BackupFormatError("Backup header is not valid.")
    container_version = raw.get(HEADER_CONTAINER_VERSION)
    payload_version = raw.get(HEADER_PAYLOAD_VERSION)
    if container_version != CONTAINER_VERSION:
        raise BackupFormatError("This backup format version is not supported.")
    if payload_version != PAYLOAD_VERSION:
        raise BackupFormatError("This backup payload version is not supported.")
    for key in (HEADER_KDF, HEADER_CIPHER, HEADER_SALT, HEADER_NONCE):
        if not isinstance(raw.get(key), str):
            raise BackupFormatError("Backup header is not valid.")
    for key in (HEADER_KDF_M, HEADER_KDF_T, HEADER_KDF_P):
        if not isinstance(raw.get(key), int) or isinstance(raw.get(key), bool):
            raise BackupFormatError("Backup header is not valid.")
    return {key: raw[key] for key in sorted(ALLOWED_HEADER_KEYS)}


def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64decode_exact(value: str, expected_length: int) -> bytes:
    if not isinstance(value, str) or not value:
        raise BackupFormatError("Backup header is not valid.")
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise BackupFormatError("Backup header is not valid.") from exc
    if len(decoded) != expected_length:
        raise BackupFormatError("Backup header is not valid.")
    return decoded
