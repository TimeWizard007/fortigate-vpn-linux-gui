# SPDX-License-Identifier: GPL-3.0-or-later
"""Argon2id + AES-256-GCM for encrypted backups.

Uses the maintained ``cryptography`` library. No custom primitives.
"""

from __future__ import annotations

import os
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from fortigate_vpn_gui.backup.format import (
    CIPHER_NAME,
    DEFAULT_KDF_MEMORY_KIB,
    DEFAULT_KDF_PARALLELISM,
    DEFAULT_KDF_TIME,
    HEADER_CIPHER,
    HEADER_CONTAINER_VERSION,
    HEADER_KDF,
    HEADER_KDF_M,
    HEADER_KDF_P,
    HEADER_KDF_T,
    HEADER_NONCE,
    HEADER_PAYLOAD_VERSION,
    HEADER_SALT,
    KDF_NAME,
    KEY_LENGTH,
    NONCE_LENGTH,
    SALT_LENGTH,
    BackupAuthError,
    BackupFormatError,
    associated_data,
    b64decode_exact,
    b64encode,
)

_KDF_MEMORY_MIN = 8
_KDF_MEMORY_MAX = 1024 * 1024
_KDF_TIME_MIN = 1
_KDF_TIME_MAX = 32
_KDF_PARALLEL_MIN = 1
_KDF_PARALLEL_MAX = 4


def new_header(
    *,
    payload_version: int,
    container_version: int,
    memory_kib: int = DEFAULT_KDF_MEMORY_KIB,
    time_cost: int = DEFAULT_KDF_TIME,
    parallelism: int = DEFAULT_KDF_PARALLELISM,
    salt: bytes | None = None,
    nonce: bytes | None = None,
) -> dict[str, Any]:
    """Return a new container header with random salt and nonce."""
    salt_bytes = salt if salt is not None else os.urandom(SALT_LENGTH)
    nonce_bytes = nonce if nonce is not None else os.urandom(NONCE_LENGTH)
    if len(salt_bytes) != SALT_LENGTH:
        raise BackupFormatError("Backup encryption salt is not valid.")
    if len(nonce_bytes) != NONCE_LENGTH:
        raise BackupFormatError("Backup encryption nonce is not valid.")
    _validate_kdf_params(memory_kib, time_cost, parallelism)
    return {
        HEADER_CONTAINER_VERSION: container_version,
        HEADER_KDF: KDF_NAME,
        HEADER_KDF_M: memory_kib,
        HEADER_KDF_T: time_cost,
        HEADER_KDF_P: parallelism,
        HEADER_SALT: b64encode(salt_bytes),
        HEADER_CIPHER: CIPHER_NAME,
        HEADER_NONCE: b64encode(nonce_bytes),
        HEADER_PAYLOAD_VERSION: payload_version,
    }


def encrypt_payload(
    plaintext: bytes,
    password: str,
    *,
    payload_version: int,
    container_version: int,
    memory_kib: int = DEFAULT_KDF_MEMORY_KIB,
    time_cost: int = DEFAULT_KDF_TIME,
    parallelism: int = DEFAULT_KDF_PARALLELISM,
) -> tuple[dict[str, Any], bytes]:
    """Encrypt *plaintext*. Returns ``(header, ciphertext_with_tag)``."""
    header = new_header(
        payload_version=payload_version,
        container_version=container_version,
        memory_kib=memory_kib,
        time_cost=time_cost,
        parallelism=parallelism,
    )
    key = derive_key(password, header)
    try:
        nonce = b64decode_exact(str(header[HEADER_NONCE]), NONCE_LENGTH)
        aad = associated_data(header)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    except BackupFormatError:
        raise
    except Exception as exc:
        raise BackupFormatError("The backup could not be encrypted.") from exc
    finally:
        key = b"\x00" * len(key)
    return header, ciphertext


def decrypt_payload(header: dict[str, Any], ciphertext: bytes, password: str) -> bytes:
    """Decrypt and authenticate *ciphertext*. Fail closed on any crypto error."""
    if not ciphertext:
        raise BackupAuthError()
    try:
        key = derive_key(password, header)
    except BackupFormatError:
        raise
    except BackupAuthError:
        raise
    except Exception:
        raise BackupAuthError() from None
    try:
        nonce = b64decode_exact(str(header[HEADER_NONCE]), NONCE_LENGTH)
        aad = associated_data(header)
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        raise BackupAuthError() from None
    except BackupAuthError:
        raise
    except Exception:
        raise BackupAuthError() from None
    finally:
        key = b"\x00" * len(key)


def derive_key(password: str, header: dict[str, Any]) -> bytes:
    """Derive a 32-byte AES key from *password* and header KDF parameters."""
    if not isinstance(password, str) or not password:
        raise BackupAuthError()
    kdf_name = header.get(HEADER_KDF)
    cipher = header.get(HEADER_CIPHER)
    if kdf_name != KDF_NAME or cipher != CIPHER_NAME:
        raise BackupFormatError("This backup encryption method is not supported.")
    try:
        memory_kib = int(header[HEADER_KDF_M])
        time_cost = int(header[HEADER_KDF_T])
        parallelism = int(header[HEADER_KDF_P])
    except (KeyError, TypeError, ValueError) as exc:
        raise BackupFormatError("Backup encryption parameters are not valid.") from exc
    _validate_kdf_params(memory_kib, time_cost, parallelism)
    salt = b64decode_exact(str(header.get(HEADER_SALT, "")), SALT_LENGTH)
    password_bytes = password.encode("utf-8")
    try:
        kdf = Argon2id(
            salt=salt,
            length=KEY_LENGTH,
            iterations=time_cost,
            lanes=parallelism,
            memory_cost=memory_kib,
        )
        return kdf.derive(password_bytes)
    except BackupFormatError:
        raise
    except Exception as exc:
        raise BackupFormatError("Backup key derivation failed.") from exc
    finally:
        password_bytes = b""


def _validate_kdf_params(memory_kib: int, time_cost: int, parallelism: int) -> None:
    if not _KDF_MEMORY_MIN <= memory_kib <= _KDF_MEMORY_MAX:
        raise BackupFormatError("Backup encryption parameters are not valid.")
    if not _KDF_TIME_MIN <= time_cost <= _KDF_TIME_MAX:
        raise BackupFormatError("Backup encryption parameters are not valid.")
    if not _KDF_PARALLEL_MIN <= parallelism <= _KDF_PARALLEL_MAX:
        raise BackupFormatError("Backup encryption parameters are not valid.")
