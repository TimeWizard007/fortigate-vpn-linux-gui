# SPDX-License-Identifier: GPL-3.0-or-later
"""Create and restore encrypted backups. Never talks to the privileged helper."""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from fortigate_vpn_gui.backup.crypto import decrypt_payload, encrypt_payload
from fortigate_vpn_gui.backup.format import (
    AUTH_FAILURE_MESSAGE,
    BACKUP_EXTENSION,
    CONTAINER_VERSION,
    DEFAULT_KDF_MEMORY_KIB,
    DEFAULT_KDF_PARALLELISM,
    DEFAULT_KDF_TIME,
    MAX_BACKUP_SIZE,
    MIN_PASSWORD_LENGTH,
    PASSWORD_MISMATCH_MESSAGE,
    PASSWORD_TOO_SHORT_MESSAGE,
    PAYLOAD_VERSION,
    RESTORE_FAILED_MESSAGE,
    BackupAuthError,
    BackupError,
    BackupFormatError,
    pack_container,
    unpack_container,
)
from fortigate_vpn_gui.backup.payload import (
    BackupProfile,
    BackupSecrets,
    RestorePlan,
    build_payload_document,
    merged_profiles,
    parse_payload_document,
    payload_has_secrets,
    plan_restore,
)
from fortigate_vpn_gui.profiles.manager import ProfileManager
from fortigate_vpn_gui.profiles.model import ConnectionProfile
from fortigate_vpn_gui.system.psk_store import PskStore, PskStoreError
from fortigate_vpn_gui.vpn.models import CONNECTABLE_STATES, ConnectionState, VpnSnapshot

KEYRING_UNAVAILABLE_MESSAGE = (
    "Secure keyring unavailable. Restore was cancelled so saved IPsec secrets were not left behind."
)
ACTIVE_PROFILE_MESSAGE = (
    "Restore cannot replace a profile that is in use by an active VPN connection. Disconnect first."
)

SaveHook = Callable[[], None]


class RestoreBlockedError(BackupError):
    """Restore refused before any write (keyring, active session, confirmation)."""


@dataclass(frozen=True)
class _SecretSnapshot:
    psk: str | None
    xauth_password: str | None


def validate_backup_password(password: str, confirmation: str | None = None) -> None:
    """Reject short or mismatched backup passwords. Restore does not use this."""
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LENGTH:
        raise BackupError(PASSWORD_TOO_SHORT_MESSAGE)
    if confirmation is not None and password != confirmation:
        raise BackupError(PASSWORD_MISMATCH_MESSAGE)


def create_backup(
    manager: ProfileManager,
    path: Path,
    password: str,
    *,
    confirmation: str | None = None,
    memory_kib: int = DEFAULT_KDF_MEMORY_KIB,
    time_cost: int = DEFAULT_KDF_TIME,
    parallelism: int = DEFAULT_KDF_PARALLELISM,
) -> Path:
    """Write an encrypted backup of all profiles and persisted IPsec secrets."""
    validate_backup_password(password, confirmation)
    profiles = list(manager.list_profiles())
    secrets_map = _collect_secrets(manager.psk_store, profiles)
    document = build_payload_document(
        profiles,
        default_profile_id=manager.default_profile_id(),
        secrets_by_id=secrets_map,
    )
    plaintext = json.dumps(
        document,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    try:
        header, ciphertext = encrypt_payload(
            plaintext,
            password,
            payload_version=PAYLOAD_VERSION,
            container_version=CONTAINER_VERSION,
            memory_kib=memory_kib,
            time_cost=time_cost,
            parallelism=parallelism,
        )
        blob = pack_container(header, ciphertext)
        if len(blob) > MAX_BACKUP_SIZE:
            raise BackupFormatError("The backup file is larger than the 1 MiB limit.")
        written = atomic_write_bytes(path, blob)
    finally:
        plaintext = b""
        for secret in secrets_map.values():
            secret.wipe()
    return written


def preflight_restore(
    manager: ProfileManager,
    path: Path,
    password: str,
    *,
    snapshot: VpnSnapshot | None = None,
) -> RestorePlan:
    """Decrypt and validate. Does not write profiles or secrets."""
    items, default_id = _load_items(path, password)
    try:
        resolved, default_id, rows, replace_ids = plan_restore(
            items,
            existing=list(manager.list_profiles()),
            default_profile_id=default_id,
        )
        has_secrets = payload_has_secrets(resolved)
        if has_secrets and not manager.psk_store.is_available():
            raise RestoreBlockedError(KEYRING_UNAVAILABLE_MESSAGE)
        if _session_blocks_restore(snapshot, replace_ids):
            raise RestoreBlockedError(ACTIVE_PROFILE_MESSAGE)
        return RestorePlan(
            profiles=resolved,
            default_profile_id=default_id,
            rows=rows,
            replace_ids=replace_ids,
            has_secrets=has_secrets,
        )
    except Exception:
        for item in items:
            item.secrets.wipe()
        raise


def restore_backup(
    manager: ProfileManager,
    path: Path,
    password: str,
    *,
    snapshot: VpnSnapshot | None = None,
    plan: RestorePlan | None = None,
    after_profiles_written: SaveHook | None = None,
) -> RestorePlan:
    """Preflight then commit with rollback on any failure."""
    owned_plan = plan is None
    if plan is None:
        plan = preflight_restore(manager, path, password, snapshot=snapshot)
    try:
        _commit_restore(manager, plan, after_profiles_written=after_profiles_written)
    except BackupError:
        plan.wipe()
        raise
    except Exception as exc:
        plan.wipe()
        raise BackupError(RESTORE_FAILED_MESSAGE) from exc
    if owned_plan:
        plan.wipe()
    return plan


def _commit_restore(
    manager: ProfileManager,
    plan: RestorePlan,
    *,
    after_profiles_written: SaveHook | None = None,
) -> None:
    previous_profiles = list(manager.list_profiles())
    previous_default = manager.default_profile_id()
    affected_ids = [item.profile.id for item in plan.profiles]
    secret_snapshot = _snapshot_secrets(manager.psk_store, affected_ids)
    profiles_written = False
    applied: list[tuple[str, str, str | None]] = []
    try:
        merged = merged_profiles(previous_profiles, plan.profiles)
        manager.install_profiles(merged, default_profile_id=plan.default_profile_id)
        profiles_written = True
        if after_profiles_written is not None:
            after_profiles_written()
        _write_secrets(manager.psk_store, plan.profiles, applied)
    except Exception as exc:
        _rollback(
            manager,
            previous_profiles=previous_profiles,
            previous_default=previous_default,
            secret_snapshot=secret_snapshot,
            applied=applied,
            profiles_written=profiles_written,
        )
        if isinstance(exc, BackupError):
            raise
        raise BackupError(RESTORE_FAILED_MESSAGE) from exc


def _write_secrets(
    store: PskStore,
    items: list[BackupProfile],
    applied: list[tuple[str, str, str | None]],
) -> None:
    for item in items:
        profile_id = item.profile.id
        previous_psk = store.get(profile_id)
        previous_xauth = store.get_xauth_password(profile_id)
        try:
            if item.secrets.psk:
                store.set(profile_id, item.secrets.psk)
            else:
                store.delete(profile_id)
            applied.append((profile_id, "psk", previous_psk))
            if item.secrets.xauth_password:
                store.set_xauth_password(profile_id, item.secrets.xauth_password)
            else:
                store.delete_xauth_password(profile_id)
            applied.append((profile_id, "xauth", previous_xauth))
        except PskStoreError as exc:
            raise BackupError(RESTORE_FAILED_MESSAGE) from exc


def _rollback(
    manager: ProfileManager,
    *,
    previous_profiles: list[ConnectionProfile],
    previous_default: str | None,
    secret_snapshot: dict[str, _SecretSnapshot],
    applied: list[tuple[str, str, str | None]],
    profiles_written: bool,
) -> None:
    store = manager.psk_store
    for profile_id, kind, previous in reversed(applied):
        try:
            if kind == "psk":
                if previous:
                    store.set(profile_id, previous)
                else:
                    store.delete(profile_id)
            elif previous:
                store.set_xauth_password(profile_id, previous)
            else:
                store.delete_xauth_password(profile_id)
        except Exception:
            continue
    del secret_snapshot
    if profiles_written:
        try:
            manager.install_profiles(previous_profiles, default_profile_id=previous_default)
        except Exception as exc:
            raise BackupError(RESTORE_FAILED_MESSAGE) from exc


def _load_items(
    path: Path,
    password: str,
) -> tuple[list[BackupProfile], str | None]:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise BackupFormatError("The backup file could not be read.") from exc
    if len(data) > MAX_BACKUP_SIZE:
        raise BackupFormatError("The backup file is larger than the 1 MiB limit.")
    header, ciphertext = unpack_container(data)
    plaintext = decrypt_payload(header, ciphertext, password)
    try:
        payload = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BackupAuthError(AUTH_FAILURE_MESSAGE) from exc
    finally:
        plaintext = b""
    items, default_id = parse_payload_document(payload)
    data = b""
    return items, default_id


def _collect_secrets(
    store: PskStore, profiles: list[ConnectionProfile]
) -> dict[str, BackupSecrets]:
    collected: dict[str, BackupSecrets] = {}
    for profile in profiles:
        psk = store.get(profile.id)
        xauth = store.get_xauth_password(profile.id)
        if psk or xauth:
            collected[profile.id] = BackupSecrets(psk=psk, xauth_password=xauth)
    return collected


def _snapshot_secrets(store: PskStore, profile_ids: list[str]) -> dict[str, _SecretSnapshot]:
    return {
        profile_id: _SecretSnapshot(
            psk=store.get(profile_id),
            xauth_password=store.get_xauth_password(profile_id),
        )
        for profile_id in profile_ids
    }


def _session_blocks_restore(snapshot: VpnSnapshot | None, replace_ids: frozenset[str]) -> bool:
    if snapshot is None or not replace_ids:
        return False
    if snapshot.profile_id not in replace_ids:
        return False
    if snapshot.reconnect_pending or snapshot.manual_reconnect:
        return True
    if snapshot.shutdown_in_progress or snapshot.state is ConnectionState.CLOSING:
        return True
    return snapshot.state not in CONNECTABLE_STATES


def atomic_write_bytes(path: Path, data: bytes, *, mode: int = 0o600) -> Path:
    """Write *data* via a same-directory temp file, mode 0600, then replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=".fvbackup.",
        suffix=".tmp",
        dir=str(path.parent),
    )
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
        os.chmod(path, mode)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    return path


def ensure_backup_suffix(path: Path) -> Path:
    if path.suffix.lower() != BACKUP_EXTENSION:
        return path.with_suffix(BACKUP_EXTENSION)
    return path
