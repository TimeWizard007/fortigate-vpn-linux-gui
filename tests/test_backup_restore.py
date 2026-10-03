# SPDX-License-Identifier: GPL-3.0-or-later
"""Backup payload, restore transaction, and filesystem tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fortigate_vpn_gui.backup.format import (
    AUTH_FAILURE_MESSAGE,
    BackupAuthError,
    BackupFormatError,
)
from fortigate_vpn_gui.backup.payload import parse_payload_document
from fortigate_vpn_gui.backup.service import (
    RESTORE_FAILED_MESSAGE,
    RestoreBlockedError,
    create_backup,
    preflight_restore,
    restore_backup,
)
from fortigate_vpn_gui.profiles.ipsec import default_ikev2_saml_settings, default_ipsec_settings
from fortigate_vpn_gui.profiles.manager import ProfileManager
from fortigate_vpn_gui.system.psk_store import MemoryPskStore, PskStoreError, UnavailablePskStore
from fortigate_vpn_gui.vpn.log_redaction import redact_log_line
from fortigate_vpn_gui.vpn.models import ConnectionState, VpnSnapshot

_FAST = {"memory_kib": 8, "time_cost": 1, "parallelism": 1}
_PASSWORD = "backup-password-ok"
_PSK = "TEST_ONLY_BACKUP_PSK_DO_NOT_USE"
_XAUTH = "TEST_ONLY_BACKUP_XAUTH_DO_NOT_USE"


def _manager(
    tmp_path: Path, store: MemoryPskStore | UnavailablePskStore | None = None
) -> ProfileManager:
    return ProfileManager(config_dir=tmp_path / "cfg", psk_store=store or MemoryPskStore())


def _ssl(manager: ProfileManager, name: str = "SSL") -> None:
    manager.add(name=name, gateway="ssl.example.com", use_sso=True)


def _ikev1(manager: ProfileManager, name: str = "IKEv1") -> str:
    profile = manager.add(
        name=name,
        gateway="ikev1.example.com",
        port=500,
        vpn_type="ipsec",
        ipsec=default_ipsec_settings().to_json(),
    )
    return profile.id


def _ikev2(manager: ProfileManager, name: str = "IKEv2") -> str:
    profile = manager.add(
        name=name,
        gateway="ikev2.example.com",
        port=500,
        use_sso=True,
        vpn_type="ipsec",
        ipsec=default_ikev2_saml_settings().to_json(),
    )
    return profile.id


def _snapshot(
    *, profile_id: str, state: ConnectionState = ConnectionState.CONNECTED
) -> VpnSnapshot:
    return VpnSnapshot(
        state=state,
        profile_id=profile_id,
        profile_name="active",
        error_code=None,
        error_message=None,
        process=None,
    )


def test_empty_profile_backup_round_trip(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    path = tmp_path / "empty.fvbackup"
    create_backup(manager, path, _PASSWORD, confirmation=_PASSWORD, **_FAST)
    other = _manager(tmp_path / "other")
    restore_backup(other, path, _PASSWORD)
    assert other.list_profiles() == ()


def test_all_families_with_and_without_secrets(tmp_path: Path) -> None:
    store = MemoryPskStore()
    manager = _manager(tmp_path, store)
    _ssl(manager)
    ikev1_id = _ikev1(manager)
    ikev2_id = _ikev2(manager)
    manager.set_default(ikev1_id)
    store.set(ikev1_id, _PSK)
    store.set_xauth_password(ikev1_id, _XAUTH)
    store.set(ikev2_id, _PSK)
    path = tmp_path / "all.fvbackup"
    create_backup(manager, path, _PASSWORD, confirmation=_PASSWORD, **_FAST)
    data = path.read_bytes()
    assert _PSK.encode() not in data
    assert _XAUTH.encode() not in data
    assert path.stat().st_mode & 0o777 == 0o600
    other_store = MemoryPskStore()
    other = _manager(tmp_path / "b", other_store)
    restore_backup(other, path, _PASSWORD)
    names = {item.name: item for item in other.list_profiles()}
    assert set(names) == {"SSL", "IKEv1", "IKEv2"}
    assert names["SSL"].id == manager.get(manager.list_profiles()[0].id).id
    assert other.default_profile_id() == ikev1_id
    assert other.get(ikev1_id) is not None
    assert other.get(ikev1_id).id == ikev1_id
    assert other_store.get(ikev1_id) == _PSK
    assert other_store.get_xauth_password(ikev1_id) == _XAUTH
    assert other_store.get(ikev2_id) == _PSK
    assert other_store.get_xauth_password(ikev2_id) is None


def test_ssl_profile_has_no_secrets(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    _ssl(manager)
    path = tmp_path / "ssl.fvbackup"
    create_backup(manager, path, _PASSWORD, confirmation=_PASSWORD, **_FAST)
    plan = preflight_restore(manager, path, _PASSWORD)
    assert plan.has_secrets is False
    assert plan.rows[0].has_psk is False


def test_wrong_password_does_not_write(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    _ssl(manager, "Keep")
    path = tmp_path / "x.fvbackup"
    create_backup(manager, path, _PASSWORD, confirmation=_PASSWORD, **_FAST)
    other = _manager(tmp_path / "o")
    other.add(name="Existing", gateway="keep.example.com")
    with pytest.raises(BackupAuthError, match=AUTH_FAILURE_MESSAGE):
        restore_backup(other, path, "wrong-password-ok")
    assert [item.name for item in other.list_profiles()] == ["Existing"]


def test_id_replace_and_name_collision(tmp_path: Path) -> None:
    source_store = MemoryPskStore()
    source = _manager(tmp_path / "src", source_store)
    original = source.add(name="Office", gateway="vpn.example.com")
    source_store.set(original.id, _PSK)
    path = tmp_path / "id.fvbackup"
    create_backup(source, path, _PASSWORD, confirmation=_PASSWORD, **_FAST)

    dest_store = MemoryPskStore()
    dest = _manager(tmp_path / "dst", dest_store)
    dest.add(name="Office", gateway="other.example.com")
    same = dest.add(name="KeepMe", gateway="keep.example.com")
    # Replace by copying the backup profile id onto dest via restore merge:
    # First, give dest a profile with the same id as original by installing.
    from fortigate_vpn_gui.profiles.model import build_profile

    existing_same_id = build_profile(
        profile_id=original.id,
        name="Legacy",
        gateway="legacy.example.com",
    )
    dest.install_profiles([existing_same_id, dest.get(same.id)], default_profile_id=None)
    dest_store.set(original.id, "OLD_PSK_VALUE_NOT_REAL")
    restore_backup(dest, path, _PASSWORD)
    replaced = dest.get(original.id)
    assert replaced is not None
    assert replaced.name == "Office"
    assert replaced.gateway == "vpn.example.com"
    assert dest_store.get(original.id) == _PSK
    assert dest.get(same.id) is not None


def test_name_collision_different_id_renames(tmp_path: Path) -> None:
    source = _manager(tmp_path / "src")
    source.add(name="Office", gateway="src.example.com")
    path = tmp_path / "n.fvbackup"
    create_backup(source, path, _PASSWORD, confirmation=_PASSWORD, **_FAST)
    dest = _manager(tmp_path / "dst")
    dest.add(name="Office", gateway="dst.example.com")
    restore_backup(dest, path, _PASSWORD)
    names = sorted(item.name for item in dest.list_profiles())
    assert "Office" in names
    assert any(name.startswith("Office (restored") for name in names)
    assert len(dest.list_profiles()) == 2


def test_keyring_unavailable_aborts(tmp_path: Path) -> None:
    source_store = MemoryPskStore()
    source = _manager(tmp_path / "src", source_store)
    ike_id = _ikev1(source)
    source_store.set(ike_id, _PSK)
    path = tmp_path / "k.fvbackup"
    create_backup(source, path, _PASSWORD, confirmation=_PASSWORD, **_FAST)
    dest = _manager(tmp_path / "dst", UnavailablePskStore())
    dest.add(name="Keep", gateway="keep.example.com")
    with pytest.raises(RestoreBlockedError, match="Secure keyring unavailable"):
        restore_backup(dest, path, _PASSWORD)
    assert [item.name for item in dest.list_profiles()] == ["Keep"]


def test_active_profile_replace_refused(tmp_path: Path) -> None:
    source = _manager(tmp_path / "src")
    profile = source.add(name="Office", gateway="vpn.example.com")
    path = tmp_path / "a.fvbackup"
    create_backup(source, path, _PASSWORD, confirmation=_PASSWORD, **_FAST)
    dest = _manager(tmp_path / "dst")
    dest.install_profiles([profile], default_profile_id=profile.id)
    with pytest.raises(RestoreBlockedError, match="active VPN"):
        restore_backup(
            dest,
            path,
            _PASSWORD,
            snapshot=_snapshot(profile_id=profile.id),
        )
    assert dest.get(profile.id) is not None


def test_failure_before_commit_leaves_state(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    with pytest.raises(BackupFormatError):
        restore_backup(manager, tmp_path / "missing.fvbackup", _PASSWORD)
    assert manager.list_profiles() == ()


def test_failure_after_profile_write_rolls_back(tmp_path: Path) -> None:
    source_store = MemoryPskStore()
    source = _manager(tmp_path / "src", source_store)
    ike_id = _ikev1(source, "Tunnel")
    source_store.set(ike_id, _PSK)
    path = tmp_path / "f.fvbackup"
    create_backup(source, path, _PASSWORD, confirmation=_PASSWORD, **_FAST)
    dest_store = MemoryPskStore()
    dest = _manager(tmp_path / "dst", dest_store)
    keep = dest.add(name="Keep", gateway="keep.example.com")
    dest_store.set(keep.id, "KEEP_PSK_NOT_REAL")

    def fail() -> None:
        raise PskStoreError("injected keyring failure")

    with pytest.raises(Exception, match=RESTORE_FAILED_MESSAGE):
        restore_backup(dest, path, _PASSWORD, after_profiles_written=fail)
    names = [item.name for item in dest.list_profiles()]
    assert names == ["Keep"]
    assert dest_store.get(keep.id) == "KEEP_PSK_NOT_REAL"
    assert dest_store.get(ike_id) is None


class _FailAfterFirstSet(MemoryPskStore):
    def __init__(self) -> None:
        super().__init__()
        self._sets = 0
        self._fail_once = True

    def set(self, profile_id: str, psk: str) -> None:
        self._sets += 1
        if self._fail_once and self._sets >= 2:
            self._fail_once = False
            raise PskStoreError("injected keyring failure")
        super().set(profile_id, psk)


def test_failure_after_first_secret_rolls_back(tmp_path: Path) -> None:
    source_store = MemoryPskStore()
    source = _manager(tmp_path / "src", source_store)
    first = _ikev1(source, "One")
    second = _ikev1(source, "Two")
    source_store.set(first, _PSK)
    source_store.set(second, _PSK)
    path = tmp_path / "s.fvbackup"
    create_backup(source, path, _PASSWORD, confirmation=_PASSWORD, **_FAST)
    dest_store = _FailAfterFirstSet()
    dest = _manager(tmp_path / "dst", dest_store)
    keep = dest.add(name="Keep", gateway="keep.example.com")
    dest_store.set(keep.id, "KEEP_PSK_NOT_REAL")
    dest_store._sets = 0
    with pytest.raises(Exception, match=RESTORE_FAILED_MESSAGE):
        restore_backup(dest, path, _PASSWORD)
    assert [item.name for item in dest.list_profiles()] == ["Keep"]
    assert dest_store.get(keep.id) == "KEEP_PSK_NOT_REAL"
    assert dest_store.get(first) is None
    assert dest_store.get(second) is None


def test_previous_secret_restored_on_rollback(tmp_path: Path) -> None:
    source_store = MemoryPskStore()
    source = _manager(tmp_path / "src", source_store)
    first = _ikev1(source, "One")
    second = _ikev1(source, "Two")
    source_store.set(first, _PSK)
    source_store.set(second, _PSK)
    path = tmp_path / "p.fvbackup"
    create_backup(source, path, _PASSWORD, confirmation=_PASSWORD, **_FAST)
    dest_store = _FailAfterFirstSet()
    dest = _manager(tmp_path / "dst", dest_store)
    from fortigate_vpn_gui.profiles.model import build_profile

    existing = build_profile(
        profile_id=first,
        name="One",
        gateway="ikev1.example.com",
        port=500,
        vpn_type="ipsec",
        ipsec=default_ipsec_settings().to_json(),
    )
    dest.install_profiles([existing], default_profile_id=None)
    dest_store.set(first, "OLD_PSK_VALUE_NOT_REAL")
    dest_store._sets = 0
    with pytest.raises(Exception, match=RESTORE_FAILED_MESSAGE):
        restore_backup(dest, path, _PASSWORD)
    assert dest_store.get(first) == "OLD_PSK_VALUE_NOT_REAL"


def test_new_secret_deleted_on_rollback(tmp_path: Path) -> None:
    source_store = MemoryPskStore()
    source = _manager(tmp_path / "src", source_store)
    first = _ikev1(source, "One")
    second = _ikev1(source, "Two")
    source_store.set(first, _PSK)
    source_store.set(second, _PSK)
    path = tmp_path / "d.fvbackup"
    create_backup(source, path, _PASSWORD, confirmation=_PASSWORD, **_FAST)
    dest_store = _FailAfterFirstSet()
    dest = _manager(tmp_path / "dst", dest_store)
    dest_store._sets = 0
    with pytest.raises(Exception, match=RESTORE_FAILED_MESSAGE):
        restore_backup(dest, path, _PASSWORD)
    assert dest_store.get(first) is None
    assert dest_store.get(second) is None


def test_short_password_rejected(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    with pytest.raises(Exception, match="at least 12"):
        create_backup(manager, tmp_path / "x.fvbackup", "short", confirmation="short", **_FAST)


def test_password_mismatch_rejected(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    with pytest.raises(Exception, match="do not match"):
        create_backup(
            manager,
            tmp_path / "x.fvbackup",
            _PASSWORD,
            confirmation="backup-password-no",
            **_FAST,
        )


def test_failed_write_removes_temp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    manager = _manager(tmp_path)
    path = tmp_path / "blocked" / "out.fvbackup"

    def boom(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        raise OSError("replace failed")

    monkeypatch.setattr("fortigate_vpn_gui.backup.service.os.replace", boom)
    with pytest.raises(OSError):
        create_backup(manager, path, _PASSWORD, confirmation=_PASSWORD, **_FAST)
    leftover = list(path.parent.glob(".fvbackup.*"))
    assert leftover == []


def test_forbidden_payload_keys() -> None:
    base = {
        "format": "fortigate-vpn-linux-gui-backup",
        "payload_version": 1,
        "profiles": [
            {
                "id": "abc",
                "name": "X",
                "gateway": "vpn.example.com",
                "port": 443,
                "description": "",
                "username_hint": "",
                "use_sso": True,
                "trusted_cert_sha256": None,
                "vpn_type": "ssl",
            }
        ],
    }
    for key, value in (
        ("tokenid", "nope"),
        ("fct_uid", "nope"),
        ("cookies", "nope"),
        ("saml_token", "nope"),
        ("password", "nope"),
        ("ssl_password", "nope"),
        ("eap_identity", "nope"),
        ("eap_password", "nope"),
    ):
        payload = json.loads(json.dumps(base))
        payload["profiles"][0][key] = value
        with pytest.raises(BackupFormatError):
            parse_payload_document(payload)


def test_secrets_allowlist_only() -> None:
    payload = {
        "format": "fortigate-vpn-linux-gui-backup",
        "payload_version": 1,
        "profiles": [
            {
                "id": "abc",
                "name": "X",
                "gateway": "vpn.example.com",
                "port": 443,
                "description": "",
                "username_hint": "",
                "use_sso": True,
                "trusted_cert_sha256": None,
                "vpn_type": "ssl",
                "secrets": {"psk": "x", "tokenid": "nope"},
            }
        ],
    }
    with pytest.raises(BackupFormatError):
        parse_payload_document(payload)


def test_redaction_covers_fixture_secrets() -> None:
    line = redact_log_line(f"password={_XAUTH} psk={_PSK}")
    assert _XAUTH not in line


def test_profiles_json_mode_0600(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    manager.add(name="Office", gateway="vpn.example.com")
    assert manager.storage_path.stat().st_mode & 0o777 == 0o600


def test_backup_modules_do_not_import_helper() -> None:
    import fortigate_vpn_gui.backup as backup
    import fortigate_vpn_gui.backup.crypto as crypto
    import fortigate_vpn_gui.backup.format as fmt
    import fortigate_vpn_gui.backup.payload as payload
    import fortigate_vpn_gui.backup.service as service

    for module in (backup, crypto, fmt, payload, service):
        names = set(module.__dict__)
        assert "helper" not in names
        assert not any(name.startswith("fortigate_vpn_gui.helper") for name in names)
        source = Path(module.__file__).read_text(encoding="utf-8")
        assert "fortigate_vpn_gui.helper" not in source
        assert "pkexec" not in source
        assert "shell=True" not in source
