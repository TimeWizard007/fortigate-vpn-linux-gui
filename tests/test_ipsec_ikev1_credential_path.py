# SPDX-License-Identifier: GPL-3.0-or-later
"""IKEv1 PSK+XAuth credential path: editor save must not stale secrets."""

from __future__ import annotations

import json
from pathlib import Path

from PySide6.QtWidgets import QCheckBox, QComboBox, QLineEdit

from fortigate_vpn_gui.gui.ipsec_connect import collect_ipsec_connect_credentials
from fortigate_vpn_gui.gui.ipsec_credentials_dialog import prompt_ipsec_credentials
from fortigate_vpn_gui.gui.profile_editor_dialog import ProfileEditorDialog
from fortigate_vpn_gui.helper.ike_ports import free_ike_port_report
from fortigate_vpn_gui.helper.protocol import BACKEND_IPSEC, HelperEventKind
from fortigate_vpn_gui.helper.service import HelperService, SwanctlCommandResult
from fortigate_vpn_gui.helper.validation import (
    connect_request_from_fields,
    parse_credentials_payload,
)
from fortigate_vpn_gui.profiles.ipsec import default_ikev2_saml_settings, default_ipsec_settings
from fortigate_vpn_gui.profiles.manager import ProfileManager
from fortigate_vpn_gui.vpn.ipsec.detect import IpsecBackendCapabilities
from fortigate_vpn_gui.vpn.ipsec.secrets import IpsecCredentials, build_swanctl_secrets
from fortigate_vpn_gui.vpn.ipsec.swanctl import build_swanctl_conf
from fortigate_vpn_gui.vpn.log_redaction import redact_log_line
from tests.vpn_fakes import FakeVpnProcess

_PSK = "tunnel-psk-secret"
_XAUTH_PASSWORD = "ad-directory-password"
_USERNAME = "mwi"


def _ikev1_profile(profile_manager: ProfileManager, psk_store, *, extra_ipsec=None):
    settings = default_ipsec_settings().to_json()
    if extra_ipsec:
        settings.update(extra_ipsec)
    profile = profile_manager.add(
        name="slimak_admin",
        gateway="93.105.89.35",
        port=500,
        vpn_type="ipsec",
        username_hint=_USERNAME,
        ipsec=settings,
    )
    psk_store.set(profile.id, _PSK)
    psk_store.set_xauth_password(profile.id, _XAUTH_PASSWORD)
    return profile


def test_ikev1_edit_save_preserves_secrets_username_and_id(
    qapp, profile_manager: ProfileManager, psk_store
) -> None:
    profile = _ikev1_profile(
        profile_manager,
        psk_store,
        extra_ipsec={"local_id": "client@example", "peer_id": "vpn.example.com"},
    )
    profile_id = profile.id
    dialog = ProfileEditorDialog(profile_manager, profile)
    psk_field = dialog.findChild(QLineEdit, "profileIpsecPsk")
    username = dialog.findChild(QLineEdit, "profileUsernameHint")
    remember = dialog.findChild(QCheckBox, "profileRememberUsername")
    assert psk_field is not None and psk_field.text() == ""
    assert username is not None and username.text() == _USERNAME
    assert remember is not None and remember.isChecked()
    assert dialog.submit() is True
    updated = profile_manager.get(profile_id)
    assert updated is not None
    assert updated.id == profile_id
    assert updated.username_hint == _USERNAME
    assert updated.vpn_type == "ipsec"
    assert updated.is_ipsec_saml_preauth() is False
    assert updated.ipsec is not None
    assert updated.ipsec.local_id == "client@example"
    assert updated.ipsec.peer_id == "vpn.example.com"
    assert updated.ipsec.ike_version == "ikev1"
    assert updated.ipsec.ike_mode == "aggressive"
    assert updated.ipsec.auth_method == "psk_xauth"
    assert psk_store.get(profile_id) == _PSK
    assert psk_store.get_xauth_password(profile_id) == _XAUTH_PASSWORD
    raw = profile_manager.storage_path.read_text(encoding="utf-8")
    assert _PSK not in raw
    assert _XAUTH_PASSWORD not in raw


def test_ikev1_blank_secret_fields_keep_stored_secrets(
    qapp, profile_manager: ProfileManager, psk_store
) -> None:
    profile = _ikev1_profile(profile_manager, psk_store)
    dialog = ProfileEditorDialog(profile_manager, profile)
    assert dialog.findChild(QLineEdit, "profileIpsecPsk").text() == ""
    assert dialog.submit() is True
    assert psk_store.get(profile.id) == _PSK
    assert psk_store.get_xauth_password(profile.id) == _XAUTH_PASSWORD


def test_ikev1_ssl_and_back_does_not_wipe_identities_or_secrets(
    qapp, profile_manager: ProfileManager, psk_store
) -> None:
    profile = _ikev1_profile(
        profile_manager,
        psk_store,
        extra_ipsec={"local_id": "client@example", "peer_id": "peer.example"},
    )
    dialog = ProfileEditorDialog(profile_manager, profile)
    vpn_type = dialog.findChild(QComboBox, "profileVpnType")
    assert vpn_type is not None
    vpn_type.setCurrentIndex(0)
    vpn_type.setCurrentIndex(1)
    local_id = dialog.findChild(QLineEdit, "profileLocalId")
    peer_id = dialog.findChild(QLineEdit, "profilePeerId")
    username = dialog.findChild(QLineEdit, "profileUsernameHint")
    assert local_id is not None and local_id.text() == "client@example"
    assert peer_id is not None and peer_id.text() == "peer.example"
    assert username is not None and username.text() == _USERNAME
    assert dialog.submit() is True
    updated = profile_manager.get(profile.id)
    assert updated is not None
    assert updated.id == profile.id
    assert updated.username_hint == _USERNAME
    assert updated.ipsec is not None
    assert updated.ipsec.local_id == "client@example"
    assert updated.ipsec.peer_id == "peer.example"
    assert updated.ipsec.auth_method == "psk_xauth"
    assert psk_store.get(profile.id) == _PSK
    assert psk_store.get_xauth_password(profile.id) == _XAUTH_PASSWORD


def test_ikev1_connect_retrieves_psk_and_xauth_password(
    qapp, profile_manager: ProfileManager, psk_store
) -> None:
    profile = _ikev1_profile(profile_manager, psk_store)
    dialog = ProfileEditorDialog(profile_manager, profile)
    assert dialog.submit() is True
    updated = profile_manager.get(profile.id)
    assert updated is not None
    credentials = prompt_ipsec_credentials(updated, psk_store=psk_store, manager=profile_manager)
    assert credentials is not None
    assert credentials.psk == _PSK
    assert credentials.username == _USERNAME
    assert credentials.password == _XAUTH_PASSWORD
    assert credentials.psk != credentials.password
    proceed, collected = collect_ipsec_connect_credentials(
        updated,
        parent=None,
        psk_store=psk_store,
        manager=profile_manager,
    )
    assert proceed is True
    assert collected is not None
    assert collected.psk == _PSK
    assert collected.username == _USERNAME
    assert collected.password == _XAUTH_PASSWORD


def test_helper_credentials_followup_writes_xauth_selectors(
    tmp_path: Path,
) -> None:
    held: dict[str, FakeVpnProcess] = {}
    events: list[object] = []

    def factory(argv, on_output, on_exit, env=None):
        proc = FakeVpnProcess(argv, on_output, on_exit, env=env)
        held["proc"] = proc
        return proc

    service = HelperService(
        process_factory=factory,
        ipsec_discover=lambda: IpsecBackendCapabilities(
            charon_path="/usr/lib/ipsec/charon",
            swanctl_path="/usr/sbin/swanctl",
            available=True,
            source="test",
        ),
        runtime_dir_factory=lambda: tmp_path / "run",
        swanctl_runner=lambda argv, timeout: SwanctlCommandResult(returncode=0),
        vici_wait=lambda path, timeout: True,
        ike_port_probe=free_ike_port_report,
        listener=events.append,
    )
    (tmp_path / "run").mkdir()
    connect_line = json.dumps(
        {
            "id": "connect",
            "operation": "connect",
            "gateway": "93.105.89.35",
            "port": 500,
            "auth_mode": "standard",
            "backend": BACKEND_IPSEC,
            "ipsec": default_ipsec_settings().to_json(),
        }
    )
    creds_payload = {
        "operation": "credentials",
        "psk": _PSK,
        "username": _USERNAME,
        "password": _XAUTH_PASSWORD,
    }
    parsed = parse_credentials_payload(creds_payload)
    assert parsed.psk != ""
    assert parsed.username == _USERNAME
    assert parsed.password != ""
    service.handle_line(connect_line)
    service.handle_line(json.dumps(creds_payload))
    service.wait_for_ipsec_setup(timeout=2.0)
    secrets = (tmp_path / "run" / "secrets.conf").read_text(encoding="utf-8")
    conf = (tmp_path / "run" / "swanctl.conf").read_text(encoding="utf-8")
    assert "ike-psk" in secrets
    assert "xauth-user" in secrets
    assert f'id = "{_USERNAME}"' in secrets
    assert "eap {" not in secrets
    assert 'xauth_id = "mwi"' in conf
    assert "auth = xauth" in conf
    assert "local-psk" in conf
    assert "version = 1" in conf
    assert "aggressive = yes" in conf
    kinds = [getattr(event, "kind", None) for event in events]
    assert HelperEventKind.CONNECTED in kinds
    logged = " ".join(getattr(event, "line", "") or "" for event in events)
    assert _PSK not in logged
    assert _XAUTH_PASSWORD not in logged
    redacted = redact_log_line(
        f'secret = "{_XAUTH_PASSWORD}" password="{_XAUTH_PASSWORD}" psk="{_PSK}"'
    )
    assert _XAUTH_PASSWORD not in redacted
    assert _PSK not in redacted
    service.disconnect()


def test_generated_secrets_and_swanctl_match_known_good_ikev1() -> None:
    settings = default_ipsec_settings()
    credentials = IpsecCredentials(psk=_PSK, username=_USERNAME, password=_XAUTH_PASSWORD)
    conf = build_swanctl_conf(
        gateway="93.105.89.35",
        port=500,
        settings=settings,
        xauth_id=credentials.username,
    )
    secrets = build_swanctl_secrets(
        credentials,
        local_id=settings.local_id,
        peer_id=settings.peer_id,
        eap=False,
    )
    assert "version = 1" in conf
    assert "aggressive = yes" in conf
    assert "encap = yes" in conf
    assert "vips = 0.0.0.0" in conf
    assert "auth = xauth" in conf
    assert f'xauth_id = "{_USERNAME}"' in conf
    assert "local-eap" not in conf
    assert "cisco_unity" not in conf
    assert "ike-psk" in secrets
    assert "xauth-user" in secrets
    assert f'id = "{_USERNAME}"' in secrets
    assert "eap {" not in secrets
    assert _PSK not in conf
    assert _XAUTH_PASSWORD not in conf


def test_ikev2_saml_secret_handling_unchanged_after_ikev1_edit(
    qapp, profile_manager: ProfileManager, psk_store
) -> None:
    ikev1 = _ikev1_profile(profile_manager, psk_store)
    dialog = ProfileEditorDialog(profile_manager, ikev1)
    assert dialog.submit() is True
    saml = profile_manager.add(
        name="SAML office",
        gateway="vpn.example.com",
        port=500,
        vpn_type="ipsec",
        use_sso=True,
        ipsec=default_ikev2_saml_settings().to_json(),
    )
    psk_store.set(saml.id, _PSK)
    proceed, credentials = collect_ipsec_connect_credentials(
        saml,
        parent=None,
        psk_store=psk_store,
        manager=profile_manager,
    )
    assert proceed is True
    assert credentials is not None
    assert credentials.psk == _PSK
    assert credentials.username == ""
    assert credentials.password == ""
    assert psk_store.get(ikev1.id) == _PSK
    assert psk_store.get_xauth_password(ikev1.id) == _XAUTH_PASSWORD
    assert psk_store.get_xauth_password(saml.id) is None


def test_helper_connect_request_from_saved_ikev1_profile(
    qapp, profile_manager: ProfileManager, psk_store
) -> None:
    profile = _ikev1_profile(
        profile_manager,
        psk_store,
        extra_ipsec={"local_id": "client@example"},
    )
    dialog = ProfileEditorDialog(profile_manager, profile)
    vpn_type = dialog.findChild(QComboBox, "profileVpnType")
    assert vpn_type is not None
    vpn_type.setCurrentIndex(2)
    vpn_type.setCurrentIndex(1)
    assert dialog.submit() is True
    updated = profile_manager.get(profile.id)
    assert updated is not None
    request = connect_request_from_fields(
        gateway=updated.gateway,
        port=updated.port,
        auth_mode="standard",
        backend=BACKEND_IPSEC,
        ipsec=updated.ipsec_payload(),
    )
    assert request.ipsec is not None
    assert request.ipsec["ike_version"] == "ikev1"
    assert request.ipsec["ike_mode"] == "aggressive"
    assert request.ipsec["auth_method"] == "psk_xauth"
    assert request.ipsec["local_id"] == "client@example"
    credentials = prompt_ipsec_credentials(updated, psk_store=psk_store, manager=profile_manager)
    assert credentials is not None
    secrets = build_swanctl_secrets(
        credentials,
        local_id=str(request.ipsec.get("local_id") or ""),
        peer_id=str(request.ipsec.get("peer_id") or ""),
        eap=request.ipsec["auth_method"] == "eap",
    )
    assert "xauth-user" in secrets
    assert f'id = "{_USERNAME}"' in secrets
    assert 'id = "client@example"' in secrets
    assert psk_store.get(updated.id) == _PSK
    assert psk_store.get_xauth_password(updated.id) == _XAUTH_PASSWORD
