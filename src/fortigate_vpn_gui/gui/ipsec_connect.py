# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared IPsec Connect routing for Connection page, Profiles page, and tray."""

from __future__ import annotations

from PySide6.QtWidgets import QWidget

from fortigate_vpn_gui.gui.ipsec_credentials_dialog import (
    prompt_ipsec_credentials,
    prompt_ipsec_tunnel_psk,
)
from fortigate_vpn_gui.profiles.manager import ProfileManager
from fortigate_vpn_gui.profiles.model import ConnectionProfile
from fortigate_vpn_gui.system.psk_store import PskStore
from fortigate_vpn_gui.vpn.ipsec.secrets import IpsecCredentials


def collect_ipsec_connect_credentials(
    profile: ConnectionProfile,
    *,
    parent: QWidget | None,
    psk_store: PskStore | None,
    manager: ProfileManager | None,
) -> tuple[bool, IpsecCredentials | None]:
    """Return ``(proceed, credentials)`` for an IPsec Connect click.

    IKEv2 SSO/SAML asks only for a missing tunnel PSK. It never opens the
    legacy PSK/XAuth dialog. IKEv1 PSK+XAuth still uses that dialog.
    ``proceed`` is False when the user cancels.
    """
    if not profile.is_ipsec():
        return True, None
    if profile.is_ipsec_saml_preauth():
        credentials = prompt_ipsec_tunnel_psk(
            profile,
            parent=parent,
            psk_store=psk_store,
        )
        if credentials is None:
            return False, None
        return True, credentials
    credentials = prompt_ipsec_credentials(
        profile,
        parent=parent,
        psk_store=psk_store,
        manager=manager,
    )
    if credentials is None:
        return False, None
    return True, credentials
