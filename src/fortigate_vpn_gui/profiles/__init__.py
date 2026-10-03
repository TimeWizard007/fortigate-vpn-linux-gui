# SPDX-License-Identifier: GPL-3.0-or-later
"""Connection profile management.

Profiles are stored per-user as JSON under the XDG config directory. The file
contains no passwords, SAML tokens, cookies, or other secrets.
"""

from __future__ import annotations

from fortigate_vpn_gui.profiles.manager import ProfileManager
from fortigate_vpn_gui.profiles.model import (
    AUTH_PASSWORD_LABEL,
    AUTH_SAML_LABEL,
    PROFILE_FAMILY_IKEV1,
    PROFILE_FAMILY_IKEV2_SAML,
    PROFILE_FAMILY_SSL,
    VPN_TYPE_IKEV1_LABEL,
    VPN_TYPE_IKEV2_SAML_LABEL,
    VPN_TYPE_IPSEC_LABEL,
    VPN_TYPE_SSL_LABEL,
    ConnectionProfile,
    ProfileError,
    ProfileNotFoundError,
    ProfileValidationError,
    auth_mode_label,
    unique_copy_name,
    unique_imported_name,
)
from fortigate_vpn_gui.profiles.storage import (
    ProfilesDocument,
    default_config_dir,
    default_profiles_path,
    display_path,
)
from fortigate_vpn_gui.profiles.transfer import (
    EXPORT_FORMAT,
    EXPORT_VERSION,
    ProfileTransferError,
)

__all__ = [
    "AUTH_PASSWORD_LABEL",
    "AUTH_SAML_LABEL",
    "EXPORT_FORMAT",
    "EXPORT_VERSION",
    "PROFILE_FAMILY_IKEV1",
    "PROFILE_FAMILY_IKEV2_SAML",
    "PROFILE_FAMILY_SSL",
    "VPN_TYPE_IKEV1_LABEL",
    "VPN_TYPE_IKEV2_SAML_LABEL",
    "VPN_TYPE_IPSEC_LABEL",
    "VPN_TYPE_SSL_LABEL",
    "ConnectionProfile",
    "ProfileError",
    "ProfileManager",
    "ProfileNotFoundError",
    "ProfileTransferError",
    "ProfileValidationError",
    "ProfilesDocument",
    "auth_mode_label",
    "default_config_dir",
    "default_profiles_path",
    "display_path",
    "unique_copy_name",
    "unique_imported_name",
]
