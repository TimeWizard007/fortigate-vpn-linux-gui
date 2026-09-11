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
    ConnectionProfile,
    ProfileError,
    ProfileNotFoundError,
    ProfileValidationError,
    auth_mode_label,
    unique_copy_name,
)
from fortigate_vpn_gui.profiles.storage import (
    ProfilesDocument,
    default_config_dir,
    default_profiles_path,
    display_path,
)

__all__ = [
    "AUTH_PASSWORD_LABEL",
    "AUTH_SAML_LABEL",
    "ConnectionProfile",
    "ProfileError",
    "ProfileManager",
    "ProfileNotFoundError",
    "ProfileValidationError",
    "ProfilesDocument",
    "auth_mode_label",
    "default_config_dir",
    "default_profiles_path",
    "display_path",
    "unique_copy_name",
]
