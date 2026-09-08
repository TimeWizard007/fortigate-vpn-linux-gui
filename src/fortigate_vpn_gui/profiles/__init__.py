# SPDX-License-Identifier: GPL-3.0-or-later
"""Connection profile management.

Profiles are stored per-user as JSON under the XDG config directory. The file
contains no passwords, SAML tokens, cookies, or other secrets.
"""

from __future__ import annotations

from fortigate_vpn_gui.profiles.manager import ProfileManager
from fortigate_vpn_gui.profiles.model import (
    ConnectionProfile,
    ProfileError,
    ProfileNotFoundError,
    ProfileValidationError,
)
from fortigate_vpn_gui.profiles.storage import (
    default_config_dir,
    default_profiles_path,
    display_path,
)

__all__ = [
    "ConnectionProfile",
    "ProfileError",
    "ProfileManager",
    "ProfileNotFoundError",
    "ProfileValidationError",
    "default_config_dir",
    "default_profiles_path",
    "display_path",
]
