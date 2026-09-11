# SPDX-License-Identifier: GPL-3.0-or-later
"""Project identity: name, URLs, author, and license.

GUI, tray, About, and diagnostics should import from here instead of
duplicating strings.
"""

from __future__ import annotations

from fortigate_vpn_gui import APP_NAME, __version__

PROJECT_URL = "https://github.com/TimeWizard007/fortigate-vpn-linux-gui"
AUTHOR = "TimeWizard007"
LICENSE_SPDX = "GPL-3.0-or-later"
LICENSE_NAME = "GNU General Public License v3.0 or later"
LICENSE_URL = "https://www.gnu.org/licenses/gpl-3.0.html"
PROJECT_DESCRIPTION = (
    "A native Linux desktop client for FortiGate SSL VPN with SAML/SSO "
    "via the system browser."
)
ABOUT_LICENSE_TEXT = (
    "FortiGate VPN Linux GUI is free and open-source software licensed under the "
    "GNU General Public License v3.0 or later.\n\n"
    "You may use, study, modify, and redistribute this software under the terms "
    "of the license.\n\n"
    "This project is independent and is not affiliated with, sponsored by, or "
    "endorsed by Fortinet."
)
HOW_IT_WORKS_TEXT = (
    "SSO profiles sign in with the system browser (for example Microsoft Entra ID "
    "via FortiGate SAML). Connect asks polkit to authorize a privileged helper "
    "that starts openfortivpn. This application stays unprivileged and never runs "
    "as root. Sign-in URL query parameters are never shown in the GUI."
)
CONNECTION_SSO_NOTICE = (
    "SSO profiles open your web browser to sign in. See the About page for how "
    "this works."
)
FORTINET_DISCLAIMER = (
    "This project is independent and is not affiliated with, sponsored by, or "
    "endorsed by Fortinet. Fortinet, FortiGate, and FortiClient are trademarks "
    "of their respective owner(s)."
)

__all__ = [
    "ABOUT_LICENSE_TEXT",
    "APP_NAME",
    "AUTHOR",
    "CONNECTION_SSO_NOTICE",
    "FORTINET_DISCLAIMER",
    "HOW_IT_WORKS_TEXT",
    "LICENSE_NAME",
    "LICENSE_SPDX",
    "LICENSE_URL",
    "PROJECT_DESCRIPTION",
    "PROJECT_URL",
    "__version__",
]
