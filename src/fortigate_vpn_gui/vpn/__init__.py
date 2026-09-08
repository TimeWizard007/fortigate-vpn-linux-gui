# SPDX-License-Identifier: GPL-3.0-or-later
"""VPN backend package.

This package will eventually host the non-GUI service layer that talks to a
privileged helper, which in turn will run openfortivpn against a FortiGate
SSL VPN gateway.

Intended future flow::

    GUI
      → application/service layer (this package)
        → privileged helper
          → openfortivpn
            → FortiGate SSL VPN

SAML/SSO authentication is expected to use the user's system browser and
Microsoft Entra ID. That work is planned and is not implemented.

This package must not import Qt widgets. v0.1.x contains documentation only.
"""
