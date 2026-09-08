# SPDX-License-Identifier: GPL-3.0-or-later
"""Future VPN backend interface.

When implemented, this module should expose a small, testable API for connect,
disconnect, and status queries. The GUI will call that API; it will not spawn
openfortivpn, invoke sudo, or change routes, DNS, or firewall rules itself.

Planned responsibilities:

* Translate UI intents (connect/disconnect) into backend commands.
* Supervise a privileged helper rather than running VPN tools in-process.
* Surface structured status and errors to the GUI.
* Never log passwords, SAML tokens, cookies, or other authentication material.

Nothing in this module is implemented in v0.1.x.
"""
