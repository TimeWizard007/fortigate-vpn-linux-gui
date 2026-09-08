# SPDX-License-Identifier: GPL-3.0-or-later
"""System integration.

This package covers Linux host checks that sit outside Qt widgets, and will
later include privileged helpers and polkit rules.

``fortigate_vpn_gui.system.dependencies`` implements the startup preflight
checker. It never installs packages and never invokes sudo or pkexec.

Security constraints:

* The GUI must never run as root.
* Privileged operations must use a minimal helper, not sudo from the GUI.
* The helper should do as little as possible (for example start/stop
  openfortivpn) and should not expose a general root shell.
* Certificate verification must not be silently disabled.
* Package-manager commands shown to users must come from static catalog
  metadata, never from untrusted input, and must not be executed by the app.
"""
