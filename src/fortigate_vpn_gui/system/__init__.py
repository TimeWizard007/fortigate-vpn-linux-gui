# SPDX-License-Identifier: GPL-3.0-or-later
"""System integration.

This package covers Linux host checks that sit outside Qt widgets, plus the
unprivileged client for the polkit VPN helper.

``fortigate_vpn_gui.system.dependencies`` implements the startup preflight
checker. It never installs packages and never invokes sudo or pkexec.

Security constraints:

* The GUI must never run as root.
* Privileged operations use a minimal helper via polkit, not sudo from the GUI.
* The helper only starts, stops, and reports VPN status. It is not a root shell.
* Certificate verification must not be silently disabled.
* Package-manager commands shown to users must come from static catalog
  metadata, never from untrusted input, and must not be executed by the app.
"""
