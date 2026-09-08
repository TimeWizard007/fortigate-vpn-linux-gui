# SPDX-License-Identifier: GPL-3.0-or-later
"""Future privileged-helper interface.

When implemented, this module should describe how the unprivileged GUI asks a
separate helper to perform operations that require extra rights (typically
via polkit).

This module must not invoke sudo, install systemd units, or modify the host.
v0.1.x contains documentation only.
"""
