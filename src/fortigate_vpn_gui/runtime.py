# SPDX-License-Identifier: GPL-3.0-or-later
"""Process-level runtime checks that do not depend on Qt."""

from __future__ import annotations

import os

_LAUNCHER_WINDOW_ENV = ("DESKTOP_STARTUP_ID", "XDG_ACTIVATION_TOKEN")


def is_running_as_root() -> bool:
    """Return True when the current process has an effective UID of 0."""
    geteuid = getattr(os, "geteuid", None)
    return geteuid is not None and geteuid() == 0


def detach_from_launcher_window() -> None:
    """Drop inherited startup tokens that can group this window with the launcher.

    When the GUI is started from another desktop app (editor, terminal), some
    compositors treat ``DESKTOP_STARTUP_ID`` / ``XDG_ACTIVATION_TOKEN`` as a
    transient relationship. Clearing them keeps this process an independent
    top-level window. Does not enable always-on-top.
    """
    for key in _LAUNCHER_WINDOW_ENV:
        os.environ.pop(key, None)
