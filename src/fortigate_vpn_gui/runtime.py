# SPDX-License-Identifier: GPL-3.0-or-later
"""Process-level runtime checks that do not depend on Qt."""

from __future__ import annotations

import os


def is_running_as_root() -> bool:
    """Return True when the current process has an effective UID of 0."""
    geteuid = getattr(os, "geteuid", None)
    return geteuid is not None and geteuid() == 0
