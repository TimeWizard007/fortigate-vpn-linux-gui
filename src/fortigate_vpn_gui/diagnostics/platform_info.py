# SPDX-License-Identifier: GPL-3.0-or-later
"""Local platform facts for diagnostics. Does not dump the environment."""

from __future__ import annotations

import os
import platform
from collections.abc import Callable
from pathlib import Path

ReadText = Callable[[str], str]


def read_os_pretty_name(read_text: ReadText | None = None) -> str:
    """Return a short distribution label from ``/etc/os-release`` when present."""
    reader = read_text or _read_text
    try:
        text = reader("/etc/os-release")
    except OSError:
        return platform.system() or "unknown"
    for line in text.splitlines():
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip().strip('"')
    return platform.system() or "unknown"


def kernel_release() -> str:
    """Return the kernel release string."""
    return platform.release() or "unknown"


def architecture() -> str:
    """Return the hardware architecture."""
    return platform.machine() or "unknown"


def desktop_session_type() -> str:
    """Return X11 / Wayland / unknown from the session type only."""
    value = (os.environ.get("XDG_SESSION_TYPE") or "").strip().lower()
    if value in {"x11", "wayland", "tty", "unspecified"}:
        if value == "x11":
            return "X11"
        if value == "wayland":
            return "Wayland"
        return value
    return "unknown"


def _read_text(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")
