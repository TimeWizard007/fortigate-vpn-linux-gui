# SPDX-License-Identifier: GPL-3.0-or-later
"""User-level XDG autostart (.desktop) without root or sudo."""

from __future__ import annotations

import os
import shlex
import sys
from pathlib import Path

from fortigate_vpn_gui.metadata import APP_NAME, PROJECT_DESCRIPTION

DESKTOP_FILENAME = "fortigate-vpn-linux-gui.desktop"


class AutostartError(RuntimeError):
    """Autostart could not be configured. The GUI stays unprivileged."""


def autostart_directory(config_home: str | os.PathLike[str] | None = None) -> Path:
    """Return ``$XDG_CONFIG_HOME/autostart`` (or ``~/.config/autostart``)."""
    if config_home is not None:
        base = Path(config_home)
    else:
        xdg = os.environ.get("XDG_CONFIG_HOME", "").strip()
        base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "autostart"


def autostart_path(config_home: str | os.PathLike[str] | None = None) -> Path:
    return autostart_directory(config_home) / DESKTOP_FILENAME


def is_autostart_enabled(config_home: str | os.PathLike[str] | None = None) -> bool:
    path = autostart_path(config_home)
    return path.is_file()


def default_exec_command(*, executable: str | None = None) -> str:
    """Return a quoted argv suitable for a .desktop Exec= line.

    Uses an absolute interpreter and ``-m fortigate_vpn_gui``. No user-supplied
    extra arguments are interpolated.
    """
    python = executable if executable is not None else sys.executable
    if not python or not os.path.isabs(python):
        raise AutostartError("Cannot determine an absolute Python interpreter path.")
    if any(ch in python for ch in "\n\r"):
        raise AutostartError("Interpreter path contains illegal characters.")
    return f"{shlex.quote(python)} -m fortigate_vpn_gui"


def build_desktop_entry(exec_command: str) -> str:
    """Return a .desktop file body. *exec_command* must already be safe."""
    if not exec_command or any(ch in exec_command for ch in "\n\r"):
        raise AutostartError("Autostart command is not safe to write.")
    comment = PROJECT_DESCRIPTION.replace("\n", " ").strip()
    return (
        "[Desktop Entry]\n"
        "Type=Application\n"
        f"Name={APP_NAME}\n"
        f"Comment={comment}\n"
        f"Exec={exec_command}\n"
        "Terminal=false\n"
        "Categories=Network;\n"
        "X-GNOME-Autostart-enabled=true\n"
        "Hidden=false\n"
    )


def enable_autostart(
    *,
    config_home: str | os.PathLike[str] | None = None,
    exec_command: str | None = None,
) -> Path:
    """Create the user autostart desktop file. Never uses sudo or root paths."""
    command = exec_command if exec_command is not None else default_exec_command()
    body = build_desktop_entry(command)
    directory = autostart_directory(config_home)
    try:
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / DESKTOP_FILENAME
        path.write_text(body, encoding="utf-8")
    except OSError as exc:
        raise AutostartError(f"Could not write autostart file: {exc}") from exc
    return path


def disable_autostart(*, config_home: str | os.PathLike[str] | None = None) -> None:
    """Remove the user autostart desktop file if it exists."""
    path = autostart_path(config_home)
    try:
        if path.is_file():
            path.unlink()
    except OSError as exc:
        raise AutostartError(f"Could not remove autostart file: {exc}") from exc
