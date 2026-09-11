# SPDX-License-Identifier: GPL-3.0-or-later
"""User-level XDG autostart tests. No root, sudo, or system-wide paths."""

from __future__ import annotations

import stat
from pathlib import Path

import pytest

from fortigate_vpn_gui.desktop.autostart import (
    DESKTOP_FILENAME,
    AutostartError,
    autostart_path,
    build_desktop_entry,
    default_exec_command,
    disable_autostart,
    enable_autostart,
    is_autostart_enabled,
)
from fortigate_vpn_gui.metadata import APP_NAME


def test_enable_and_disable_autostart_desktop_file(tmp_path: Path) -> None:
    config_home = tmp_path / "config"
    command = default_exec_command(executable="/usr/bin/python3")
    path = enable_autostart(config_home=config_home, exec_command=command)
    assert path == config_home / "autostart" / DESKTOP_FILENAME
    assert path.is_file()
    body = path.read_text(encoding="utf-8")
    assert body.startswith("[Desktop Entry]\n")
    assert f"Name={APP_NAME}" in body
    assert "Exec=/usr/bin/python3 -m fortigate_vpn_gui" in body
    assert "Icon=fortigate-vpn-linux-gui" in body
    assert "pkexec" not in body
    assert "sudo" not in body
    assert str(path).startswith(str(config_home))
    assert "/etc/" not in str(path)
    assert is_autostart_enabled(config_home=config_home) is True
    disable_autostart(config_home=config_home)
    assert path.exists() is False
    assert is_autostart_enabled(config_home=config_home) is False


def test_autostart_uses_xdg_config_home(isolate_xdg_config: Path) -> None:
    path = enable_autostart(exec_command=default_exec_command(executable="/usr/bin/python3"))
    assert path.parent == isolate_xdg_config / "autostart"
    assert path.is_relative_to(isolate_xdg_config)


def test_desktop_entry_rejects_newlines() -> None:
    with pytest.raises(AutostartError, match="not safe"):
        build_desktop_entry("/usr/bin/python3\n-c evil")
    with pytest.raises(AutostartError, match="illegal"):
        default_exec_command(executable="/usr/bin/python3\n")


def test_desktop_entry_requires_absolute_interpreter() -> None:
    with pytest.raises(AutostartError, match="absolute"):
        default_exec_command(executable="python3")


def test_unwritable_autostart_destination(tmp_path: Path) -> None:
    config_home = tmp_path / "config"
    blocked = config_home / "autostart"
    blocked.mkdir(parents=True)
    blocked.chmod(stat.S_IRUSR | stat.S_IXUSR)
    try:
        with pytest.raises(AutostartError, match="Could not write"):
            enable_autostart(
                config_home=config_home,
                exec_command=default_exec_command(executable="/usr/bin/python3"),
            )
    finally:
        blocked.chmod(stat.S_IRWXU)


def test_autostart_path_is_user_level(tmp_path: Path) -> None:
    path = autostart_path(tmp_path)
    assert path.name == DESKTOP_FILENAME
    assert "autostart" in path.parts
    assert path.parts[0] != "/etc"


def test_default_exec_prefers_installed_launcher(tmp_path: Path) -> None:
    launcher = tmp_path / "fortigate-vpn-linux-gui"
    launcher.write_text("#!/bin/sh\n", encoding="utf-8")
    launcher.chmod(0o755)
    command = default_exec_command(launcher_path=str(launcher))
    assert command == str(launcher)
    assert "python" not in command
    assert "pkexec" not in command
