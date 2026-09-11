# SPDX-License-Identifier: GPL-3.0-or-later
"""Packaging metadata and production path tests. No network, no dpkg install."""

from __future__ import annotations

import configparser
from pathlib import Path

from fortigate_vpn_gui import __version__
from fortigate_vpn_gui.helper.protocol import (
    APPROVED_OPENFORTIVPN_PATHS,
    HELPER_VERSION,
    INSTALLED_HELPER_PATH,
    PACKAGE_OPENFORTIVPN_PATH,
    POLKIT_ACTION_ID,
)
from fortigate_vpn_gui.metadata import (
    DESKTOP_FILENAME,
    ICON_NAME,
    INSTALLED_LAUNCHER_PATH,
    LAUNCHER_NAME,
)

ROOT = Path(__file__).resolve().parents[1]


def test_application_version_is_1_0_0() -> None:
    assert __version__ == "1.0.0"


def test_helper_protocol_remains_0_7_0() -> None:
    assert HELPER_VERSION == "0.7.0"


def test_production_helper_path() -> None:
    assert INSTALLED_HELPER_PATH == "/usr/libexec/fortigate-vpn-linux-gui/vpn-helper"
    assert PACKAGE_OPENFORTIVPN_PATH == "/usr/libexec/fortigate-vpn-linux-gui/openfortivpn"
    assert APPROVED_OPENFORTIVPN_PATHS[0] == PACKAGE_OPENFORTIVPN_PATH


def test_production_launcher_path() -> None:
    assert LAUNCHER_NAME == "fortigate-vpn-linux-gui"
    assert INSTALLED_LAUNCHER_PATH == "/usr/bin/fortigate-vpn-linux-gui"
    assert not INSTALLED_LAUNCHER_PATH.startswith("/home/")


def test_desktop_entry_static_content() -> None:
    path = ROOT / "packaging" / "desktop" / DESKTOP_FILENAME
    body = path.read_text(encoding="utf-8")
    parser = configparser.ConfigParser(interpolation=None)
    parser.read_string(body)
    entry = parser["Desktop Entry"]
    assert entry["Type"] == "Application"
    assert entry["Name"] == "FortiGate VPN Linux GUI"
    assert entry["Exec"] == LAUNCHER_NAME
    assert entry["TryExec"] == LAUNCHER_NAME
    assert entry["Icon"] == ICON_NAME
    assert entry["Terminal"] == "false"
    assert "Network" in entry["Categories"]
    assert "Security" in entry["Categories"]
    assert entry["Categories"].startswith("Network")
    assert "/home/" not in body
    assert "pkexec" not in entry["Exec"]
    assert "sudo" not in body
    assert ".venv" not in body


def test_polkit_policy_path_and_action() -> None:
    policy = (ROOT / "packaging" / "polkit" / "com.fortigate-vpn-linux-gui.policy").read_text(
        encoding="utf-8"
    )
    assert POLKIT_ACTION_ID in policy
    assert INSTALLED_HELPER_PATH in policy
    assert "allow_any>no" in policy
    assert "allow_inactive>no" in policy
    assert "auth_admin" in policy
    assert "setuid" not in policy.lower()


def test_helper_wrapper_uses_system_python_in_source() -> None:
    text = (ROOT / "packaging" / "libexec" / "vpn-helper").read_text(encoding="utf-8")
    assert text.startswith("#!/usr/bin/python3\n")
    assert "fortigate_vpn_gui.helper.main" in text
    assert "sudo" not in text
    assert "/home/" not in text


def test_launcher_script_has_no_shell_injection() -> None:
    text = (ROOT / "scripts" / "build-deb.sh").read_text(encoding="utf-8")
    assert "-m fortigate_vpn_gui" in text
    assert "exec ${VENV_DIR}/bin/python -m fortigate_vpn_gui" in text
    assert "shell=True" not in text
    assert "/home/mwi/Development" not in (ROOT / "packaging/desktop" / DESKTOP_FILENAME).read_text(
        encoding="utf-8"
    )


def test_debian_control_metadata() -> None:
    control = (ROOT / "packaging" / "debian" / "control").read_text(encoding="utf-8")
    assert "Package: fortigate-vpn-linux-gui" in control
    assert "Version: 1.0.0-2" in control
    assert "Architecture: amd64" in control
    assert "Depends:" in control
    depends = next(line for line in control.splitlines() if line.startswith("Depends:"))
    assert "openfortivpn" not in depends
    assert "libssl3" in depends
    assert "ppp" in depends
    assert "pkexec" in depends
    assert "iproute2" in control
    assert "PySide6_Essentials==6.11.2" in (
        ROOT / "packaging" / "requirements-bundle.txt"
    ).read_text(encoding="utf-8")


def test_icon_resource_is_packaged() -> None:
    icon = ROOT / "src" / "fortigate_vpn_gui" / "resources" / "icons" / f"{ICON_NAME}.svg"
    assert icon.is_file()
    svg = icon.read_text(encoding="utf-8")
    assert "<svg" in svg
    assert "fortinet" not in svg.lower()
    from importlib.resources import files

    bundled = files("fortigate_vpn_gui.resources").joinpath("icons", f"{ICON_NAME}.svg")
    assert bundled.is_file()
