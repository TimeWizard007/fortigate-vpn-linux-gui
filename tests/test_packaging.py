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
    PROTOCOL_VERSION,
)
from fortigate_vpn_gui.metadata import (
    DESKTOP_FILENAME,
    ICON_NAME,
    INSTALLED_LAUNCHER_PATH,
    LAUNCHER_NAME,
)

ROOT = Path(__file__).resolve().parents[1]


def test_application_version_is_1_6_0() -> None:
    assert __version__ == "1.6.0"


def test_helper_protocol_is_0_9_0() -> None:
    assert HELPER_VERSION == "0.9.0"
    assert PROTOCOL_VERSION == 1


def test_production_helper_path(monkeypatch) -> None:
    from fortigate_vpn_gui.system.helper_client import default_helper_client, resolve_helper_path

    monkeypatch.delenv("FORTIGATE_VPN_HELPER", raising=False)
    assert INSTALLED_HELPER_PATH == "/usr/libexec/fortigate-vpn-linux-gui/vpn-helper"
    assert PACKAGE_OPENFORTIVPN_PATH == "/usr/libexec/fortigate-vpn-linux-gui/openfortivpn"
    assert APPROVED_OPENFORTIVPN_PATHS[0] == PACKAGE_OPENFORTIVPN_PATH
    assert resolve_helper_path() == INSTALLED_HELPER_PATH
    assert type(default_helper_client()).__name__ == "PolkitHelperClient"


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
    assert "IPsec" in entry["Keywords"]
    assert "IKEv1" in entry["Keywords"]
    assert "IKEv2" in entry["Keywords"]
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
    assert '<action id="com.fortigate-vpn-linux-gui.manage-vpn">' in policy
    assert POLKIT_ACTION_ID in policy
    assert INSTALLED_HELPER_PATH in policy
    assert (
        '<annotate key="org.freedesktop.policykit.exec.path">'
        "/usr/libexec/fortigate-vpn-linux-gui/vpn-helper</annotate>"
    ) in policy
    assert "<allow_any>no</allow_any>" in policy
    assert "<allow_inactive>no</allow_inactive>" in policy
    assert "<allow_active>yes</allow_active>" in policy
    assert "auth_admin" not in policy
    assert "setuid" not in policy.lower()
    assert "sudoers" not in policy.lower()
    rules = list((ROOT / "packaging").rglob("*.rules"))
    assert rules == []


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
    assert "Version: 1.6.0-1" in control
    assert "1.5.0-1" not in control.split("Depends:", 1)[0]
    assert "1.4.0-1" not in control.split("Depends:", 1)[0]
    assert "1.3.0-1" not in control.split("Depends:", 1)[0]
    assert "1.2.0-1" not in control.split("Depends:", 1)[0]
    assert "1.0.0-2" not in control
    assert "Architecture: amd64" in control
    assert "Depends:" in control
    depends = next(line for line in control.splitlines() if line.startswith("Depends:"))
    assert "openfortivpn" not in depends
    assert "libssl3" in depends
    assert "ppp" in depends
    assert "pkexec" in depends
    assert "strongswan," in depends
    assert "strongswan-swanctl" in depends
    assert "libcharon-extra-plugins" in depends
    assert "libcharon-extauth-plugins" in depends
    assert "Recommends:" not in control
    bundle = (ROOT / "packaging" / "requirements-bundle.txt").read_text(encoding="utf-8")
    assert "PySide6_Essentials==6.11.2" in bundle
    assert "keyring==25.7.0" in bundle
    assert "SecretStorage==3.5.0" in bundle
    assert "jeepney==0.9.0" in bundle
    assert "cryptography==50.0.1" in bundle
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "keyring" in pyproject
    assert "cryptography" in pyproject
    changelog = (ROOT / "packaging" / "debian" / "changelog").read_text(encoding="utf-8")
    assert changelog.startswith("fortigate-vpn-linux-gui (1.6.0-1)")
    script = (ROOT / "scripts" / "build-deb.sh").read_text(encoding="utf-8")
    assert 'VERSION="1.6.0"' in script
    assert 'REVISION="1"' in script
    assert "import keyring" in script
    assert 'OPENFORTIVPN_VERSION="1.24.1"' in script
    assert "apparmor/usr.sbin.swanctl.local" in script
    assert 'SYSTEM_PYTHON="/usr/bin/python3.12"' in script
    assert "build-fvl-forticlient-vid.sh" in script
    assert "libstrongswan-fvl-forticlient-vid.so" in script
    assert "build_package_forticlient_vid" in script
    assert "/usr/lib/ipsec/plugins" in script
    assert '"${SYSTEM_PYTHON}" -m venv' in script
    assert "python3.12 -m venv" not in script
    assert "staging still contains the development checkout path" in script
    postinst = (ROOT / "packaging" / "debian" / "postinst").read_text(encoding="utf-8")
    postrm = (ROOT / "packaging" / "debian" / "postrm").read_text(encoding="utf-8")
    for text in (postinst, postrm):
        assert "fvl-forticlient-vid.conf" not in text
        assert "/etc/strongswan.conf" not in text


def test_apparmor_local_snippet_is_private_vici_only() -> None:
    snippet = (ROOT / "packaging" / "apparmor" / "usr.sbin.swanctl.local").read_text(
        encoding="utf-8"
    )
    assert "/run/charon.fvl.vici rw," in snippet
    assert "/run/charon.fvl.conf r," in snippet
    assert "/run/charon.vici rw" not in snippet
    postinst = (ROOT / "packaging" / "debian" / "postinst").read_text(encoding="utf-8")
    assert "BEGIN fortigate-vpn-linux-gui vici" in postinst
    postrm = (ROOT / "packaging" / "debian" / "postrm").read_text(encoding="utf-8")
    assert "BEGIN fortigate-vpn-linux-gui vici" in postrm
    for text in (postinst, postrm):
        assert "strongswan-starter" not in text
        assert "systemctl" not in text
        assert "charon.pid" not in text


def test_dev_helper_install_script_keeps_polkit_path() -> None:
    script = (ROOT / "scripts" / "install-dev-helper.sh").read_text(encoding="utf-8")
    assert "/usr/libexec/${PACKAGE_NAME}/vpn-helper" in script
    assert "install-dev-helper.sh" in script
    assert "does not install a setuid" in script.lower()
    assert "chmod 4755" not in script
    assert "chmod u+s" not in script
    assert "pkexec" in script
    assert "restore" in script
    assert "apt install --reinstall fortigate-vpn-linux-gui" in script
    assert "Install kind" in script
    assert "capabilities" in script
    assert "system strongSwan" in script
    assert "/usr/lib/ipsec/plugins" in script
    assert "libstrongswan-fvl-forticlient-vid.so" in script
    assert "/etc/strongswan.d/charon/fvl-forticlient-vid.conf" in script
    assert "systemctl" not in script
    assert "/home/" not in script
    assert (ROOT / "scripts" / "install-dev-helper.sh").stat().st_mode & 0o111


def test_icon_resource_is_packaged() -> None:
    icon = ROOT / "src" / "fortigate_vpn_gui" / "resources" / "icons" / f"{ICON_NAME}.svg"
    assert icon.is_file()
    svg = icon.read_text(encoding="utf-8")
    assert "<svg" in svg
    assert "fortinet" not in svg.lower()
    from importlib.resources import files

    bundled = files("fortigate_vpn_gui.resources").joinpath("icons", f"{ICON_NAME}.svg")
    assert bundled.is_file()
