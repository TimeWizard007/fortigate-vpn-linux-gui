# SPDX-License-Identifier: GPL-3.0-or-later
"""Helper import isolation tests. No root, pkexec, or GUI startup."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from fortigate_vpn_gui.helper.handshake import parse_helper_hello_output
from fortigate_vpn_gui.helper.protocol import HELPER_VERSION

_FORBIDDEN_MODULES = (
    "PySide6",
    "fortigate_vpn_gui.app",
    "fortigate_vpn_gui.gui",
    "fortigate_vpn_gui.gui.main_window",
    "fortigate_vpn_gui.vpn.backend",
    "fortigate_vpn_gui.system.helper_client",
)

_IMPORT_SCRIPT = """
import fortigate_vpn_gui.helper.main as helper_main
import sys
forbidden = [
    "PySide6",
    "fortigate_vpn_gui.app",
    "fortigate_vpn_gui.gui",
    "fortigate_vpn_gui.gui.main_window",
    "fortigate_vpn_gui.vpn.backend",
    "fortigate_vpn_gui.system.helper_client",
]
loaded = [name for name in forbidden if name in sys.modules]
assert not loaded, loaded
assert helper_main.main is not None
print("OK")
"""


def test_helper_main_imports_in_clean_process() -> None:
    result = subprocess.run(
        [sys.executable, "-c", _IMPORT_SCRIPT],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "OK"
    assert "ImportError" not in result.stderr
    assert "circular" not in result.stderr.lower()


def test_installed_helper_entry_point_version_without_gui() -> None:
    helper = Path(__file__).resolve().parents[1] / "packaging" / "libexec" / "vpn-helper"
    result = subprocess.run(
        [sys.executable, str(helper), "--version"],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stderr
    parsed = parse_helper_hello_output(
        stdout=result.stdout,
        stderr=result.stderr,
        returncode=result.returncode,
    )
    assert parsed.status == "ok"
    assert parsed.helper_version == HELPER_VERSION
    assert "Traceback" not in result.stdout
    assert "PySide6" not in result.stderr
    for name in _FORBIDDEN_MODULES:
        assert name not in result.stdout
