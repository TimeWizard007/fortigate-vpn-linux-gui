# SPDX-License-Identifier: GPL-3.0-or-later
"""Real QApplication.exec() termination after Tray -> Quit.

Unit tests that only assert close_finalized() cannot prove app.exec() returns.
This child process runs the same hide-to-tray then Quit path the desktop uses.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SRC = _REPO_ROOT / "src"

_TRAY_QUIT_AFTER_HIDE_SCRIPT = r"""
import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QApplication

from fortigate_vpn_gui.gui.main_window import MainWindow
from fortigate_vpn_gui.profiles.manager import ProfileManager
from fortigate_vpn_gui.vpn.detect import OpenfortivpnDetection

config = Path(os.environ["XDG_CONFIG_HOME"]) / "ui.ini"
app = QApplication(sys.argv)
app.setQuitOnLastWindowClosed(False)
window = MainWindow(
    profile_manager=ProfileManager(config_dir=Path(os.environ["XDG_CONFIG_HOME"]) / "profiles"),
    detect=lambda **kwargs: OpenfortivpnDetection(available=False, path=None, version=None),
    settings=QSettings(str(config), QSettings.Format.IniFormat),
    tray_available=True,
)
window.set_close_to_tray(True)
window._interactive_tray_hint = False
window.show()
window.close()
if not window.isHidden():
    raise SystemExit("window did not hide to tray")
window.tray._quit_action.trigger()
code = app.exec()
if not window.close_finalized():
    raise SystemExit("close was not finalized")
if window.tray.active:
    raise SystemExit("tray icon still active")
print("EXEC_RETURNED", code, flush=True)
raise SystemExit(0 if code == 0 else code)
"""


def test_tray_quit_after_hide_returns_from_app_exec(tmp_path: Path) -> None:
    xdg = tmp_path / "xdg"
    xdg.mkdir()
    env = os.environ.copy()
    env["QT_QPA_PLATFORM"] = "offscreen"
    env["XDG_CONFIG_HOME"] = str(xdg)
    pythonpath = str(_SRC)
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = pythonpath if not existing else pythonpath + os.pathsep + existing
    try:
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-c", _TRAY_QUIT_AFTER_HIDE_SCRIPT],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
            env=env,
            cwd=str(_REPO_ROOT),
        )
    except subprocess.TimeoutExpired as exc:
        raise AssertionError(
            "python process stayed alive after Tray -> Quit; app.exec() did not return"
        ) from exc
    assert result.returncode == 0, result.stderr
    assert "EXEC_RETURNED 0" in result.stdout
