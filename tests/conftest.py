# SPDX-License-Identifier: GPL-3.0-or-later
"""Pytest fixtures.

``QT_QPA_PLATFORM`` is set before PySide6 is imported so tests can run
headless (including GitHub Actions).
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(autouse=True)
def isolate_xdg_config(tmp_path, monkeypatch):
    """Keep profile files out of the real ~/.config directory."""
    config_home = tmp_path / "xdg-config"
    config_home.mkdir()
    monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))
    return config_home


@pytest.fixture
def profile_manager(tmp_path):
    """Profile manager that stores JSON under a temporary directory."""
    from fortigate_vpn_gui.profiles.manager import ProfileManager

    return ProfileManager(config_dir=tmp_path / "fortigate-vpn-linux-gui")


@pytest.fixture(autouse=True)
def psk_store(monkeypatch):
    """Keep IPsec PSKs out of the real desktop keyring during tests."""
    from fortigate_vpn_gui.system.psk_store import MemoryPskStore

    store = MemoryPskStore()
    monkeypatch.setattr(
        "fortigate_vpn_gui.system.psk_store.default_psk_store",
        lambda: store,
    )
    monkeypatch.setattr(
        "fortigate_vpn_gui.profiles.manager.default_psk_store",
        lambda: store,
    )
    return store


@pytest.fixture(autouse=True)
def _reap_qt_toplevels():
    """Destroy leaked top-level widgets so the session QApplication stays clean.

    MainWindow is parentless. Without this, QTimer / QSystemTrayIcon objects
    survive into later tests and PySide6 can abort when a helper thread starts.
    """
    yield
    import sys

    if "PySide6.QtWidgets" not in sys.modules:
        return
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance()
    if app is None:
        return
    for widget in list(app.topLevelWidgets()):
        widget.hide()
        widget.deleteLater()
    app.processEvents()


@pytest.fixture(scope="session")
def qapp():
    """Session-wide QApplication for widget tests."""
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app
