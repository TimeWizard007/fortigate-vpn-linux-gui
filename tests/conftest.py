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


@pytest.fixture(scope="session")
def qapp():
    """Session-wide QApplication for widget tests."""
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app
