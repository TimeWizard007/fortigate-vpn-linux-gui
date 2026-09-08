# SPDX-License-Identifier: GPL-3.0-or-later
"""Pytest fixtures.

``QT_QPA_PLATFORM`` is set before PySide6 is imported so tests can run
headless (including GitHub Actions).
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(scope="session")
def qapp():
    """Session-wide QApplication for widget tests."""
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app
