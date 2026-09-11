# SPDX-License-Identifier: GPL-3.0-or-later
"""Desktop preference defaults and backward-compatible QSettings loading."""

from __future__ import annotations

from PySide6.QtCore import QSettings

from fortigate_vpn_gui.desktop.settings import (
    ALWAYS_ON_TOP_KEY,
    DesktopPreferences,
    load_desktop_preferences,
    save_desktop_preferences,
)


def test_desktop_preference_defaults() -> None:
    prefs = DesktopPreferences()
    assert prefs.always_on_top is False
    assert prefs.close_to_tray is False
    assert prefs.autostart is False
    assert prefs.auto_reconnect is False
    assert prefs.tray_hint_shown is False


def test_load_defaults_from_empty_settings(tmp_path) -> None:
    settings = QSettings(str(tmp_path / "ui.ini"), QSettings.Format.IniFormat)
    prefs = load_desktop_preferences(settings)
    assert prefs == DesktopPreferences()


def test_backward_compatible_always_on_top_only(tmp_path) -> None:
    settings = QSettings(str(tmp_path / "ui.ini"), QSettings.Format.IniFormat)
    settings.setValue(ALWAYS_ON_TOP_KEY, True)
    prefs = load_desktop_preferences(settings)
    assert prefs.always_on_top is True
    assert prefs.close_to_tray is False
    assert prefs.autostart is False
    assert prefs.auto_reconnect is False


def test_desktop_preferences_persist(tmp_path) -> None:
    settings = QSettings(str(tmp_path / "ui.ini"), QSettings.Format.IniFormat)
    save_desktop_preferences(
        settings,
        DesktopPreferences(
            always_on_top=True,
            close_to_tray=True,
            autostart=True,
            auto_reconnect=True,
            tray_hint_shown=True,
        ),
    )
    settings.sync()
    loaded = load_desktop_preferences(settings)
    assert loaded.always_on_top is True
    assert loaded.close_to_tray is True
    assert loaded.autostart is True
    assert loaded.auto_reconnect is True
    assert loaded.tray_hint_shown is True
