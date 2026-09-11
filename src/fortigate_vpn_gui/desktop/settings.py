# SPDX-License-Identifier: GPL-3.0-or-later
"""Per-user desktop preferences stored in QSettings."""

from __future__ import annotations

from dataclasses import dataclass

ALWAYS_ON_TOP_KEY = "ui/always_on_top"
CLOSE_TO_TRAY_KEY = "ui/close_to_tray"
AUTOSTART_KEY = "desktop/autostart"
AUTO_RECONNECT_KEY = "vpn/auto_reconnect"
TRAY_HINT_SHOWN_KEY = "ui/tray_minimize_hint_shown"


@dataclass(frozen=True)
class DesktopPreferences:
    """User desktop options. Defaults keep v0.6.x behaviour."""

    always_on_top: bool = False
    close_to_tray: bool = False
    autostart: bool = False
    auto_reconnect: bool = False
    tray_hint_shown: bool = False


def _as_bool(value: object, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in {"1", "true", "yes"}
    return bool(value)


def load_desktop_preferences(settings) -> DesktopPreferences:
    """Load preferences from a QSettings-like mapping. Unknown keys are ignored."""
    return DesktopPreferences(
        always_on_top=_as_bool(settings.value(ALWAYS_ON_TOP_KEY, False)),
        close_to_tray=_as_bool(settings.value(CLOSE_TO_TRAY_KEY, False)),
        autostart=_as_bool(settings.value(AUTOSTART_KEY, False)),
        auto_reconnect=_as_bool(settings.value(AUTO_RECONNECT_KEY, False)),
        tray_hint_shown=_as_bool(settings.value(TRAY_HINT_SHOWN_KEY, False)),
    )


def save_desktop_preferences(settings, prefs: DesktopPreferences) -> None:
    """Persist *prefs*. Does not write secrets."""
    settings.setValue(ALWAYS_ON_TOP_KEY, prefs.always_on_top)
    settings.setValue(CLOSE_TO_TRAY_KEY, prefs.close_to_tray)
    settings.setValue(AUTOSTART_KEY, prefs.autostart)
    settings.setValue(AUTO_RECONNECT_KEY, prefs.auto_reconnect)
    settings.setValue(TRAY_HINT_SHOWN_KEY, prefs.tray_hint_shown)


def close_behavior_label(close_to_tray: bool) -> str:
    return "Minimize to system tray" if close_to_tray else "Exit application"
