# SPDX-License-Identifier: GPL-3.0-or-later
"""Local update-check timestamps. Never stores VPN or profile data."""

from __future__ import annotations

import time

LAST_CHECK_UNIX_KEY = "updates/last_check_unix"
LAST_KNOWN_VERSION_KEY = "updates/last_known_version"
LAST_KNOWN_URL_KEY = "updates/last_known_url"
LAST_NOTIFIED_VERSION_KEY = "updates/last_notified_version"
CHECK_INTERVAL_SECONDS = 24 * 60 * 60


def should_auto_check(settings, *, now: float | None = None) -> bool:
    """Return True when an automatic check is due (once per 24 hours)."""
    current = time.time() if now is None else now
    raw = settings.value(LAST_CHECK_UNIX_KEY, 0)
    try:
        last = float(raw)
    except (TypeError, ValueError):
        last = 0.0
    if last <= 0:
        return True
    return (current - last) >= CHECK_INTERVAL_SECONDS


def record_check(
    settings,
    *,
    version: str | None = None,
    html_url: str | None = None,
    now: float | None = None,
) -> None:
    """Persist the last attempt. Does not write secrets or VPN identifiers."""
    settings.setValue(LAST_CHECK_UNIX_KEY, float(time.time() if now is None else now))
    if version:
        settings.setValue(LAST_KNOWN_VERSION_KEY, version)
    if html_url:
        settings.setValue(LAST_KNOWN_URL_KEY, html_url)


def last_known_version(settings) -> str:
    value = settings.value(LAST_KNOWN_VERSION_KEY, "")
    return str(value or "")


def last_known_url(settings) -> str:
    value = settings.value(LAST_KNOWN_URL_KEY, "")
    return str(value or "")


def last_notified_version(settings) -> str:
    value = settings.value(LAST_NOTIFIED_VERSION_KEY, "")
    return str(value or "")


def should_notify_update(settings, latest: str) -> bool:
    """Return True once per newly observed latest version."""
    version = str(latest or "").strip()
    if not version:
        return False
    return last_notified_version(settings) != version


def record_notified_version(settings, latest: str) -> None:
    version = str(latest or "").strip()
    if not version:
        return
    settings.setValue(LAST_NOTIFIED_VERSION_KEY, version)
