# SPDX-License-Identifier: GPL-3.0-or-later
"""About page metadata tests. No real browser is opened."""

from __future__ import annotations

import time

from fortigate_vpn_gui.gui.about_page import AboutPage
from fortigate_vpn_gui.metadata import (
    ABOUT_LICENSE_TEXT,
    AUTHOR,
    FORTINET_DISCLAIMER,
    LICENSE_SPDX,
    LICENSE_URL,
    PROJECT_URL,
    __version__,
)
from fortigate_vpn_gui.updates.checker import UpdateCheckResult

RELEASE_URL = f"{PROJECT_URL}/releases/tag/v1.5.0"


def _pump_until(qapp, predicate, timeout: float = 3.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        qapp.processEvents()
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError("timed out waiting for update-check UI")


def test_about_page_metadata(qapp) -> None:
    opened: list[str] = []
    page = AboutPage(open_url=opened.append)
    assert page.version_text() == f"Application: {__version__}"
    assert page.project_url_text() == PROJECT_URL
    assert PROJECT_URL == "https://github.com/TimeWizard007/fortigate-vpn-linux-gui"
    assert AUTHOR in page.author_text()
    assert LICENSE_SPDX == "GPL-3.0-or-later"
    assert "GPL-3.0-or-later" in page._license.text()
    assert "free and open-source" in ABOUT_LICENSE_TEXT
    assert "not affiliated with, sponsored by, or endorsed by Fortinet" in ABOUT_LICENSE_TEXT
    assert "not affiliated with, sponsored by, or endorsed by Fortinet" in FORTINET_DISCLAIMER
    assert "privileged helper" in page.how_it_works_text()
    assert "unprivileged" in page.how_it_works_text()
    assert page._ssl_backend.text().startswith("SSL backend:")
    assert page._ipsec_backend.text().startswith("IPsec backend:")
    assert "psk" not in page._ssl_backend.text().lower()
    assert page._helper_expected.text().startswith("Helper expected:")
    assert page._helper_detected.text().startswith("Helper detected:")
    assert page._protocol.text() == "Protocol: 1"
    assert page._debian.text().startswith("Debian package:")
    assert page._install_method.text().startswith("Install method:")
    assert page._python.text().startswith("Python:")
    assert page._qt.text().startswith("Qt:")
    assert page._pyside.text().startswith("PySide:")
    page._open_project()
    page._open_license()
    assert opened == [PROJECT_URL, LICENSE_URL]


def test_about_check_up_to_date(qapp) -> None:
    opened: list[str] = []
    result = UpdateCheckResult(
        status="up_to_date",
        installed=__version__,
        latest=__version__,
        html_url=RELEASE_URL,
    )
    page = AboutPage(open_url=opened.append, checker=lambda _installed: result)
    page.start_check()
    _pump_until(qapp, lambda: page.update_status_text() != "Checking...")
    assert page.update_status_text() == "Up to date"
    assert page.view_release_enabled() is False
    page._view_release_button.click()
    assert opened == []
    page.shutdown_update_thread()


def test_about_check_update_available_opens_release_only_on_click(qapp) -> None:
    opened: list[str] = []
    result = UpdateCheckResult(
        status="update_available",
        installed="1.4.0",
        latest="1.5.0",
        html_url=RELEASE_URL,
    )
    page = AboutPage(open_url=opened.append, checker=lambda _installed: result)
    page.start_check()
    _pump_until(qapp, lambda: page.update_status_text() != "Checking...")
    assert "Update available" in page.update_status_text()
    assert "Available: 1.5.0" in page.update_status_text()
    assert page.view_release_enabled() is True
    assert opened == []
    page._view_release_button.click()
    assert opened == [RELEASE_URL]
    page.shutdown_update_thread()


def test_about_check_failure(qapp) -> None:
    opened: list[str] = []
    result = UpdateCheckResult(status="error", installed=__version__, detail="timeout")
    page = AboutPage(open_url=opened.append, checker=lambda _installed: result)
    page.start_check()
    _pump_until(qapp, lambda: page.update_status_text() != "Checking...")
    assert page.update_status_text() == "Unable to check for updates"
    assert page.view_release_enabled() is False
    page._view_release_button.click()
    assert opened == []
    page.shutdown_update_thread()


def test_about_rejects_disallowed_release_url(qapp) -> None:
    opened: list[str] = []
    result = UpdateCheckResult(
        status="update_available",
        installed="1.4.0",
        latest="1.5.0",
        html_url="https://evil.example/releases/tag/v1.5.0",
    )
    page = AboutPage(open_url=opened.append, checker=lambda _installed: result)
    page.start_check()
    _pump_until(qapp, lambda: page.update_status_text() != "Checking...")
    assert "Update available" in page.update_status_text()
    assert "Available: 1.5.0" in page.update_status_text()
    assert page.view_release_enabled() is False
    page._view_release_button.click()
    assert opened == []
    page.shutdown_update_thread()
