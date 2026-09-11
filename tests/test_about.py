# SPDX-License-Identifier: GPL-3.0-or-later
"""About page metadata tests. No real browser is opened."""

from __future__ import annotations

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


def test_about_page_metadata(qapp) -> None:
    opened: list[str] = []
    page = AboutPage(open_url=opened.append)
    assert page.version_text() == f"Version {__version__}"
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
    page._open_project()
    page._open_license()
    assert opened == [PROJECT_URL, LICENSE_URL]
