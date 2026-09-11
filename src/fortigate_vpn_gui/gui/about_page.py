# SPDX-License-Identifier: GPL-3.0-or-later
"""About page: version, license, project link, and Fortinet disclaimer."""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QMessageBox, QPushButton, QVBoxLayout, QWidget

from fortigate_vpn_gui.gui.page_container import create_page_scroll_area
from fortigate_vpn_gui.gui.windowing import dialog_parent_for
from fortigate_vpn_gui.metadata import (
    ABOUT_LICENSE_TEXT,
    APP_NAME,
    AUTHOR,
    FORTINET_DISCLAIMER,
    HOW_IT_WORKS_TEXT,
    LICENSE_NAME,
    LICENSE_SPDX,
    LICENSE_URL,
    PROJECT_DESCRIPTION,
    PROJECT_URL,
    __version__,
)
from fortigate_vpn_gui.vpn.browser import BrowserLauncher, BrowserLaunchError, SystemBrowserLauncher


class AboutPage(QWidget):
    """Static project metadata. No secrets. URLs open in the system browser."""

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        browser: BrowserLauncher | None = None,
        open_url: Callable[[str], None] | None = None,
    ) -> None:
        super().__init__(parent)
        self._browser = browser if browser is not None else SystemBrowserLauncher()
        self._open_url = open_url

        title = QLabel("About")
        title.setObjectName("pageTitle")
        self._name = QLabel(APP_NAME)
        self._name.setObjectName("aboutAppName")
        self._name.setStyleSheet("font-size: 18px; font-weight: 600;")
        self._version = QLabel(f"Version {__version__}")
        self._version.setObjectName("aboutVersion")
        description = QLabel(PROJECT_DESCRIPTION)
        description.setWordWrap(True)
        description.setObjectName("aboutDescription")
        how = QLabel(HOW_IT_WORKS_TEXT)
        how.setWordWrap(True)
        how.setObjectName("aboutHowItWorks")
        self._how = how
        self._author = QLabel(f"Author: {AUTHOR}")
        self._author.setObjectName("aboutAuthor")
        self._license = QLabel(f"License: {LICENSE_NAME} ({LICENSE_SPDX})")
        self._license.setObjectName("aboutLicense")
        self._license.setWordWrap(True)
        body = QLabel(ABOUT_LICENSE_TEXT)
        body.setWordWrap(True)
        body.setObjectName("aboutLicenseText")
        disclaimer = QLabel(FORTINET_DISCLAIMER)
        disclaimer.setWordWrap(True)
        disclaimer.setObjectName("aboutDisclaimer")
        self._url = QLabel(PROJECT_URL)
        self._url.setObjectName("aboutProjectUrl")
        self._url.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

        self._project_button = QPushButton("Open project page")
        self._project_button.setObjectName("aboutOpenProjectButton")
        self._project_button.clicked.connect(self._open_project)
        self._license_button = QPushButton("View license")
        self._license_button.setObjectName("aboutViewLicenseButton")
        self._license_button.clicked.connect(self._open_license)

        inner = QWidget()
        layout = QVBoxLayout(inner)
        layout.setContentsMargins(16, 12, 24, 16)
        layout.setSpacing(12)
        layout.addWidget(title)
        layout.addWidget(self._name)
        layout.addWidget(self._version)
        layout.addWidget(description)
        layout.addWidget(self._how)
        layout.addWidget(self._author)
        layout.addWidget(self._license)
        layout.addWidget(body)
        layout.addWidget(disclaimer)
        layout.addWidget(self._url)
        layout.addWidget(self._project_button)
        layout.addWidget(self._license_button)
        layout.addStretch(1)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(create_page_scroll_area(inner))

    def version_text(self) -> str:
        return self._version.text()

    def project_url_text(self) -> str:
        return self._url.text()

    def author_text(self) -> str:
        return self._author.text()

    def how_it_works_text(self) -> str:
        return self._how.text()

    def _open_project(self) -> None:
        self._launch(PROJECT_URL)

    def _open_license(self) -> None:
        self._launch(LICENSE_URL)

    def _launch(self, url: str) -> None:
        try:
            if self._open_url is not None:
                self._open_url(url)
                return
            self._browser.open(url)
        except BrowserLaunchError:
            QMessageBox.warning(
                dialog_parent_for(self),
                APP_NAME,
                f"Could not open the link in a browser.\n\n{url}",
            )
