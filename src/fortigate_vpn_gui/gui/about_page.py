# SPDX-License-Identifier: GPL-3.0-or-later
"""About page: version, components, updates, license, and Fortinet disclaimer."""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import QObject, Qt, QThread, Signal
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from fortigate_vpn_gui import __version__
from fortigate_vpn_gui.diagnostics.platform_info import (
    ipsec_backend_label,
    ssl_backend_label,
)
from fortigate_vpn_gui.gui.page_container import create_page_scroll_area
from fortigate_vpn_gui.gui.windowing import dialog_parent_for
from fortigate_vpn_gui.helper.protocol import PROTOCOL_VERSION
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
)
from fortigate_vpn_gui.updates.checker import (
    UpdateCheckResult,
    check_for_update,
    is_allowed_release_url,
)
from fortigate_vpn_gui.updates.components import collect_component_versions
from fortigate_vpn_gui.updates.install_source import (
    InstallInfo,
    detect_install_info,
    format_update_instructions,
)
from fortigate_vpn_gui.vpn.browser import BrowserLauncher, BrowserLaunchError, SystemBrowserLauncher

Checker = Callable[[str], UpdateCheckResult]


class _UpdateWorker(QObject):
    finished = Signal(object)

    def __init__(self, checker: Checker, installed: str) -> None:
        super().__init__()
        self._checker = checker
        self._installed = installed

    def run(self) -> None:
        try:
            result = self._checker(self._installed)
        except Exception:
            result = UpdateCheckResult(
                status="error",
                installed=self._installed,
                detail="unable to check for updates",
            )
        self.finished.emit(result)


class AboutPage(QWidget):
    """Project metadata, component versions, and a non-blocking update check."""

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        browser: BrowserLauncher | None = None,
        open_url: Callable[[str], None] | None = None,
        checker: Checker | None = None,
        helper_detected: str | None = None,
        on_check_finished: Callable[[UpdateCheckResult], None] | None = None,
        install_info: InstallInfo | None = None,
    ) -> None:
        super().__init__(parent)
        self._browser = browser if browser is not None else SystemBrowserLauncher()
        self._open_url = open_url
        self._checker = checker or (lambda installed: check_for_update(installed))
        self._on_check_finished = on_check_finished
        self._install_info = install_info if install_info is not None else detect_install_info()
        self._release_url = ""
        self._thread: QThread | None = None
        self._worker: _UpdateWorker | None = None
        components = collect_component_versions(helper_detected=helper_detected)

        title = QLabel("About")
        title.setObjectName("pageTitle")
        self._name = QLabel(APP_NAME)
        self._name.setObjectName("aboutAppName")
        self._name.setStyleSheet("font-size: 18px; font-weight: 600;")
        self._version = QLabel(f"Application: {__version__}")
        self._version.setObjectName("aboutVersion")
        debian = self._install_info.debian_version or "not installed as a Debian package"
        self._debian = QLabel(f"Debian package: {debian}")
        self._debian.setObjectName("aboutDebianPackage")
        self._install_method = QLabel(f"Install method: {self._install_info.method_label()}")
        self._install_method.setObjectName("aboutInstallMethod")
        self._ssl_backend = QLabel(ssl_backend_label())
        self._ssl_backend.setObjectName("aboutSslBackend")
        self._ipsec_backend = QLabel(ipsec_backend_label())
        self._ipsec_backend.setObjectName("aboutIpsecBackend")

        self._helper_expected = QLabel(f"Helper expected: {components.helper_expected}")
        self._helper_expected.setObjectName("aboutHelperExpected")
        self._helper_detected = QLabel(f"Helper detected: {components.helper_detected}")
        self._helper_detected.setObjectName("aboutHelperDetected")
        self._protocol = QLabel(f"Protocol: {PROTOCOL_VERSION}")
        self._protocol.setObjectName("aboutProtocol")
        self._python = QLabel(f"Python: {components.python}")
        self._python.setObjectName("aboutPython")
        self._qt = QLabel(f"Qt: {components.qt}")
        self._qt.setObjectName("aboutQt")
        self._pyside = QLabel(f"PySide: {components.pyside}")
        self._pyside.setObjectName("aboutPyside")
        self._openfortivpn = QLabel(
            f"openfortivpn: {components.openfortivpn} ({components.openfortivpn_path})"
        )
        self._openfortivpn.setObjectName("aboutOpenfortivpn")
        self._openfortivpn.setWordWrap(True)
        self._strongswan = QLabel(f"strongSwan: {components.strongswan}")
        self._strongswan.setObjectName("aboutStrongswan")
        self._swanctl = QLabel(f"swanctl: {components.swanctl}")
        self._swanctl.setObjectName("aboutSwanctl")

        self._update_status = QLabel("Update status has not been checked yet.")
        self._update_status.setObjectName("aboutUpdateStatus")
        self._update_status.setWordWrap(True)
        self._update_instructions = QLabel(
            "This application does not install system updates itself."
        )
        self._update_instructions.setObjectName("aboutUpdateInstructions")
        self._update_instructions.setWordWrap(True)
        self._update_instructions.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        self._check_button = QPushButton("Check for updates")
        self._check_button.setObjectName("aboutCheckUpdatesButton")
        self._check_button.clicked.connect(self.start_check)
        self._view_release_button = QPushButton("View release")
        self._view_release_button.setObjectName("aboutViewReleaseButton")
        self._view_release_button.setEnabled(False)
        self._view_release_button.clicked.connect(self._open_release)
        privacy = QLabel(
            "Update checks query public GitHub Releases over HTTPS. They do not "
            "send profiles, gateways, usernames, or other VPN data. The GUI never "
            "downloads or installs packages; use apt or a downloaded .deb."
        )
        privacy.setWordWrap(True)
        privacy.setObjectName("aboutUpdatePrivacy")

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

        actions = QHBoxLayout()
        actions.addWidget(self._check_button)
        actions.addWidget(self._view_release_button)
        actions.addStretch(1)

        inner = QWidget()
        layout = QVBoxLayout(inner)
        layout.setContentsMargins(16, 12, 24, 16)
        layout.setSpacing(12)
        layout.addWidget(title)
        layout.addWidget(self._name)
        layout.addWidget(self._version)
        layout.addWidget(self._debian)
        layout.addWidget(self._install_method)
        layout.addWidget(self._helper_expected)
        layout.addWidget(self._helper_detected)
        layout.addWidget(self._protocol)
        layout.addWidget(self._python)
        layout.addWidget(self._qt)
        layout.addWidget(self._pyside)
        layout.addWidget(self._openfortivpn)
        layout.addWidget(self._strongswan)
        layout.addWidget(self._swanctl)
        layout.addWidget(self._ssl_backend)
        layout.addWidget(self._ipsec_backend)
        layout.addWidget(self._update_status)
        layout.addWidget(self._update_instructions)
        layout.addLayout(actions)
        layout.addWidget(privacy)
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

    def update_status_text(self) -> str:
        return self._update_status.text()

    def view_release_enabled(self) -> bool:
        return self._view_release_button.isEnabled()

    def shutdown_update_thread(self) -> None:
        thread = self._thread
        if thread is None:
            return
        if thread.isRunning():
            thread.quit()
            thread.wait(2000)
        self._thread = None
        self._worker = None
        self._check_button.setEnabled(True)

    def start_check(self) -> None:
        if self._thread is not None and self._thread.isRunning():
            return
        self._view_release_button.setEnabled(False)
        self._release_url = ""
        self._update_status.setText("Checking...")
        self._check_button.setEnabled(False)
        worker = _UpdateWorker(self._checker, __version__)
        thread = QThread(self)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.finished.connect(self._apply_result)
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(self._clear_thread)
        self._worker = worker
        self._thread = thread
        thread.start()

    def _clear_thread(self) -> None:
        self._thread = None
        self._worker = None
        self._check_button.setEnabled(True)

    def _apply_result(self, result: object) -> None:
        if not isinstance(result, UpdateCheckResult):
            result = UpdateCheckResult(status="error", installed=__version__)
        if result.status == "up_to_date":
            self._update_status.setText("Up to date")
            self._release_url = ""
            self._view_release_button.setEnabled(False)
        elif result.status == "update_available" and result.latest and result.html_url:
            self._update_status.setText(
                f"Update available\nInstalled: {result.installed}\nAvailable: {result.latest}"
            )
            if is_allowed_release_url(result.html_url):
                self._release_url = result.html_url
                self._view_release_button.setEnabled(True)
            else:
                self._release_url = ""
                self._view_release_button.setEnabled(False)
        else:
            self._update_status.setText("Unable to check for updates")
            self._release_url = ""
            self._view_release_button.setEnabled(False)
        self._update_instructions.setText(format_update_instructions(result, self._install_info))
        if self._on_check_finished is not None:
            self._on_check_finished(result)

    def _open_release(self) -> None:
        if not self._release_url or not is_allowed_release_url(self._release_url):
            return
        self._launch(self._release_url)

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
