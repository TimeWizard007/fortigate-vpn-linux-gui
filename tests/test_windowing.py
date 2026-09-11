# SPDX-License-Identifier: GPL-3.0-or-later
"""Main window stacking and dialog parenting. Headless Qt only."""

from __future__ import annotations

from PySide6.QtCore import QSettings, Qt
from PySide6.QtWidgets import QScrollArea

from fortigate_vpn_gui.gui.certificate_dialog import CertificateTrustDialog
from fortigate_vpn_gui.gui.main_window import MainWindow
from fortigate_vpn_gui.gui.profile_editor_dialog import ProfileEditorDialog
from fortigate_vpn_gui.helper.protocol import CertificateInfo
from fortigate_vpn_gui.profiles.manager import ProfileManager
from fortigate_vpn_gui.vpn.detect import OpenfortivpnDetection
from tests.vpn_fakes import VpnHarness


def _no_openfortivpn(**kwargs) -> OpenfortivpnDetection:
    return OpenfortivpnDetection(available=False, path=None, version=None)


def _window(qapp, profile_manager: ProfileManager, tmp_path) -> MainWindow:
    del qapp
    settings = QSettings(str(tmp_path / "ui.ini"), QSettings.Format.IniFormat)
    harness = VpnHarness()
    return MainWindow(
        profile_manager=profile_manager,
        vpn_backend=harness.backend,
        detect=_no_openfortivpn,
        settings=settings,
        tray_available=False,
    )


def test_main_window_is_independent_top_level(
    qapp, profile_manager: ProfileManager, tmp_path
) -> None:
    window = _window(qapp, profile_manager, tmp_path)
    assert window.parent() is None
    assert window.isWindow()
    assert window.windowType() == Qt.WindowType.Window
    assert window.windowModality() == Qt.WindowModality.NonModal
    assert window.windowType() not in {
        Qt.WindowType.Tool,
        Qt.WindowType.Dialog,
        Qt.WindowType.Popup,
    }
    assert not bool(window.windowFlags() & Qt.WindowType.WindowStaysOnTopHint)
    window.show()
    qapp.processEvents()
    handle = window.windowHandle()
    assert handle is not None
    assert handle.transientParent() is None
    window.close()


def test_certificate_dialog_is_parented_to_main_window(
    qapp, profile_manager: ProfileManager, tmp_path
) -> None:
    window = _window(qapp, profile_manager, tmp_path)
    info = CertificateInfo(subject="CN=vpn.example.com", issuer="CA", sha256="aa" * 32)
    dialog = CertificateTrustDialog(
        gateway="vpn.example.com",
        certificate=info,
        parent=window,
    )
    assert dialog.parentWidget() is window
    assert dialog.windowModality() == Qt.WindowModality.WindowModal
    window.close()


def test_profile_editor_dialog_is_parented_to_main_window(
    qapp, profile_manager: ProfileManager, tmp_path
) -> None:
    window = _window(qapp, profile_manager, tmp_path)
    dialog = ProfileEditorDialog(profile_manager, parent=window)
    assert dialog.parentWidget() is window
    window.close()


def test_always_on_top_toggle_default_off(qapp, profile_manager: ProfileManager, tmp_path) -> None:
    window = _window(qapp, profile_manager, tmp_path)
    assert window.always_on_top() is False
    checkbox = window.settings_page._always_on_top
    assert checkbox.isChecked() is False
    window.set_always_on_top(True)
    assert window.always_on_top() is True
    assert bool(window.windowFlags() & Qt.WindowType.WindowStaysOnTopHint)
    window.set_always_on_top(False)
    assert not bool(window.windowFlags() & Qt.WindowType.WindowStaysOnTopHint)
    window.close()


def test_pages_use_scroll_areas(qapp, profile_manager: ProfileManager, tmp_path) -> None:
    window = _window(qapp, profile_manager, tmp_path)
    window.resize(640, 420)
    window.show()
    qapp.processEvents()
    for page in (
        window.connection_page,
        window.profiles_page,
        window.diagnostics_page,
        window.settings_page,
        window.about_page,
    ):
        area = page.findChild(QScrollArea, "pageScrollArea")
        assert area is not None
        assert area.widgetResizable()
    window.close()
