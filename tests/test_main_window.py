# SPDX-License-Identifier: GPL-3.0-or-later
"""GUI smoke tests. These tests must not access the network."""

from __future__ import annotations

from PySide6.QtCore import QSettings

from fortigate_vpn_gui import APP_NAME
from fortigate_vpn_gui.gui.main_window import MainWindow
from fortigate_vpn_gui.profiles.manager import ProfileManager
from fortigate_vpn_gui.updates.checker import UpdateCheckResult
from fortigate_vpn_gui.vpn.detect import OpenfortivpnDetection
from tests.vpn_fakes import VpnHarness


def _no_openfortivpn(**kwargs) -> OpenfortivpnDetection:
    return OpenfortivpnDetection(available=False, path=None, version=None)


def _silent_checker(installed: str) -> UpdateCheckResult:
    return UpdateCheckResult(status="up_to_date", installed=installed, latest=installed)


def _make_window(
    profile_manager: ProfileManager,
    tmp_path,
    harness=None,
    *,
    tray_available: bool = False,
    update_checker=None,
    auto_check_delay_ms: int = 60_000,
    settings: QSettings | None = None,
) -> MainWindow:
    if settings is None:
        settings = QSettings(str(tmp_path / "ui.ini"), QSettings.Format.IniFormat)
    vpn = harness.backend if harness is not None else VpnHarness().backend
    return MainWindow(
        profile_manager=profile_manager,
        vpn_backend=vpn,
        detect=_no_openfortivpn,
        settings=settings,
        tray_available=tray_available,
        update_checker=update_checker or _silent_checker,
        auto_check_delay_ms=auto_check_delay_ms,
    )


def test_main_window_can_be_instantiated(qapp, profile_manager: ProfileManager, tmp_path) -> None:
    window = _make_window(profile_manager, tmp_path)
    assert window.windowTitle() == APP_NAME
    assert window.connection_status() == "Disconnected"
    window.close()
    qapp.processEvents()


def test_main_window_shows_profile_config_path(
    qapp, profile_manager: ProfileManager, tmp_path
) -> None:
    window = _make_window(profile_manager, tmp_path)
    from PySide6.QtWidgets import QLineEdit

    field = window.findChild(QLineEdit, "profileConfigPath")
    assert field is not None
    assert "fortigate-vpn-linux-gui" in field.text()
    window.close()


def test_main_window_shutdown_stops_process(
    qapp, profile_manager: ProfileManager, tmp_path
) -> None:
    harness = VpnHarness()
    profile_manager.add(name="Office", gateway="vpn.example.com", use_sso=False)
    window = _make_window(profile_manager, tmp_path, harness=harness)
    window.connection_page._on_action_clicked()
    assert harness.process is not None
    window.close()
    assert harness.process.terminate_called
    qapp.processEvents()
    assert window.close_finalized() is True


def test_main_window_tray_has_icon_before_show(
    qapp, profile_manager: ProfileManager, tmp_path
) -> None:
    window = _make_window(profile_manager, tmp_path, tray_available=True)
    assert window.tray.available is True
    assert window.tray.icon_assigned is True
    assert window.tray.shown_before_icon is False
    window.close()
    qapp.processEvents()
    assert window.close_finalized() is True


def test_main_window_auto_check_uses_injected_checker(
    qapp, profile_manager: ProfileManager, tmp_path
) -> None:
    import time

    seen: list[str] = []
    result = UpdateCheckResult(
        status="update_available",
        installed="1.4.0",
        latest="1.5.0",
        html_url="https://github.com/TimeWizard007/fortigate-vpn-linux-gui/releases/tag/v1.5.0",
    )

    def checker(installed: str) -> UpdateCheckResult:
        seen.append(installed)
        return result

    window = _make_window(
        profile_manager,
        tmp_path,
        update_checker=checker,
        auto_check_delay_ms=0,
    )
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline and window.about_page.update_status_text() in {
        "Update status has not been checked yet.",
        "Checking...",
    }:
        qapp.processEvents()
        time.sleep(0.01)
    assert seen
    assert window.about_page.update_status_text() == "Update available: v1.5.0"
    window.close()
    qapp.processEvents()


def test_main_window_skips_auto_check_when_disabled(
    qapp, profile_manager: ProfileManager, tmp_path
) -> None:
    import time

    from fortigate_vpn_gui.desktop.settings import AUTO_CHECK_UPDATES_KEY

    seen: list[str] = []
    settings = QSettings(str(tmp_path / "ui.ini"), QSettings.Format.IniFormat)
    settings.setValue(AUTO_CHECK_UPDATES_KEY, False)
    window = _make_window(
        profile_manager,
        tmp_path,
        settings=settings,
        update_checker=lambda installed: seen.append(installed) or _silent_checker(installed),
        auto_check_delay_ms=0,
    )
    deadline = time.monotonic() + 0.4
    while time.monotonic() < deadline:
        qapp.processEvents()
        time.sleep(0.01)
    assert seen == []
    assert window.settings_page.auto_check_updates_checked() is False
    window.close()
    qapp.processEvents()
