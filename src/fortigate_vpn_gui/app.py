# SPDX-License-Identifier: GPL-3.0-or-later
"""Application entry point.

This module constructs the Qt application and main window. It does not
perform networking, authentication, or privileged operations.
"""

from __future__ import annotations

import sys
from collections.abc import Callable

from PySide6.QtWidgets import QApplication, QMessageBox

from fortigate_vpn_gui import APP_NAME, __version__
from fortigate_vpn_gui.gui.dependency_dialog import show_missing_dependency_dialog
from fortigate_vpn_gui.gui.main_window import MainWindow
from fortigate_vpn_gui.runtime import is_running_as_root
from fortigate_vpn_gui.system.dependencies import (
    PreflightReport,
    check_gui_startup,
    format_missing_dependencies_message,
    prepare_qt_platform_for_missing_dependencies,
    qt_platform_can_start_safely,
)


def main(
    argv: list[str] | None = None,
    *,
    running_as_root: Callable[[], bool] = is_running_as_root,
    check_dependencies: Callable[[], PreflightReport] = check_gui_startup,
    present_root_error: Callable[[], None] | None = None,
    present_dependency_error: Callable[[PreflightReport], None] | None = None,
    create_window: Callable[[], MainWindow] | None = None,
    create_application: Callable[[list[str]], QApplication] | None = None,
) -> int:
    """Start the GUI.

    Preflight runs before the main window is created. Missing libraries produce
    a dialog (when Qt can start) and a stderr message. Nothing is installed.

    Returns:
        ``1`` if the process is root or required runtime libraries are missing.
        Otherwise the Qt event-loop exit code.
    """
    args = list(sys.argv if argv is None else argv)
    report = check_dependencies()

    if running_as_root():
        _present_root_block(
            args,
            report,
            present_root_error=present_root_error,
            create_application=create_application,
        )
        return 1

    if not report.ok:
        _present_dependency_block(
            args,
            report,
            present_dependency_error=present_dependency_error,
            create_application=create_application,
        )
        return 1

    app = _ensure_application(args, create_application)
    _configure_application(app)
    window = (create_window or MainWindow)()
    window.show()
    return app.exec()


def _present_root_block(
    args: list[str],
    report: PreflightReport,
    *,
    present_root_error: Callable[[], None] | None,
    create_application: Callable[[list[str]], QApplication] | None,
) -> None:
    if present_root_error is not None:
        _ensure_application(args, create_application)
        present_root_error()
        return
    if _can_show_qt_dialog(report):
        app = _ensure_application(args, create_application)
        _configure_application(app)
        _show_root_error()
        return
    print(
        "This application must never run as root.\nThe GUI stays unprivileged.",
        file=sys.stderr,
    )


def _present_dependency_block(
    args: list[str],
    report: PreflightReport,
    *,
    present_dependency_error: Callable[[PreflightReport], None] | None,
    create_application: Callable[[list[str]], QApplication] | None,
) -> None:
    prepare_qt_platform_for_missing_dependencies(report)
    print(format_missing_dependencies_message(report), file=sys.stderr, end="")
    if present_dependency_error is not None:
        _ensure_application(args, create_application)
        present_dependency_error(report)
        return
    if _can_show_qt_dialog(report):
        app = _ensure_application(args, create_application)
        _configure_application(app)
        show_missing_dependency_dialog(report)


def _can_show_qt_dialog(report: PreflightReport) -> bool:
    return QApplication.instance() is not None or qt_platform_can_start_safely(report)


def _configure_application(app: QApplication) -> None:
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(__version__)
    app.setOrganizationName("fortigate-vpn-linux-gui")
    app.setStyle("Fusion")


def _ensure_application(
    args: list[str],
    factory: Callable[[list[str]], QApplication] | None,
) -> QApplication:
    existing = QApplication.instance()
    if isinstance(existing, QApplication):
        return existing
    create = factory or QApplication
    return create(args)


def _show_root_error() -> None:
    QMessageBox.critical(
        None,
        APP_NAME,
        "This application must never run as root.\n\n"
        "The GUI stays unprivileged. Future VPN operations will use a "
        "minimal helper (for example polkit), not a root GUI.",
    )


if __name__ == "__main__":
    raise SystemExit(main())
