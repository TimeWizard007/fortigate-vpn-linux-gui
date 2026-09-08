# SPDX-License-Identifier: GPL-3.0-or-later
"""Dialog for missing runtime dependencies.

The dialog only displays trusted install commands produced by
``fortigate_vpn_gui.system.dependencies``. It never executes them.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from fortigate_vpn_gui import APP_NAME
from fortigate_vpn_gui.system.dependencies import (
    PreflightReport,
    format_missing_dependencies_message,
)


class MissingDependencyDialog(QDialog):
    """Explain missing libraries and offer to copy a static apt command."""

    def __init__(self, report: PreflightReport, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"{APP_NAME} — Missing dependencies")
        self.setModal(True)
        self.setMinimumWidth(520)
        self._command = report.install_command or ""

        summary = QLabel(format_missing_dependencies_message(report))
        summary.setWordWrap(True)
        summary.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

        command_label = QLabel("Install command")
        self._command_field = QLineEdit(self._command)
        self._command_field.setReadOnly(True)
        self._command_field.setObjectName("installCommand")

        buttons = QDialogButtonBox()
        self._copy_button = QPushButton("Copy command")
        self._copy_button.setObjectName("copyCommandButton")
        self._copy_button.setEnabled(bool(self._command))
        self._copy_button.clicked.connect(self.copy_command)
        buttons.addButton(self._copy_button, QDialogButtonBox.ButtonRole.ActionRole)
        buttons.addButton(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        close_button = buttons.button(QDialogButtonBox.StandardButton.Close)
        if close_button is not None:
            close_button.setText("Exit")
            close_button.setObjectName("exitButton")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)
        layout.addWidget(summary)
        layout.addWidget(command_label)
        layout.addWidget(self._command_field)
        layout.addWidget(buttons)

    def install_command(self) -> str:
        """Return the trusted command shown in the dialog."""
        return self._command

    def copy_command(self) -> None:
        """Copy the trusted install command to the clipboard. Does not run it."""
        if not self._command:
            return
        clipboard = QGuiApplication.clipboard()
        if clipboard is not None:
            clipboard.setText(self._command)


def show_missing_dependency_dialog(
    report: PreflightReport,
    parent: QWidget | None = None,
) -> None:
    """Block until the user closes the missing-dependency dialog."""
    dialog = MissingDependencyDialog(report, parent)
    dialog.exec()
