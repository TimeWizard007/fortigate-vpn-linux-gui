# SPDX-License-Identifier: GPL-3.0-or-later
"""Settings page: local configuration paths and notes."""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtWidgets import QCheckBox, QLabel, QVBoxLayout, QWidget

from fortigate_vpn_gui.gui.config_path_widget import ProfileConfigPathWidget
from fortigate_vpn_gui.gui.page_container import create_page_scroll_area
from fortigate_vpn_gui.profiles.manager import ProfileManager


class SettingsPage(QWidget):
    """Application settings. Certificate verification will never be silently disabled."""

    def __init__(
        self,
        manager: ProfileManager,
        parent: QWidget | None = None,
        *,
        always_on_top: bool = False,
        on_always_on_top: Callable[[bool], None] | None = None,
    ) -> None:
        super().__init__(parent)
        self._on_always_on_top = on_always_on_top
        title = QLabel("Settings")
        title.setStyleSheet("font-size: 20px; font-weight: 600;")
        intro = QLabel(
            "Application preferences. Certificate verification must not be "
            "silently disabled. Always on top is optional and off by default."
        )
        intro.setWordWrap(True)

        self._always_on_top = QCheckBox("Always on top")
        self._always_on_top.setObjectName("alwaysOnTopCheckbox")
        self._always_on_top.setChecked(always_on_top)
        self._always_on_top.toggled.connect(self._emit_always_on_top)

        inner = QWidget()
        inner_layout = QVBoxLayout(inner)
        inner_layout.setContentsMargins(16, 12, 24, 16)
        inner_layout.setSpacing(12)
        inner_layout.addWidget(title)
        inner_layout.addWidget(intro)
        inner_layout.addWidget(self._always_on_top)
        inner_layout.addWidget(ProfileConfigPathWidget(manager.storage_path))
        inner_layout.addStretch(1)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(create_page_scroll_area(inner))

    def always_on_top_checked(self) -> bool:
        return self._always_on_top.isChecked()

    def _emit_always_on_top(self, checked: bool) -> None:
        if self._on_always_on_top is not None:
            self._on_always_on_top(checked)
