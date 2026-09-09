# SPDX-License-Identifier: GPL-3.0-or-later
"""Independent top-level window helpers.

The main window must not be a tool/dialog transient of another application.
Always-on-top is optional and off by default.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QWidget

_INDEPENDENT_FLAGS = (
    Qt.WindowType.Window
    | Qt.WindowType.WindowTitleHint
    | Qt.WindowType.WindowSystemMenuHint
    | Qt.WindowType.WindowMinMaxButtonsHint
    | Qt.WindowType.WindowCloseButtonHint
)
_TRANSIENT_TYPES = (
    Qt.WindowType.Dialog
    | Qt.WindowType.Tool
    | Qt.WindowType.Popup
    | Qt.WindowType.Sheet
    | Qt.WindowType.ToolTip
    | Qt.WindowType.SplashScreen
    | Qt.WindowType.SubWindow
)


def configure_independent_main_window(window: QWidget, *, always_on_top: bool = False) -> None:
    """Make *window* a normal independent desktop window."""
    window.setWindowModality(Qt.WindowModality.NonModal)
    flags = _INDEPENDENT_FLAGS
    if always_on_top:
        flags |= Qt.WindowType.WindowStaysOnTopHint
    window.setWindowFlags(flags)


def apply_always_on_top(window: QWidget, enabled: bool) -> None:
    """Toggle ``WindowStaysOnTopHint`` without changing other window types."""
    flags = window.windowFlags()
    flags &= ~_TRANSIENT_TYPES
    flags |= Qt.WindowType.Window
    if enabled:
        flags |= Qt.WindowType.WindowStaysOnTopHint
    else:
        flags &= ~Qt.WindowType.WindowStaysOnTopHint
    visible = window.isVisible()
    window.setWindowFlags(flags)
    if visible:
        window.show()


def clear_transient_parent(window: QWidget) -> None:
    """Clear any native transient-for relationship after the window is created."""
    handle = window.windowHandle()
    if handle is not None:
        handle.setTransientParent(None)


def dialog_parent_for(widget: QWidget) -> QWidget:
    """Return the VPN top-level window for dialogs owned by *widget*."""
    return widget.window()
