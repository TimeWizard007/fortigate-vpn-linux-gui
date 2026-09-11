# SPDX-License-Identifier: GPL-3.0-or-later
"""Diagnostics page: grouped health checks and a copyable report."""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from fortigate_vpn_gui import __version__ as APP_VERSION
from fortigate_vpn_gui.diagnostics.model import (
    GROUP_ORDER,
    STATUS_LABEL,
    CheckStatus,
    DiagnosticCheck,
    DiagnosticRun,
)
from fortigate_vpn_gui.diagnostics.platform_info import (
    architecture,
    desktop_session_type,
    kernel_release,
    read_os_pretty_name,
)
from fortigate_vpn_gui.diagnostics.report import format_diagnostic_report
from fortigate_vpn_gui.diagnostics.service import (
    DiagnosticDeps,
    DiagnosticRequest,
    DiagnosticService,
)
from fortigate_vpn_gui.diagnostics.viewmodel import DiagnosticsViewModel
from fortigate_vpn_gui.gui.config_path_widget import ProfileConfigPathWidget
from fortigate_vpn_gui.gui.page_container import create_page_scroll_area
from fortigate_vpn_gui.helper.protocol import HELPER_VERSION
from fortigate_vpn_gui.profiles.manager import ProfileManager
from fortigate_vpn_gui.profiles.model import ConnectionProfile
from fortigate_vpn_gui.vpn.backend import VpnBackend
from fortigate_vpn_gui.vpn.detect import detect_openfortivpn

_STATUS_COLORS = {
    CheckStatus.PASS: "#2e7d32",
    CheckStatus.WARNING: "#ef6c00",
    CheckStatus.FAIL: "#c62828",
    CheckStatus.INFO: "#546e7a",
    CheckStatus.NOT_TESTED: "#9e9e9e",
}


class _DiagnosticsWorker(QThread):
    """Run diagnostics off the GUI thread."""

    completed = Signal(object)

    def __init__(
        self,
        viewmodel: DiagnosticsViewModel,
        request: DiagnosticRequest,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._viewmodel = viewmodel
        self._request = request

    def run(self) -> None:
        result = self._viewmodel.execute(self._request)
        self.completed.emit(result)


class DiagnosticsPage(QWidget):
    """Health overview and copyable diagnostic report. No secrets are shown."""

    def __init__(
        self,
        manager: ProfileManager,
        vpn: VpnBackend,
        selected_profile: Callable[[], ConnectionProfile | None],
        parent: QWidget | None = None,
        *,
        detect=detect_openfortivpn,
        desktop_info: Callable[[], dict[str, str]] | None = None,
        service: DiagnosticService | None = None,
        viewmodel: DiagnosticsViewModel | None = None,
        execute_in_thread: bool = True,
    ) -> None:
        super().__init__(parent)
        self._manager = manager
        self._vpn = vpn
        self._selected_profile = selected_profile
        self._desktop_info = desktop_info
        self._execute_in_thread = execute_in_thread
        self._worker: _DiagnosticsWorker | None = None
        self._displayed_run: DiagnosticRun | None = None
        self._row_widgets: dict[str, QWidget] = {}
        self._full_run_done = False

        self._service = service or DiagnosticService(DiagnosticDeps(detect=detect))
        self._viewmodel = viewmodel or DiagnosticsViewModel(self._service)

        title = QLabel("Diagnostics")
        title.setObjectName("pageTitle")
        intro = QLabel(
            "Troubleshooting checks for why a VPN connection may fail. "
            "Opening this page does not request administrator rights. "
            "Copied reports never include passwords, tokens, cookies, or SAML payloads."
        )
        intro.setWordWrap(True)

        self._profile_combo = QComboBox()
        self._profile_combo.setObjectName("diagnosticsProfileSelector")
        self._profile_combo.setMinimumWidth(280)
        self._profile_combo.currentIndexChanged.connect(self._on_profile_changed)

        self._run_button = QPushButton("Run diagnostics")
        self._run_button.setObjectName("runDiagnosticsButton")
        self._run_button.clicked.connect(self.start_run)

        self._copy_button = QPushButton("Copy report")
        self._copy_button.setObjectName("copyDiagnosticsReportButton")
        self._copy_button.clicked.connect(self.copy_report)

        self._last_run_label = QLabel("Last run: not yet")
        self._last_run_label.setObjectName("diagnosticsLastRun")

        self._stale_hint = QLabel("")
        self._stale_hint.setObjectName("diagnosticsStaleHint")
        self._stale_hint.setWordWrap(True)
        self._stale_hint.setVisible(False)

        actions = QHBoxLayout()
        actions.addWidget(self._run_button)
        actions.addWidget(self._copy_button)
        actions.addWidget(self._last_run_label)
        actions.addStretch(1)

        profile_row = QHBoxLayout()
        profile_label = QLabel("Profile:")
        profile_row.addWidget(profile_label)
        profile_row.addWidget(self._profile_combo, 1)

        self._groups_host = QWidget()
        self._groups_layout = QVBoxLayout(self._groups_host)
        self._groups_layout.setContentsMargins(0, 0, 0, 0)
        self._groups_layout.setSpacing(12)

        inner = QWidget()
        inner_layout = QVBoxLayout(inner)
        inner_layout.setContentsMargins(16, 12, 24, 16)
        inner_layout.setSpacing(12)
        inner_layout.addWidget(title)
        inner_layout.addWidget(intro)
        inner_layout.addLayout(profile_row)
        inner_layout.addLayout(actions)
        inner_layout.addWidget(self._stale_hint)
        inner_layout.addWidget(self._groups_host)
        inner_layout.addWidget(ProfileConfigPathWidget(manager.storage_path))
        inner_layout.addStretch(1)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(create_page_scroll_area(inner))

        self._manager.add_change_listener(self._refresh_profile_combo)
        self._refresh_profile_combo()
        self.refresh(include_version=False)

    def showEvent(self, event) -> None:  # noqa: N802 — Qt API
        super().showEvent(event)
        if getattr(self, "_vpn", None) is None:
            return
        if not self._viewmodel.running:
            self.refresh(include_version=False)

    def refresh(self, *, include_version: bool = True) -> None:
        """Show lightweight local status. Does not probe the gateway."""
        if self._viewmodel.running:
            return
        self._sync_combo_from_connection()
        request = self._request(include_network=False)
        try:
            run = self._viewmodel.execute_local(request)
        except RuntimeError:
            return
        self._apply_run(run, full=False)

    def start_run(self) -> None:
        """Start an active diagnostics pass. Duplicate clicks are ignored."""
        if not self._viewmodel.can_start():
            return
        self._set_running_ui(True)
        request = self._request(include_network=True)
        if not self._execute_in_thread:
            self._finish_run(self._viewmodel.execute(request))
            return
        worker = _DiagnosticsWorker(self._viewmodel, request, self)
        self._worker = worker
        worker.completed.connect(self._finish_run)
        worker.finished.connect(self._clear_worker)
        worker.start()

    def copy_report(self) -> str:
        """Copy the current sanitized report to the clipboard and return it."""
        text = self.report_text()
        clipboard = QApplication.clipboard()
        if clipboard is not None:
            clipboard.setText(text)
        return text

    def report_text(self) -> str:
        """Return the current sanitized diagnostic report."""
        run = self._displayed_run
        if run is None:
            run = self._viewmodel.last_run
        if run is None:
            return ""
        profile = self.selected_profile()
        return format_diagnostic_report(
            run,
            app_version=APP_VERSION,
            os_name=read_os_pretty_name(),
            kernel=kernel_release(),
            architecture=architecture(),
            profile=profile,
            snapshot=self._vpn.snapshot(),
            helper_protocol=HELPER_VERSION,
            session_type=desktop_session_type(),
        )

    def selected_profile(self) -> ConnectionProfile | None:
        profile_id = self._profile_combo.currentData()
        if not profile_id:
            return None
        return self._manager.get(str(profile_id))

    def _request(self, *, include_network: bool) -> DiagnosticRequest:
        return DiagnosticRequest(
            snapshot=self._vpn.snapshot(),
            profile=self.selected_profile(),
            include_network=include_network,
            app_version=APP_VERSION,
            helper_protocol=HELPER_VERSION,
        )

    def _finish_run(self, run: object) -> None:
        if not isinstance(run, DiagnosticRun):
            self._set_running_ui(False)
            return
        self._full_run_done = True
        self._apply_run(run, full=True)
        self._set_running_ui(False)

    def _clear_worker(self) -> None:
        self._worker = None

    def _set_running_ui(self, running: bool) -> None:
        self._run_button.setEnabled(not running)
        self._run_button.setText("Running diagnostics…" if running else "Run diagnostics")
        self._profile_combo.setEnabled(not running)

    def _apply_run(self, run: DiagnosticRun, *, full: bool) -> None:
        self._displayed_run = run
        if full:
            self._last_run_label.setText(self._viewmodel.last_run_label())
            self._stale_hint.setVisible(False)
        elif not self._full_run_done:
            self._last_run_label.setText("Last run: not yet")
        self._rebuild_rows(run.checks)

    def _rebuild_rows(self, checks: tuple[DiagnosticCheck, ...]) -> None:
        while self._groups_layout.count():
            item = self._groups_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.setObjectName("")
                widget.setParent(None)
                widget.deleteLater()
        self._row_widgets.clear()
        by_group: dict[str, list[DiagnosticCheck]] = {group: [] for group in GROUP_ORDER}
        extra: list[DiagnosticCheck] = []
        for check in checks:
            if check.group in by_group:
                by_group[check.group].append(check)
            else:
                extra.append(check)
        for group in GROUP_ORDER:
            grouped = by_group[group]
            if not grouped:
                continue
            heading = QLabel(group)
            heading.setStyleSheet("font-weight: 600;")
            self._groups_layout.addWidget(heading)
            for check in grouped:
                row = self._make_row(check)
                self._row_widgets[check.id] = row
                self._groups_layout.addWidget(row)
        for check in extra:
            row = self._make_row(check)
            self._row_widgets[check.id] = row
            self._groups_layout.addWidget(row)

    def _make_row(self, check: DiagnosticCheck) -> QWidget:
        row = QWidget()
        slug = check.id.replace(".", "_")
        row.setObjectName(f"diagCheck_{slug}")
        layout = QVBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 4)
        layout.setSpacing(2)
        line = QHBoxLayout()
        status = QLabel(STATUS_LABEL[check.status])
        status.setObjectName(f"diagCheckStatus_{slug}")
        status.setStyleSheet(
            f"color: {_STATUS_COLORS[check.status]}; font-weight: 600; min-width: 92px;"
        )
        name = QLabel(check.label)
        name.setObjectName(f"diagCheckLabel_{slug}")
        name.setMinimumWidth(180)
        summary = QLabel(check.summary)
        summary.setObjectName(f"diagCheckSummary_{slug}")
        summary.setWordWrap(True)
        summary.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        summary.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        line.addWidget(status, 0, Qt.AlignmentFlag.AlignTop)
        line.addWidget(name, 0, Qt.AlignmentFlag.AlignTop)
        line.addWidget(summary, 1)
        layout.addLayout(line)
        extra_bits = [part for part in (check.detail, check.hint) if part]
        if extra_bits:
            extra = QLabel("\n".join(extra_bits))
            extra.setObjectName(f"diagCheckDetail_{slug}")
            extra.setWordWrap(True)
            extra.setStyleSheet("color: #616161; padding-left: 92px;")
            extra.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            layout.addWidget(extra)
        return row

    def _refresh_profile_combo(self) -> None:
        previous = self._profile_combo.currentData()
        self._profile_combo.blockSignals(True)
        self._profile_combo.clear()
        profiles = self._manager.list_profiles()
        if not profiles:
            self._profile_combo.addItem("No profiles configured")
            self._profile_combo.blockSignals(False)
            return
        default_id = self._manager.default_profile_id()
        selected_index = 0
        previous_index: int | None = None
        default_index: int | None = None
        connection = self._selected_profile()
        connection_index: int | None = None
        for index, profile in enumerate(profiles):
            label = profile.name
            if profile.id == default_id:
                label = f"{profile.name} (default)"
                default_index = index
            self._profile_combo.addItem(label, profile.id)
            if previous and profile.id == previous:
                previous_index = index
            if connection is not None and profile.id == connection.id:
                connection_index = index
        if previous_index is not None:
            selected_index = previous_index
        elif connection_index is not None:
            selected_index = connection_index
        elif default_index is not None:
            selected_index = default_index
        self._profile_combo.setCurrentIndex(selected_index)
        self._profile_combo.blockSignals(False)
        self._viewmodel.selected_profile_id = self._profile_combo.currentData()

    def _sync_combo_from_connection(self) -> None:
        connection = self._selected_profile()
        if connection is None:
            return
        if self._profile_combo.currentData() == connection.id:
            return
        if self._full_run_done:
            return
        for index in range(self._profile_combo.count()):
            if self._profile_combo.itemData(index) == connection.id:
                self._profile_combo.blockSignals(True)
                self._profile_combo.setCurrentIndex(index)
                self._profile_combo.blockSignals(False)
                return

    def _on_profile_changed(self) -> None:
        profile_id = self._profile_combo.currentData()
        self._viewmodel.mark_profile_changed(str(profile_id) if profile_id else None)
        if self._full_run_done:
            self._stale_hint.setText(
                "The selected profile changed. Run diagnostics again for DNS, "
                "routing, and gateway checks."
            )
            self._stale_hint.setVisible(True)
            self._last_run_label.setText(self._viewmodel.last_run_label())
            return
        if not self._viewmodel.running:
            self.refresh(include_version=False)
