# SPDX-License-Identifier: GPL-3.0-or-later
"""Run-state for Diagnostics. Independent of Qt widgets."""

from __future__ import annotations

import threading

from fortigate_vpn_gui.diagnostics.model import DiagnosticRun
from fortigate_vpn_gui.diagnostics.service import DiagnosticRequest, DiagnosticService


class DiagnosticsViewModel:
    """Track run/cancel/stale state for the Diagnostics page."""

    def __init__(self, service: DiagnosticService | None = None) -> None:
        self._service = service or DiagnosticService()
        self._running = False
        self._cancel = threading.Event()
        self.last_run: DiagnosticRun | None = None
        self.stale = False
        self.selected_profile_id: str | None = None

    @property
    def running(self) -> bool:
        return self._running

    def can_start(self) -> bool:
        return not self._running

    def mark_profile_changed(self, profile_id: str | None) -> None:
        self.selected_profile_id = profile_id
        if self.last_run is not None:
            self.stale = True

    def cancel(self) -> None:
        self._cancel.set()

    def execute(self, request: DiagnosticRequest) -> DiagnosticRun:
        """Run diagnostics. Raises if a run is already active."""
        if self._running:
            raise RuntimeError("diagnostics already running")
        self._running = True
        self._cancel.clear()
        try:
            result = self._service.run(request, cancel=self._cancel.is_set)
            self.last_run = result
            self.stale = False
            return result
        finally:
            self._running = False

    def execute_local(self, request: DiagnosticRequest) -> DiagnosticRun:
        """Lightweight local status. Ignored while a full run is active."""
        if self._running:
            if self.last_run is not None:
                return self.last_run
            raise RuntimeError("diagnostics already running")
        result = self._service.collect_local(request)
        if self.last_run is None:
            self.last_run = result
        return result

    def last_run_label(self) -> str:
        if self.last_run is None:
            return "Last run: not yet"
        stamp = self.last_run.finished_at.astimezone().strftime("%H:%M:%S")
        label = f"Last run: {stamp}"
        if self.stale:
            label += " (profile changed — run again)"
        return label
