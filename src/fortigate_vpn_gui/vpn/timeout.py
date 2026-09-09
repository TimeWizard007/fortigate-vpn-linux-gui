# SPDX-License-Identifier: GPL-3.0-or-later
"""Injectable later() scheduler for SAML authentication timeouts."""

from __future__ import annotations

import threading
from collections.abc import Callable

CancelTimeout = Callable[[], None]
TimeoutScheduler = Callable[[float, Callable[[], None]], CancelTimeout]


def threaded_timeout_scheduler(delay: float, callback: Callable[[], None]) -> CancelTimeout:
    """Run *callback* after *delay* seconds on a daemon thread."""
    timer = threading.Timer(delay, callback)
    timer.daemon = True
    timer.start()
    return timer.cancel
