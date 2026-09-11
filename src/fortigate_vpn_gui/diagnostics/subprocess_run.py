# SPDX-License-Identifier: GPL-3.0-or-later
"""Bounded subprocess execution for diagnostics.

Always uses a list argv and ``shell=False``. Never suitable for privileged
operations; diagnostics stay unprivileged.
"""

from __future__ import annotations

import subprocess
from collections.abc import Sequence
from dataclasses import dataclass

from fortigate_vpn_gui.diagnostics.timeouts import SUBPROCESS_TIMEOUT_SECONDS


@dataclass(frozen=True)
class CommandResult:
    """Outcome of one unprivileged command."""

    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    missing: bool = False
    error: str = ""


def run_argv(
    argv: Sequence[str],
    *,
    timeout: float = SUBPROCESS_TIMEOUT_SECONDS,
) -> CommandResult:
    """Run *argv* without a shell. Missing binaries and timeouts are results."""
    if not argv:
        return CommandResult(error="empty argv")
    try:
        completed = subprocess.run(  # noqa: S603 — argv is a list, shell is False
            list(argv),
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
    except FileNotFoundError:
        return CommandResult(missing=True, error="command not found")
    except subprocess.TimeoutExpired:
        return CommandResult(timed_out=True, error="timed out")
    except OSError as exc:
        return CommandResult(error=str(exc.strerror or exc))
    return CommandResult(
        returncode=completed.returncode,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
    )
