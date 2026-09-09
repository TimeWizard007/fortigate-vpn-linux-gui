# SPDX-License-Identifier: GPL-3.0-or-later
"""Privileged helper entry point.

Run as root via pkexec. Talks JSON-lines on stdin/stdout. Never launches a
desktop browser and never executes a caller-supplied command string.
"""

from __future__ import annotations

import json
import sys

from fortigate_vpn_gui.helper.handshake import encode_hello_line
from fortigate_vpn_gui.helper.protocol import (
    HELPER_VERSION,
    PROTOCOL_VERSION,
    HelperError,
    HelperEvent,
    HelperEventKind,
    encode_event,
)
from fortigate_vpn_gui.helper.service import HelperService
from fortigate_vpn_gui.runtime import is_running_as_root


def main(argv: list[str] | None = None) -> int:
    """CLI entry for the privileged helper."""
    args = list(sys.argv[1:] if argv is None else argv)
    if args == ["--version"]:
        sys.stdout.write(encode_hello_line() + "\n")
        return 0
    if args == ["--protocol-version"]:
        print(str(PROTOCOL_VERSION))
        return 0

    service = HelperService()

    def emit(event: HelperEvent) -> None:
        sys.stdout.write(json.dumps(encode_event(event), separators=(",", ":")) + "\n")
        sys.stdout.flush()

    service.set_listener(emit)
    emit(
        HelperEvent(
            kind=HelperEventKind.HELLO,
            helper_version=HELPER_VERSION,
            protocol_version=PROTOCOL_VERSION,
            message="unprivileged" if not is_running_as_root() else None,
        )
    )
    for raw in sys.stdin:
        line = raw.strip()
        if not line:
            continue
        try:
            service.handle_line(line)
        except HelperError as exc:
            emit(HelperEvent(kind=HelperEventKind.ERROR, code=exc.code, message=exc.message))
        except Exception as exc:  # pragma: no cover - last-resort guard
            emit(
                HelperEvent(
                    kind=HelperEventKind.ERROR,
                    code="HELPER_INTERNAL",
                    message="Helper request failed.",
                )
            )
            del exc
    service.disconnect(wait=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
