# SPDX-License-Identifier: GPL-3.0-or-later
"""IPsec credential handling. Secrets never appear on argv or in logs."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class IpsecCredentials:
    """Connect-time IPsec secrets. Not persisted with profiles."""

    psk: str
    username: str
    password: str

    def wipe(self) -> None:
        self.psk = ""
        self.username = ""
        self.password = ""


def build_swanctl_secrets(credentials: IpsecCredentials, *, local_id: str, peer_id: str) -> str:
    """Return a swanctl secrets snippet. Caller must write it mode 0600."""
    lines = [
        "secrets {",
        "    ike-psk {",
    ]
    if local_id:
        lines.append(f"        id = {_quoted(local_id)}")
    if peer_id:
        lines.append(f"        id = {_quoted(peer_id)}")
    lines.extend(
        [
            f"        secret = {_quoted(credentials.psk)}",
            "    }",
            "    xauth-user {",
            f"        id = {_quoted(credentials.username)}",
            f"        secret = {_quoted(credentials.password)}",
            "    }",
            "}",
            "",
        ]
    )
    return "\n".join(lines)


def secrets_contain_plaintext(text: str, credentials: IpsecCredentials) -> bool:
    """Return True when any secret value is visible in *text*."""
    for value in (credentials.psk, credentials.password):
        if value and value in text:
            return True
    return False


def _quoted(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'
