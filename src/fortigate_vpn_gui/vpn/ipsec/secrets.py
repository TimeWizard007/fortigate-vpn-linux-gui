# SPDX-License-Identifier: GPL-3.0-or-later
"""IPsec credential handling. Secrets never appear on argv or in logs."""

from __future__ import annotations

from dataclasses import dataclass

_REDACTED = "***"


@dataclass
class IpsecCredentials:
    """Connect-time IPsec secrets. Not persisted with profiles.

    For IKEv1 PSK+XAuth: ``username``/``password`` are XAuth.
    For IKEv2 EAP-MSCHAPv2: ``username`` is EAP Identity (FCT_UID) and
    ``password`` is the ephemeral EAP-MSCHAPv2 secret (tokenid).
    """

    psk: str
    username: str
    password: str

    def wipe(self) -> None:
        self.psk = ""
        self.username = ""
        self.password = ""

    def __repr__(self) -> str:
        return f"IpsecCredentials(psk={_REDACTED}, username={_REDACTED}, password={_REDACTED})"

    def __str__(self) -> str:
        return self.__repr__()


def build_swanctl_secrets(
    credentials: IpsecCredentials,
    *,
    local_id: str,
    peer_id: str,
    eap: bool = False,
) -> str:
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
        ]
    )
    if eap:
        lines.extend(
            [
                "    eap {",
                f"        id = {_quoted(credentials.username)}",
                f"        secret = {_quoted(credentials.password)}",
                "    }",
            ]
        )
    else:
        lines.extend(
            [
                "    xauth-user {",
                f"        id = {_quoted(credentials.username)}",
                f"        secret = {_quoted(credentials.password)}",
                "    }",
            ]
        )
    lines.extend(["}", ""])
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
