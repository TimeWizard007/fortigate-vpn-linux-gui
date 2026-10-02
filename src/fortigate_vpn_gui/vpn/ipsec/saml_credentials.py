# SPDX-License-Identifier: GPL-3.0-or-later
"""In-memory IPsec SAML callback result.

``tokenid`` is the ephemeral EAP-MSCHAPv2 password. ``eap_identity`` is the
persistent FCT_UID used as EAP Identity. Python strings are immutable;
``wipe()`` drops this object's references but cannot guarantee that copies
elsewhere are physically zeroed.
"""

from __future__ import annotations

_REDACTED = "***"


class IpsecSamlCredentials:
    """Localhost callback fields. Secrets must never be logged or repr'd."""

    __slots__ = ("username", "_tokenid", "_eap_identity")

    def __init__(self, *, username: str, tokenid: str, eap_identity: str = "") -> None:
        self.username = username
        self._tokenid = tokenid
        self._eap_identity = eap_identity

    @property
    def tokenid(self) -> str:
        """Return the ephemeral tokenid. Callers must not log this value."""
        return self._tokenid

    @property
    def eap_identity(self) -> str:
        """Return FCT_UID for EAP Identity. Callers must not log this value."""
        return self._eap_identity

    def attach_eap_identity(self, uid: str) -> IpsecSamlCredentials:
        """Record FCT_UID as EAP Identity. The value must not be logged."""
        self._eap_identity = uid
        return self

    def wipe(self) -> None:
        """Drop secret and identity references held by this object."""
        self._tokenid = ""
        self._eap_identity = ""
        self.username = ""

    def __repr__(self) -> str:
        return (
            "IpsecSamlCredentials("
            f"username={_REDACTED}, eap_identity={_REDACTED}, tokenid={_REDACTED})"
        )

    def __str__(self) -> str:
        return self.__repr__()


__all__ = ["IpsecSamlCredentials"]
