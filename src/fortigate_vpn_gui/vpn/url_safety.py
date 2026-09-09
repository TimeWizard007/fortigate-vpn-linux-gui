# SPDX-License-Identifier: GPL-3.0-or-later
"""Validate untrusted URLs before handing them to a browser."""

from __future__ import annotations

from urllib.parse import urlparse

_ALLOWED_SCHEMES = frozenset({"http", "https"})
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})


class InvalidAuthUrl(ValueError):
    """The candidate URL is not safe to open."""


def validate_auth_url(raw: str) -> str:
    """Return a cleaned http(s) URL or raise ``InvalidAuthUrl``.

    Loopback hosts are rejected so the local SAML callback is never opened
    as the sign-in page. Query strings are allowed for launch but must not
    be logged or shown in full.
    """
    if raw is None or not str(raw).strip():
        raise InvalidAuthUrl("empty URL")
    cleaned = str(raw).strip().strip("'\"")
    if any(ch.isspace() for ch in cleaned) or "\\" in cleaned:
        raise InvalidAuthUrl("URL contains illegal characters")
    parsed = urlparse(cleaned)
    scheme = (parsed.scheme or "").lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise InvalidAuthUrl("URL scheme is not http or https")
    if not parsed.netloc:
        raise InvalidAuthUrl("URL is missing a host")
    host = _hostname(parsed.netloc)
    if host in _LOOPBACK_HOSTS:
        raise InvalidAuthUrl("refusing to open a loopback callback URL")
    return cleaned


def safe_url_for_display(url: str) -> str:
    """Origin plus path, with query and fragment removed."""
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return "(redacted URL)"
    path = parsed.path or ""
    return f"{parsed.scheme}://{parsed.netloc}{path}"


def _hostname(netloc: str) -> str:
    host = netloc.rsplit("@", 1)[-1]
    if host.startswith("["):
        end = host.find("]")
        if end != -1:
            return host[: end + 1].lower()
    return host.split(":", 1)[0].lower()
