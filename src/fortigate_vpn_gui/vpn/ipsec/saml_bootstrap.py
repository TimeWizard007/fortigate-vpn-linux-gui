# SPDX-License-Identifier: GPL-3.0-or-later
"""Unprivileged FortiGate IPsec SAML bootstrap (SAML-before-IKE).

Proven FortiClient 7.4.8.2066 external-browser request against ``:1001``:

* bind ``127.0.0.1:0`` first, then send the assigned decimal port
* ``POST https://<GATEWAY>:<saml_port>/saml_login?``
* ``Content-Type: application/x-www-form-urlencoded``
* body ``UID=<FCT_UID>&REDIRECT_PORT=<callback-port>`` (raw 32-hex UID)
* parse HTML ``window.location="https://<GATEWAY>:<port>/saml?<16-hex>"``
* open that URL in the system browser
* wait for ``/?tokenid=&username=``

TLS verification stays enabled. Request bodies are not logged.
"""

from __future__ import annotations

import re
import ssl
import threading
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Protocol
from urllib.parse import urlparse

from fortigate_vpn_gui import __version__
from fortigate_vpn_gui.metadata import LAUNCHER_NAME
from fortigate_vpn_gui.profiles.ipsec import DEFAULT_SAML_PORT
from fortigate_vpn_gui.profiles.model import ConnectionProfile
from fortigate_vpn_gui.system.ipsec_saml_uid import (
    IpsecSamlUidError,
    get_or_create_ipsec_saml_uid,
    validate_ipsec_saml_uid,
)
from fortigate_vpn_gui.vpn.browser import BrowserLauncher
from fortigate_vpn_gui.vpn.ipsec.saml_credentials import IpsecSamlCredentials
from fortigate_vpn_gui.vpn.ipsec.saml_listener import (
    DEFAULT_LISTEN_TIMEOUT_SECONDS,
    IpsecSamlListener,
    IpsecSamlListenerError,
)
from fortigate_vpn_gui.vpn.url_safety import InvalidAuthUrl, safe_url_for_display, validate_auth_url

IPSEC_SAML_HTTP_UNKNOWN_MESSAGE = (
    "IMPLEMENTATION BLOCKED AT HTTP BOOTSTRAP DETAIL: HTTP method, request "
    "path, FCT_UID field name, and localhost callback-URL registration for "
    "FortiGate :1001 are not proven. This client will not guess a request "
    "body or path."
)
IPSEC_SAML_BOOTSTRAP_PATH = "/saml_login?"
IPSEC_SAML_BOOTSTRAP_CONTENT_TYPE = "application/x-www-form-urlencoded"
IPSEC_SAML_BOOTSTRAP_USER_AGENT = f"{LAUNCHER_NAME}/{__version__}"
IPSEC_SAML_BOOTSTRAP_TIMEOUT_SECONDS = 10.0
IPSEC_SAML_CONNECT_MESSAGE = "Could not connect to the FortiGate IPsec SAML service."
IPSEC_SAML_START_URL_MESSAGE = "FortiGate IPsec SAML bootstrap HTML did not contain a start URL."
_START_LOCATION_RE = re.compile(
    r'window\.location\s*=\s*["\'](https://[^"\']+/saml\?[0-9a-fA-F]{16})["\']',
    re.IGNORECASE,
)
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost"})


class IpsecSamlBootstrapError(RuntimeError):
    """Unprivileged IPsec SAML bootstrap failed. Messages never include secrets."""


class IpsecSamlHttpUnknownError(IpsecSamlBootstrapError):
    """Kept for tests that still inject a blocked fetcher."""


class IpsecSamlConnectError(IpsecSamlBootstrapError):
    """TCP/HTTP connect to the FortiGate SAML port failed."""


class IpsecSamlHttpRejectedError(IpsecSamlBootstrapError):
    """FortiGate returned a non-success HTTP status for the bootstrap POST."""

    def __init__(self, status: int) -> None:
        self.status = int(status)
        super().__init__(
            f"FortiGate rejected the IPsec SAML bootstrap request (HTTP {self.status})."
        )


class IpsecSamlStartUrlError(IpsecSamlBootstrapError):
    """Bootstrap HTML did not contain a usable ``window.location`` start URL."""


class IpsecSamlHtmlFetcher(Protocol):
    """Fetch FortiGate bootstrap HTML. Must not disable TLS validation."""

    def fetch_html(
        self,
        *,
        gateway: str,
        saml_port: int,
        callback_url: str,
        uid: str,
    ) -> str: ...


class BlockedIpsecSamlHtmlFetcher:
    """Explicit blocked fetcher. Tests may inject this; production does not."""

    def fetch_html(
        self,
        *,
        gateway: str,
        saml_port: int,
        callback_url: str,
        uid: str,
    ) -> str:
        raise IpsecSamlHttpUnknownError(IPSEC_SAML_HTTP_UNKNOWN_MESSAGE)


def ipsec_saml_tls_context() -> ssl.SSLContext:
    """Return a verifying TLS context. ``verify_mode`` is never disabled."""
    return ssl.create_default_context()


def ipsec_saml_bootstrap_url(gateway: str, saml_port: int) -> str:
    """Return the proven FortiGate IPsec SAML bootstrap URL."""
    host = gateway.strip()
    if not host:
        raise IpsecSamlBootstrapError("FortiGate IPsec SAML gateway is missing.")
    port = int(saml_port)
    if port < 1 or port > 65535:
        raise IpsecSamlBootstrapError("FortiGate IPsec SAML port is invalid.")
    return f"https://{host}:{port}{IPSEC_SAML_BOOTSTRAP_PATH}"


def redirect_port_from_callback_url(callback_url: str) -> int:
    """Return the decimal loopback port registered as ``REDIRECT_PORT``."""
    parsed = urlparse(callback_url)
    host = (parsed.hostname or "").lower()
    if host not in _LOOPBACK_HOSTS:
        raise IpsecSamlBootstrapError("IPsec SAML callback was not loopback.")
    port = parsed.port
    if port is None or port < 1 or port > 65535:
        raise IpsecSamlBootstrapError("IPsec SAML callback port was invalid.")
    return int(port)


def build_ipsec_saml_bootstrap_body(*, uid: str, redirect_port: int) -> bytes:
    """Build the proven ``UID`` + ``REDIRECT_PORT`` form body.

    FortiClient concatenates these fields as UTF-8 with no extra wrapping
    and no ``saml:ipsecvpn:`` prefix. The UID must already be 32 hex.
    """
    try:
        validated = validate_ipsec_saml_uid(uid)
    except IpsecSamlUidError as exc:
        raise IpsecSamlBootstrapError("IPsec SAML identity is invalid.") from exc
    port = int(redirect_port)
    if port < 1 or port > 65535:
        raise IpsecSamlBootstrapError("IPsec SAML callback port was invalid.")
    return f"UID={validated}&REDIRECT_PORT={port}".encode("ascii")


def parse_ipsec_saml_start_url(html: str, *, gateway: str, saml_port: int) -> str:
    """Extract the proven JS redirect URL. The 16-hex query is not tokenid."""
    if not isinstance(html, str) or not html:
        raise IpsecSamlStartUrlError(IPSEC_SAML_START_URL_MESSAGE)
    match = _START_LOCATION_RE.search(html)
    if match is None:
        raise IpsecSamlStartUrlError(IPSEC_SAML_START_URL_MESSAGE)
    raw = match.group(1)
    parsed = urlparse(raw)
    host = (parsed.hostname or "").lower()
    expected = gateway.strip().lower()
    if host != expected:
        raise IpsecSamlStartUrlError(
            "FortiGate IPsec SAML start URL host did not match the profile gateway."
        )
    port = parsed.port
    if port is None or int(port) != int(saml_port):
        raise IpsecSamlStartUrlError(
            "FortiGate IPsec SAML start URL port did not match the profile SAML port."
        )
    if (parsed.path or "") != "/saml":
        raise IpsecSamlStartUrlError("FortiGate IPsec SAML start URL path was not /saml.")
    query = parsed.query or ""
    if re.fullmatch(r"[0-9a-fA-F]{16}", query) is None:
        raise IpsecSamlStartUrlError("FortiGate IPsec SAML start URL query was malformed.")
    try:
        return validate_auth_url(raw)
    except InvalidAuthUrl as exc:
        raise IpsecSamlStartUrlError(
            "FortiGate IPsec SAML start URL was not safe to open."
        ) from exc


class FortiGateIpsecSamlHtmlFetcher:
    """POST the proven ``:1001`` bootstrap request with TLS verification."""

    def __init__(
        self,
        *,
        tls_context: ssl.SSLContext | None = None,
        timeout_seconds: float = IPSEC_SAML_BOOTSTRAP_TIMEOUT_SECONDS,
        urlopen: Callable[..., object] | None = None,
    ) -> None:
        self._tls_context = tls_context
        self._timeout_seconds = float(timeout_seconds)
        self._urlopen = urllib.request.urlopen if urlopen is None else urlopen

    def fetch_html(
        self,
        *,
        gateway: str,
        saml_port: int,
        callback_url: str,
        uid: str,
    ) -> str:
        redirect_port = redirect_port_from_callback_url(callback_url)
        body = build_ipsec_saml_bootstrap_body(uid=uid, redirect_port=redirect_port)
        request = urllib.request.Request(
            ipsec_saml_bootstrap_url(gateway, saml_port),
            data=body,
            method="POST",
            headers={
                "Content-Type": IPSEC_SAML_BOOTSTRAP_CONTENT_TYPE,
                "User-Agent": IPSEC_SAML_BOOTSTRAP_USER_AGENT,
            },
        )
        context = self._tls_context if self._tls_context is not None else ipsec_saml_tls_context()
        try:
            raw = self._read_response(request, context)
        except ssl.SSLCertVerificationError:
            raise
        except ssl.SSLError:
            raise
        except IpsecSamlBootstrapError:
            raise
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise IpsecSamlConnectError(IPSEC_SAML_CONNECT_MESSAGE) from exc
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise IpsecSamlStartUrlError(IPSEC_SAML_START_URL_MESSAGE) from exc

    def _read_response(self, request: urllib.request.Request, context: ssl.SSLContext) -> bytes:
        try:
            with self._urlopen(  # type: ignore[operator]
                request,
                timeout=self._timeout_seconds,
                context=context,
            ) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            status = int(getattr(exc, "code", 0) or 0)
            if status:
                raise IpsecSamlHttpRejectedError(status) from exc
            raise IpsecSamlConnectError(IPSEC_SAML_CONNECT_MESSAGE) from exc
        except urllib.error.URLError as exc:
            reason = getattr(exc, "reason", None)
            if isinstance(reason, ssl.SSLCertVerificationError):
                raise reason from exc
            if isinstance(reason, ssl.SSLError):
                raise reason from exc
            raise IpsecSamlConnectError(IPSEC_SAML_CONNECT_MESSAGE) from exc


class IpsecSamlPreauthSession:
    """Run UID + listener + HTML fetch + browser + callback wait."""

    def __init__(
        self,
        *,
        fetcher: IpsecSamlHtmlFetcher | None = None,
        uid_path: Path | None = None,
        timeout_seconds: float = DEFAULT_LISTEN_TIMEOUT_SECONDS,
        listener_factory: Callable[[], IpsecSamlListener] | None = None,
    ) -> None:
        self._fetcher: IpsecSamlHtmlFetcher = (
            fetcher if fetcher is not None else FortiGateIpsecSamlHtmlFetcher()
        )
        self._uid_path = uid_path
        self._timeout_seconds = float(timeout_seconds)
        self._listener_factory = listener_factory or (
            lambda: IpsecSamlListener(timeout_seconds=self._timeout_seconds)
        )

    def run(
        self,
        profile: ConnectionProfile,
        *,
        browser: BrowserLauncher,
        cancel_event: threading.Event | None = None,
        on_waiting: Callable[[str], None] | None = None,
    ) -> IpsecSamlCredentials:
        """Return in-memory callback credentials. Does not start IKE or the helper."""
        if cancel_event is not None and cancel_event.is_set():
            raise IpsecSamlListenerError("IPsec SAML listener was cancelled.")
        try:
            uid = get_or_create_ipsec_saml_uid(path=self._uid_path)
        except IpsecSamlUidError as exc:
            raise IpsecSamlBootstrapError("IPsec SAML identity is invalid.") from exc
        settings = profile.ipsec
        saml_port = DEFAULT_SAML_PORT if settings is None else int(settings.saml_port)
        listener = self._listener_factory()
        try:
            callback_url = listener.start()
            html = self._fetcher.fetch_html(
                gateway=profile.gateway,
                saml_port=saml_port,
                callback_url=callback_url,
                uid=uid,
            )
            start_url = parse_ipsec_saml_start_url(
                html, gateway=profile.gateway, saml_port=saml_port
            )
            browser.open(start_url)
            if on_waiting is not None:
                on_waiting(safe_url_for_display(start_url))
            return listener.wait(
                timeout_seconds=self._timeout_seconds,
                cancel_event=cancel_event,
            ).attach_eap_identity(uid)
        finally:
            listener.close()


__all__ = [
    "IPSEC_SAML_BOOTSTRAP_CONTENT_TYPE",
    "IPSEC_SAML_BOOTSTRAP_PATH",
    "IPSEC_SAML_BOOTSTRAP_USER_AGENT",
    "IPSEC_SAML_CONNECT_MESSAGE",
    "IPSEC_SAML_HTTP_UNKNOWN_MESSAGE",
    "IPSEC_SAML_START_URL_MESSAGE",
    "BlockedIpsecSamlHtmlFetcher",
    "FortiGateIpsecSamlHtmlFetcher",
    "IpsecSamlBootstrapError",
    "IpsecSamlConnectError",
    "IpsecSamlHtmlFetcher",
    "IpsecSamlHttpRejectedError",
    "IpsecSamlHttpUnknownError",
    "IpsecSamlPreauthSession",
    "IpsecSamlStartUrlError",
    "build_ipsec_saml_bootstrap_body",
    "ipsec_saml_bootstrap_url",
    "ipsec_saml_tls_context",
    "parse_ipsec_saml_start_url",
    "redirect_port_from_callback_url",
]
