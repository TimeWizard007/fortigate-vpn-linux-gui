# SPDX-License-Identifier: GPL-3.0-or-later
"""Loopback IPsec SAML callback listener.

Binds 127.0.0.1 with an OS-chosen ephemeral port. Never binds 0.0.0.0.
The HTTP access log is disabled so tokenid cannot leak through logging.
"""

from __future__ import annotations

import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

from fortigate_vpn_gui.vpn.ipsec.saml_credentials import IpsecSamlCredentials

DEFAULT_LISTEN_TIMEOUT_SECONDS = 300.0
TOKENID_PATTERN = re.compile(r"^[0-9a-fA-F]{32}$")
_MAX_USERNAME_LENGTH = 256
_SUCCESS_HTML = (
    '<!DOCTYPE html><html><head><meta charset="utf-8">'
    "<title>VPN sign-in complete</title></head>"
    "<body><p>Authentication complete. You can close this window.</p></body></html>"
)
_FAIL_HTML = (
    '<!DOCTYPE html><html><head><meta charset="utf-8">'
    "<title>VPN sign-in failed</title></head>"
    "<body><p>Authentication did not complete.</p></body></html>"
)


class IpsecSamlListenerError(RuntimeError):
    """The localhost callback failed. Messages never include tokenid."""


class IpsecSamlListener:
    """One-shot HTTP listener for ``GET /?tokenid=&username=``."""

    def __init__(self, *, timeout_seconds: float = DEFAULT_LISTEN_TIMEOUT_SECONDS) -> None:
        self._timeout_seconds = float(timeout_seconds)
        self._httpd: HTTPServer | None = None
        self._result: IpsecSamlCredentials | None = None
        self._error: IpsecSamlListenerError | None = None
        self._done = threading.Event()
        self._closed = False

    @property
    def port(self) -> int:
        if self._httpd is None:
            raise IpsecSamlListenerError("IPsec SAML listener is not bound.")
        return int(self._httpd.server_address[1])

    def callback_url(self) -> str:
        """Return the loopback origin the FortiGate ACS should redirect to."""
        return f"http://127.0.0.1:{self.port}/"

    def start(self) -> str:
        """Bind 127.0.0.1:0 and return the callback URL."""
        if self._httpd is not None:
            return self.callback_url()
        handler = _make_handler(self)
        try:
            self._httpd = HTTPServer(("127.0.0.1", 0), handler)
        except OSError as exc:
            raise IpsecSamlListenerError("IPsec SAML listener could not bind loopback.") from exc
        host, _port = self._httpd.server_address
        if host not in {"127.0.0.1", "localhost"}:
            self.close()
            raise IpsecSamlListenerError("IPsec SAML listener refused a non-loopback bind.")
        self._httpd.timeout = 0.25
        return self.callback_url()

    def wait(
        self,
        *,
        timeout_seconds: float | None = None,
        cancel_event: threading.Event | None = None,
    ) -> IpsecSamlCredentials:
        """Accept requests until success, timeout, cancel, or close."""
        httpd = self._httpd
        if httpd is None:
            raise IpsecSamlListenerError("IPsec SAML listener is not bound.")
        deadline = timeout_seconds if timeout_seconds is not None else self._timeout_seconds
        remaining = deadline
        slice_timeout = min(0.25, max(deadline, 0.05))
        while remaining > 0:
            if self._closed:
                raise IpsecSamlListenerError("IPsec SAML listener was cancelled.")
            if cancel_event is not None and cancel_event.is_set():
                raise IpsecSamlListenerError("IPsec SAML listener was cancelled.")
            if self._done.is_set():
                return self._finished_result()
            httpd.timeout = min(slice_timeout, remaining)
            try:
                httpd.handle_request()
            except OSError:
                if self._closed:
                    raise IpsecSamlListenerError("IPsec SAML listener was cancelled.") from None
                raise
            remaining -= httpd.timeout
        if self._done.is_set():
            return self._finished_result()
        raise IpsecSamlListenerError("IPsec SAML sign-in timed out.")

    def close(self) -> None:
        """Stop accepting connections. Safe to call more than once."""
        self._closed = True
        httpd = self._httpd
        self._httpd = None
        if httpd is not None:
            try:
                httpd.server_close()
            except OSError:
                pass

    def _accept(self, credentials: IpsecSamlCredentials) -> None:
        if self._done.is_set():
            return
        self._result = credentials
        self._error = None
        self._done.set()

    def _reject(self, error: IpsecSamlListenerError) -> None:
        if self._done.is_set():
            return
        self._error = error
        self._done.set()

    def _finished_result(self) -> IpsecSamlCredentials:
        if self._error is not None:
            raise self._error
        if self._result is None:
            raise IpsecSamlListenerError("IPsec SAML callback did not provide credentials.")
        return self._result


def parse_ipsec_saml_callback_query(query: str) -> IpsecSamlCredentials:
    """Parse ``tokenid`` / ``username`` from a query string. Never logs values."""
    params = parse_qs(query, keep_blank_values=True)
    if "tokenid" not in params:
        raise IpsecSamlListenerError("IPsec SAML callback is missing tokenid.")
    token_values = params.get("tokenid") or []
    if len(token_values) != 1:
        raise IpsecSamlListenerError("IPsec SAML callback has a malformed tokenid.")
    tokenid = token_values[0]
    if TOKENID_PATTERN.fullmatch(tokenid) is None:
        raise IpsecSamlListenerError("IPsec SAML callback has a malformed tokenid.")
    user_values = params.get("username") or []
    if len(user_values) > 1:
        raise IpsecSamlListenerError("IPsec SAML callback has a malformed username.")
    username = user_values[0] if user_values else ""
    if len(username) > _MAX_USERNAME_LENGTH:
        raise IpsecSamlListenerError("IPsec SAML callback has a malformed username.")
    if any(ord(char) < 32 for char in username):
        raise IpsecSamlListenerError("IPsec SAML callback has a malformed username.")
    extra = set(params) - {"tokenid", "username"}
    if extra:
        raise IpsecSamlListenerError("IPsec SAML callback has unexpected parameters.")
    return IpsecSamlCredentials(username=username, tokenid=tokenid)


def _make_handler(listener: IpsecSamlListener) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, _format: str, *_args: object) -> None:
            return

        def do_GET(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler API
            self._handle_expected()

        def do_POST(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler API
            self._send(_FAIL_HTML, 405)
            listener._reject(
                IpsecSamlListenerError("IPsec SAML callback request was not expected.")
            )

        def _handle_expected(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path not in {"/", ""}:
                self._send(_FAIL_HTML, 404)
                listener._reject(
                    IpsecSamlListenerError("IPsec SAML callback path was not expected.")
                )
                return
            try:
                credentials = parse_ipsec_saml_callback_query(parsed.query)
            except IpsecSamlListenerError as exc:
                self._send(_FAIL_HTML, 400)
                listener._reject(exc)
                return
            self._send(_SUCCESS_HTML, 200)
            listener._accept(credentials)

        def _send(self, body: str, status: int) -> None:
            payload = body.encode("ascii")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(payload)

    return Handler


__all__ = [
    "DEFAULT_LISTEN_TIMEOUT_SECONDS",
    "IpsecSamlListener",
    "IpsecSamlListenerError",
    "parse_ipsec_saml_callback_query",
]
