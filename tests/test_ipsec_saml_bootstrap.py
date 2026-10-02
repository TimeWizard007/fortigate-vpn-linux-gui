# SPDX-License-Identifier: GPL-3.0-or-later
"""Unprivileged IPsec SAML bootstrap tests. Synthetic values only."""

from __future__ import annotations

import ssl
import threading
import urllib.error
from pathlib import Path

import pytest

from fortigate_vpn_gui.profiles.ipsec import (
    AUTH_EAP,
    DEFAULT_SAML_PORT,
    IKE_V2,
    default_ipsec_settings,
)
from fortigate_vpn_gui.profiles.model import build_profile
from fortigate_vpn_gui.vpn.browser import BrowserLaunchError
from fortigate_vpn_gui.vpn.ipsec.saml_bootstrap import (
    IPSEC_SAML_BOOTSTRAP_CONTENT_TYPE,
    IPSEC_SAML_BOOTSTRAP_PATH,
    IPSEC_SAML_BOOTSTRAP_USER_AGENT,
    IPSEC_SAML_HTTP_UNKNOWN_MESSAGE,
    BlockedIpsecSamlHtmlFetcher,
    FortiGateIpsecSamlHtmlFetcher,
    IpsecSamlBootstrapError,
    IpsecSamlConnectError,
    IpsecSamlHttpRejectedError,
    IpsecSamlHttpUnknownError,
    IpsecSamlPreauthSession,
    build_ipsec_saml_bootstrap_body,
    ipsec_saml_bootstrap_url,
    ipsec_saml_tls_context,
    parse_ipsec_saml_start_url,
    redirect_port_from_callback_url,
)
from fortigate_vpn_gui.vpn.ipsec.saml_credentials import IpsecSamlCredentials
from fortigate_vpn_gui.vpn.ipsec.saml_listener import IpsecSamlListener, IpsecSamlListenerError
from tests.vpn_fakes import FakeBrowser

_TOKEN = "cafebabefacefeedcafebabefacefeed"
_START_QUERY = "0123456789abcdef"
_UID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
_PROVEN_HTML = (
    f'<html><script>window.location="https://vpn.example.com:1001/saml?{_START_QUERY}"'
    "</script></html>"
)


def _profile():
    return build_profile(
        name="IPsec SAML",
        gateway="vpn.example.com",
        port=500,
        vpn_type="ipsec",
        use_sso=True,
        ipsec={
            **default_ipsec_settings().to_json(),
            "ike_version": IKE_V2,
            "ike_mode": "main",
            "auth_method": AUTH_EAP,
            "saml_port": DEFAULT_SAML_PORT,
        },
    )


class _StaticHtmlFetcher:
    def __init__(self, html: str, *, error: BaseException | None = None) -> None:
        self.html = html
        self.error = error
        self.calls: list[dict[str, object]] = []

    def fetch_html(self, **kwargs: object) -> str:
        self.calls.append(dict(kwargs))
        if self.error is not None:
            raise self.error
        return self.html


class _ImmediateListener(IpsecSamlListener):
    def wait(self, *, timeout_seconds=None, cancel_event=None) -> IpsecSamlCredentials:
        if cancel_event is not None and cancel_event.is_set():
            raise IpsecSamlListenerError("IPsec SAML listener was cancelled.")
        return IpsecSamlCredentials(username="saml-user", tokenid=_TOKEN)


def test_parse_proven_start_url() -> None:
    url = parse_ipsec_saml_start_url(_PROVEN_HTML, gateway="vpn.example.com", saml_port=1001)
    assert url == f"https://vpn.example.com:1001/saml?{_START_QUERY}"


def test_malformed_fortigate_html() -> None:
    with pytest.raises(IpsecSamlBootstrapError, match="did not contain a start URL"):
        parse_ipsec_saml_start_url(
            "<html>no redirect</html>", gateway="vpn.example.com", saml_port=1001
        )


def test_blocked_fetcher_does_not_guess_http() -> None:
    fetcher = BlockedIpsecSamlHtmlFetcher()
    with pytest.raises(
        IpsecSamlHttpUnknownError, match="IMPLEMENTATION BLOCKED AT HTTP BOOTSTRAP DETAIL"
    ):
        fetcher.fetch_html(
            gateway="vpn.example.com",
            saml_port=1001,
            callback_url="http://127.0.0.1:9/",
            uid=_UID,
        )
    assert "tokenid" not in IPSEC_SAML_HTTP_UNKNOWN_MESSAGE.lower()


def test_tls_context_validates_certificates() -> None:
    context = ipsec_saml_tls_context()
    assert context.verify_mode != ssl.CERT_NONE
    assert context.check_hostname is True


def test_browser_launch_with_injected_html(tmp_path: Path) -> None:
    fetcher = _StaticHtmlFetcher(_PROVEN_HTML)
    browser = FakeBrowser()
    session = IpsecSamlPreauthSession(
        fetcher=fetcher,
        uid_path=tmp_path / "ipsec-saml-uid",
        timeout_seconds=1,
        listener_factory=lambda: _ImmediateListener(timeout_seconds=1),
    )
    result = session.run(_profile(), browser=browser, on_waiting=lambda _url: None)
    assert browser.opened == [f"https://vpn.example.com:1001/saml?{_START_QUERY}"]
    assert result.tokenid == _TOKEN
    assert result.eap_identity
    assert _TOKEN not in repr(result)
    assert result.eap_identity not in repr(result)
    result.wipe()
    assert result.tokenid == ""
    assert result.eap_identity == ""


def test_bootstrap_cancellation(tmp_path: Path) -> None:
    cancel = threading.Event()
    cancel.set()
    session = IpsecSamlPreauthSession(
        fetcher=_StaticHtmlFetcher(_PROVEN_HTML),
        uid_path=tmp_path / "ipsec-saml-uid",
        timeout_seconds=1,
    )
    with pytest.raises(IpsecSamlListenerError, match="cancelled"):
        session.run(_profile(), browser=FakeBrowser(), cancel_event=cancel)


def test_bootstrap_timeout(tmp_path: Path) -> None:
    session = IpsecSamlPreauthSession(
        fetcher=_StaticHtmlFetcher(_PROVEN_HTML),
        uid_path=tmp_path / "ipsec-saml-uid",
        timeout_seconds=0.2,
    )
    with pytest.raises(IpsecSamlListenerError, match="timed out"):
        session.run(_profile(), browser=FakeBrowser())


def test_certificate_error_propagates(tmp_path: Path) -> None:
    fetcher = _StaticHtmlFetcher(
        _PROVEN_HTML,
        error=ssl.SSLCertVerificationError("certificate verify failed"),
    )
    session = IpsecSamlPreauthSession(
        fetcher=fetcher,
        uid_path=tmp_path / "ipsec-saml-uid",
        timeout_seconds=1,
    )
    with pytest.raises(ssl.SSLCertVerificationError):
        session.run(_profile(), browser=FakeBrowser())


def test_browser_failure(tmp_path: Path) -> None:
    browser = FakeBrowser()
    browser.fail = True
    session = IpsecSamlPreauthSession(
        fetcher=_StaticHtmlFetcher(_PROVEN_HTML),
        uid_path=tmp_path / "ipsec-saml-uid",
        timeout_seconds=1,
        listener_factory=lambda: _ImmediateListener(timeout_seconds=1),
    )
    with pytest.raises(BrowserLaunchError):
        session.run(_profile(), browser=browser)


def test_no_token_leakage_in_bootstrap_errors() -> None:
    with pytest.raises(IpsecSamlBootstrapError) as excinfo:
        parse_ipsec_saml_start_url(
            f"<html>tokenid={_TOKEN}</html>",
            gateway="vpn.example.com",
            saml_port=1001,
        )
    assert _TOKEN not in str(excinfo.value)


def test_bootstrap_body_is_raw_uid_and_decimal_port() -> None:
    body = build_ipsec_saml_bootstrap_body(uid=_UID, redirect_port=34567)
    assert body == b"UID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&REDIRECT_PORT=34567"
    assert b"saml:ipsecvpn:" not in body
    assert body.decode("ascii").startswith("UID=")


def test_bootstrap_url_keeps_trailing_question_mark() -> None:
    url = ipsec_saml_bootstrap_url("vpn.example.com", 1001)
    assert url == "https://vpn.example.com:1001/saml_login?"
    assert url.endswith(IPSEC_SAML_BOOTSTRAP_PATH)


def test_redirect_port_from_loopback_callback() -> None:
    assert redirect_port_from_callback_url("http://127.0.0.1:34567/") == 34567


def test_redirect_port_rejects_non_loopback() -> None:
    with pytest.raises(IpsecSamlBootstrapError, match="not loopback"):
        redirect_port_from_callback_url("http://10.0.0.1:34567/")


def test_live_fetcher_posts_proven_form() -> None:
    captured: dict[str, object] = {}

    class _Response:
        def __enter__(self) -> _Response:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self) -> bytes:
            return _PROVEN_HTML.encode("utf-8")

    def _urlopen(request, timeout=None, context=None):
        captured["url"] = request.full_url
        captured["selector"] = request.selector
        captured["method"] = request.get_method()
        captured["data"] = request.data
        captured["content_type"] = request.get_header("Content-type")
        captured["user_agent"] = request.get_header("User-agent")
        captured["timeout"] = timeout
        captured["context"] = context
        return _Response()

    fetcher = FortiGateIpsecSamlHtmlFetcher(urlopen=_urlopen)
    html = fetcher.fetch_html(
        gateway="vpn.example.com",
        saml_port=1001,
        callback_url="http://127.0.0.1:34567/",
        uid=_UID,
    )
    assert html == _PROVEN_HTML
    assert captured["method"] == "POST"
    assert captured["url"] == "https://vpn.example.com:1001/saml_login?"
    assert captured["selector"] == "/saml_login?"
    assert captured["data"] == b"UID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&REDIRECT_PORT=34567"
    assert captured["content_type"] == IPSEC_SAML_BOOTSTRAP_CONTENT_TYPE
    assert captured["user_agent"] == IPSEC_SAML_BOOTSTRAP_USER_AGENT
    assert "FortiSSLVPN" not in str(captured["user_agent"])
    assert "fortigate-vpn-linux-gui/" in str(captured["user_agent"])
    context = captured["context"]
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode != ssl.CERT_NONE
    assert context.check_hostname is True
    assert _UID not in IPSEC_SAML_BOOTSTRAP_PATH
    assert "tokenid" not in str(captured["url"]).lower()


def test_live_fetcher_does_not_put_uid_in_errors() -> None:
    def _urlopen(request, timeout=None, context=None):
        raise OSError("connection refused")

    fetcher = FortiGateIpsecSamlHtmlFetcher(urlopen=_urlopen)
    with pytest.raises(IpsecSamlConnectError, match="IPsec SAML service") as excinfo:
        fetcher.fetch_html(
            gateway="vpn.example.com",
            saml_port=1001,
            callback_url="http://127.0.0.1:34567/",
            uid=_UID,
        )
    assert _UID not in str(excinfo.value)
    assert "connection refused" not in str(excinfo.value)


def test_live_fetcher_http_reject_reports_status_only() -> None:
    def _urlopen(request, timeout=None, context=None):
        raise urllib.error.HTTPError(
            "https://vpn.example.com:1001/saml_login?",
            403,
            "Forbidden",
            hdrs=None,
            fp=None,
        )

    fetcher = FortiGateIpsecSamlHtmlFetcher(urlopen=_urlopen)
    with pytest.raises(IpsecSamlHttpRejectedError, match="HTTP 403") as excinfo:
        fetcher.fetch_html(
            gateway="vpn.example.com",
            saml_port=1001,
            callback_url="http://127.0.0.1:34567/",
            uid=_UID,
        )
    assert excinfo.value.status == 403
    assert _UID not in str(excinfo.value)
    assert "Forbidden" not in str(excinfo.value)


def test_live_fetcher_rejects_uid_wrapper() -> None:
    fetcher = FortiGateIpsecSamlHtmlFetcher(
        urlopen=lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("must not send"))
    )
    with pytest.raises(IpsecSamlBootstrapError, match="identity is invalid"):
        fetcher.fetch_html(
            gateway="vpn.example.com",
            saml_port=1001,
            callback_url="http://127.0.0.1:34567/",
            uid="saml:ipsecvpn:" + _UID,
        )


def test_default_session_uses_live_fetcher() -> None:
    session = IpsecSamlPreauthSession()
    assert isinstance(session._fetcher, FortiGateIpsecSamlHtmlFetcher)


def test_fetcher_second_call_opens_a_fresh_http_request() -> None:
    calls: list[str] = []

    class _Response:
        def __enter__(self) -> _Response:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self) -> bytes:
            return _PROVEN_HTML.encode("utf-8")

    def _urlopen(request, timeout=None, context=None):
        calls.append(request.full_url)
        assert context is not None
        assert context.verify_mode != ssl.CERT_NONE
        return _Response()

    fetcher = FortiGateIpsecSamlHtmlFetcher(urlopen=_urlopen)
    kwargs = {
        "gateway": "vpn.example.com",
        "saml_port": 1001,
        "callback_url": "http://127.0.0.1:34567/",
        "uid": _UID,
    }
    assert fetcher.fetch_html(**kwargs) == _PROVEN_HTML
    assert fetcher.fetch_html(**kwargs) == _PROVEN_HTML
    assert calls == [
        "https://vpn.example.com:1001/saml_login?",
        "https://vpn.example.com:1001/saml_login?",
    ]


def test_preauth_session_second_run_binds_fresh_listener(tmp_path: Path) -> None:
    fetcher = _StaticHtmlFetcher(_PROVEN_HTML)
    ports: list[int] = []

    def factory() -> _ImmediateListener:
        listener = _ImmediateListener(timeout_seconds=0.4)
        inner_start = listener.start

        def start() -> str:
            url = inner_start()
            ports.append(listener.port)
            return url

        listener.start = start  # type: ignore[method-assign]
        return listener

    session = IpsecSamlPreauthSession(
        fetcher=fetcher,
        uid_path=tmp_path / "ipsec-saml-uid",
        timeout_seconds=0.4,
        listener_factory=factory,
    )
    browser = FakeBrowser()
    first = session.run(_profile(), browser=browser)
    first.wipe()
    second = session.run(_profile(), browser=browser)
    second.wipe()
    assert len(fetcher.calls) == 2
    assert len(ports) == 2
    assert all(port > 0 for port in ports)
    assert len(browser.opened) == 2
    assert _TOKEN not in str(fetcher.calls)
    assert _UID not in str(ports)
