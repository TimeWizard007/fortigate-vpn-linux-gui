# SPDX-License-Identifier: GPL-3.0-or-later
"""Localhost IPsec SAML callback listener tests. Synthetic tokenid only."""

from __future__ import annotations

import threading
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

import pytest

from fortigate_vpn_gui.vpn.ipsec.saml_listener import (
    IpsecSamlListener,
    IpsecSamlListenerError,
    parse_ipsec_saml_callback_query,
)

_TOKEN = "cafebabefacefeedcafebabefacefeed"
_USER = "saml-user"


def test_parse_valid_callback() -> None:
    result = parse_ipsec_saml_callback_query(f"tokenid={_TOKEN}&username={_USER}")
    assert result.username == _USER
    assert result.tokenid == _TOKEN
    assert _TOKEN not in repr(result)
    result.wipe()
    assert result.tokenid == ""
    assert result.username == ""


def test_parse_missing_tokenid() -> None:
    with pytest.raises(IpsecSamlListenerError, match="missing tokenid"):
        parse_ipsec_saml_callback_query(f"username={_USER}")


def test_parse_malformed_tokenid() -> None:
    with pytest.raises(IpsecSamlListenerError, match="malformed tokenid"):
        parse_ipsec_saml_callback_query("tokenid=not-hex&username=x")


def test_parse_duplicate_tokenid() -> None:
    with pytest.raises(IpsecSamlListenerError, match="malformed tokenid"):
        parse_ipsec_saml_callback_query(f"tokenid={_TOKEN}&tokenid={_TOKEN}")


def test_parse_errors_do_not_include_tokenid() -> None:
    with pytest.raises(IpsecSamlListenerError) as excinfo:
        parse_ipsec_saml_callback_query(
            f"tokenid={_TOKEN}&tokenid=deadbeefdeadbeefdeadbeefdeadbeef"
        )
    assert _TOKEN not in str(excinfo.value)
    assert "deadbeef" not in str(excinfo.value)


def test_loopback_ephemeral_bind_and_valid_callback() -> None:
    listener = IpsecSamlListener(timeout_seconds=2)
    box: dict[str, object] = {}

    def wait() -> None:
        try:
            box["result"] = listener.wait(timeout_seconds=2)
        except Exception as exc:  # noqa: BLE001 — capture for assertion
            box["error"] = exc

    try:
        url = listener.start()
        assert url.startswith("http://127.0.0.1:")
        assert listener.port > 0
        thread = threading.Thread(target=wait)
        thread.start()
        with urlopen(f"{url}?tokenid={_TOKEN}&username={_USER}", timeout=2) as response:
            body = response.read().decode("ascii")
        thread.join(timeout=2)
        assert "result" in box
        credentials = box["result"]
        assert credentials.tokenid == _TOKEN
        assert credentials.username == _USER
        assert _TOKEN not in body
        assert "tokenid" not in body.lower()
        credentials.wipe()
    finally:
        listener.close()


def test_missing_tokenid_callback_fails() -> None:
    listener = IpsecSamlListener(timeout_seconds=2)
    box: dict[str, object] = {}

    def wait() -> None:
        try:
            box["result"] = listener.wait(timeout_seconds=2)
        except Exception as exc:  # noqa: BLE001
            box["error"] = exc

    try:
        listener.start()
        thread = threading.Thread(target=wait)
        thread.start()
        with pytest.raises(HTTPError):
            urlopen(f"http://127.0.0.1:{listener.port}/?username={_USER}", timeout=2)
        thread.join(timeout=2)
        assert isinstance(box.get("error"), IpsecSamlListenerError)
        assert _TOKEN not in str(box["error"])
    finally:
        listener.close()


def test_timeout() -> None:
    listener = IpsecSamlListener(timeout_seconds=0.2)
    try:
        listener.start()
        with pytest.raises(IpsecSamlListenerError, match="timed out"):
            listener.wait(timeout_seconds=0.2)
    finally:
        listener.close()


def test_cancellation() -> None:
    listener = IpsecSamlListener(timeout_seconds=2)
    cancel = threading.Event()
    box: dict[str, object] = {}

    def wait() -> None:
        try:
            listener.wait(timeout_seconds=2, cancel_event=cancel)
        except Exception as exc:  # noqa: BLE001
            box["error"] = exc

    try:
        listener.start()
        thread = threading.Thread(target=wait)
        thread.start()
        cancel.set()
        thread.join(timeout=2)
        assert isinstance(box.get("error"), IpsecSamlListenerError)
        assert "cancelled" in str(box["error"]).lower()
    finally:
        listener.close()


def test_listener_cleanup_closes_port() -> None:
    listener = IpsecSamlListener(timeout_seconds=1)
    listener.start()
    port = listener.port
    listener.close()
    with pytest.raises((URLError, OSError, ConnectionError)):
        urlopen(f"http://127.0.0.1:{port}/", timeout=0.5)


def test_new_listener_can_bind_after_previous_close() -> None:
    first = IpsecSamlListener(timeout_seconds=1)
    first.start()
    first.close()
    second = IpsecSamlListener(timeout_seconds=1)
    try:
        url = second.start()
        assert url.startswith("http://127.0.0.1:")
        assert second.port > 0
    finally:
        second.close()
