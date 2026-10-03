# SPDX-License-Identifier: GPL-3.0-or-later
"""Update checker tests. These tests never access the network."""

from __future__ import annotations

import json

from fortigate_vpn_gui.updates.cache import CHECK_INTERVAL_SECONDS, should_auto_check
from fortigate_vpn_gui.updates.checker import (
    GITHUB_API_LATEST,
    USER_AGENT,
    UpdateCheckError,
    check_for_update,
    compare_to_latest,
    fetch_github_json,
    is_allowed_release_url,
    parse_release_item,
    select_latest_stable,
)
from fortigate_vpn_gui.updates.semver import compare_semver, parse_semver


def _release(
    tag: str,
    *,
    draft: bool = False,
    prerelease: bool = False,
    html_url: str | None = None,
) -> dict[str, object]:
    version = tag[1:] if tag.startswith("v") else tag
    return {
        "tag_name": tag,
        "draft": draft,
        "prerelease": prerelease,
        "html_url": html_url
        or f"https://github.com/TimeWizard007/fortigate-vpn-linux-gui/releases/tag/{tag}",
        "name": version,
    }


def test_semver_is_not_lexicographic() -> None:
    assert parse_semver("1.10.0") == (1, 10, 0)
    assert parse_semver("v1.9.0") == (1, 9, 0)
    assert compare_semver("1.9.0", "1.10.0") == -1
    assert compare_semver("1.4.0", "1.5.0") == -1
    assert compare_semver("1.5.0", "1.5.0") == 0
    assert compare_semver("1.5.0", "1.4.0") == 1
    assert parse_semver("1.5.0-rc1") is None
    assert parse_semver("1.5") is None


def test_current_equals_latest() -> None:
    latest = parse_release_item(_release("v1.5.0"))
    assert latest is not None
    result = compare_to_latest("1.5.0", latest)
    assert result.status == "up_to_date"
    assert result.latest == "1.5.0"


def test_newer_stable_release_available() -> None:
    latest = parse_release_item(_release("v1.5.0"))
    assert latest is not None
    result = compare_to_latest("1.4.0", latest)
    assert result.status == "update_available"
    assert result.latest == "1.5.0"
    assert result.html_url is not None
    assert result.html_url.endswith("/v1.5.0")


def test_older_release_is_ignored() -> None:
    latest = parse_release_item(_release("v1.4.0"))
    assert latest is not None
    result = compare_to_latest("1.5.0", latest)
    assert result.status == "up_to_date"
    assert result.latest == "1.4.0"


def test_prerelease_and_draft_are_ignored() -> None:
    payload = [
        _release("v1.6.0", prerelease=True),
        _release("v1.5.1", draft=True),
        _release("v1.5.0"),
        _release("v1.4.0"),
    ]
    latest = select_latest_stable(payload)
    assert latest.version == "1.5.0"


def test_malformed_api_response() -> None:
    result = check_for_update("1.5.0", fetcher=lambda url: "not-json-object")
    assert result.status == "error"
    assert result.latest is None


def test_http_and_timeout_are_errors_not_updates() -> None:
    def boom(_url: str) -> object:
        raise UpdateCheckError("GitHub release API returned HTTP 502")

    http = check_for_update("1.4.0", fetcher=boom)
    assert http.status == "error"

    def timeout(_url: str) -> object:
        raise TimeoutError("timed out")

    timed = check_for_update("1.4.0", fetcher=timeout)
    assert timed.status == "error"
    assert timed.latest is None


def test_fetch_builds_https_request_without_auth_or_vpn_data(monkeypatch) -> None:
    captured: dict[str, object] = {}

    class _Response:
        status = 200

        def read(self) -> bytes:
            return json.dumps(_release("v1.5.0")).encode("utf-8")

        def __enter__(self) -> _Response:
            return self

        def __exit__(self, *args: object) -> None:
            return None

    def fake_urlopen(request, timeout=None, context=None):  # noqa: ANN001
        captured["url"] = request.full_url
        captured["headers"] = {k.lower(): v for k, v in request.header_items()}
        captured["timeout"] = timeout
        captured["has_auth"] = request.has_header("Authorization")
        body = " ".join(f"{k}:{v}" for k, v in request.header_items()).lower()
        captured["leaks"] = any(
            token in body for token in ("psk", "tokenid", "fct", "password", "cookie", "profile")
        )
        return _Response()

    monkeypatch.setattr("fortigate_vpn_gui.updates.checker.urllib.request.urlopen", fake_urlopen)
    payload = fetch_github_json(GITHUB_API_LATEST, timeout=4)
    assert isinstance(payload, dict)
    assert captured["url"] == GITHUB_API_LATEST
    assert str(captured["url"]).startswith("https://")
    headers = captured["headers"]
    assert isinstance(headers, dict)
    assert headers["user-agent"].startswith("fortigate-vpn-linux-gui/")
    assert captured["has_auth"] is False
    assert captured["leaks"] is False
    assert captured["timeout"] == 4
    assert USER_AGENT.startswith("fortigate-vpn-linux-gui/")


def test_check_for_update_uses_injected_fetcher_endpoint() -> None:
    seen: list[str] = []

    def fake(url: str) -> object:
        seen.append(url)
        return _release("v1.5.0")

    result = check_for_update("1.5.0", fetcher=fake, endpoint=GITHUB_API_LATEST)
    assert seen == [GITHUB_API_LATEST]
    assert result.status == "up_to_date"


def test_disallowed_release_url_is_rejected() -> None:
    assert is_allowed_release_url("https://evil.example/releases/tag/v1.5.0") is False
    assert (
        parse_release_item(
            _release("v1.5.0", html_url="https://github.com/other/repo/releases/tag/v1.5.0")
        )
        is None
    )


def test_auto_check_interval() -> None:
    class _Settings:
        def __init__(self, value: object) -> None:
            self._value = value

        def value(self, _key: str, default: object = 0) -> object:
            return self._value if self._value is not None else default

    assert should_auto_check(_Settings(0), now=1000) is True
    assert should_auto_check(_Settings(1000), now=1000 + CHECK_INTERVAL_SECONDS - 1) is False
    assert should_auto_check(_Settings(1000), now=1000 + CHECK_INTERVAL_SECONDS) is True


def test_notify_once_per_version() -> None:
    from fortigate_vpn_gui.updates.cache import (
        record_notified_version,
        should_notify_update,
    )

    class _Settings:
        def __init__(self) -> None:
            self.values: dict[str, object] = {}

        def value(self, key: str, default: object = "") -> object:
            return self.values.get(key, default)

        def setValue(self, key: str, value: object) -> None:
            self.values[key] = value

    settings = _Settings()
    assert should_notify_update(settings, "1.7.0") is True
    record_notified_version(settings, "1.7.0")
    assert should_notify_update(settings, "1.7.0") is False
    assert should_notify_update(settings, "1.8.0") is True
    assert should_notify_update(settings, "") is False
