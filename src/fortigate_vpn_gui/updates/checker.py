# SPDX-License-Identifier: GPL-3.0-or-later
"""Public GitHub Releases update check. No tokens, no VPN/profile data."""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlparse

from fortigate_vpn_gui import __version__
from fortigate_vpn_gui.metadata import PROJECT_URL
from fortigate_vpn_gui.updates.semver import compare_semver, parse_semver

GITHUB_OWNER = "TimeWizard007"
GITHUB_REPO = "fortigate-vpn-linux-gui"
GITHUB_API_LATEST = f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/releases/latest"
GITHUB_API_RELEASES = f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/releases"
RELEASE_URL_PREFIX = f"{PROJECT_URL}/releases/"
USER_AGENT = f"fortigate-vpn-linux-gui/{__version__}"
DEFAULT_TIMEOUT_SECONDS = 8.0

UpdateStatus = Literal["up_to_date", "update_available", "error"]
Fetcher = Callable[[str], object]


class UpdateCheckError(RuntimeError):
    """The public release API could not be used."""


@dataclass(frozen=True)
class ReleaseInfo:
    """One GitHub release after draft/prerelease filtering."""

    version: str
    tag: str
    html_url: str
    draft: bool = False
    prerelease: bool = False


@dataclass(frozen=True)
class UpdateCheckResult:
    """Outcome of comparing the installed version to the latest stable release."""

    status: UpdateStatus
    installed: str
    latest: str | None = None
    html_url: str | None = None
    detail: str = ""


def is_allowed_release_url(url: str) -> bool:
    """Return True when *url* is an https GitHub Releases page for this project."""
    cleaned = str(url).strip()
    if not cleaned.startswith(RELEASE_URL_PREFIX):
        return False
    parsed = urlparse(cleaned)
    return parsed.scheme == "https" and not parsed.username and not parsed.password


def parse_release_item(item: object) -> ReleaseInfo | None:
    """Parse one GitHub release object. Drafts and prereleases return None."""
    if not isinstance(item, dict):
        return None
    if item.get("draft") is True or item.get("prerelease") is True:
        return None
    tag = str(item.get("tag_name") or "").strip()
    html_url = str(item.get("html_url") or "").strip()
    version = parse_semver(tag)
    if version is None or not is_allowed_release_url(html_url):
        return None
    normalized = f"{version[0]}.{version[1]}.{version[2]}"
    return ReleaseInfo(version=normalized, tag=tag, html_url=html_url)


def select_latest_stable(payload: object) -> ReleaseInfo:
    """Return the highest stable release from a GitHub API payload."""
    if isinstance(payload, dict):
        items: list[object] = [payload]
    elif isinstance(payload, list):
        items = payload
    else:
        raise UpdateCheckError("malformed GitHub release response")
    stable: list[ReleaseInfo] = []
    for item in items:
        parsed = parse_release_item(item)
        if parsed is not None:
            stable.append(parsed)
    if not stable:
        raise UpdateCheckError("no stable GitHub release was found")
    stable.sort(key=lambda info: parse_semver(info.version) or (0, 0, 0))
    return stable[-1]


def compare_to_latest(installed: str, latest: ReleaseInfo) -> UpdateCheckResult:
    """Compare *installed* to *latest* without lexicographic string comparison."""
    order = compare_semver(installed, latest.version)
    if order is None:
        return UpdateCheckResult(
            status="error",
            installed=installed,
            detail="installed version is not a stable X.Y.Z value",
        )
    if order >= 0:
        return UpdateCheckResult(
            status="up_to_date",
            installed=installed,
            latest=latest.version,
            html_url=latest.html_url,
        )
    return UpdateCheckResult(
        status="update_available",
        installed=installed,
        latest=latest.version,
        html_url=latest.html_url,
    )


def fetch_github_json(url: str, *, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> object:
    """GET a GitHub JSON URL over HTTPS. Never sends a token or VPN data."""
    if not url.startswith("https://"):
        raise UpdateCheckError("update checks require HTTPS")
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/vnd.github+json",
        },
        method="GET",
    )
    if request.has_header("Authorization"):
        raise UpdateCheckError("refusing to send an Authorization header")
    try:
        with urllib.request.urlopen(  # noqa: S310 — HTTPS URL, default SSL context
            request,
            timeout=timeout,
            context=ssl.create_default_context(),
        ) as response:
            status = int(getattr(response, "status", 0) or 0)
            if status != 200:
                raise UpdateCheckError(f"GitHub release API returned HTTP {status}")
            raw = response.read()
    except UpdateCheckError:
        raise
    except TimeoutError as exc:
        raise UpdateCheckError("update check timed out") from exc
    except urllib.error.HTTPError as exc:
        raise UpdateCheckError(f"GitHub release API returned HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise UpdateCheckError("unable to reach GitHub Releases") from exc
    except OSError as exc:
        raise UpdateCheckError("unable to reach GitHub Releases") from exc
    try:
        text = raw.decode("utf-8")
        return json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UpdateCheckError("malformed GitHub release response") from exc


def check_for_update(
    installed: str,
    *,
    fetcher: Fetcher | None = None,
    endpoint: str = GITHUB_API_LATEST,
) -> UpdateCheckResult:
    """Return whether a newer stable GitHub Release exists.

    Network and API failures become ``error``, never ``update_available``.
    """
    fetch = fetcher if fetcher is not None else fetch_github_json
    try:
        payload = fetch(endpoint)
        latest = select_latest_stable(payload)
        return compare_to_latest(installed, latest)
    except UpdateCheckError as exc:
        return UpdateCheckResult(status="error", installed=installed, detail=str(exc))
    except (TimeoutError, OSError, ValueError, TypeError):
        return UpdateCheckResult(
            status="error",
            installed=installed,
            detail="unable to check for updates",
        )
