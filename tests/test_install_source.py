# SPDX-License-Identifier: GPL-3.0-or-later
"""Read-only install-source and APT policy parsing tests."""

from __future__ import annotations

from pathlib import Path

from fortigate_vpn_gui.updates.checker import UpdateCheckResult
from fortigate_vpn_gui.updates.install_source import (
    APT_UPGRADE_COMMANDS,
    NO_SELF_UPDATE_NOTE,
    InstallInfo,
    debian_upstream_version,
    detect_install_info,
    format_update_instructions,
    format_update_status,
    parse_apt_policy,
    query_apt_policy,
)


def test_parse_apt_policy() -> None:
    text = "fortigate-vpn-linux-gui:\n  Installed: 1.5.0-1\n  Candidate: 1.6.0-1\n"
    installed, candidate = parse_apt_policy(text)
    assert installed == "1.5.0-1"
    assert candidate == "1.6.0-1"


def test_parse_apt_policy_none() -> None:
    text = "fortigate-vpn-linux-gui:\n  Installed: (none)\n  Candidate: (none)\n"
    installed, candidate = parse_apt_policy(text)
    assert installed == ""
    assert candidate == ""


def test_debian_upstream_version() -> None:
    assert debian_upstream_version("1.6.0-1") == "1.6.0"
    assert debian_upstream_version("garbage") == ""


def test_detect_source_method(tmp_path: Path) -> None:
    info = detect_install_info(
        application="1.6.0",
        debian_version="",
        apt_candidate="",
        apt_source_present=False,
        executable="/home/user/venv/bin/python",
        apt_source_path=tmp_path / "missing.sources",
    )
    assert info.method == "source"
    assert info.method_label() == "source"


def test_detect_deb_without_apt_source(tmp_path: Path) -> None:
    info = detect_install_info(
        application="1.6.0",
        debian_version="1.6.0-1",
        apt_candidate="1.6.0-1",
        apt_source_present=False,
        executable="/usr/lib/fortigate-vpn-linux-gui/venv/bin/python",
        apt_source_path=tmp_path / "missing.sources",
    )
    assert info.method == "deb"
    assert info.method_label() == "Debian package"


def test_detect_apt_method(tmp_path: Path) -> None:
    source = tmp_path / "fortigate-vpn-linux-gui.sources"
    source.write_text("Types: deb\n", encoding="utf-8")
    info = detect_install_info(
        application="1.6.0",
        debian_version="1.6.0-1",
        apt_candidate="1.6.0-1",
        apt_source_present=True,
        executable="/usr/lib/fortigate-vpn-linux-gui/venv/bin/python",
        apt_source_path=source,
    )
    assert info.method == "apt"


def test_github_newer_than_candidate_shows_both() -> None:
    info = InstallInfo(
        application="1.6.0",
        debian_version="1.6.0-1",
        apt_candidate="1.6.0-1",
        method="apt",
        apt_source_present=True,
    )
    result = UpdateCheckResult(
        status="update_available",
        installed="1.6.0",
        latest="1.7.0",
        html_url="https://github.com/TimeWizard007/fortigate-vpn-linux-gui/releases/tag/v1.7.0",
    )
    text = format_update_instructions(result, info)
    assert APT_UPGRADE_COMMANDS in text
    assert "GitHub has 1.7.0" in text
    assert "1.6.0-1" in text
    status = format_update_status(result, info)
    assert status.startswith("Update available")
    assert "Installed: 1.6.0" in status
    assert "Available: 1.7.0" in status
    assert "APT candidate: 1.6.0-1" in status


def test_candidate_equals_installed_instructions() -> None:
    info = InstallInfo(
        application="1.6.0",
        debian_version="1.6.0-1",
        apt_candidate="1.6.0-1",
        method="apt",
        apt_source_present=True,
    )
    result = UpdateCheckResult(status="up_to_date", installed="1.6.0", latest="1.6.0")
    assert NO_SELF_UPDATE_NOTE in format_update_instructions(result, info)


def test_deb_without_apt_mentions_github() -> None:
    info = InstallInfo(
        application="1.6.0",
        debian_version="1.6.0-1",
        apt_candidate="",
        method="deb",
        apt_source_present=False,
    )
    result = UpdateCheckResult(
        status="update_available",
        installed="1.6.0",
        latest="1.7.0",
        html_url="https://github.com/TimeWizard007/fortigate-vpn-linux-gui/releases/tag/v1.7.0",
    )
    text = format_update_instructions(result, info)
    assert "GitHub Releases" in text
    assert "apt install" not in text.lower() or "APT repository" in text


def test_source_run_instructions() -> None:
    info = InstallInfo(
        application="1.6.0",
        debian_version="",
        apt_candidate="",
        method="source",
        apt_source_present=False,
    )
    result = UpdateCheckResult(
        status="update_available",
        installed="1.6.0",
        latest="1.7.0",
        html_url="https://github.com/TimeWizard007/fortigate-vpn-linux-gui/releases/tag/v1.7.0",
    )
    assert "running from source" in format_update_instructions(result, info)


def test_error_is_not_update_available() -> None:
    info = InstallInfo(
        application="1.6.0",
        debian_version="1.6.0-1",
        apt_candidate="",
        method="apt",
        apt_source_present=True,
    )
    result = UpdateCheckResult(status="error", installed="1.6.0", detail="offline")
    status = format_update_status(result, info)
    assert status.startswith("Unable to check for updates")
    assert "Update available" not in status
    assert "Debian package: 1.6.0-1" in status


def test_query_apt_policy_rejects_injection() -> None:
    assert query_apt_policy("fortigate; rm -rf /") == ("", "")
    assert query_apt_policy("") == ("", "")


def test_candidate_newer_than_installed_without_github_mismatch() -> None:
    info = InstallInfo(
        application="1.6.0",
        debian_version="1.6.0-1",
        apt_candidate="1.7.0-1",
        method="apt",
        apt_source_present=True,
    )
    result = UpdateCheckResult(
        status="update_available",
        installed="1.6.0",
        latest="1.7.0",
        html_url="https://github.com/TimeWizard007/fortigate-vpn-linux-gui/releases/tag/v1.7.0",
    )
    text = format_update_instructions(result, info)
    assert APT_UPGRADE_COMMANDS in text
    assert "GitHub has" not in text


def test_query_apt_policy_uses_argv_and_timeout(monkeypatch) -> None:
    import subprocess

    seen: dict[str, object] = {}

    def fake_run(argv, **kwargs):  # type: ignore[no-untyped-def]
        seen["argv"] = argv
        seen["shell"] = kwargs.get("shell")
        seen["timeout"] = kwargs.get("timeout")
        completed = subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
        return completed

    monkeypatch.setattr("fortigate_vpn_gui.updates.install_source.subprocess.run", fake_run)
    assert query_apt_policy("fortigate-vpn-linux-gui") == ("", "")
    assert seen["argv"] == ["apt-cache", "policy", "fortigate-vpn-linux-gui"]
    assert seen["shell"] is False
    assert seen["timeout"] == 2


def test_query_apt_policy_timeout(monkeypatch) -> None:
    import subprocess

    def boom(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        raise subprocess.TimeoutExpired(cmd=["apt-cache"], timeout=2)

    monkeypatch.setattr("fortigate_vpn_gui.updates.install_source.subprocess.run", boom)
    assert query_apt_policy("fortigate-vpn-linux-gui") == ("", "")
