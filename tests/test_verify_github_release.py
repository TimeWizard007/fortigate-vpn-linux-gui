# SPDX-License-Identifier: GPL-3.0-or-later
"""Fail-closed GitHub Release verification used by APT publishing."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load():
    path = ROOT / "scripts" / "verify-github-release.py"
    spec = importlib.util.spec_from_file_location("verify_github_release", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_parse_stable_tag_rejects_branches_and_prereleases() -> None:
    module = _load()
    assert module.parse_stable_tag("v1.5.0") == "v1.5.0"
    assert module.parse_stable_tag("refs/tags/v1.5.0") == "v1.5.0"
    assert module.parse_stable_tag("v1.4.0") == "v1.4.0"
    assert module.parse_stable_tag("feature/v1.5-distribution") is None
    assert module.parse_stable_tag("main") is None
    assert module.parse_stable_tag("v1.5.0-rc1") is None
    assert module.parse_stable_tag("v1.5.0-1") is None
    assert module.parse_stable_tag("1.5.0") is None
    assert module.expected_deb_filename("v1.5.0") == ("fortigate-vpn-linux-gui_1.5.0-1_amd64.deb")
    assert module.debian_version_from_tag("v1.5.0") == "1.5.0-1"
    assert module.application_version_from_tag("v1.5.0") == "1.5.0"


def test_workflow_run_must_be_successful_release_tag_push() -> None:
    module = _load()
    module.validate_workflow_run(name="Release", event="push", conclusion="success")
    with pytest.raises(module.ReleaseVerifyError, match="not success"):
        module.validate_workflow_run(
            name="Release",
            event="push",
            conclusion="failure",
        )
    with pytest.raises(module.ReleaseVerifyError, match="not success"):
        module.validate_workflow_run(
            name="Release",
            event="push",
            conclusion="cancelled",
        )
    with pytest.raises(module.ReleaseVerifyError, match="not a tag push"):
        module.validate_workflow_run(
            name="Release",
            event="workflow_dispatch",
            conclusion="success",
        )
    with pytest.raises(module.ReleaseVerifyError, match="not a stable"):
        module.resolve_release_tag(
            head_branch="feature/v1.5-distribution",
            head_sha="abc123",
            repository="TimeWizard007/fortigate-vpn-linux-gui",
            token="unused",
        )
    with pytest.raises(module.ReleaseVerifyError, match="not a stable"):
        module.resolve_release_tag(
            head_branch="main",
            head_sha="abc123",
            repository="TimeWizard007/fortigate-vpn-linux-gui",
            token="unused",
        )


def test_release_document_requires_exact_stable_deb() -> None:
    module = _load()
    expected = module.expected_deb_filename("v1.5.0")
    ok = {
        "draft": False,
        "prerelease": False,
        "tag_name": "v1.5.0",
        "assets": [
            {"name": expected},
            {"name": f"{expected}.sha256"},
        ],
    }
    assert module.validate_release_document(ok, "v1.5.0") == expected
    with pytest.raises(module.ReleaseVerifyError, match="draft"):
        module.validate_release_document({**ok, "draft": True}, "v1.5.0")
    with pytest.raises(module.ReleaseVerifyError, match="prerelease"):
        module.validate_release_document({**ok, "prerelease": True}, "v1.5.0")
    with pytest.raises(module.ReleaseVerifyError, match="missing required asset"):
        module.validate_release_document(
            {**ok, "assets": [{"name": "unrelated_1.5.0-1_amd64.deb"}]},
            "v1.5.0",
        )
    with pytest.raises(module.ReleaseVerifyError, match="missing required asset"):
        module.validate_release_document({**ok, "assets": []}, "v1.5.0")
    with pytest.raises(module.ReleaseVerifyError, match="missing required asset"):
        module.validate_release_document(
            {
                **ok,
                "assets": [{"name": "fortigate-vpn-linux-gui_1.4.0-1_amd64.deb"}],
            },
            "v1.5.0",
        )
