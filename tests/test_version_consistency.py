# SPDX-License-Identifier: GPL-3.0-or-later
"""Version metadata must stay consistent. These tests do not require a git tag."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load():
    path = ROOT / "scripts" / "check-version-consistency.py"
    spec = importlib.util.spec_from_file_location("check_version_consistency", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_source_versions_are_1_6_0() -> None:
    module = _load()
    versions = module.collect_versions()
    assert versions["application"] == "1.6.0"
    assert versions["pyproject"] == "1.6.0"
    assert versions["debian_control"] == "1.6.0-1"
    assert versions["debian_changelog"] == "1.6.0-1"
    assert versions["build_script"] == "1.6.0-1"


def test_validate_passes_without_tag(monkeypatch) -> None:
    module = _load()
    monkeypatch.delenv("GITHUB_REF_TYPE", raising=False)
    monkeypatch.delenv("GITHUB_REF_NAME", raising=False)
    monkeypatch.delenv("GITHUB_REF", raising=False)
    monkeypatch.setattr(module, "detect_release_tag", lambda: None)
    assert module.validate(require_tag=False) == []
    errors = module.validate(require_tag=True)
    assert errors
    assert any("tag is required" in item for item in errors)


def test_tag_must_match_application(monkeypatch) -> None:
    module = _load()
    monkeypatch.setattr(module, "detect_release_tag", lambda: "v1.4.0")
    errors = module.validate()
    assert any("v1.4.0" in item and "v1.6.0" in item for item in errors)
    monkeypatch.setattr(module, "detect_release_tag", lambda: "v1.6.0")
    assert module.validate(require_tag=True) == []


def test_github_ref_tag_is_detected(monkeypatch) -> None:
    module = _load()
    monkeypatch.setenv("GITHUB_REF_TYPE", "tag")
    monkeypatch.setenv("GITHUB_REF_NAME", "v1.5.0")
    assert module.detect_release_tag() == "v1.5.0"


def test_parse_stable_tag_rejects_non_release_refs() -> None:
    module = _load()
    assert module.parse_stable_tag("v1.5.0") == "v1.5.0"
    assert module.parse_stable_tag("main") is None
    assert module.parse_stable_tag("v1.5.0-rc1") is None
    assert module.parse_stable_tag("1.5.0") is None


def test_expected_tag_wins_over_workflow_run_github_ref(monkeypatch) -> None:
    module = _load()
    monkeypatch.setenv("GITHUB_REF", "refs/heads/main")
    monkeypatch.setenv("GITHUB_REF_NAME", "main")
    monkeypatch.setenv("GITHUB_REF_TYPE", "branch")
    monkeypatch.setattr(module, "detect_release_tag", lambda: None)
    assert module.validate(require_tag=True)
    assert module.validate(require_tag=True, expected_tag="v1.6.0") == []


def test_expected_tag_must_be_stable() -> None:
    module = _load()
    for value in ("main", "v1.5.0-rc1", "1.5.0", "v1.5.0-1", ""):
        errors = module.validate(require_tag=True, expected_tag=value)
        assert any("not a stable vX.Y.Z tag" in item for item in errors)


def test_expected_tag_must_match_source_version() -> None:
    module = _load()
    errors = module.validate(require_tag=True, expected_tag="v1.6.1")
    assert any("v1.6.1" in item and "v1.6.0" in item for item in errors)


def test_expected_tag_rejects_wrong_deb_version(monkeypatch) -> None:
    module = _load()
    monkeypatch.setattr(
        module,
        "debian_package_fields",
        lambda _path: ("fortigate-vpn-linux-gui", "1.6.1-1", "amd64"),
    )
    errors = module.validate(
        require_tag=True,
        expected_tag="v1.6.0",
        deb=Path("fortigate-vpn-linux-gui_1.6.1-1_amd64.deb"),
    )
    assert any("1.6.1-1" in item and "1.6.0-1" in item for item in errors)


def test_expected_tag_rejects_wrong_package(monkeypatch) -> None:
    module = _load()
    monkeypatch.setattr(
        module,
        "debian_package_fields",
        lambda _path: ("unrelated-vpn", "1.6.0-1", "amd64"),
    )
    errors = module.validate(
        require_tag=True,
        expected_tag="v1.6.0",
        deb=Path("fortigate-vpn-linux-gui_1.6.0-1_amd64.deb"),
    )
    assert any("Package" in item and "unrelated-vpn" in item for item in errors)


def test_expected_tag_rejects_wrong_architecture(monkeypatch) -> None:
    module = _load()
    monkeypatch.setattr(
        module,
        "debian_package_fields",
        lambda _path: ("fortigate-vpn-linux-gui", "1.6.0-1", "arm64"),
    )
    errors = module.validate(
        require_tag=True,
        expected_tag="v1.6.0",
        deb=Path("fortigate-vpn-linux-gui_1.6.0-1_amd64.deb"),
    )
    assert any("Architecture" in item and "arm64" in item for item in errors)
