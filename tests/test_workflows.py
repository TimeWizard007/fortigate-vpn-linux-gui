# SPDX-License-Identifier: GPL-3.0-or-later
"""Release workflow security invariants. No secret values, no PR signing."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"


def _apt_publish() -> str:
    return (WORKFLOWS / "apt-publish.yml").read_text(encoding="utf-8")


def _on_block(text: str) -> str:
    marker = "\non:"
    start = text.find(marker)
    assert start != -1
    jobs = text.find("\njobs:", start)
    assert jobs != -1
    return text[start:jobs]


def test_ci_stays_on_python_3_10_and_3_12() -> None:
    text = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    assert "3.10" in text
    assert "3.12" in text
    assert "APT_SIGNING_KEY" not in text
    assert "APT_SIGNING_PASSPHRASE" not in text
    assert "permissions:" in text
    assert "contents: read" in text


def test_release_workflow_is_tag_only() -> None:
    text = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
    assert "pull_request" not in text
    assert "tags:" in text
    assert "v*.*.*" in text
    assert "./scripts/build-deb.sh" in text
    assert "scripts/check-version-consistency.py" in text
    assert "scripts/inspect-deb.sh" in text
    assert "build-fvl-forticlient-vid.sh" in text
    assert "ldd -r" in text
    assert "APT_SIGNING_KEY" not in text
    assert "APT_SIGNING_PASSPHRASE" not in text
    assert "softprops/action-gh-release" in text


def test_apt_publish_does_not_trigger_on_release_published() -> None:
    header = _on_block(_apt_publish())
    assert "release:" not in header
    assert "published" not in header
    assert "workflow_run:" in header
    assert "Release" in header
    assert "completed" in header


def test_apt_publish_requires_successful_release_workflow() -> None:
    text = _apt_publish()
    header = _on_block(text)
    assert "workflow_run:" in header
    assert "github.event.workflow_run.conclusion == 'success'" in text
    assert "github.event.workflow_run.name == 'Release'" in text
    assert "github.event.workflow_run.event == 'push'" in text
    assert "github.event_name == 'workflow_dispatch'" in text


def test_apt_publish_cannot_use_arbitrary_branch_or_ref() -> None:
    text = _apt_publish()
    assert "github.head_ref" not in text
    assert "github.event.pull_request" not in text
    assert "github.event.inputs.ref" not in text
    assert "github.event.inputs.sha" not in text
    assert "github.event.inputs.branch" not in text
    assert "ref: ${{ github.ref }}" not in text
    assert "ref: ${{ github.event.workflow_run.head_branch }}" not in text
    assert "ref: ${{ github.event.inputs.tag }}" not in text
    assert "ref: ${{ steps.release.outputs.sha }}" in text
    assert "persist-credentials: false" in text
    assert "contents: write" not in text
    assert "contents: read" in text
    assert "softprops/action-gh-release" not in text
    assert "gh release create" not in text
    assert "gh release upload" not in text
    assert "gh release edit" not in text


def test_apt_publish_recovery_is_tag_only() -> None:
    text = _apt_publish()
    header = _on_block(text)
    assert "workflow_dispatch:" in header
    assert "inputs:" in header
    assert "tag:" in header
    assert "--mode recovery" in text
    assert "--requested-tag" in text
    assert "github.event.inputs.tag" in text
    assert "--mode workflow_run" in text
    assert "python3 scripts/verify-github-release.py" in text
    assert header.count("type: string") == 1


def test_apt_signing_secrets_are_not_in_ci_or_pr_workflows() -> None:
    ci = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    release = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
    apt = _apt_publish()
    for text in (ci, release):
        assert "APT_SIGNING_KEY" not in text
        assert "APT_SIGNING_PASSPHRASE" not in text
        assert "pull_request" in ci
    assert "pull_request" not in apt
    assert "APT_SIGNING_KEY" in apt
    assert "APT_SIGNING_PASSPHRASE" in apt
    assert "ghp_" not in apt
    assert "-----BEGIN PGP PRIVATE KEY BLOCK-----" not in apt
    assert "pages: write" in apt
    assert "id-token: write" in apt
    assert "if: always()" in apt
    assert "apt-key add" not in apt


def test_apt_publish_verifies_release_asset_before_signing() -> None:
    text = _apt_publish()
    verify = text.index("Verify Release tag, GitHub Release, and exact .deb")
    signing = text.index("secrets.APT_SIGNING_KEY")
    generate = text.index("Generate signed repository")
    deploy = text.index("Deploy GitHub Pages")
    assert verify < signing
    assert verify < generate
    assert generate < deploy
    assert signing < deploy
    assert "scripts/verify-github-release.py" in text
    assert generate < text.index("actions/upload-pages-artifact")
    assert generate < text.index("actions/deploy-pages")
    assert "umask 077" in text
    assert "--passphrase-file" in text
    assert "--passphrase " not in text.replace("--passphrase-file", "")
    assert "if: always()" in text
    assert "GITHUB_TOKEN" in text.split("Generate signed repository", 1)[0]


def test_apt_publish_pages_deploy_is_after_signed_generation() -> None:
    text = _apt_publish()
    generate = text.index("python3 scripts/apt_repo.py")
    inrelease = text.index("site/apt/dists/noble/InRelease")
    upload = text.index("actions/upload-pages-artifact")
    deploy = text.index("actions/deploy-pages")
    assert generate < inrelease < upload < deploy
    assert "Configure GitHub Pages" in text[inrelease:]


def test_apt_publish_uses_verified_tag_not_github_ref() -> None:
    text = _apt_publish()
    verify = text.index("Verify Release tag, GitHub Release, and exact .deb")
    consistency = text.index("Version-consistency against triggering package")
    signing = text.index("secrets.APT_SIGNING_KEY")
    assert verify < consistency < signing
    assert '--expected-tag "${TAG}"' in text or '--expected-tag "${TAG}"' in text
    assert "steps.release.outputs.tag" in text
    assert "--root tagged-src" in text
    assert "python3 scripts/check-version-consistency.py" in text
    assert "python3 tagged-src/scripts/check-version-consistency.py" not in text
    assert "verified release outputs are missing" in text
    assert "GITHUB_REF_TYPE" not in text
    assert "GITHUB_REF_NAME" not in text
    assert "--require-tag" in text
