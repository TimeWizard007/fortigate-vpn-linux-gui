#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Fail closed when application, packaging, and optional git tag versions diverge."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE_NAME = "fortigate-vpn-linux-gui"


class VersionError(RuntimeError):
    """Version metadata is inconsistent."""


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def application_version() -> str:
    match = re.search(
        r'^__version__ = "([0-9]+\.[0-9]+\.[0-9]+)"$',
        _read(ROOT / "src" / "fortigate_vpn_gui" / "__init__.py"),
        re.MULTILINE,
    )
    if match is None:
        raise VersionError("could not read src package version")
    return match.group(1)


def pyproject_version() -> str:
    match = re.search(
        r'^version = "([0-9]+\.[0-9]+\.[0-9]+)"$',
        _read(ROOT / "pyproject.toml"),
        re.MULTILINE,
    )
    if match is None:
        raise VersionError("could not read pyproject.toml version")
    return match.group(1)


def debian_control_version() -> str:
    match = re.search(
        r"^Version: ([0-9]+\.[0-9]+\.[0-9]+-[0-9]+)$",
        _read(ROOT / "packaging" / "debian" / "control"),
        re.MULTILINE,
    )
    if match is None:
        raise VersionError("could not read debian/control Version")
    return match.group(1)


def debian_changelog_version() -> str:
    first = _read(ROOT / "packaging" / "debian" / "changelog").splitlines()[0]
    match = re.match(rf"^{re.escape(PACKAGE_NAME)} \(([0-9]+\.[0-9]+\.[0-9]+-[0-9]+)\) ", first)
    if match is None:
        raise VersionError("could not read debian/changelog version")
    return match.group(1)


def build_script_versions() -> tuple[str, str]:
    text = _read(ROOT / "scripts" / "build-deb.sh")
    version = re.search(r'^VERSION="([0-9]+\.[0-9]+\.[0-9]+)"$', text, re.MULTILINE)
    revision = re.search(r'^REVISION="([0-9]+)"$', text, re.MULTILINE)
    if version is None or revision is None:
        raise VersionError("could not read scripts/build-deb.sh VERSION/REVISION")
    return version.group(1), revision.group(1)


def split_debian_version(value: str) -> tuple[str, str]:
    if "-" not in value:
        raise VersionError(f"Debian version is not upstream-revision: {value}")
    upstream, revision = value.rsplit("-", 1)
    return upstream, revision


def detect_release_tag() -> str | None:
    if os.environ.get("GITHUB_REF_TYPE") == "tag":
        name = (os.environ.get("GITHUB_REF_NAME") or "").strip()
        return name or None
    ref = (os.environ.get("GITHUB_REF") or "").strip()
    if ref.startswith("refs/tags/"):
        return ref.rsplit("/", 1)[-1]
    try:
        return subprocess.check_output(
            ["git", "describe", "--tags", "--exact-match", "HEAD"],
            cwd=ROOT,
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip() or None
    except (OSError, subprocess.CalledProcessError):
        return None


def debian_package_version_from_deb(path: Path) -> str:
    try:
        output = subprocess.check_output(
            ["dpkg-deb", "-f", str(path), "Version"],
            text=True,
        ).strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise VersionError(f"could not read package Version from {path}") from exc
    if not output:
        raise VersionError(f"empty package Version in {path}")
    return output


def collect_versions() -> dict[str, str]:
    app = application_version()
    pyproject = pyproject_version()
    control = debian_control_version()
    changelog = debian_changelog_version()
    script_version, script_revision = build_script_versions()
    control_upstream, control_revision = split_debian_version(control)
    changelog_upstream, changelog_revision = split_debian_version(changelog)
    return {
        "application": app,
        "pyproject": pyproject,
        "debian_control": control,
        "debian_changelog": changelog,
        "build_script": f"{script_version}-{script_revision}",
        "control_upstream": control_upstream,
        "control_revision": control_revision,
        "changelog_upstream": changelog_upstream,
        "changelog_revision": changelog_revision,
        "script_version": script_version,
        "script_revision": script_revision,
    }


def validate(*, require_tag: bool = False, deb: Path | None = None) -> list[str]:
    versions = collect_versions()
    errors: list[str] = []
    app = versions["application"]
    if versions["pyproject"] != app:
        errors.append(
            f"pyproject.toml version {versions['pyproject']} != application {app}"
        )
    expected_deb = f"{app}-1"
    for label in ("debian_control", "debian_changelog", "build_script"):
        if versions[label] != expected_deb:
            errors.append(f"{label} {versions[label]} != expected {expected_deb}")
    if versions["script_version"] != app:
        errors.append(
            f"build-deb.sh VERSION {versions['script_version']} != application {app}"
        )
    tag = detect_release_tag()
    if tag:
        expected_tag = f"v{app}"
        if tag != expected_tag:
            errors.append(f"git tag {tag} != expected {expected_tag}")
    elif require_tag:
        errors.append("a vX.Y.Z git tag is required for this release check")
    if deb is not None:
        package_version = debian_package_version_from_deb(deb)
        if package_version != expected_deb:
            errors.append(f"package {deb.name} Version {package_version} != {expected_deb}")
        expected_name = f"{PACKAGE_NAME}_{expected_deb}_amd64.deb"
        if deb.name != expected_name:
            errors.append(f"package filename {deb.name} != {expected_name}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--require-tag",
        action="store_true",
        help="fail when HEAD / GITHUB_REF is not the matching vX.Y.Z tag",
    )
    parser.add_argument("--deb", type=Path, help="built .deb to check against source versions")
    args = parser.parse_args(argv)
    try:
        errors = validate(require_tag=args.require_tag, deb=args.deb)
    except VersionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if errors:
        for item in errors:
            print(f"error: {item}", file=sys.stderr)
        return 1
    versions = collect_versions()
    print(f"application {versions['application']}")
    print(f"debian {versions['debian_control']}")
    tag = detect_release_tag()
    if tag:
        print(f"tag {tag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
