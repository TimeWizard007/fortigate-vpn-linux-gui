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
STABLE_TAG_RE = re.compile(r"^v([0-9]+)\.([0-9]+)\.([0-9]+)$")
ARCH = "amd64"


class VersionError(RuntimeError):
    """Version metadata is inconsistent."""


def configure_root(path: Path) -> None:
    """Read version metadata from *path* instead of this script's repository root."""
    global ROOT
    ROOT = path.resolve()


def parse_stable_tag(value: str) -> str | None:
    """Return *value* when it is a stable ``vX.Y.Z`` tag, otherwise None."""
    text = str(value or "").strip()
    if STABLE_TAG_RE.fullmatch(text) is None:
        return None
    return text


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


def debian_package_fields(path: Path) -> tuple[str, str, str]:
    """Return ``(Package, Version, Architecture)`` from *path*. Fail closed."""
    try:
        package = subprocess.check_output(
            ["dpkg-deb", "-f", str(path), "Package"], text=True
        ).strip()
        version = subprocess.check_output(
            ["dpkg-deb", "-f", str(path), "Version"], text=True
        ).strip()
        architecture = subprocess.check_output(
            ["dpkg-deb", "-f", str(path), "Architecture"], text=True
        ).strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise VersionError(f"could not read package identity from {path}") from exc
    if not package or not version or not architecture:
        raise VersionError(f"incomplete package identity in {path}")
    return package, version, architecture


def debian_package_version_from_deb(path: Path) -> str:
    _package, version, _architecture = debian_package_fields(path)
    return version


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


def resolve_checked_tag(*, require_tag: bool, expected_tag: str | None) -> tuple[str | None, list[str]]:
    """Return the tag used for consistency, preferring an explicit verified tag."""
    errors: list[str] = []
    if expected_tag is not None:
        parsed = parse_stable_tag(expected_tag)
        if parsed is None:
            errors.append(f"expected-tag {expected_tag!r} is not a stable vX.Y.Z tag")
            return None, errors
        return parsed, errors
    tag = detect_release_tag()
    if tag:
        return tag, errors
    if require_tag:
        errors.append("a vX.Y.Z git tag is required for this release check")
    return None, errors


def validate(
    *,
    require_tag: bool = False,
    deb: Path | None = None,
    expected_tag: str | None = None,
) -> list[str]:
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
    tag, tag_errors = resolve_checked_tag(require_tag=require_tag, expected_tag=expected_tag)
    errors.extend(tag_errors)
    if tag is not None:
        expected = f"v{app}"
        if tag != expected:
            errors.append(f"git tag {tag} != expected {expected}")
    if deb is not None:
        package, package_version, architecture = debian_package_fields(deb)
        if package != PACKAGE_NAME:
            errors.append(f"package {deb.name} Package {package} != {PACKAGE_NAME}")
        if architecture != ARCH:
            errors.append(f"package {deb.name} Architecture {architecture} != {ARCH}")
        if package_version != expected_deb:
            errors.append(f"package {deb.name} Version {package_version} != {expected_deb}")
        expected_name = f"{PACKAGE_NAME}_{expected_deb}_{ARCH}.deb"
        if deb.name != expected_name:
            errors.append(f"package filename {deb.name} != {expected_name}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--require-tag",
        action="store_true",
        help="fail when no matching vX.Y.Z tag is available",
    )
    parser.add_argument(
        "--expected-tag",
        help="authoritative already-verified stable vX.Y.Z tag; preferred over GITHUB_REF",
    )
    parser.add_argument(
        "--root",
        type=Path,
        help="source tree to read application/packaging versions from",
    )
    parser.add_argument("--deb", type=Path, help="built .deb to check against source versions")
    args = parser.parse_args(argv)
    if args.root is not None:
        configure_root(args.root)
    try:
        errors = validate(
            require_tag=args.require_tag,
            deb=args.deb,
            expected_tag=args.expected_tag,
        )
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
    tag, _errors = resolve_checked_tag(
        require_tag=args.require_tag, expected_tag=args.expected_tag
    )
    if tag:
        print(f"tag {tag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
