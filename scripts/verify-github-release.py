#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Fail closed unless a completed Release workflow has a matching stable .deb."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

STABLE_TAG_RE = re.compile(r"^v([0-9]+)\.([0-9]+)\.([0-9]+)$")
PACKAGE_NAME = "fortigate-vpn-linux-gui"
DEBIAN_REVISION = "1"
ARCH = "amd64"
RELEASE_WORKFLOW_NAME = "Release"
REQUIRED_RUN_EVENT = "push"


class ReleaseVerifyError(RuntimeError):
    """The triggering GitHub Release cannot be used for APT publishing."""


def parse_stable_tag(value: str) -> str | None:
    """Return *value* when it is a stable ``vX.Y.Z`` tag, otherwise None."""
    text = str(value or "").strip()
    if text.startswith("refs/tags/"):
        text = text[len("refs/tags/") :]
    if STABLE_TAG_RE.fullmatch(text) is None:
        return None
    return text


def parse_recovery_tag(value: str) -> str | None:
    """Accept only a bare stable ``vX.Y.Z`` tag. Refs, branches, and SHAs fail."""
    text = str(value or "").strip()
    if STABLE_TAG_RE.fullmatch(text) is None:
        return None
    return text


def require_recovery_tag(value: str) -> str:
    parsed = parse_recovery_tag(value)
    if parsed is None:
        raise ReleaseVerifyError(f"recovery tag {value!r} is not a stable vX.Y.Z tag")
    return parsed


def application_version_from_tag(tag: str) -> str:
    parsed = parse_stable_tag(tag)
    if parsed is None:
        raise ReleaseVerifyError(f"not a stable vX.Y.Z tag: {tag}")
    return parsed[1:]


def debian_version_from_tag(tag: str) -> str:
    return f"{application_version_from_tag(tag)}-{DEBIAN_REVISION}"


def expected_deb_filename(tag: str) -> str:
    return f"{PACKAGE_NAME}_{debian_version_from_tag(tag)}_{ARCH}.deb"


def validate_workflow_run(
    *,
    name: str,
    event: str,
    conclusion: str,
) -> None:
    """Reject failed, cancelled, or non-Release runs. Tag resolution is separate."""
    if name != RELEASE_WORKFLOW_NAME:
        raise ReleaseVerifyError(f"unexpected workflow {name!r}")
    if event != REQUIRED_RUN_EVENT:
        raise ReleaseVerifyError(f"Release workflow event {event!r} is not a tag push")
    if conclusion != "success":
        raise ReleaseVerifyError(f"Release workflow conclusion is {conclusion!r}, not success")


def validate_release_document(payload: object, tag: str) -> str:
    """Return the expected .deb asset name. Drafts, prereleases, and missing assets fail."""
    if not isinstance(payload, dict):
        raise ReleaseVerifyError("malformed GitHub Release response")
    if payload.get("draft") is True:
        raise ReleaseVerifyError(f"GitHub Release {tag} is a draft")
    if payload.get("prerelease") is True:
        raise ReleaseVerifyError(f"GitHub Release {tag} is a prerelease")
    remote_tag = str(payload.get("tag_name") or "").strip()
    if parse_stable_tag(remote_tag) != tag:
        raise ReleaseVerifyError(f"GitHub Release tag {remote_tag!r} != {tag}")
    expected = expected_deb_filename(tag)
    assets = payload.get("assets")
    if not isinstance(assets, list):
        raise ReleaseVerifyError(f"GitHub Release {tag} has no asset list")
    names = [str(item.get("name") or "") for item in assets if isinstance(item, dict)]
    if expected not in names:
        raise ReleaseVerifyError(f"GitHub Release {tag} is missing required asset {expected}")
    return expected


def peel_to_commit_sha(payload: object, *, allow_tag_object: bool = False) -> tuple[str, str]:
    if not isinstance(payload, dict):
        raise ReleaseVerifyError("malformed git object response")
    obj = payload.get("object")
    if not isinstance(obj, dict):
        raise ReleaseVerifyError("git object is missing")
    sha = str(obj.get("sha") or "").strip()
    kind = str(obj.get("type") or "").strip()
    if not sha:
        raise ReleaseVerifyError("git object SHA is empty")
    if kind == "commit":
        return sha, kind
    if allow_tag_object and kind == "tag":
        return sha, kind
    raise ReleaseVerifyError(f"unsupported git object type {kind!r}")


def github_api_json(url: str, *, token: str) -> Any:
    request = Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "fortigate-vpn-linux-gui-apt-publish",
            "Authorization": f"Bearer {token}",
        },
        method="GET",
    )
    try:
        with urlopen(request, timeout=30) as response:  # noqa: S310 — HTTPS GitHub API
            if int(getattr(response, "status", 0) or 0) != 200:
                raise ReleaseVerifyError(f"GitHub API HTTP {getattr(response, 'status', 0)}")
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        if exc.code == 404:
            raise ReleaseVerifyError("GitHub Release or git tag was not found") from exc
        raise ReleaseVerifyError(f"GitHub API HTTP {exc.code}") from exc
    except (URLError, TimeoutError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ReleaseVerifyError("unable to query GitHub Release API") from exc


def resolve_tag_commit_sha(*, repository: str, tag: str, token: str) -> str:
    ref = github_api_json(
        f"https://api.github.com/repos/{repository}/git/ref/tags/{tag}",
        token=token,
    )
    sha, kind = peel_to_commit_sha(ref, allow_tag_object=True)
    if kind == "commit":
        return sha
    annotated = github_api_json(
        f"https://api.github.com/repos/{repository}/git/tags/{sha}",
        token=token,
    )
    commit_sha, _kind = peel_to_commit_sha(annotated, allow_tag_object=False)
    return commit_sha


def load_release(*, repository: str, tag: str, token: str) -> dict[str, Any]:
    payload = github_api_json(
        f"https://api.github.com/repos/{repository}/releases/tags/{tag}",
        token=token,
    )
    if not isinstance(payload, dict):
        raise ReleaseVerifyError("malformed GitHub Release response")
    return payload


def _load_apt_repo():
    path = Path(__file__).resolve().with_name("apt_repo.py")
    spec = importlib.util.spec_from_file_location("apt_repo", path)
    if spec is None or spec.loader is None:
        raise ReleaseVerifyError("unable to load apt_repo.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify_local_deb(deb_path: Path, tag: str) -> None:
    expected_version = debian_version_from_tag(tag)
    expected_name = expected_deb_filename(tag)
    if deb_path.name != expected_name:
        raise ReleaseVerifyError(f"local package {deb_path.name} != {expected_name}")
    apt_repo = _load_apt_repo()
    try:
        _package, version, _arch = apt_repo.validate_deb_identity(deb_path)
    except apt_repo.AptRepoError as exc:
        raise ReleaseVerifyError(str(exc)) from exc
    if version != expected_version:
        raise ReleaseVerifyError(
            f"package Version {version} != expected {expected_version} for {tag}"
        )


def _gh_download(tag: str, dest: Path, pattern: str) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    completed = subprocess.run(
        [
            "gh",
            "release",
            "download",
            tag,
            "--pattern",
            pattern,
            "--dir",
            str(dest),
            "--clobber",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise ReleaseVerifyError(f"failed to download {pattern} from release {tag}")


def stable_release_tags(payload: object) -> list[str]:
    if not isinstance(payload, list):
        raise ReleaseVerifyError("malformed GitHub releases list")
    tags: list[str] = []
    for release in payload:
        if not isinstance(release, dict):
            continue
        if release.get("draft") or release.get("prerelease"):
            continue
        tag = parse_stable_tag(str(release.get("tag_name") or ""))
        if tag is None:
            continue
        try:
            validate_release_document(release, tag)
        except ReleaseVerifyError:
            continue
        tags.append(tag)
    return tags


def matching_stable_tags_for_sha(*, repository: str, sha: str, token: str) -> list[str]:
    refs = github_api_json(
        f"https://api.github.com/repos/{repository}/git/matching-refs/tags/v",
        token=token,
    )
    if not isinstance(refs, list):
        raise ReleaseVerifyError("malformed git matching-refs response")
    found: list[str] = []
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        tag = parse_stable_tag(str(ref.get("ref") or ""))
        if tag is None:
            continue
        try:
            commit = resolve_tag_commit_sha(repository=repository, tag=tag, token=token)
        except ReleaseVerifyError:
            continue
        if commit == sha:
            found.append(tag)
    return found


def resolve_release_tag(
    *,
    head_branch: str,
    head_sha: str,
    repository: str,
    token: str,
) -> tuple[str, str]:
    """Resolve the immutable tag and commit. Branch names never qualify."""
    expected_sha = str(head_sha or "").strip()
    if not expected_sha:
        raise ReleaseVerifyError("workflow run head_sha is empty")
    from_branch = parse_stable_tag(head_branch)
    if from_branch is not None:
        commit = resolve_tag_commit_sha(repository=repository, tag=from_branch, token=token)
        if commit != expected_sha:
            raise ReleaseVerifyError(
                f"tag {from_branch} commit {commit} != workflow head_sha {expected_sha}"
            )
        return from_branch, commit
    if str(head_branch or "").strip():
        raise ReleaseVerifyError(f"head_branch {head_branch!r} is not a stable vX.Y.Z tag")
    matches = matching_stable_tags_for_sha(
        repository=repository, sha=expected_sha, token=token
    )
    if len(matches) != 1:
        raise ReleaseVerifyError(
            f"could not uniquely resolve a stable vX.Y.Z tag for SHA {expected_sha}"
        )
    return matches[0], expected_sha


def download_stable_debs(*, repository: str, token: str, dest: Path, required_tag: str) -> None:
    os.environ.setdefault("GH_TOKEN", token)
    os.environ.setdefault("GITHUB_TOKEN", token)
    _gh_download(required_tag, dest, expected_deb_filename(required_tag))
    payload = github_api_json(
        f"https://api.github.com/repos/{repository}/releases?per_page=100",
        token=token,
    )
    for tag in stable_release_tags(payload):
        if tag == required_tag:
            continue
        try:
            _gh_download(tag, dest, expected_deb_filename(tag))
        except ReleaseVerifyError:
            continue


def verify_existing_release(*, repository: str, tag: str, token: str, dest: Path) -> tuple[str, str]:
    """Shared fail-closed path: existing tag + published Release + exact .deb."""
    commit_sha = resolve_tag_commit_sha(repository=repository, tag=tag, token=token)
    release = load_release(repository=repository, tag=tag, token=token)
    expected = validate_release_document(release, tag)
    dest.mkdir(parents=True, exist_ok=True)
    download_stable_debs(
        repository=repository,
        token=token,
        dest=dest,
        required_tag=tag,
    )
    local_deb = dest / expected
    if not local_deb.is_file():
        raise ReleaseVerifyError(f"triggering asset {expected} was not downloaded")
    verify_local_deb(local_deb, tag)
    return commit_sha, expected


def write_github_output(path: Path, values: dict[str, str]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        for key, value in values.items():
            handle.write(f"{key}={value}\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("workflow_run", "recovery"), required=True)
    parser.add_argument("--requested-tag")
    parser.add_argument("--head-branch")
    parser.add_argument("--head-sha")
    parser.add_argument("--run-event")
    parser.add_argument("--run-name")
    parser.add_argument("--run-conclusion")
    parser.add_argument("--repository", required=True)
    parser.add_argument("--download-dir", type=Path, required=True)
    parser.add_argument(
        "--github-output",
        type=Path,
        default=(Path(os.environ["GITHUB_OUTPUT"]) if os.environ.get("GITHUB_OUTPUT") else None),
    )
    args = parser.parse_args(argv)
    token = (os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or "").strip()
    if not token:
        print("error: GITHUB_TOKEN is required", file=sys.stderr)
        return 1
    try:
        if args.mode == "recovery":
            if not args.requested_tag:
                raise ReleaseVerifyError("recovery mode requires --requested-tag")
            tag = require_recovery_tag(args.requested_tag)
        else:
            if args.head_sha is None or args.run_event is None or args.run_name is None or args.run_conclusion is None:
                raise ReleaseVerifyError("workflow_run mode requires run identity arguments")
            validate_workflow_run(
                name=args.run_name,
                event=args.run_event,
                conclusion=args.run_conclusion,
            )
            tag, _resolved = resolve_release_tag(
                head_branch=args.head_branch or "",
                head_sha=args.head_sha,
                repository=args.repository,
                token=token,
            )
        commit_sha, expected = verify_existing_release(
            repository=args.repository,
            tag=tag,
            token=token,
            dest=args.download_dir,
        )
        if args.mode == "workflow_run" and commit_sha != str(args.head_sha or "").strip():
            raise ReleaseVerifyError(
                f"tag {tag} commit {commit_sha} != workflow head_sha {args.head_sha}"
            )
    except ReleaseVerifyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.github_output is not None:
        write_github_output(
            args.github_output,
            {
                "tag": tag,
                "sha": commit_sha,
                "deb": expected,
                "app_version": application_version_from_tag(tag),
                "debian_version": debian_version_from_tag(tag),
            },
        )
    print(f"tag {tag}")
    print(f"sha {commit_sha}")
    print(f"deb {expected}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
