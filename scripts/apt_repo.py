#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Generate a static signed APT repository. Never prints private key material."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import os
import re
import stat
import subprocess
import sys
import time
from email.utils import formatdate
from pathlib import Path

PACKAGE_NAME = "fortigate-vpn-linux-gui"
CODENAME = "noble"
COMPONENT = "main"
ARCH = "amd64"
ORIGIN = "FortiGate VPN Linux GUI"
LABEL = "fortigate-vpn-linux-gui"
DESCRIPTION = "FortiGate VPN Linux GUI packages for Ubuntu 24.04 amd64"
PUBLIC_KEY_NAME = "fortigate-vpn-linux-gui.gpg"
DEBIAN_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+-[0-9]+$")

FORBIDDEN_OUTPUT_MARKERS = (
    "BEGIN PGP PRIVATE KEY BLOCK",
    "BEGIN OPENSSH PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "GITHUB_TOKEN=",
    "ghp_",
)


class AptRepoError(RuntimeError):
    """Repository generation failed."""


def pool_relative_path(filename: str) -> Path:
    return Path("pool") / COMPONENT / "f" / PACKAGE_NAME / filename


def dists_binary_dir() -> Path:
    return Path("dists") / CODENAME / COMPONENT / f"binary-{ARCH}"


def release_dir() -> Path:
    return Path("dists") / CODENAME


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _md5(data: bytes) -> str:
    return hashlib.md5(data, usedforsecurity=False).hexdigest()


def _sha1(data: bytes) -> str:
    return hashlib.sha1(data, usedforsecurity=False).hexdigest()


def _run(argv: list[str], *, env: dict[str, str] | None = None, cwd: Path | None = None) -> str:
    try:
        completed = subprocess.run(
            argv,
            check=True,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError as exc:
        raise AptRepoError(f"missing command: {argv[0]}") from exc
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or "").strip()
        raise AptRepoError(f"{argv[0]} failed: {detail}") from exc
    combined = f"{completed.stdout}\n{completed.stderr}"
    for marker in FORBIDDEN_OUTPUT_MARKERS:
        if marker in combined:
            raise AptRepoError("refusing to continue: private material appeared in command output")
    return completed.stdout


def deb_identity(deb_path: Path) -> tuple[str, str, str]:
    """Return ``(Package, Version, Architecture)`` from *deb_path*. Fail closed."""
    if deb_path.suffix != ".deb" or not deb_path.is_file():
        raise AptRepoError(f"not a .deb file: {deb_path}")
    try:
        package = _run(["dpkg-deb", "-f", str(deb_path), "Package"]).strip()
        version = _run(["dpkg-deb", "-f", str(deb_path), "Version"]).strip()
        architecture = _run(["dpkg-deb", "-f", str(deb_path), "Architecture"]).strip()
    except AptRepoError as exc:
        raise AptRepoError(f"malformed Debian package {deb_path.name}: {exc}") from exc
    return package, version, architecture


def validate_deb_identity(deb_path: Path) -> tuple[str, str, str]:
    """Reject unrelated, wrong-architecture, or malformed packages."""
    package, version, architecture = deb_identity(deb_path)
    if package != PACKAGE_NAME:
        raise AptRepoError(f"unexpected Package {package!r} in {deb_path.name}")
    if architecture != ARCH:
        raise AptRepoError(f"unexpected Architecture {architecture!r} in {deb_path.name}")
    if DEBIAN_VERSION_RE.fullmatch(version) is None:
        raise AptRepoError(f"malformed Debian Version {version!r} in {deb_path.name}")
    expected_name = f"{PACKAGE_NAME}_{version}_{ARCH}.deb"
    if deb_path.name != expected_name:
        raise AptRepoError(f"package filename {deb_path.name} != {expected_name}")
    return package, version, architecture


def add_deb(repo_root: Path, deb_path: Path) -> Path:
    """Copy *deb_path* into pool/. Existing different files are kept; same name must match."""
    validate_deb_identity(deb_path)
    dest = repo_root / pool_relative_path(deb_path.name)
    dest.parent.mkdir(parents=True, exist_ok=True)
    incoming = deb_path.read_bytes()
    if dest.is_file():
        if dest.read_bytes() != incoming:
            raise AptRepoError(
                f"refusing to replace existing {dest.name} with different contents"
            )
        return dest
    dest.write_bytes(incoming)
    dest.chmod(0o644)
    return dest


def list_pool_debs(repo_root: Path) -> list[Path]:
    pool = repo_root / "pool"
    if not pool.is_dir():
        return []
    return sorted(path for path in pool.rglob("*.deb") if path.is_file())


def _control_fields(deb_path: Path) -> str:
    text = _run(["dpkg-deb", "-f", str(deb_path)]).strip() + "\n"
    if "Package:" not in text or "Version:" not in text:
        raise AptRepoError(f"incomplete control metadata in {deb_path.name}")
    return text


def packages_stanza(repo_root: Path, deb_path: Path) -> str:
    body = _control_fields(deb_path)
    data = deb_path.read_bytes()
    relative = deb_path.resolve().relative_to(repo_root.resolve()).as_posix()
    extra = (
        f"Filename: {relative}\n"
        f"Size: {len(data)}\n"
        f"MD5sum: {_md5(data)}\n"
        f"SHA1: {_sha1(data)}\n"
        f"SHA256: {_sha256(data)}\n"
    )
    return body.rstrip() + "\n" + extra


def write_packages(repo_root: Path) -> Path:
    packages_dir = repo_root / dists_binary_dir()
    packages_dir.mkdir(parents=True, exist_ok=True)
    stanzas = [packages_stanza(repo_root, path) for path in list_pool_debs(repo_root)]
    packages_path = packages_dir / "Packages"
    packages_path.write_text("\n".join(stanzas).rstrip() + ("\n" if stanzas else ""), encoding="utf-8")
    gz_path = packages_dir / "Packages.gz"
    gz_path.write_bytes(gzip.compress(packages_path.read_bytes(), mtime=0, compresslevel=9))
    release_component = packages_dir / "Release"
    release_component.write_text(
        (
            f"Archive: {CODENAME}\n"
            f"Component: {COMPONENT}\n"
            f"Origin: {ORIGIN}\n"
            f"Label: {LABEL}\n"
            f"Architecture: {ARCH}\n"
        ),
        encoding="utf-8",
    )
    return packages_path


def _hash_block(label: str, files: list[Path], repo_root: Path) -> str:
    lines = [f"{label}:"]
    for path in files:
        data = path.read_bytes()
        digest = {
            "MD5Sum": _md5,
            "SHA1": _sha1,
            "SHA256": _sha256,
        }[label](data)
        relative = path.resolve().relative_to((repo_root / release_dir()).resolve()).as_posix()
        lines.append(f" {digest} {len(data):>16} {relative}")
    return "\n".join(lines)


def write_release(repo_root: Path, *, now: float | None = None) -> Path:
    write_packages(repo_root)
    dist = repo_root / release_dir()
    hashed = [
        dist / COMPONENT / f"binary-{ARCH}" / name
        for name in ("Packages", "Packages.gz", "Release")
    ]
    date = formatdate(timeval=time.time() if now is None else now, usegmt=True)
    body = (
        f"Origin: {ORIGIN}\n"
        f"Label: {LABEL}\n"
        f"Suite: {CODENAME}\n"
        f"Codename: {CODENAME}\n"
        f"Date: {date}\n"
        f"Architectures: {ARCH}\n"
        f"Components: {COMPONENT}\n"
        f"Description: {DESCRIPTION}\n"
        f"Acquire-By-Hash: no\n"
        f"{_hash_block('MD5Sum', hashed, repo_root)}\n"
        f"{_hash_block('SHA1', hashed, repo_root)}\n"
        f"{_hash_block('SHA256', hashed, repo_root)}\n"
    )
    path = dist / "Release"
    path.write_text(body, encoding="utf-8")
    return path


def gpg_argv(
    *,
    homedir: Path,
    output: Path,
    source: Path,
    mode: str,
    passphrase_file: Path | None,
    key_id: str | None = None,
) -> list[str]:
    """Build a gpg command. Passphrase is never placed on the command line."""
    if mode not in {"detach", "clearsign", "export"}:
        raise AptRepoError(f"unsupported gpg mode: {mode}")
    argv = [
        "gpg",
        "--homedir",
        str(homedir),
        "--batch",
        "--yes",
        "--pinentry-mode",
        "loopback",
        "--trust-model",
        "always",
    ]
    if passphrase_file is not None:
        argv.extend(["--passphrase-file", str(passphrase_file)])
    if key_id:
        argv.extend(["--local-user", key_id])
    if mode == "detach":
        argv.extend(["--armor", "--detach-sign", "--output", str(output), str(source)])
    elif mode == "clearsign":
        argv.extend(["--clearsign", "--output", str(output), str(source)])
    else:
        argv.extend(["--armor", "--export", "--output", str(output)])
        if key_id:
            argv.append(key_id)
    if any(part.startswith("--passphrase=") or part == "--passphrase" for part in argv):
        raise AptRepoError("refusing to put a passphrase on the gpg command line")
    return argv


def sign_release(
    repo_root: Path,
    *,
    homedir: Path,
    passphrase_file: Path | None = None,
    key_id: str | None = None,
) -> tuple[Path, Path]:
    release = repo_root / release_dir() / "Release"
    if not release.is_file():
        raise AptRepoError("Release file is missing; generate the repository first")
    detached = repo_root / release_dir() / "Release.gpg"
    inrelease = repo_root / release_dir() / "InRelease"
    env = os.environ.copy()
    env["GNUPGHOME"] = str(homedir)
    env.pop("GPG_TTY", None)
    _run(
        gpg_argv(
            homedir=homedir,
            output=detached,
            source=release,
            mode="detach",
            passphrase_file=passphrase_file,
            key_id=key_id,
        ),
        env=env,
    )
    _run(
        gpg_argv(
            homedir=homedir,
            output=inrelease,
            source=release,
            mode="clearsign",
            passphrase_file=passphrase_file,
            key_id=key_id,
        ),
        env=env,
    )
    return detached, inrelease


def export_public_key(
    repo_root: Path,
    *,
    homedir: Path,
    key_id: str | None = None,
    passphrase_file: Path | None = None,
) -> Path:
    dest = repo_root / PUBLIC_KEY_NAME
    env = os.environ.copy()
    env["GNUPGHOME"] = str(homedir)
    _run(
        gpg_argv(
            homedir=homedir,
            output=dest,
            source=dest,
            mode="export",
            passphrase_file=passphrase_file,
            key_id=key_id,
        ),
        env=env,
    )
    text = dest.read_text(encoding="utf-8")
    if "BEGIN PGP PUBLIC KEY BLOCK" not in text:
        raise AptRepoError("exported repository key is not an OpenPGP public key")
    if "BEGIN PGP PRIVATE KEY BLOCK" in text:
        dest.unlink(missing_ok=True)
        raise AptRepoError("refusing to publish a private key")
    dest.chmod(0o644)
    return dest


def write_index(repo_root: Path) -> Path:
    path = repo_root / "index.html"
    path.write_text(
        (
            "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<title>FortiGate VPN Linux GUI APT</title></head><body>"
            "<h1>FortiGate VPN Linux GUI APT repository</h1>"
            "<p>This is a static Debian repository for Ubuntu 24.04 (noble) amd64. "
            "See the project README for signed-by installation. The GUI never "
            "installs packages itself.</p>"
            f"<p>Public key: <a href=\"{PUBLIC_KEY_NAME}\">{PUBLIC_KEY_NAME}</a></p>"
            "</body></html>\n"
        ),
        encoding="utf-8",
    )
    return path


def import_secret_key(homedir: Path, key_file: Path) -> None:
    homedir.mkdir(parents=True, exist_ok=True)
    homedir.chmod(stat.S_IRWXU)
    env = os.environ.copy()
    env["GNUPGHOME"] = str(homedir)
    _run(
        ["gpg", "--homedir", str(homedir), "--batch", "--import", str(key_file)],
        env=env,
    )


def generate(
    repo_root: Path,
    debs: list[Path],
    *,
    sign: bool,
    homedir: Path | None = None,
    passphrase_file: Path | None = None,
    key_id: str | None = None,
) -> None:
    repo_root.mkdir(parents=True, exist_ok=True)
    for deb in debs:
        add_deb(repo_root, deb)
    pool_debs = list_pool_debs(repo_root)
    if not pool_debs:
        raise AptRepoError("repository has no .deb files in pool/")
    for path in pool_debs:
        validate_deb_identity(path)
    write_release(repo_root)
    write_index(repo_root)
    if sign:
        if homedir is None:
            raise AptRepoError("signing requires a GnuPG homedir")
        sign_release(
            repo_root,
            homedir=homedir,
            passphrase_file=passphrase_file,
            key_id=key_id,
        )
        export_public_key(
            repo_root,
            homedir=homedir,
            key_id=key_id,
            passphrase_file=passphrase_file,
        )


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--deb", type=Path, action="append", default=[], dest="debs")
    parser.add_argument("--sign", action="store_true")
    parser.add_argument("--gnupg-home", type=Path)
    parser.add_argument("--passphrase-file", type=Path)
    parser.add_argument("--key-id")
    parser.add_argument("--import-key", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        if args.import_key is not None:
            if args.gnupg_home is None:
                raise AptRepoError("--import-key requires --gnupg-home")
            import_secret_key(args.gnupg_home, args.import_key)
        generate(
            args.repo_root,
            args.debs,
            sign=args.sign,
            homedir=args.gnupg_home,
            passphrase_file=args.passphrase_file,
            key_id=args.key_id,
        )
    except AptRepoError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(args.repo_root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
