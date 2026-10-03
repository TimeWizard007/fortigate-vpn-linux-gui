# SPDX-License-Identifier: GPL-3.0-or-later
"""APT repository generation tests. Uses synthetic packages and a local test key."""

from __future__ import annotations

import importlib.util
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load():
    path = ROOT / "scripts" / "apt_repo.py"
    spec = importlib.util.spec_from_file_location("apt_repo", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PRODUCTION_APT_FINGERPRINT = "E0388D37D6E52C7675A933B1AAD0826D6E18C01E"
PRODUCTION_PUBLIC_ASC = ROOT / "packaging" / "apt" / "fortigate-vpn-linux-gui-apt.asc"


def _have_dpkg_deb() -> bool:
    return shutil.which("dpkg-deb") is not None


def _have_gpg() -> bool:
    return shutil.which("gpg") is not None


def _have_apt_get() -> bool:
    return shutil.which("apt-get") is not None


def _gpg_inspect_env(tmp_path: Path) -> dict[str, str]:
    home = tmp_path / "gpg-inspect"
    home.mkdir(exist_ok=True)
    home.chmod(stat.S_IRWXU)
    return {"GNUPGHOME": str(home), "PATH": os.environ.get("PATH", "")}


def _primary_fingerprint(path: Path, tmp_path: Path) -> str:
    env = _gpg_inspect_env(tmp_path)
    completed = subprocess.run(
        [
            "gpg",
            "--homedir",
            env["GNUPGHOME"],
            "--batch",
            "--show-keys",
            "--with-colons",
            str(path),
        ],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )
    fingerprints: list[str] = []
    for line in completed.stdout.splitlines():
        fields = line.split(":")
        if fields and fields[0] == "fpr" and len(fields) > 9 and fields[9]:
            fingerprints.append(fields[9])
    assert fingerprints, f"no fingerprints in {path}"
    return fingerprints[0]


def _assert_binary_public_keyring(path: Path, tmp_path: Path) -> bytes:
    data = path.read_bytes()
    assert data
    assert not data.lstrip().startswith(b"-----")
    assert b"BEGIN PGP PUBLIC KEY BLOCK" not in data
    assert b"BEGIN PGP PRIVATE KEY BLOCK" not in data
    env = _gpg_inspect_env(tmp_path)
    packets = subprocess.run(
        ["gpg", "--homedir", env["GNUPGHOME"], "--batch", "--list-packets", str(path)],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )
    lowered = packets.stdout.lower()
    assert ":secret key packet:" not in lowered
    assert ":secret sub key packet:" not in lowered
    shown = subprocess.run(
        [
            "gpg",
            "--homedir",
            env["GNUPGHOME"],
            "--batch",
            "--show-keys",
            "--with-colons",
            str(path),
        ],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )
    assert "pub:" in shown.stdout
    assert "sec:" not in shown.stdout
    return data


def _make_deb(
    tmp_path: Path,
    version: str,
    *,
    package: str = "fortigate-vpn-linux-gui",
    architecture: str = "amd64",
    filename: str | None = None,
) -> Path:
    staging = tmp_path / f"stage-{package}-{version}-{architecture}"
    debian = staging / "DEBIAN"
    debian.mkdir(parents=True)
    (debian / "control").write_text(
        (
            f"Package: {package}\n"
            f"Version: {version}\n"
            "Section: net\n"
            "Priority: optional\n"
            f"Architecture: {architecture}\n"
            "Maintainer: Test <apt-test@example.invalid>\n"
            "Description: synthetic package for repository tests\n"
        ),
        encoding="utf-8",
    )
    doc = staging / "usr" / "share" / "doc" / package
    doc.mkdir(parents=True)
    (doc / "README").write_text("synthetic\n", encoding="utf-8")
    out = tmp_path / (filename or f"{package}_{version}_{architecture}.deb")
    subprocess.run(
        ["dpkg-deb", "--root-owner-group", "-Zxz", "--build", str(staging), str(out)],
        check=True,
        capture_output=True,
        text=True,
    )
    return out


def _make_gnupg_home(tmp_path: Path) -> Path:
    home = tmp_path / "gnupg"
    home.mkdir()
    home.chmod(stat.S_IRWXU)
    batch = tmp_path / "key.batch"
    batch.write_text(
        "\n".join(
            [
                "%no-protection",
                "Key-Type: EDDSA",
                "Key-Curve: Ed25519",
                "Key-Usage: sign",
                "Name-Real: FVL Test",
                "Name-Email: apt-test@example.invalid",
                "Expire-Date: 0",
                "%commit",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    subprocess.run(
        ["gpg", "--homedir", str(home), "--batch", "--generate-key", str(batch)],
        check=True,
        capture_output=True,
        text=True,
        env={"GNUPGHOME": str(home), "PATH": os.environ.get("PATH", "")},
    )
    return home


@pytest.mark.skipif(not _have_dpkg_deb(), reason="dpkg-deb is required")
def test_pool_packages_release_and_old_versions(tmp_path: Path) -> None:
    module = _load()
    first = _make_deb(tmp_path, "1.4.0-1")
    second = _make_deb(tmp_path, "1.5.0-1")
    repo = tmp_path / "repo"
    module.add_deb(repo, first)
    module.write_release(repo)
    module.add_deb(repo, second)
    module.write_release(repo)
    pool_files = {path.name for path in module.list_pool_debs(repo)}
    assert pool_files == {
        "fortigate-vpn-linux-gui_1.4.0-1_amd64.deb",
        "fortigate-vpn-linux-gui_1.5.0-1_amd64.deb",
    }
    packages = (repo / module.dists_binary_dir() / "Packages").read_text(encoding="utf-8")
    assert "Version: 1.4.0-1" in packages
    assert "Version: 1.5.0-1" in packages
    assert "Filename: pool/main/f/fortigate-vpn-linux-gui/" in packages
    release = (repo / module.release_dir() / "Release").read_text(encoding="utf-8")
    assert "Codename: noble" in release
    assert "SHA256:" in release
    assert "BEGIN PGP PRIVATE KEY BLOCK" not in packages
    assert "BEGIN PGP PRIVATE KEY BLOCK" not in release


def test_signing_command_does_not_embed_passphrase(tmp_path: Path) -> None:
    module = _load()
    passphrase = tmp_path / "pass"
    passphrase.write_text("secret-passphrase\n", encoding="utf-8")
    argv = module.gpg_argv(
        homedir=tmp_path / "gnupg",
        output=tmp_path / "Release.gpg",
        source=tmp_path / "Release",
        mode="detach",
        passphrase_file=passphrase,
        key_id="TESTKEYID",
    )
    joined = " ".join(argv)
    assert "--passphrase-file" in argv
    assert "secret-passphrase" not in joined
    assert "--passphrase" not in argv
    assert not any(part.startswith("--passphrase=") for part in argv)


def test_export_command_writes_binary_keyring(tmp_path: Path) -> None:
    module = _load()
    argv = module.gpg_argv(
        homedir=tmp_path / "gnupg",
        output=tmp_path / "fortigate-vpn-linux-gui.gpg",
        source=tmp_path / "unused",
        mode="export",
        passphrase_file=None,
    )
    assert "--export" in argv
    assert "--no-armor" in argv
    assert "--armor" not in argv
    assert "--output" in argv


@pytest.mark.skipif(not _have_dpkg_deb() or not _have_gpg(), reason="dpkg-deb and gpg are required")
def test_signed_repository_exports_public_key_only(tmp_path: Path) -> None:
    module = _load()
    deb = _make_deb(tmp_path, "1.5.0-1")
    older = _make_deb(tmp_path, "1.4.0-1")
    repo = tmp_path / "repo"
    home = _make_gnupg_home(tmp_path)
    module.generate(repo, [older, deb], sign=True, homedir=home)
    assert (repo / "dists" / "noble" / "InRelease").is_file()
    assert (repo / "dists" / "noble" / "Release.gpg").is_file()
    public_path = repo / module.PUBLIC_KEY_NAME
    assert public_path.is_file()
    _assert_binary_public_keyring(public_path, tmp_path)
    throwaway_fpr = _primary_fingerprint(public_path, tmp_path)
    assert throwaway_fpr != PRODUCTION_APT_FINGERPRINT
    for path in repo.rglob("*"):
        if not path.is_file():
            continue
        text = path.read_bytes()
        assert b"BEGIN PGP PRIVATE KEY BLOCK" not in text
        assert b"BEGIN OPENSSH PRIVATE KEY" not in text
    # A second generate with only the new package must keep the old pool file.
    module.generate(repo, [deb], sign=True, homedir=home)
    names = {path.name for path in module.list_pool_debs(repo)}
    assert "fortigate-vpn-linux-gui_1.4.0-1_amd64.deb" in names
    assert "fortigate-vpn-linux-gui_1.5.0-1_amd64.deb" in names


@pytest.mark.skipif(not _have_gpg(), reason="gpg is required")
def test_production_source_asc_exports_binary_keyring_with_expected_fingerprint(
    tmp_path: Path,
) -> None:
    module = _load()
    text = PRODUCTION_PUBLIC_ASC.read_text(encoding="utf-8")
    assert "BEGIN PGP PUBLIC KEY BLOCK" in text
    assert "BEGIN PGP PRIVATE KEY BLOCK" not in text
    home = tmp_path / "gnupg"
    home.mkdir()
    home.chmod(stat.S_IRWXU)
    subprocess.run(
        [
            "gpg",
            "--homedir",
            str(home),
            "--batch",
            "--import",
            str(PRODUCTION_PUBLIC_ASC),
        ],
        check=True,
        capture_output=True,
        text=True,
        env={"GNUPGHOME": str(home), "PATH": os.environ.get("PATH", "")},
    )
    repo = tmp_path / "repo"
    repo.mkdir()
    exported = module.export_public_key(repo, homedir=home)
    _assert_binary_public_keyring(exported, tmp_path)
    assert _primary_fingerprint(exported, tmp_path) == PRODUCTION_APT_FINGERPRINT


@pytest.mark.skipif(
    not _have_dpkg_deb() or not _have_gpg() or not _have_apt_get(),
    reason="dpkg-deb, gpg, and apt-get are required",
)
def test_binary_keyring_authenticates_signed_repo_with_apt_signed_by(tmp_path: Path) -> None:
    module = _load()
    deb = _make_deb(tmp_path, "1.5.0-1")
    repo = tmp_path / "repo"
    home = _make_gnupg_home(tmp_path)
    module.generate(repo, [deb], sign=True, homedir=home)
    keyring = repo / module.PUBLIC_KEY_NAME
    _assert_binary_public_keyring(keyring, tmp_path)

    apt_root = tmp_path / "apt-root"
    lists = apt_root / "var" / "lib" / "apt" / "lists"
    cache = apt_root / "var" / "cache" / "apt" / "archives"
    dpkg = apt_root / "var" / "lib" / "dpkg"
    log = apt_root / "var" / "log" / "apt"
    etc = apt_root / "etc" / "apt"
    (lists / "partial").mkdir(parents=True)
    (cache / "partial").mkdir(parents=True)
    dpkg.mkdir(parents=True)
    log.mkdir(parents=True)
    (etc / "apt.conf.d").mkdir(parents=True)
    (etc / "preferences.d").mkdir(parents=True)
    (etc / "trusted.gpg.d").mkdir(parents=True)
    (etc / "sources.list.d").mkdir(parents=True)
    (dpkg / "status").write_text("", encoding="utf-8")
    (etc / "sources.list").write_text("", encoding="utf-8")
    key_dest = etc / "keyrings" / "fortigate-vpn-linux-gui.gpg"
    key_dest.parent.mkdir(parents=True)
    key_dest.write_bytes(keyring.read_bytes())
    (etc / "sources.list.d" / "fvl.sources").write_text(
        (
            "Types: deb\n"
            f"URIs: file:{repo.resolve()}\n"
            "Suites: noble\n"
            "Components: main\n"
            "Architectures: amd64\n"
            f"Signed-By: {key_dest}\n"
        ),
        encoding="utf-8",
    )
    env = os.environ.copy()
    env.pop("APT_CONFIG", None)
    completed = subprocess.run(
        [
            "apt-get",
            "update",
            "-o",
            f"Dir={apt_root}",
            "-o",
            "APT::Get::AllowUnauthenticated=false",
            "-o",
            "Acquire::AllowInsecureRepositories=false",
            "-o",
            "Acquire::AllowDowngradeToInsecureRepositories=false",
            "-o",
            f"APT::Sandbox::User={os.environ.get('USER', 'nobody')}",
        ],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    output = f"{completed.stdout}\n{completed.stderr}"
    assert completed.returncode == 0, output
    assert "NO_PUBKEY" not in output
    assert "not signed" not in output.lower()
    policy = subprocess.run(
        [
            "apt-cache",
            "policy",
            "fortigate-vpn-linux-gui",
            "-o",
            f"Dir={apt_root}",
        ],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )
    assert "1.5.0-1" in policy.stdout


@pytest.mark.skipif(not _have_dpkg_deb(), reason="dpkg-deb is required")
def test_add_deb_rejects_wrong_package_name(tmp_path: Path) -> None:
    module = _load()
    deb = _make_deb(tmp_path, "1.5.0-1", package="unrelated-vpn")
    with pytest.raises(module.AptRepoError, match="unexpected Package"):
        module.add_deb(tmp_path / "repo", deb)


@pytest.mark.skipif(not _have_dpkg_deb(), reason="dpkg-deb is required")
def test_add_deb_rejects_wrong_architecture(tmp_path: Path) -> None:
    module = _load()
    deb = _make_deb(tmp_path, "1.5.0-1", architecture="arm64")
    with pytest.raises(module.AptRepoError, match="unexpected Architecture"):
        module.add_deb(tmp_path / "repo", deb)


@pytest.mark.skipif(not _have_dpkg_deb(), reason="dpkg-deb is required")
def test_add_deb_rejects_malformed_package(tmp_path: Path) -> None:
    module = _load()
    deb = tmp_path / "fortigate-vpn-linux-gui_1.5.0-1_amd64.deb"
    deb.write_bytes(b"this is not a debian package\n")
    with pytest.raises(module.AptRepoError, match="malformed Debian package"):
        module.add_deb(tmp_path / "repo", deb)


@pytest.mark.skipif(not _have_dpkg_deb(), reason="dpkg-deb is required")
@pytest.mark.parametrize("version", ["1.5.0", "1.5.0-rc1"])
def test_add_deb_rejects_malformed_version(tmp_path: Path, version: str) -> None:
    module = _load()
    deb = _make_deb(tmp_path, version)
    with pytest.raises(module.AptRepoError, match="malformed Debian Version"):
        module.add_deb(tmp_path / "repo", deb)


@pytest.mark.skipif(not _have_dpkg_deb(), reason="dpkg-deb is required")
def test_add_deb_rejects_filename_that_does_not_match_control(tmp_path: Path) -> None:
    module = _load()
    deb = _make_deb(
        tmp_path,
        "1.5.0-1",
        filename="unrelated_1.5.0-1_amd64.deb",
    )
    with pytest.raises(module.AptRepoError, match="package filename"):
        module.add_deb(tmp_path / "repo", deb)


@pytest.mark.skipif(not _have_dpkg_deb(), reason="dpkg-deb is required")
def test_generate_rejects_unrelated_file_already_in_pool(tmp_path: Path) -> None:
    module = _load()
    repo = tmp_path / "repo"
    good = _make_deb(tmp_path, "1.5.0-1")
    module.add_deb(repo, good)
    planted = repo / module.pool_relative_path("evil_1.0.0_amd64.deb")
    planted.parent.mkdir(parents=True, exist_ok=True)
    planted.write_bytes(b"not a debian package\n")
    with pytest.raises(module.AptRepoError, match="malformed Debian package"):
        module.generate(repo, [], sign=False)
