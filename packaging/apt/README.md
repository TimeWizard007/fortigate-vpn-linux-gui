# APT repository

Static Debian repository layout for Ubuntu 24.04 (`noble`) amd64. Generated
files are **not** committed to `main`. GitHub Pages serves `dists/` and `pool/`
after a trusted **Release** workflow succeeds, or after a tag-only APT recovery
dispatch for an already-published stable GitHub Release.

The GUI does not consume this repository. Users add it with `Signed-By` and
upgrade with `apt`.

v1.5.0 introduced the production APT repository. It is **live**.

## Current status

- Canonical URL:
  `https://timewizard007.github.io/fortigate-vpn-linux-gui/apt`
- GitHub Pages **Source = GitHub Actions**.
- `fortigate-vpn-linux-gui.gpg` is a **binary** OpenPGP public keyring for
  apt `Signed-By`. Clients download it directly; they must not run
  `gpg --dearmor`.
- Direct GitHub Release `.deb` install remains an alternative, not the only
  supported production method.

## Layout

```text
apt/
  index.html
  fortigate-vpn-linux-gui.gpg          # binary public keyring only
  dists/noble/Release
  dists/noble/Release.gpg
  dists/noble/InRelease
  dists/noble/main/binary-amd64/Packages
  dists/noble/main/binary-amd64/Packages.gz
  pool/main/f/fortigate-vpn-linux-gui/*.deb
```

```text
https://timewizard007.github.io/fortigate-vpn-linux-gui/apt
```

## Generate locally (unsigned or synthetic key)

```bash
python3 scripts/apt_repo.py --repo-root /tmp/fvl-apt --deb dist/fortigate-vpn-linux-gui_1.6.0-1_amd64.deb
```

Signing requires a GnuPG homedir. Do **not** generate a production private key
in this checkout. Tests use a throwaway key.

```bash
python3 scripts/apt_repo.py \
  --repo-root /tmp/fvl-apt \
  --deb dist/fortigate-vpn-linux-gui_1.6.0-1_amd64.deb \
  --sign \
  --gnupg-home "$GNUPGHOME" \
  --import-key /path/to/private.asc \
  --passphrase-file /path/to/passphrase
```

`add_deb` accepts only `Package: fortigate-vpn-linux-gui`, `Architecture: amd64`,
and Debian `Version` `X.Y.Z-N` whose filename is
`fortigate-vpn-linux-gui_X.Y.Z-N_amd64.deb`. Old `.deb` files already in
`pool/` are kept. A file with the same name but different contents is rejected.

Export writes a binary public keyring (`gpg --no-armor --export`). The committed
source public key remains ASCII-armored
`packaging/apt/fortigate-vpn-linux-gui-apt.asc` (public only).

## GitHub Secrets (names only)

| Secret | Purpose |
| ------ | ------- |
| `APT_SIGNING_KEY` | Armored OpenPGP **private** key used to sign `Release` / `InRelease` |
| `APT_SIGNING_PASSPHRASE` | Optional passphrase for that private key |

Never put secret values in this repository, in workflow logs, or in Pages
artifacts. Pages contains only the binary public keyring
`fortigate-vpn-linux-gui.gpg`. The committed public key is
`packaging/apt/fortigate-vpn-linux-gui-apt.asc`.

## GitHub settings

1. **Settings → Pages**: Source = **GitHub Actions** (configured).
2. Allow the **github-pages** environment for the `APT repository` workflow
   (restrict to this repository and do not allow pull requests).
3. Repository secrets `APT_SIGNING_KEY` and `APT_SIGNING_PASSPHRASE` exist.
   Do not print, echo, or retrieve their values.
4. Do not grant the APT workflow to forks or `pull_request` events.
5. Keep historical GitHub Release `.deb` assets. The publisher rebuilds `pool/`
   from all stable (non-draft, non-prerelease) release packages so rollback
   remains possible.

## Workflows

- `.github/workflows/ci.yml` — lint/tests on push and pull request (no APT
  signing secrets).
- `.github/workflows/release.yml` — `push` of tag `vX.Y.Z`; builds, inspects,
  and attaches the `.deb` plus `.sha256` to the GitHub Release.
- `.github/workflows/apt-publish.yml` — automatic after **Release** succeeds
  (`workflow_run`), or a **tag-only** `workflow_dispatch` recovery for an
  already-published stable `vX.Y.Z` GitHub Release. Both paths run the same
  fail-closed verifier before importing `APT_SIGNING_KEY`. Manual recovery
  accepts only a bare stable tag (not branches, SHAs, or refs) and never
  mutates GitHub Releases. There is no `release.published` trigger. Version
  consistency uses `--expected-tag`, not `GITHUB_REF`. `contents: read`,
  `pages: write`, and `id-token: write` only.
