# APT repository

Static Debian repository layout for Ubuntu 24.04 (`noble`) amd64. Generated
files are **not** committed to `main`. GitHub Pages serves `dists/` and `pool/`
after a trusted **Release** workflow succeeds.

The GUI does not consume this repository. Users add it with `signed-by=` and
upgrade with `apt`.

## Current status

- GitHub Pages **Source = GitHub Actions** is configured.
- Production APT deployment has **not** happened yet.
- Do not treat this repository as live until the first signed Pages
  deployment has been verified.
- Until then, install from the GitHub Release `.deb` only.

## Layout

```text
apt/
  index.html
  fortigate-vpn-linux-gui.gpg          # public key only
  dists/noble/Release
  dists/noble/Release.gpg
  dists/noble/InRelease
  dists/noble/main/binary-amd64/Packages
  dists/noble/main/binary-amd64/Packages.gz
  pool/main/f/fortigate-vpn-linux-gui/*.deb
```

Expected Pages URL after the first verified signed deployment:

```text
https://timewizard007.github.io/fortigate-vpn-linux-gui/apt
```

## Generate locally (unsigned or synthetic key)

```bash
python3 scripts/apt_repo.py --repo-root /tmp/fvl-apt --deb dist/fortigate-vpn-linux-gui_1.5.0-1_amd64.deb
```

Signing requires a GnuPG homedir. Do **not** generate a production private key
in this checkout. Tests use a throwaway key.

```bash
python3 scripts/apt_repo.py \
  --repo-root /tmp/fvl-apt \
  --deb dist/fortigate-vpn-linux-gui_1.5.0-1_amd64.deb \
  --sign \
  --gnupg-home "$GNUPGHOME" \
  --import-key /path/to/private.asc \
  --passphrase-file /path/to/passphrase
```

`add_deb` accepts only `Package: fortigate-vpn-linux-gui`, `Architecture: amd64`,
and Debian `Version` `X.Y.Z-N` whose filename is
`fortigate-vpn-linux-gui_X.Y.Z-N_amd64.deb`. Old `.deb` files already in
`pool/` are kept. A file with the same name but different contents is rejected.

## GitHub Secrets (names only)

| Secret | Purpose |
| ------ | ------- |
| `APT_SIGNING_KEY` | Armored OpenPGP **private** key used to sign `Release` / `InRelease` |
| `APT_SIGNING_PASSPHRASE` | Optional passphrase for that private key |

Never put secret values in this repository, in workflow logs, or in Pages
artifacts. The public key is exported to `fortigate-vpn-linux-gui.gpg`.
The committed public key is `packaging/apt/fortigate-vpn-linux-gui-apt.asc`.

## GitHub settings

1. **Settings → Pages**: Source = **GitHub Actions** (configured).
2. Allow the **github-pages** environment for the `APT repository` workflow
   (created on first `actions/deploy-pages` run; restrict to this repository
   and do not allow pull requests).
3. Repository secrets `APT_SIGNING_KEY` and `APT_SIGNING_PASSPHRASE` exist.
   Do not print, echo, or retrieve their values.
4. Do not grant the APT workflow to forks or `pull_request` events.
5. Keep historical GitHub Release `.deb` assets. The publisher rebuilds `pool/`
   from all stable (non-draft, non-prerelease) release packages so rollback
   remains possible.

Pages hosting is configured. The signed APT repository is still **not live**
until the first production deployment is verified.

## Workflows

- `.github/workflows/ci.yml` — lint/tests on push and pull request (no APT
  signing secrets).
- `.github/workflows/release.yml` — `push` of tag `vX.Y.Z`; builds, inspects,
  and attaches the `.deb` plus `.sha256` to the GitHub Release.
- `.github/workflows/apt-publish.yml` — runs only after the **Release**
  workflow **completes successfully** (`workflow_run`). It verifies the
  triggering tag, published stable GitHub Release, and exact expected `.deb`
  **before** importing `APT_SIGNING_KEY`. There is no `workflow_dispatch` and
  no `release.published` trigger. Version consistency uses the verified tag
  from that step (`--expected-tag`), not `GITHUB_REF` from the `workflow_run`
  default-branch context. `pages: write` and `id-token: write` are limited to
  that job.
