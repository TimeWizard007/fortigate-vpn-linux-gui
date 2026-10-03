# Installation, updates, and APT repository

v1.5.0 is a distribution and update-experience release. It introduced the
production APT repository. SSL VPN, IPsec, SAML, and helper protocol behavior
remain the frozen v1.4.0 / v1.3.0 baseline.

The GUI never downloads or installs packages and never calls `sudo`, `pkexec`,
or `apt` to upgrade itself. `apt` remains responsible for installed-package
upgrades.

Validated install platform: **Ubuntu 24.04 LTS (`noble`), amd64**. Other
distributions are untested.

## APT repository (production, live)

Canonical repository:

```text
https://timewizard007.github.io/fortigate-vpn-linux-gui/apt
```

`fortigate-vpn-linux-gui.gpg` is a **binary** OpenPGP public keyring. Download
it directly into `/etc/apt/keyrings/`. Do not run `gpg --dearmor`. Do not use
`apt-key`, `trusted=yes`, or `--allow-unauthenticated`.

```bash
sudo mkdir -p /etc/apt/keyrings
sudo chmod 0755 /etc/apt/keyrings
curl -fsSL https://timewizard007.github.io/fortigate-vpn-linux-gui/apt/fortigate-vpn-linux-gui.gpg \
  | sudo tee /etc/apt/keyrings/fortigate-vpn-linux-gui.gpg >/dev/null
sudo chmod 0644 /etc/apt/keyrings/fortigate-vpn-linux-gui.gpg
sudo tee /etc/apt/sources.list.d/fortigate-vpn-linux-gui.sources >/dev/null <<'EOF'
Types: deb
URIs: https://timewizard007.github.io/fortigate-vpn-linux-gui/apt
Suites: noble
Components: main
Architectures: amd64
Signed-By: /etc/apt/keyrings/fortigate-vpn-linux-gui.gpg
EOF
sudo apt update
sudo apt install fortigate-vpn-linux-gui
```

Upgrade:

```bash
sudo apt update
sudo apt upgrade
```

or:

```bash
sudo apt install --only-upgrade fortigate-vpn-linux-gui
```

Expected Pages layout:

```text
https://timewizard007.github.io/fortigate-vpn-linux-gui/apt/
https://timewizard007.github.io/fortigate-vpn-linux-gui/apt/fortigate-vpn-linux-gui.gpg
https://timewizard007.github.io/fortigate-vpn-linux-gui/apt/dists/noble/
https://timewizard007.github.io/fortigate-vpn-linux-gui/apt/pool/
```

### Remove the repository

```bash
sudo rm -f /etc/apt/sources.list.d/fortigate-vpn-linux-gui.sources
sudo rm -f /etc/apt/keyrings/fortigate-vpn-linux-gui.gpg
sudo apt update
```

Removing the source does not remove the installed application. Use
`sudo apt remove fortigate-vpn-linux-gui` for that.

### Rollback

Historical `.deb` versions are kept in `pool/` so `apt` can downgrade when
those versions are still published:

```bash
apt-cache madison fortigate-vpn-linux-gui
sudo apt install fortigate-vpn-linux-gui=1.4.0-1
```

Pinning or holding a version is optional (`apt-mark hold`). Do not delete
published GitHub Release assets; the APT publisher rebuilds `pool/` from
stable GitHub Release `.deb` files.

## Direct `.deb` install (alternative)

Download `fortigate-vpn-linux-gui_1.5.0-1_amd64.deb` from
[GitHub Releases](https://github.com/TimeWizard007/fortigate-vpn-linux-gui/releases)
and install:

```bash
sudo apt install ./fortigate-vpn-linux-gui_1.5.0-1_amd64.deb
```

Upgrade later by installing a newer downloaded `.deb` the same way, or by
using the APT repository above.

Remove:

```bash
sudo apt remove fortigate-vpn-linux-gui
```

User profiles in `~/.config/fortigate-vpn-linux-gui/` are preserved.

## Update checks in the GUI

About can **Check for updates**. Settings can enable an automatic check at
most once per 24 hours after startup. Checks use the public GitHub Releases
API over HTTPS, do not require a token, and do not send profile, gateway, or
user information. There is no telemetry.

States: `Up to date`, `Update available: vX.Y.Z`, `Checking...`,
`Unable to check for updates`. Network failures are not treated as an
available update.

**View release** opens the GitHub Release page in the system browser after an
explicit click. The GUI does not self-update.

## Trust model

- Clients trust only this repository's public key via `Signed-By`.
- Pages publishes a binary public keyring. The committed source public key is
  ASCII-armored `packaging/apt/fortigate-vpn-linux-gui-apt.asc`.
- The signing **private** key is never committed. GitHub Actions uses
  repository secrets `APT_SIGNING_KEY` and optional `APT_SIGNING_PASSPHRASE`.
- Temporary key material is deleted after the publish job.
- Pull requests cannot run the signing workflow.

## Maintainer release procedure

1. Keep application version, `pyproject.toml`, Debian changelog/control, and
   `scripts/build-deb.sh` aligned (`1.5.0` / `1.5.0-1`).
   `python scripts/check-version-consistency.py` must pass.
2. Do not move historical tags. `v1.4.0` and `v1.5.0` are immutable.
3. After review, tag `vX.Y.Z` on the release commit. The **Release** workflow
   builds the `.deb` from that tag and attaches it to the GitHub Release.
4. After **Release** succeeds, **APT repository** verifies the matching
   published `.deb` and then signs/deploys Pages. A tag-only recovery dispatch
   can republish APT metadata from an existing stable Release without modifying
   that Release.

See [`packaging/apt/README.md`](../../packaging/apt/README.md) for the
repository layout and required GitHub settings.
