# Installation, updates, and APT repository

v1.5.0 is a distribution and update-experience release. SSL VPN, IPsec, SAML,
and helper protocol behavior remain the frozen v1.4.0 / v1.3.0 baseline.

The GUI never downloads or installs packages and never calls `sudo`, `pkexec`,
or `apt` to upgrade itself. `apt` remains responsible for installed-package
upgrades.

## Direct `.deb` install (always available)

Download `fortigate-vpn-linux-gui_1.5.0-1_amd64.deb` from
[GitHub Releases](https://github.com/TimeWizard007/fortigate-vpn-linux-gui/releases)
and install:

```bash
sudo apt install ./fortigate-vpn-linux-gui_1.5.0-1_amd64.deb
```

Upgrade later by installing a newer downloaded `.deb` the same way, or by
using the APT repository once it is published.

Remove:

```bash
sudo apt remove fortigate-vpn-linux-gui
```

User profiles in `~/.config/fortigate-vpn-linux-gui/` are preserved.

## APT repository (not live until first signed deployment is verified)

GitHub Pages is configured to deploy from GitHub Actions. Production APT
publication has not happened yet. The intended user flow after the first
signed deployment is verified is:

```bash
sudo apt update
sudo apt install fortigate-vpn-linux-gui
sudo apt upgrade
```

**This repository is not live until a signed GitHub Pages deployment has been
tested.** Do not treat the URLs below as a production source until that is
done. The application `.deb` from GitHub Releases remains the supported
install path until then.

Expected Pages layout after deployment:

```text
https://timewizard007.github.io/fortigate-vpn-linux-gui/apt/
https://timewizard007.github.io/fortigate-vpn-linux-gui/apt/dists/noble/
https://timewizard007.github.io/fortigate-vpn-linux-gui/apt/pool/
https://timewizard007.github.io/fortigate-vpn-linux-gui/apt/fortigate-vpn-linux-gui.gpg
```

### Add the repository (Ubuntu 24.04)

Use a dedicated keyring and `Signed-By`. Do not run `apt-key add` and do not
globally trust the key.

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

- Clients trust only this repository's public key via `signed-by=`.
- The signing **private** key is never committed. GitHub Actions uses
  repository secrets `APT_SIGNING_KEY` and optional `APT_SIGNING_PASSPHRASE`.
- Temporary key material is deleted after the publish job.
- Pull requests cannot run the signing workflow.

## Maintainer release procedure

1. Keep application version, `pyproject.toml`, Debian changelog/control, and
   `scripts/build-deb.sh` aligned (`1.5.0` / `1.5.0-1`).
   `python scripts/check-version-consistency.py` must pass.
2. Do not move historical tags. `v1.4.0` is immutable.
3. After review, tag `v1.5.0` on the release commit. The **Release** workflow
   builds the `.deb` from that tag and attaches it to the GitHub Release.
4. GitHub Pages (Source = GitHub Actions) and APT signing secrets are already
   configured. After **Release** succeeds, **APT repository** verifies the
   matching published `.deb` and then signs/deploys. Do not treat the APT
   repository as live until that first signed deployment is verified. Until
   then, ship the GitHub Release `.deb` only.

See [`packaging/apt/README.md`](../../packaging/apt/README.md) for the
repository layout and required GitHub settings.
