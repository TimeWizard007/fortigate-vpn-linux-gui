# Scripts

Maintainer scripts live here. This directory is not a place for VPN
connect/disconnect wrappers, sudo helpers, or anything that changes the host
network.

## Package build

```bash
./scripts/build-deb.sh
```

Builds `dist/fortigate-vpn-linux-gui_1.5.0-1_amd64.deb` from this checkout.
Fails on errors. Does not install, publish, or modify user configuration.

```bash
python3 scripts/check-version-consistency.py
bash scripts/inspect-deb.sh dist/fortigate-vpn-linux-gui_1.5.0-1_amd64.deb
```

`check-version-consistency.py` compares the application version, pyproject,
Debian changelog/control, `build-deb.sh`, and an optional `vX.Y.Z` git tag.
`--expected-tag vX.Y.Z` supplies an already-verified stable tag and is
preferred over `GITHUB_REF` (required for `workflow_run` APT publishing).
`--root` selects the source tree whose metadata is compared.
`inspect-deb.sh` fails if the package contains credentials, private keys,
research binaries, or FortiClient proprietary files.
`verify-github-release.py` is used by the APT publisher to fail closed unless
the completed Release workflow, or a tag-only recovery dispatch, matches a
published stable GitHub Release and the exact expected `.deb`.

## APT repository (generated, not committed to main)

```bash
python3 scripts/apt_repo.py --repo-root /tmp/fvl-apt --deb dist/fortigate-vpn-linux-gui_1.5.0-1_amd64.deb
```

Writes `dists/` and `pool/` for Ubuntu 24.04 (`noble`). Signing uses a local
GnuPG homedir and never prints the private key. See
[`packaging/apt/README.md`](../packaging/apt/README.md).

## Native plugin

```bash
./scripts/build-fvl-forticlient-vid.sh build
./scripts/check-fvl-forticlient-vid-symbols.sh native/fvl-forticlient-vid/libstrongswan-fvl-forticlient-vid.so
```

## Development helper

```bash
sudo ./scripts/install-dev-helper.sh
./scripts/install-dev-helper.sh status
```

Installs this checkout's helper into `/usr/libexec/fortigate-vpn-linux-gui/vpn-helper`
without changing the polkit action, without setuid, and without modifying
the system strongSwan daemon. It also builds the application-owned
FortiClient Vendor ID plugin (`libstrongswan-fvl-forticlient-vid.so`) and
installs that uniquely named file into `/usr/lib/ipsec/plugins` **without**
writing `/etc/strongswan.d/charon/fvl-forticlient-vid.conf`, so Ubuntu's
system charon does not load it. `status` prints install kind, helper
version, protocol version, capabilities, and plugin presence. Restore the
released helper with `sudo ./scripts/install-dev-helper.sh restore`.
