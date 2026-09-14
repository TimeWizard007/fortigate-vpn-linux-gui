# Packaging

Debian/Ubuntu packaging for Ubuntu 24.04 LTS (amd64).

The GUI is never installed setuid and never launched with pkexec. The
privileged helper remains `/usr/libexec/fortigate-vpn-linux-gui/vpn-helper`
and polkit action `com.fortigate-vpn-linux-gui.manage-vpn`. Helper protocol
**0.8.0** is required by application version **1.1.0**.

## Build

From a clean checkout:

```bash
./scripts/build-deb.sh
```

The script writes `dist/fortigate-vpn-linux-gui_1.1.0-1_amd64.deb` and prints
its path and SHA-256. It does not install the package, publish anything, or
modify user configuration.

Build-time tools for the bundled openfortivpn: `gcc`, `make`, `pkg-config`,
`autoconf`, `automake`, `libssl-dev`. The script downloads the upstream
**1.24.1** source tarball, verifies SHA-256, and compiles it. It does not
vendor a prebuilt binary.

Ubuntu 24.04 does not ship `python3-pyside6`. The package therefore installs a
**package-owned** private Python environment under
`/usr/lib/fortigate-vpn-linux-gui/venv` with PySide6 and the Secret Service
`keyring` stack from PyPI wheels. That environment is root-owned after
install and is not a user venv. A clean `.deb` install does not require
`pip install`.

## Install

```bash
sudo apt install ./dist/fortigate-vpn-linux-gui_1.1.0-1_amd64.deb
```

Launch:

```bash
fortigate-vpn-linux-gui
```

or use the GNOME application menu. Do not run the GUI as root.

## Installed layout

```text
/usr/bin/fortigate-vpn-linux-gui
/usr/lib/fortigate-vpn-linux-gui/venv/
/usr/libexec/fortigate-vpn-linux-gui/vpn-helper
/usr/libexec/fortigate-vpn-linux-gui/openfortivpn
/usr/share/applications/fortigate-vpn-linux-gui.desktop
/usr/share/icons/hicolor/scalable/apps/fortigate-vpn-linux-gui.svg
/usr/share/polkit-1/actions/com.fortigate-vpn-linux-gui.policy
```

The helper is not setuid. Privilege escalation stays on the existing
polkit/pkexec path. The helper shebang uses the package-owned interpreter so
it can import `fortigate_vpn_gui` without a Git checkout.

v1.1.0 **Depends** on distro strongSwan packages (`strongswan`,
`strongswan-swanctl`, `libcharon-extra-plugins`,
`libcharon-extauth-plugins`). They are not bundled. `/etc/strongswan.conf`
is not modified. Optional IPsec PSK and XAuth password storage uses the
packaged Python `keyring` Secret Service interface. There is no plaintext
fallback in `profiles.json`. GNOME Keyring is one compatible provider;
any Secret Service implementation is accepted.

## User data

Profiles stay in:

```text
${XDG_CONFIG_HOME:-$HOME/.config}/fortigate-vpn-linux-gui/
```

`apt remove` and `apt purge` do not delete home-directory profiles. There are
no maintainer scripts that walk user homes.

## What this package does not install

- No sudoers rules
- No setuid `openfortivpn` (the package-owned copy is mode 0755)
- No replacement of `/usr/bin/openfortivpn`
- No bundled strongSwan
- No world-writable helper directories
- No systemd VPN service
- No passwordless polkit rule
