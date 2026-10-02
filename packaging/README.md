# Packaging

Debian/Ubuntu packaging for Ubuntu 24.04 LTS (amd64).

The GUI is never installed setuid and never launched with pkexec. The
privileged helper remains `/usr/libexec/fortigate-vpn-linux-gui/vpn-helper`
and polkit action `com.fortigate-vpn-linux-gui.manage-vpn`. Packaged
**1.3.0** ships helper **0.9.0** (`protocol_version` remains 1) including
IKEv2 SAML/SSO and the application-owned FortiClient Vendor ID plugin used
only by the private IKEv2 SSO charon. `sudo ./scripts/install-dev-helper.sh`
installs unreleased helper changes for live development.

## Build

From a clean checkout:

```bash
./scripts/build-deb.sh
```

The script writes `dist/fortigate-vpn-linux-gui_1.3.0-1_amd64.deb` and prints
its path and SHA-256. It does not install the package, publish anything, or
modify user configuration.

Build-time tools for the bundled openfortivpn: `gcc`, `make`, `pkg-config`,
`autoconf`, `automake`, `libssl-dev`. The script downloads the upstream
**1.24.1** source tarball, verifies SHA-256, and compiles it. It does not
vendor a prebuilt binary. The FortiClient compatibility plugin is compiled
against fetched strongSwan **5.9.13** headers and linked to distro
libcharon/libstrongswan.

Ubuntu 24.04 does not ship `python3-pyside6`. The package therefore installs a
**package-owned** private Python environment under
`/usr/lib/fortigate-vpn-linux-gui/venv` with PySide6 and the Secret Service
`keyring` stack from PyPI wheels. That environment is root-owned after
install and is not a user venv. A clean `.deb` install does not require
`pip install`.

## Install

```bash
sudo apt install ./dist/fortigate-vpn-linux-gui_1.3.0-1_amd64.deb
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
/usr/libexec/fortigate-vpn-linux-gui/plugins/libstrongswan-fvl-forticlient-vid.so
/usr/lib/ipsec/plugins/libstrongswan-fvl-forticlient-vid.so
/usr/share/applications/fortigate-vpn-linux-gui.desktop
/usr/share/icons/hicolor/scalable/apps/fortigate-vpn-linux-gui.svg
/usr/share/polkit-1/actions/com.fortigate-vpn-linux-gui.policy
/usr/share/fortigate-vpn-linux-gui/apparmor/usr.sbin.swanctl.local
```

The helper is not setuid. Privilege escalation stays on the existing
polkit/pkexec path. The helper shebang uses the package-owned interpreter so
it can import `fortigate_vpn_gui` without a Git checkout.

The Ubuntu package **Depends** on distro strongSwan packages (`strongswan`,
`strongswan-swanctl`, `libcharon-extra-plugins`,
`libcharon-extauth-plugins`). They are not bundled. `/etc/strongswan.conf`
is not modified. Install, upgrade, and removal **do not** stop or disable
`strongswan-starter`. The uniquely named plugin `.so` is not given a
`/etc/strongswan.d/charon/` snippet, so system charon does not load it.
Optional IPsec PSK and XAuth password storage uses the packaged Python
`keyring` Secret Service interface. There is no plaintext fallback in
`profiles.json`. GNOME Keyring is one compatible provider; any Secret
Service implementation is accepted.

`postinst` appends a minimal AppArmor local snippet so distro `swanctl` may
read `/run/charon.fvl.conf` and connect to `/run/charon.fvl.vici`. It does
not grant `/run/charon.vici`. `postrm` removes that snippet only on purge.

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
- No automatic stop or disable of `strongswan-starter`
- No `/etc/strongswan.d/charon/fvl-forticlient-vid.conf`
