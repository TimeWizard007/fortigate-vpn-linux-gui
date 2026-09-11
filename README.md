# FortiGate VPN Linux GUI

A native Linux desktop client for FortiGate SSL VPN. SAML/SSO uses the system
browser (for example Microsoft Entra ID via FortiGate). The GUI never runs as
root.

**This project is independent and is not affiliated with, endorsed by, or
sponsored by Fortinet.** Fortinet, FortiGate, and FortiClient are trademarks of
their respective owner(s).

## Supported platform

Primary release target: **Ubuntu 24.04 LTS, amd64**. Other Debian-family
distributions are untested.

The current version is **1.0.0**. Helper protocol remains **0.7.0**.

## Features

- Persistent connection profiles (create, edit, duplicate, delete, default)
- Connect from Profiles or the Connection page
- SAML/SSO via `openfortivpn --saml-login` and the system browser
- Username/password profiles when SSO is not used
- Explicit FortiGate certificate pinning (never auto-trusted)
- Privileged helper authorized through polkit (`pkexec` starts only the helper)
- System tray, optional close-to-tray, optional user autostart
- Optional auto-reconnect after unexpected tunnel loss (off by default)
- Diagnostics with DNS, routing, TCP, tunnel, helper, and polkit checks
- Copyable sanitized diagnostic report

## Install (Ubuntu 24.04)

```bash
sudo apt install ./fortigate-vpn-linux-gui_1.0.0-2_amd64.deb
```

`apt` resolves runtime libraries, `pkexec`, `ppp`, and `iproute2`. No virtualenv
is required. The package includes a private SAML-capable `openfortivpn`
**1.24.1**; it does not replace `/usr/bin/openfortivpn`.

Launch from the GNOME application menu as **FortiGate VPN Linux GUI**, or:

```bash
fortigate-vpn-linux-gui
```

Do not run the GUI as root. Connecting shows a normal polkit prompt when the
helper needs authorization. SSO then continues in the system browser.

### openfortivpn and SAML

SAML/SSO needs `openfortivpn --saml-login`. Ubuntu 24.04's packaged
`openfortivpn` is **1.21.0** and does **not** provide that option. This
application's `.deb` installs a package-owned **1.24.1** at
`/usr/libexec/fortigate-vpn-linux-gui/openfortivpn`. The helper prefers that
binary, then `/usr/local/bin/openfortivpn`, then `/usr/bin/openfortivpn`.
Diagnostics reports the same effective binary. Username/password profiles can
still use a non-SAML build if that is the only approved binary present.

### Remove

```bash
sudo apt remove fortigate-vpn-linux-gui
```

User profiles in `~/.config/fortigate-vpn-linux-gui/` are preserved.
`apt purge` also leaves those files; delete them yourself if you want them
gone.

## Usage

1. Start the application.
2. Add a profile (gateway, port, SAML/SSO or username/password).
3. Connect. Authorize the helper in the polkit dialog if asked.
4. For SSO, complete sign-in in the system browser.
5. If FortiGate presents an unknown certificate, pin it explicitly for that
   profile or cancel.
6. Use Diagnostics if a connection fails. **Run diagnostics** then
   **Copy report** for a sanitized text summary.
7. Disconnect from the Connection page or the tray. Quit from the tray always
   shuts the application down (it waits for helper/openfortivpn cleanup).

Closing the window exits by default. Settings can change that to minimize to
the tray. Autostart only launches the GUI after login; it does not connect the
VPN.

## Profiles

Profiles are stored per-user as UTF-8 JSON:

```text
${XDG_CONFIG_HOME:-$HOME/.config}/fortigate-vpn-linux-gui/profiles.json
```

The file does not store passwords, SAML tokens, cookies, or other secrets.
`trusted_cert_sha256` is a public certificate pin.

## Security model

```text
GUI                          PySide6 widgets (unprivileged)
  ↓ structured request
Privileged helper            root via polkit (pkexec)
  ↓ controlled argv
openfortivpn                 PPP / routes / DNS
  ↓ SAML URL event
System browser               unprivileged desktop session
```

`pkexec` starts only `/usr/libexec/fortigate-vpn-linux-gui/vpn-helper`. There
are no sudoers rules, no setuid helper, and no passwordless polkit policy.
Passwords and SAML cookies are not stored and are not passed on the command
line. Copied diagnostic reports are sanitized.

## Troubleshooting

Open **Diagnostics** in the application first. It checks helper/polkit
install, DNS, the route to the gateway, TCP reachability, and tunnel state
without starting a VPN by itself. Opening Diagnostics does not show a polkit
prompt.

If SSO fails, confirm `openfortivpn --help` lists `--saml-login`.

## Development

Developer setup is separate from the packaged application. The installed
`fortigate-vpn-linux-gui` command must not require this checkout or `.venv`.

```bash
sudo apt install python3.12-venv libxcb-cursor0
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
python -m fortigate_vpn_gui
```

```bash
ruff check src tests
python -m pytest
./scripts/build-deb.sh
```

Development helper install (not required after the `.deb` is installed):
see [`packaging/README.md`](packaging/README.md).

## Documentation

- English: [`docs/en/`](docs/en/)
- Polish: [`docs/pl/`](docs/pl/) and [`README.pl.md`](README.pl.md)
- Security: [`SECURITY.md`](SECURITY.md)
- Contributing: [`CONTRIBUTING.md`](CONTRIBUTING.md)
- Changelog: [`CHANGELOG.md`](CHANGELOG.md)

## License

GNU General Public License v3.0 or later. See [`LICENSE`](LICENSE).
