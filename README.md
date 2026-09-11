# FortiGate VPN Linux GUI

A modern native Linux desktop GUI client for FortiGate SSL VPN, with
SAML/SSO authentication using Microsoft Entra ID via the system browser.

**This project is independent and is not affiliated with, endorsed by, or
sponsored by Fortinet.** Fortinet, FortiGate, and FortiClient are trademarks of
their respective owner(s).

## Status

The current version is **0.7.1**. Persistent profiles, SAML/SSO via
`--saml-login` and the system browser, a polkit privileged helper, and
explicit FortiGate certificate pinning are implemented. Connection lifecycle
is hardened. Desktop integration adds a system tray, optional close-to-tray,
optional user autostart, optional auto-reconnect after unexpected tunnel
loss, and an About page with project/license information.

| Capability | Status |
| ---------- | ------ |
| Application window and navigation | Implemented |
| Persistent connection profiles | Implemented |
| openfortivpn process lifecycle | Implemented |
| Connect / disconnect (non-SSO profiles) | Implemented |
| Logs (in-memory, redacted) | Implemented |
| Runtime openfortivpn detection | Implemented |
| SAML / SSO (Microsoft Entra ID, system browser) | Implemented |
| Privileged helper / polkit | Implemented |
| Explicit gateway certificate pinning | Implemented |
| System tray and desktop notifications | Implemented |
| Optional auto-reconnect | Implemented (off by default) |
| Optional user autostart | Implemented (off by default) |
| About / project / license | Implemented |

| Capability | Status |
| ---------- | ------ |
| Application window and navigation | Implemented |
| Persistent connection profiles | Implemented |
| openfortivpn process lifecycle | Implemented |
| Connect / disconnect (non-SSO profiles) | Implemented |
| Logs (in-memory, redacted) | Implemented |
| Runtime openfortivpn detection | Implemented |
| SAML / SSO (Microsoft Entra ID, system browser) | Implemented |
| Privileged helper / polkit | Implemented |
| Explicit gateway certificate pinning | Implemented |

SSO profiles send a structured connect request to a minimal privileged helper.
The helper constructs `[openfortivpn, gateway:port, --saml-login]` (list argv,
`shell=False`) from approved paths only. The GUI stays unprivileged, receives
the validated SAML URL, and opens it once in the system browser. FortiGate then
redirects to Microsoft Entra ID. The local callback listener belongs to
openfortivpn; this GUI does not bind an extra port.

The Ubuntu 24.04 package (`/usr/bin/openfortivpn` 1.21.0) may **not** provide
`--saml-login`. A newer build such as **openfortivpn 1.24.1** (for example
`/usr/local/bin/openfortivpn`) is required for SSO. The helper discovers
approved candidates and prefers a SAML-capable executable. It does not fall
back to insecure authentication.

The GUI never runs as root and never uses sudo. Connecting asks polkit to
authorize the helper (`pkexec` starts only the helper, not the GUI).
Passwords, SAML tokens, and SVPNCOOKIE are not stored and are not passed on
the command line. Gateway certificates are never auto-trusted.

## Connection profiles

Profiles are stored per-user as UTF-8 JSON:

```text
${XDG_CONFIG_HOME:-$HOME/.config}/fortigate-vpn-linux-gui/profiles.json
```

Typical Ubuntu path: `~/.config/fortigate-vpn-linux-gui/profiles.json`.

Each profile has a stable id, name, gateway, port (default 443), optional
description, optional username hint, a Use SSO flag (default on), and an
optional `trusted_cert_sha256` pin. The pin is a SHA-256 fingerprint, not a
secret.

**The profile file does not store passwords, SAML tokens, cookies, client
secrets, or MFA data.** The application never writes those fields.

Add, edit, and delete profiles on the Profiles page. The Connection page
selector updates immediately. The Settings and Diagnostics pages show the
configuration path as read-only.

## openfortivpn

`openfortivpn` is a real runtime dependency for VPN connectivity. The GUI
still starts if it is missing; the Connection page explains that VPN
connectivity is unavailable.

On Ubuntu the packaged client is often too old for SAML:

```bash
sudo apt install openfortivpn
```

That typically installs **1.21.0** at `/usr/bin/openfortivpn` without
`--saml-login`. SSO needs a build that advertises `--saml-login` (tested:
**1.24.1** at `/usr/local/bin/openfortivpn`). The GUI will select the
SAML-capable binary when an SSO profile is used.

The application never installs packages automatically. It never runs `sudo`
or `apt`. Connecting uses `pkexec` only to start the privileged helper.

Because `openfortivpn` needs extra rights for PPP, routes, or DNS, it runs
through the helper after a normal Linux authentication dialog. Do not start
this GUI as root.

## Architecture (current)

```text
GUI                          PySide6 widgets (unprivileged)
  ↓ structured request
Privileged helper            root via polkit (pkexec)
  ↓ controlled argv
openfortivpn                 PPP / routes / DNS
  ↓ SAML URL event
System browser               unprivileged desktop session
  ↓
FortiGate SSL VPN            gateway
```

The helper exposes only connect, disconnect, and status. It constructs the
openfortivpn command itself. The GUI never sends a shell string or an
arbitrary executable path.

When FortiGate certificate validation fails, the GUI shows a pinning dialog.
Trust stores the SHA-256 fingerprint on that profile only. A later different
fingerprint is a certificate-change warning and is never auto-replaced.

## Desktop integration

The application can use a system tray icon when the desktop provides one. The
tray shows connection state and offers Show/Hide, Connect, Disconnect,
Reconnect, Settings, About, and Quit. Quit always shuts the application down
safely (it waits for helper/openfortivpn cleanup). If no tray is available,
the main window works as before.

Closing the window exits the application by default. Settings can change that
to **Minimize to system tray**; the VPN keeps running until you Quit from the
tray. The first time this happens, a short notification explains that the
app is still running.

**Automatically reconnect if VPN connection is lost** is off by default. It
only runs after an unexpected tunnel loss, not after Disconnect or Quit, and
not after a certificate rejection. It never auto-approves certificates and
never skips SAML. Failed authentication does not retry in a loop. Manual
Reconnect disconnects safely, waits for cleanup, then connects the same
profile again.

**Start FortiGate VPN Linux GUI automatically after login** writes a user
`.desktop` file under `~/.config/autostart/`. It does not require root and
does not connect the VPN at login. Starting the app and connecting remain
separate.

The About page shows the version, author (TimeWizard007), GPL-3.0-or-later
license, project URL, and a Fortinet independence disclaimer. FortiGate VPN
Linux GUI is free and open-source software.

## Privileged helper install (development)

```bash
sudo install -D -m 0755 packaging/libexec/vpn-helper \
  /usr/libexec/fortigate-vpn-linux-gui/vpn-helper
sudo install -D -m 0644 packaging/polkit/com.fortigate-vpn-linux-gui.policy \
  /usr/share/polkit-1/actions/com.fortigate-vpn-linux-gui.policy
```

The helper must be able to import `fortigate_vpn_gui` (editable install into
the system interpreter, or a packaged install). Details:
[`packaging/README.md`](packaging/README.md).

## Requirements

- Linux (Ubuntu is the primary supported distribution)
- Python 3.10 or newer
- Qt 6 via PySide6
- A desktop session (X11 or Wayland)
- `openfortivpn` to actually start a tunnel (optional for launching the GUI)

On Ubuntu 24.04 with Python 3.12, install the runtime and venv packages
before creating a virtual environment:

```bash
sudo apt install python3.12-venv libxcb-cursor0
```

The `python3.x-venv` package name follows the installed Python version
(`python3.12-venv` on Ubuntu 24.04, `python3.10-venv` on Ubuntu 22.04 with
the default Python). `python3-venv` is a metapackage that pulls the matching
version.

`libxcb-cursor0` provides `libxcb-cursor.so.0`. PySide6/Qt needs it to create
desktop windows. The application **does not** install this package (or any
other system package) automatically. At startup it checks that the library
can be loaded; if it is missing, it shows a dialog with a copyable

`sudo apt install libxcb-cursor0`

command and exits. It never runs `sudo` or `apt` to install packages. `pkexec`
is used later only to start the VPN helper, never to launch this GUI.

## Development setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

Run the application (never as root):

```bash
python -m fortigate_vpn_gui
```

Lint and test:

```bash
ruff check src tests
ruff format src tests
python -m pytest
```

## Documentation

- English: [`docs/en/`](docs/en/)
- Polish: [`docs/pl/`](docs/pl/) and [`README.pl.md`](README.pl.md)
- Security: [`SECURITY.md`](SECURITY.md)
- Contributing: [`CONTRIBUTING.md`](CONTRIBUTING.md)
- Changelog: [`CHANGELOG.md`](CHANGELOG.md)

## License

GNU General Public License v3.0 or later. See [`LICENSE`](LICENSE).
