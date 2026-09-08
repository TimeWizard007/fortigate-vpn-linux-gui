# FortiGate VPN Linux GUI

A modern native Linux desktop GUI client for FortiGate SSL VPN, with planned
support for SAML/SSO authentication using Microsoft Entra ID.

**This project is independent and is not affiliated with, endorsed by, or
sponsored by Fortinet.** Fortinet, FortiGate, and FortiClient are trademarks of
their respective owner(s).

## Status

The current version is **0.2.0**. Persistent connection profiles are implemented.
VPN connectivity and SAML/SSO are **not**.

| Capability | Status |
| ---------- | ------ |
| Application window and navigation | Implemented |
| Persistent connection profiles | Implemented |
| Connect / disconnect a VPN | **Not implemented** |
| SAML / SSO (Microsoft Entra ID) | **Not implemented** |
| openfortivpn integration | **Not implemented** |
| Privileged helper / polkit | **Not implemented** |

The **Connect with SSO** button stays a placeholder. It does not open a browser,
authenticate, or change your network. It is enabled only when a profile exists.

## Connection profiles

Profiles are stored per-user as UTF-8 JSON:

```text
${XDG_CONFIG_HOME:-$HOME/.config}/fortigate-vpn-linux-gui/profiles.json
```

Typical Ubuntu path: `~/.config/fortigate-vpn-linux-gui/profiles.json`.

Each profile has a stable id, name, gateway, port (default 443), optional
description, optional username hint, and a Use SSO flag (default on).

**The profile file does not store passwords, SAML tokens, cookies, client
secrets, or MFA data.** The application never writes those fields.

Add, edit, and delete profiles on the Profiles page. The Connection page
selector updates immediately. The Settings and Diagnostics pages show the
configuration path as read-only.

`openfortivpn` is **not** required for v0.2.x.

## Intended architecture (planned)

SAML authentication is expected to use the user's system browser and Microsoft
Entra ID. The following stack is the design target. Profiles already live in
the application layer; VPN, helper, and openfortivpn layers do not exist yet:

```text
GUI
  ↓
Application / service layer
  ↓
Privileged helper
  ↓
openfortivpn
  ↓
FortiGate SSL VPN
```

The GUI will stay unprivileged. Privileged work (starting the VPN process,
routes, DNS) will go through a minimal helper, not `sudo` from the desktop app.

## Requirements

- Linux (Ubuntu is the primary supported distribution)
- Python 3.10 or newer
- Qt 6 via PySide6
- A desktop session (X11 or Wayland)

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

command and exits. It never runs `sudo`, `pkexec`, or `apt`.

`openfortivpn` is **not** required for v0.2.x.

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
