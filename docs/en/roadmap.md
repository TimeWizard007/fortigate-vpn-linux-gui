# Roadmap

Dates are not committed. Order may change as design work proceeds.

## v0.1.x — foundation

- Python package and `python -m fortigate_vpn_gui` entry point
- Placeholder PySide6 GUI (no VPN operations)
- Startup runtime dependency check
- English and Polish documentation, pytest, Ruff, and GitHub Actions CI

## v0.2.x — profiles (current)

- Persistent FortiGate connection profiles
- XDG JSON storage without secrets
- Profiles page Add / Edit / Delete
- Connection page selector integration

## Later (planned, not implemented)

- Privileged helper design and polkit policy
- openfortivpn-backed connect / disconnect / status
- SAML/SSO through the system browser and Microsoft Entra ID
- Redacted logs and user-triggered diagnostics
- Ubuntu packaging (`.deb` and a desktop entry)

SAML authentication and openfortivpn execution are **planned**. They are not
available in this version.
