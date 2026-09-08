# Roadmap

Dates are not committed. Order may change as design work proceeds.

## v0.1.x — foundation

- Python package and `python -m fortigate_vpn_gui` entry point
- Placeholder PySide6 GUI (no VPN operations)
- Startup runtime dependency check
- English and Polish documentation, pytest, Ruff, and GitHub Actions CI

## v0.2.x — profiles

- Persistent FortiGate connection profiles
- XDG JSON storage without secrets
- Profiles page Add / Edit / Delete
- Connection page selector integration

## v0.3.x — openfortivpn backend (current)

- Unprivileged `openfortivpn` process lifecycle
- Connection states and Connect / Disconnect wiring
- Runtime detection of `openfortivpn` (GUI still starts without it)
- In-memory Logs page with redaction
- Diagnostics: path, version, VPN state, PID
- Mocked process tests (no real VPN, sudo, or network)

## Later (planned, not implemented)

- Privileged helper design and polkit policy
- SAML/SSO through the system browser and Microsoft Entra ID (target v0.4.0)
- Ubuntu packaging (`.deb` and a desktop entry)

SAML authentication and privilege escalation are **planned**. They are not
available in this version.
