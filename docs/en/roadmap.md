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

## v0.3.x — openfortivpn backend

- Unprivileged `openfortivpn` process lifecycle
- Connection states and Connect / Disconnect wiring
- Runtime detection of `openfortivpn`
- In-memory Logs page with redaction

## v0.4.x — SAML/SSO

- Native `openfortivpn --saml-login`
- System-browser Microsoft Entra ID / FortiGate SAML
- SAML-capable binary discovery (PATH, `/usr/local/bin`, `/usr/bin`)
- `WAITING_FOR_AUTH`, Cancel, 120s timeout
- Expanded redaction and SAML diagnostics

## v0.5.x — privileged helper (current)

- polkit helper for connect / disconnect / status
- Controlled privileged openfortivpn execution
- Explicit per-profile SHA-256 certificate pinning
- Certificate-change warning
- Helper diagnostics

## Later (planned, not implemented)

- Ubuntu packaging (`.deb` and a desktop entry)
- Broader distribution packaging

The GUI must never run as root.
