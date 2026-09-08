# Roadmap

Dates are not committed. Order may change as design work proceeds.

## v0.1.x — foundation (current)

- Python package and `python -m fortigate_vpn_gui` entry point
- Placeholder PySide6 GUI (no VPN operations)
- Documented stubs for backend, profiles, system integration, and diagnostics
- English and Polish documentation
- pytest, Ruff, and GitHub Actions CI

## Later (planned, not implemented)

- Connection profile persistence without plaintext passwords
- Privileged helper design and polkit policy
- openfortivpn-backed connect / disconnect / status
- SAML/SSO through the system browser and Microsoft Entra ID
- Redacted logs and user-triggered diagnostics
- Ubuntu packaging (`.deb` and a desktop entry)

SAML authentication and openfortivpn execution are **planned**. They are not
available in this version.
