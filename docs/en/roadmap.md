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

## v0.5.x — privileged helper

- polkit helper for connect / disconnect / status
- Controlled privileged openfortivpn execution
- Explicit per-profile SHA-256 certificate pinning
- Certificate-change warning
- Helper diagnostics

## v0.6.x — connection reliability (current)

- Explicit `WAITING_FOR_CERTIFICATE_TRUST` wait
- One active connection attempt; retry waits for cleanup
- Certificate event/dialog deduplication
- Unexpected tunnel-loss detection (no auto-reconnect)
- Safer Disconnect/Cancel during all active phases
- Clearer lifecycle diagnostics and user-facing logs

## v0.7.0 — desktop UX (planned)

- Tray icon
- Auto-reconnect after unexpected tunnel loss
- Autostart / session restore

## Later (planned, not implemented)

- Ubuntu packaging (`.deb` and a desktop entry)
- Broader distribution packaging

The GUI must never run as root.
