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

## v0.6.x — connection reliability

- Explicit `WAITING_FOR_CERTIFICATE_TRUST` wait
- One active connection attempt; retry waits for cleanup
- Certificate event/dialog deduplication
- Unexpected tunnel-loss detection (no auto-reconnect in 0.6.x)
- Safer Disconnect/Cancel during all active phases
- Clearer lifecycle diagnostics and user-facing logs

## v0.9.0 — Diagnostics

- Expanded diagnostics for helper, DNS, routing, and VPN interface
- Diagnostic report export (sanitized, copyable)

## v1.0.0 — packaging and stable release (current)

- Debian/Ubuntu `.deb` for Ubuntu 24.04 LTS amd64
- Desktop launcher, icon, packaged helper and polkit policy
- Application version 1.0.0; helper protocol remains 0.7.0

## v0.8.0 — Profiles UX

- First-class Profiles management for many FortiGate gateways
- Connect from the profile list using the existing VPN controller
- Duplicate, default profile, empty state, field-level validation
- Unique profile names (case-insensitive); v0.7.1 config remains loadable

## v0.7.1 — UI/UX polish

- Connection-page copy and button hierarchy
- About-page helper/SAML explanation
- reconnect log noise reduction
- failed-state on-page hint

## v0.7.0 — desktop UX

- Tray integration
- Desktop UX (close-to-tray, shutdown “Closing...” feedback)
- Optional automatic reconnect after unexpected tunnel loss
- Manual reconnect
- Optional user-level autostart
- About / project / license information
- Graceful shutdown UI

The GUI must never run as root.
