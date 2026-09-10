# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0] - 2026-09-09

### Added

- explicit certificate-trust waiting state
- improved connection lifecycle diagnostics
- unexpected tunnel-loss detection

### Changed

- hardened connect/disconnect/retry lifecycle
- improved state accuracy
- cleaner user-facing logging

### Fixed

- duplicate certificate validation events/dialogs
- overlapping connection attempts
- retry races
- stale process/PID states
- timeout cleanup races
- CONNECTED emitted before the VPN tunnel was fully ready
- SAML authentication URL query strings visible in openfortivpn logs

### Security

- certificate changes still require explicit approval
- no new privilege or secret-storage paths introduced

## [0.5.0] - 2026-09-08

### Added

- polkit privileged VPN helper
- controlled privileged openfortivpn execution
- explicit gateway certificate trust workflow
- per-profile certificate SHA-256 pinning
- certificate-change detection
- privileged helper diagnostics
- optional Always on top window setting (off by default)

### Fixed

- privileged helper circular import that prevented standalone helper startup
- Diagnostics treating helper crash tracebacks as the helper version
- main window stacking when launched beside other applications
- Diagnostics and other pages clipping or overlapping at smaller window heights

### Security

- GUI remains unprivileged
- no sudo/sudoers integration
- helper does not expose arbitrary root command execution
- certificate trust requires explicit user approval
- pinned certificate changes are not automatically accepted

## [0.4.0] - 2026-09-08

### Added

- FortiGate SSL VPN SAML/SSO backend flow
- Microsoft Entra ID compatible system-browser authentication
- openfortivpn SAML capability detection
- automatic selection of SAML-capable openfortivpn binary
- WAITING_FOR_AUTH state
- browser launch integration
- SAML timeout/cancel handling
- SAML diagnostics
- expanded secret redaction

### Security

- authentication handled in system browser
- no passwords or SAML cookies stored
- no authentication secrets passed in command-line arguments
- authentication URLs validated before browser launch
- raw SAML output never reaches GUI logs

### Limitations

- privileged helper/polkit is still not implemented
- successful tunnel creation may still fail due to insufficient privileges
- GUI must never be run as root

## [0.3.0] - 2026-09-08

### Added

- openfortivpn backend integration
- process lifecycle management
- connection states
- Connect/Disconnect GUI wiring
- runtime openfortivpn detection
- Logs page
- Diagnostics backend information
- log redaction
- mocked backend tests

### Security

- no shell execution
- no credentials in command-line arguments
- redaction of sensitive VPN output
- GUI remains unprivileged

### Limitations

- SAML/SSO is not implemented yet
- privileged helper/polkit is not implemented yet

## [0.2.0] - 2026-09-08

### Added

- Persistent FortiGate connection profiles (name, gateway, port, description, username hint, SSO flag).
- XDG-compatible local JSON storage (`$XDG_CONFIG_HOME` or `~/.config/fortigate-vpn-linux-gui/profiles.json`).
- Profile Add / Edit / Delete GUI with validation and delete confirmation.
- Connection page integration with saved profiles (gateway, port, and SSO status).
- Read-only profile configuration path on the Settings and Diagnostics pages.
- Tests for profile validation, storage, XDG paths, and GUI add/edit/delete behaviour.

### Security

- Profile storage contains no passwords, SAML tokens, cookies, or secrets.

## [0.1.0] - 2026-09-08

### Added

- Initial project foundation for a native Linux FortiGate SSL VPN GUI.
- PySide6 application shell with Connection, Profiles, Diagnostics, Logs, and Settings pages.
- Placeholder "Connect with SSO" control that does not perform networking or authentication.
- Package layout with documented stubs for VPN backend, profiles, system integration, and diagnostics.
- English and Polish documentation, GPL-3.0-or-later license, and GitHub Actions CI (Ruff and pytest).
- Initial GUI validated on Ubuntu 24.04 / Python 3.12.
- Startup runtime dependency check (loads `libxcb-cursor.so.0`; does not install packages).
- Clear missing-dependency dialog with a copyable Ubuntu install command.
- Documentation of Ubuntu runtime prerequisites (`python3.x-venv`, `libxcb-cursor0`).

[unreleased]: https://github.com/TimeWizard007/fortigate-vpn-linux-gui/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/TimeWizard007/fortigate-vpn-linux-gui/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/TimeWizard007/fortigate-vpn-linux-gui/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/TimeWizard007/fortigate-vpn-linux-gui/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/TimeWizard007/fortigate-vpn-linux-gui/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/TimeWizard007/fortigate-vpn-linux-gui/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/TimeWizard007/fortigate-vpn-linux-gui/releases/tag/v0.1.0
