# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-09-11

### Added

- Ubuntu 24.04 LTS amd64 Debian package (`fortigate-vpn-linux-gui`)
- `fortigate-vpn-linux-gui` launcher on PATH and a GNOME desktop entry
- Application icon (original project artwork, not Fortinet branding)
- Packaged privileged helper and polkit policy with the `.deb`
- Package-owned SAML-capable openfortivpn 1.24.1 at `/usr/libexec/fortigate-vpn-linux-gui/openfortivpn`

### Changed

- Application version is 1.0.0; Debian revision is 1.0.0-2
- README documents package install/remove separately from developer setup
- Helper, Diagnostics, and Connect use the same approved openfortivpn search order
- Diagnostics reports whether the effective openfortivpn supports SAML
- SAML/SSO is refused before pkexec when `--saml-login` is missing

### Security

- privileged helper protocol version remains 0.7.0 (no protocol migration)
- GUI still never runs as root; helper is not setuid
- `apt remove` / `apt purge` do not delete user profiles
- packaged reports, profiles, and credentials are not included in the `.deb`

## [0.9.0] - 2026-09-11

### Added

- Diagnostics page grouped health checks for system, VPN components, profile/gateway, network, and tunnel
- Explicit Run diagnostics action with bounded timeouts and no parallel runs
- Copyable plain-text diagnostic report for support tickets and GitHub issues
- Unprivileged checks for openfortivpn, helper, polkit policy, DNS, route, gateway TCP, VPN interface, and certificate pin metadata

### Changed

- Diagnostics opens with lightweight local status and does not probe the gateway until Run diagnostics
- Opening Diagnostics does not launch pkexec or request administrator authorization

### Security

- copied diagnostic reports are sanitized (passwords, tokens, cookies, SAML payloads, helper request bodies)
- privileged helper protocol version remains 0.7.0 (no helper reinstall required)

## [0.8.0] - 2026-09-11

### Added

- Profiles list shows name, gateway:port, authentication type, default marker, and Connect
- Connect from the Profiles page using the existing VPN/SAML/certificate-trust flow
- Duplicate profile with deterministic unique names (`(copy)`, `(copy 2)`, …)
- Explicit default profile (exactly one; deleting it clears the default)
- Empty state on the Profiles page when no profiles exist
- Field-level validation for profile name, gateway, and port

### Changed

- Profile editor uses explicit SAML / SSO vs Username / Password authentication
- Connection page selector follows the Profiles store, including the default profile
- Duplicate copies safe metadata and the certificate pin; passwords and tokens are not stored

### Security

- privileged helper protocol version remains 0.7.0 (no helper reinstall required)
- profile JSON still contains no passwords, SAML tokens, cookies, or other secrets

## [0.7.1] - 2026-09-11

### Changed

- shorter Connection-page SSO explanation; technical helper/SAML details moved to About
- Disconnect remains the primary connected action; Reconnect is visually secondary
- failed connections show a short on-page message and keep Connect again available
- reconnect logging no longer duplicates Disconnect/start messages
- SAML sign-in URL details are DEBUG; openfortivpn errors stay in Logs

### Fixed

- Connection page helper-missing copy was overly technical for a first-run screen
- page titles and button sizing were inconsistent across main pages

### Security

- privileged helper protocol version remains 0.7.0 (no helper reinstall required)

## [0.7.0] - 2026-09-10

### Added

- system tray integration
- tray connection controls
- optional automatic reconnect
- manual reconnect
- optional user autostart
- About/project/license information
- desktop notifications

### Changed

- improved desktop state synchronization
- improved shutdown UX
- expanded Settings and Diagnostics

### Fixed

- application appearing unresponsive during multi-second shutdown
- reconnect races
- duplicate tray actions/state inconsistencies

### Security

- autostart remains user-level only
- no new privilege path
- certificate trust remains explicit
- reconnect never bypasses SAML or certificate validation

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

[unreleased]: https://github.com/TimeWizard007/fortigate-vpn-linux-gui/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/TimeWizard007/fortigate-vpn-linux-gui/compare/v0.9.0...v1.0.0
[0.9.0]: https://github.com/TimeWizard007/fortigate-vpn-linux-gui/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/TimeWizard007/fortigate-vpn-linux-gui/compare/v0.7.1...v0.8.0
[0.7.1]: https://github.com/TimeWizard007/fortigate-vpn-linux-gui/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/TimeWizard007/fortigate-vpn-linux-gui/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/TimeWizard007/fortigate-vpn-linux-gui/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/TimeWizard007/fortigate-vpn-linux-gui/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/TimeWizard007/fortigate-vpn-linux-gui/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/TimeWizard007/fortigate-vpn-linux-gui/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/TimeWizard007/fortigate-vpn-linux-gui/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/TimeWizard007/fortigate-vpn-linux-gui/releases/tag/v0.1.0
