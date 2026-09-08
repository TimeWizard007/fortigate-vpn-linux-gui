# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[unreleased]: https://github.com/TimeWizard007/fortigate-vpn-linux-gui/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/TimeWizard007/fortigate-vpn-linux-gui/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/TimeWizard007/fortigate-vpn-linux-gui/releases/tag/v0.1.0
