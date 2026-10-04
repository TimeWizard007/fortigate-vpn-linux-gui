# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Application **1.6.0**, Debian **1.6.0-1** (development tree; not tagged).

### Added

- Encrypted **Backup** / **Restore** of all profiles and saved IPsec secrets (Argon2id + AES-256-GCM, `.fvbackup`)
- Profiles-page Backup/Restore entry points, separate from secret-free Import/Export
- APT-aware About context: Debian package version, install method, copyable apt instructions (never executed)
- Tray notification once per newly observed GitHub release version
- Desktop Keywords for IPsec / IKEv1 / IKEv2

### Changed

- Application version is 1.6.0; helper capability version remains 0.9.0; JSON-lines `protocol_version` remains 1; Debian package is 1.6.0-1
- Frozen v1.4.0 / v1.3.0 VPN protocol backend is unchanged
- About shows Installed vs Available on update, plus Protocol 1 and Debian/install method
- `profiles.json` writes use mode 0600
- `cryptography` is a direct project dependency (already bundled at 50.0.1)
- polkit action `com.fortigate-vpn-linux-gui.manage-vpn` uses `allow_active=yes` (still `allow_any=no`, `allow_inactive=no`) so an active local desktop user can start the helper without an administrator password

### Fixed

- Backup and Restore now open the file dialog before the password prompt. Button `clicked(bool)` is no longer treated as a backup path.

### Security

- Export remains secret-free; Backup may include PSK and XAuth password only inside authenticated encryption
- SSL passwords, SAML cookies/tokens/tokenid/FCT UID are not backed up
- Restore is all-or-nothing: keyring failure or mid-write errors roll back
- The GUI still never installs packages and never calls sudo/pkexec/apt to upgrade itself
- Active local desktop users may invoke the narrowly scoped VPN helper without an administrator password; inactive and non-local sessions remain denied. The helper still performs privileged networking and is not arbitrary root execution. Package install/upgrade still requires administrator privileges.

## [1.5.0] - 2026-10-03

Application **1.5.0**, Debian **1.5.0-1**. Tagged, published, and production-verified.

### Added

- GitHub Releases update check (HTTPS, no token, no telemetry, no VPN/profile data)
- About component versions: application, helper expected/detected, Python, Qt, PySide, openfortivpn, strongSwan/swanctl
- Manual **Check for updates** and optional automatic check at most once per 24 hours
- **View release** opens the GitHub Release page in the system browser after an explicit click
- GitHub Actions **Release** workflow on `v*.*.*` tags: Ruff, tests, native plugin/symbol/`ldd -r`, `scripts/build-deb.sh`, SHA-256, attach `.deb`
- Version consistency check across application, pyproject, Debian metadata, and optional git tag
- Static APT repository generator (`dists/` + `pool/`, Packages, Release, InRelease) with `Signed-By` documentation
- Production APT repository for Ubuntu 24.04 (`noble`) amd64 at https://timewizard007.github.io/fortigate-vpn-linux-gui/apt
- Package inspection script that rejects credentials, private keys, research binaries, and FortiClient proprietary files

### Changed

- Application version is 1.5.0; helper capability version remains 0.9.0; JSON-lines `protocol_version` remains 1; Debian package is 1.5.0-1
- Frozen v1.4.0 / v1.3.0 VPN protocol backend is unchanged
- Direct `.deb` install remains supported as an alternative; production APT is **live** with a binary OpenPGP `Signed-By` keyring (fingerprint `E0388D37D6E52C7675A933B1AAD0826D6E18C01E`); historical package versions remain published

### Security

- Update checks never send Authorization headers, profiles, gateways, or user identifiers
- The GUI never self-updates and never invokes `sudo`/`pkexec`/`apt` to install packages
- APT signing private keys are not committed; GitHub Actions secrets are referenced by name only
- Signing/publishing workflows do not run on pull requests

## [1.4.0] - 2026-10-03

### Added

- First-class GUI profile families: SSL VPN, IPsec IKEv1, and IPsec IKEv2 SAML/SSO
- Profile **Import** and **Export** using a versioned, secret-free application format
- Diagnostics **Copy diagnostic report** (same sanitized engine as Export diagnostics)
- SAML service reachability check for IKEv2 SAML/SSO profiles
- Connect disabled for stored IPsec combinations this release cannot start

### Changed

- Application version is 1.4.0; helper capability version remains 0.9.0; JSON-lines `protocol_version` remains 1; Debian package is 1.4.0-1
- Profile editor progressive disclosure: users pick a supported VPN family instead of low-level IKE/ESP controls
- Profiles page: **New profile**, **Import**, **Export**, and delete confirmation that also removes saved secrets
- Connection page shows the human-readable VPN family and authentication method
- Existing v1.3.0 SSL, IKEv1, and IKEv2 SAML/SSO profiles continue to load without recreation
- Live-validated against real FortiGate gateways: SSL VPN SAML/SSO; IKEv1 PSK + XAuth including Edit/Save reconnect; IKEv2 SAML/SSO

### Security

- GUI still never runs as root; helper is not setuid; JSON-lines protocol_version is unchanged
- Profile export never contains PSK, passwords, tokenid, FCT UID, cookies, or filesystem/config fragments
- Duplicate creates a new profile id / keyring namespace and does not copy saved secrets
- Editing a profile keeps an existing saved PSK when the field is left blank
- The editor never loads a stored PSK into the pre-shared-key field; Show/Hide applies only to a newly typed replacement
- Diagnostics and logs remain structurally redacted

### Fixed

- IPsec editor Show control is disabled while the PSK field is empty so a stored key is not implied to be revealable
- Opening and saving an existing IKEv1 profile no longer resets IKE identity/settings or stored PSK/XAuth secrets
- Frozen v1.3.0 VPN protocol backend is unchanged

## [1.3.0] - 2026-10-02

### Added

- FortiGate IPsec IKEv2 + SAML/SSO with unprivileged external-browser bootstrap
- FortiClient-compatible EAP-MSCHAPv2 after SAML (`tokenid` as EAP password; FCT UID as EAP identity)
- Application-owned FortiClient compatibility plugin for the private IKEv2 SSO charon only (Vendor IDs, AUTH omission, INITIAL_CONTACT, Notify `0xF100`, CP16, CFG_REPLY split-include)
- Negotiated split-tunnel from FortiGate `INTERNAL_IP4_SUBNET` (table 220 / XFRM; no default route in table 220)
- Split DNS (VPN DNS on the VIP link without hijacking public resolution)
- Explicit main-table gateway `/32` snapshot and restore so Connect → Disconnect → Connect keeps the pre-VPN endpoint path
- Deterministic IPsec teardown ownership: IKE/CHILD terminate, private charon exit, DNS/`nmcli reapply`, then `/32` restore and kernel verification

### Changed

- Application version is 1.3.0; helper capability version is 0.9.0; JSON-lines `protocol_version` remains 1; Debian package is 1.3.0-1
- Packaged helper now advertises `ipsec_ikev2_eap` and ships the uniquely named FortiClient compatibility plugin
- Every production `swanctl` invocation uses the private `STRONGSWAN_CONF` client conf (`load = vici`); distro plugin lists are not requested
- Existing SSL/SAML and IKEv1 PSK+XAuth paths remain supported

### Security

- GUI still never runs as root; helper is not setuid; JSON-lines protocol_version is unchanged
- EAP identity / FCT UID, `tokenid`, PSK, EAP password, and SAML URL/query/cookie/session data stay redacted in application logs
- The FortiClient compatibility plugin is not given a `/etc/strongswan.d/charon/` snippet; system charon does not load it
- `/etc/strongswan.conf` is not modified; `strongswan-starter` is not stopped
- Gateway-route restore never invents a `/32`, never copies table 220, and never writes `src`

### Fixed

- Disconnect DNS restore / `nmcli device reapply` no longer leaves the FortiGate endpoint `/32` missing on dual-homed hosts
- Overlapping `disconnect()` and charon `_on_exit` no longer race network restoration
- Private `swanctl` no longer logs distro optional-plugin load failures (`test-vectors`, `ldap`, `pkcs11`, …)

## [1.2.0] - 2026-09-28

### Added

- Human-readable Connection-page failures for SSL and IPsec when backend output proves the cause
- **Copy diagnostics** and **Export diagnostics** (text or ZIP) for GitHub issues
- IPsec leftover detection in Diagnostics and owned-state cleanup before the next connect
- Profile credential status: stored securely, not stored, or secure storage unavailable
- Forget saved PSK / XAuth password without revealing stored secrets
- About page backend version lines for packaged openfortivpn and distro strongSwan

### Changed

- Application version is 1.2.0; helper protocol remains 0.8.0; Debian package is 1.2.0-1
- IPsec profile editor groups: Connection, Authentication, IKE / Phase 1, Child SA / Phase 2, Advanced
- Lifecycle logs use Starting connection / VPN connected / Cleanup completed (CHILD_SA still required for IPsec connected)
- Diagnostics export reuses centralized redaction (PSK, passwords, cookies, tokens, private keys, helper requests)

### Security

- GUI still never runs as root; helper is not setuid; helper protocol is unchanged
- Diagnostics export must not contain PSK, passwords, keyring values, SAML cookies/tokens, or private keys
- Leftover IPsec recovery stops only charon bound to `/run/charon.fvl.conf`
  and never treats `/run/charon.pid`, `/run/charon.vici`, or occupied UDP/500
  as proof of ownership. Unrelated charon is never killed.
- IPsec `swanctl` talks only to the application VICI socket
  `/run/charon.fvl.vici` via `STRONGSWAN_CONF`; it never uses the system
  default `unix:///var/run/charon.vici`.

### Fixed

- IPsec no longer binds the system VICI socket or injects PSK/XAuth into a
  running `strongswan-starter` charon
- Occupied UDP/500 or UDP/4500 fails with an IKE port-conflict message instead
  of an authentication or negotiation error

## [1.1.0] - 2026-09-14

### Added

- Generic FortiGate IPsec remote-access profile type (not site-specific)
- Live-tested IPsec: IKEv1 Aggressive Mode, PSK, XAuth username/password, Mode Config, NAT-T, Phase 1/2, Cisco Unity / FortiGate split include
- Distro strongSwan backend (charon/swanctl allowlisted paths; not bundled)
- Private charon instance with swanctl `--load-all` / `--initiate` (no secrets on argv)
- Connect-time PSK and XAuth prompt; either secret may be saved in Secret Service when the user opts in
- `scripts/install-dev-helper.sh` installs checkout helper protocol 0.8.0 onto the polkit path
- IPsec Diagnostics checks that never include PSK or passwords
- NetworkManager-safe IPsec DNS overlay and restore (pre-VPN snapshot, temporary `~.`, no `resolvectl revert` on NM-managed links)

### Changed

- Application version is 1.1.0; helper protocol is 0.8.0; Debian package is 1.1.0-1
- Missing `vpn_type` in existing profiles is treated as SSL VPN (schema version remains 1)
- Ubuntu package Depends on distro strongSwan (`strongswan`, `strongswan-swanctl`, `libcharon-extra-plugins`, `libcharon-extauth-plugins`); they are not bundled
- Package-owned venv includes `keyring` and the Secret Service Python stack so a clean `.deb` does not need `pip`
- Tray Quit disposes the tray and calls `QApplication.quit()` so `app.exec()` returns after helper cleanup

### Fixed

- Ubuntu 5.9.13 `swanctl` has no `--unix`; load uses `--load-all --file` and the default VICI socket `/run/charon.vici`
- IPsec CHILD_SA `remote_ts` is `0.0.0.0/0` with `charon.cisco_unity = yes` so FortiGate Unity split-include can narrow; the public gateway is not used as a traffic selector
- IPsec PSK/XAuth Secret Service detection accepts GNOME Keyring / python-keyring SecretService (including a chainer wrapper) and no longer treats a missing venv `keyring` package or a locked collection as a generic “unavailable” backend

### Security

- GUI still never runs as root; helper is not setuid
- IPsec secrets are written to a 0600 helper runtime file and wiped on disconnect
- PSK/password are not passed on command-line arguments
- IPsec PSK is never stored in profiles.json; optional save uses Secret Service only
- XAuth password may be stored in Secret Service only; never in profiles.json

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

[Unreleased]: https://github.com/TimeWizard007/fortigate-vpn-linux-gui/compare/v1.5.0...HEAD
[1.5.0]: https://github.com/TimeWizard007/fortigate-vpn-linux-gui/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/TimeWizard007/fortigate-vpn-linux-gui/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/TimeWizard007/fortigate-vpn-linux-gui/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/TimeWizard007/fortigate-vpn-linux-gui/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/TimeWizard007/fortigate-vpn-linux-gui/compare/v1.0.0...v1.1.0
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
