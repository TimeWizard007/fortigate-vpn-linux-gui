# Planned architecture

The long-term design separates the desktop UI from VPN mechanics and from
privilege.

```text
GUI                          PySide6 widgets (unprivileged)
  ↓
Application / service layer  profiles, status, connect/disconnect intents
  ↓
Privileged helper            minimal polkit-activated process
  ↓
openfortivpn                 SSL VPN client
  ↓
FortiGate SSL VPN            gateway
```

## Layers

### GUI

Qt widgets in `src/fortigate_vpn_gui/gui/`. The GUI displays state and collects
user intent. It must not run as root, spawn `openfortivpn`, call `sudo`, or
change routes, DNS, or firewall rules. Profile add/edit/delete talks to
`ProfileManager`; widgets do not read or write JSON themselves.

### Application / service layer

Non-Qt packages (`vpn`, `profiles`, `diagnostics`). `profiles` loads and saves
per-user connection profiles. `vpn` remains documentation-only until connect is
implemented. This layer keeps secrets out of logs and out of profile files.

### Privileged helper

A future small helper (`system` package / packaging artifacts) activated with
polkit. It should only perform the operations that actually need extra rights.
The GUI will never be that helper.

### openfortivpn

The planned VPN engine. Not invoked in v0.2.x.

### FortiGate SSL VPN

The remote gateway. This project does not implement the VPN protocol itself.

## Connection profiles

Profiles are local, per-user configuration:

```text
${XDG_CONFIG_HOME:-$HOME/.config}/fortigate-vpn-linux-gui/profiles.json
```

JSON schema (version 1): `id`, `name`, `gateway`, `port` (default 443),
`description`, `username_hint`, `use_sso` (default true).

Passwords, SAML tokens, cookies, client secrets, and MFA data are not stored.
Unknown JSON fields are ignored. Malformed files do not crash the application.

`ProfileManager` notifies listeners after add/update/delete so the Connection
page refreshes without restarting.

## SAML / SSO (planned)

SAML authentication is expected to use the **user's system browser** and
**Microsoft Entra ID**. Tokens and cookies from that flow must not be written
to logs or profile files. This path is planned and is not implemented.

## Package map

| Package | Role |
| ------- | ---- |
| `fortigate_vpn_gui.gui` | Qt windows and pages |
| `fortigate_vpn_gui.runtime` | Process checks (the GUI refuses to run as root) |
| `fortigate_vpn_gui.vpn` | Future service layer over the helper / openfortivpn |
| `fortigate_vpn_gui.profiles` | Profile model, XDG JSON storage, manager |
| `fortigate_vpn_gui.system` | Startup preflight checks; future helper / polkit integration |
| `fortigate_vpn_gui.diagnostics` | Future redacted troubleshooting data |
