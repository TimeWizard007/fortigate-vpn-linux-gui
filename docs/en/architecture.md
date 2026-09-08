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
change routes, DNS, or firewall rules.

### Application / service layer

Non-Qt packages (`vpn`, `profiles`, `diagnostics`). This layer will translate
UI actions into backend operations and keep secrets out of logs. In v0.1.x
these packages contain documentation only.

### Privileged helper

A future small helper (`system` package / packaging artifacts) activated with
polkit. It should only perform the operations that actually need extra rights.
The GUI will never be that helper.

### openfortivpn

The planned VPN engine. Not invoked in v0.1.x.

### FortiGate SSL VPN

The remote gateway. This project does not implement the VPN protocol itself.

## SAML / SSO (planned)

SAML authentication is expected to use the **user's system browser** and
**Microsoft Entra ID**. Tokens and cookies from that flow must not be written
to logs. This path is planned and is not implemented.

## Package map

| Package | Role |
| ------- | ---- |
| `fortigate_vpn_gui.gui` | Qt windows and pages |
| `fortigate_vpn_gui.runtime` | Process checks (the GUI refuses to run as root) |
| `fortigate_vpn_gui.vpn` | Future service layer over the helper / openfortivpn |
| `fortigate_vpn_gui.profiles` | Future profile storage and validation |
| `fortigate_vpn_gui.system` | Startup preflight checks; future helper / polkit integration |
| `fortigate_vpn_gui.diagnostics` | Future redacted troubleshooting data |
