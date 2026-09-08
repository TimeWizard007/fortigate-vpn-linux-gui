# Project purpose

FortiGate VPN Linux GUI aims to be a maintainable, native Linux desktop client
for FortiGate SSL VPN.

Users of FortiGate SSL VPN on Linux often rely on the official FortiClient
build, a command-line `openfortivpn` session, or distribution-specific wrappers.
This project exists to provide a clear, modern GUI that:

- feels at home on a Linux desktop (Ubuntu first)
- keeps privileged work out of the GUI process
- plans for SAML/SSO with Microsoft Entra ID via the system browser
- stays independent of Fortinet

The application uses [openfortivpn](https://github.com/adrienverge/openfortivpn)
as the VPN backend. v0.3.x starts it as the current user. SAML/SSO and a
privileged helper are **not** part of this version.

v0.3.x adds process lifecycle, Connect/Disconnect, redacted logs, and
runtime openfortivpn detection on top of persistent profiles. It is still
not a complete VPN client.

This project is **not** affiliated with, endorsed by, or sponsored by Fortinet.
Fortinet, FortiGate, and FortiClient are trademarks of their respective
owner(s).
