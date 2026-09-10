# Project purpose

FortiGate VPN Linux GUI aims to be a maintainable, native Linux desktop client
for FortiGate SSL VPN.

Users of FortiGate SSL VPN on Linux often rely on the official FortiClient
build, a command-line `openfortivpn` session, or distribution-specific wrappers.
This project exists to provide a clear, modern GUI that:

- feels at home on a Linux desktop (Ubuntu first)
- keeps privilege outside the GUI process (polkit helper)
- uses SAML/SSO with Microsoft Entra ID via the system browser
- stays independent of Fortinet

The application uses [openfortivpn](https://github.com/adrienverge/openfortivpn)
as the VPN backend. v0.6.x still starts it through a minimal privileged helper.
The GUI remains unprivileged, opens the system browser for SAML, and does not
auto-reconnect after an unexpected tunnel loss.

This project is **not** affiliated with, endorsed by, or sponsored by Fortinet.
Fortinet, FortiGate, and FortiClient are trademarks of their respective
owner(s).
