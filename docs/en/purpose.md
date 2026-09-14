# Project purpose

FortiGate VPN Linux GUI aims to be a maintainable, native Linux desktop client
for FortiGate SSL VPN and IPsec remote access.

Users of FortiGate SSL VPN on Linux often rely on the official FortiClient
build, a command-line `openfortivpn` session, or distribution-specific wrappers.
This project exists to provide a clear, modern GUI that:

- feels at home on a Linux desktop (Ubuntu first)
- keeps privilege outside the GUI process (polkit helper)
- uses SAML/SSO with Microsoft Entra ID via the system browser
- stays independent of Fortinet

The application uses [openfortivpn](https://github.com/adrienverge/openfortivpn)
for SSL VPN and distribution strongSwan for IPsec. Both are started through a
minimal privileged helper (protocol 0.8.0 in v1.1.0). The GUI remains
unprivileged. SSL SAML opens the system browser. Optional auto-reconnect after
unexpected tunnel loss is off by default and never skips certificate approval
or SAML.

This project is **not** affiliated with, endorsed by, or sponsored by Fortinet.
Fortinet, FortiGate, and FortiClient are trademarks of their respective
owner(s).
