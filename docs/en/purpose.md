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

The application will eventually use [openfortivpn](https://github.com/adrienverge/openfortivpn)
as the VPN backend. That integration is **not** part of v0.1.x.

v0.1.x delivers the repository structure, packaging, a non-connecting GUI
shell, documentation in English and Polish, tests, and CI. It is a starting
point for a serious open-source application, not a working VPN client.

This project is **not** affiliated with, endorsed by, or sponsored by Fortinet.
Fortinet, FortiGate, and FortiClient are trademarks of their respective
owner(s).
