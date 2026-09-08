# Known limitations

v0.1.x is a foundation release. It is **not** a working VPN client.

- No VPN connection: `openfortivpn` is not executed.
- No SAML/SSO: Microsoft Entra ID login is planned, not implemented.
- No profile storage: the profile selector is a disabled placeholder.
- No privileged helper, polkit rules, or systemd services.
- No route, DNS, or firewall changes.
- No password or token storage.
- Linux only; Ubuntu is the primary supported distribution.
- Other desktop environments should work where PySide6 works; they are not
  first-class targets yet.
- Documentation exists in English and Polish; other languages are not provided.
- The GUI "Connect with SSO" control only explains that the feature is missing.
- Ubuntu runtime packages (`python3.x-venv`, `libxcb-cursor0`) must be
  installed by the user. The application never installs system packages.
- If `libxcb-cursor.so.0` is missing, startup shows a dialog (and stderr)
  with `sudo apt install libxcb-cursor0` and exits instead of crashing inside
  Qt. On a pure X11 session without that library, Qt itself cannot draw a
  window; the same instructions are still printed to the terminal.

This project is independent software. It is not FortiClient, and it is not
affiliated with, endorsed by, or sponsored by Fortinet. Fortinet, FortiGate,
and FortiClient are trademarks of their respective owner(s).
