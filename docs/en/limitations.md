# Known limitations

v0.2.x adds persistent profiles. It is **not** a working VPN client.

- No VPN connection: `openfortivpn` is not executed.
- No SAML/SSO: Microsoft Entra ID login is planned, not implemented. Connect
  with SSO only shows a not-implemented message.
- Profiles are local per-user JSON. They are not synced and not encrypted
  beyond ordinary home-directory permissions.
- Profile files contain no passwords, tokens, cookies, or other secrets.
- No privileged helper, polkit rules, or systemd services.
- No route, DNS, or firewall changes.
- Linux only; Ubuntu is the primary supported distribution.
- Other desktop environments should work where PySide6 works; they are not
  first-class targets yet.
- Documentation exists in English and Polish; other languages are not provided.
- Ubuntu runtime packages (`python3.x-venv`, `libxcb-cursor0`) must be
  installed by the user. The application never installs system packages.
- If `libxcb-cursor.so.0` is missing, startup shows a dialog (and stderr)
  with `sudo apt install libxcb-cursor0` and exits instead of crashing inside
  Qt. On a pure X11 session without that library, Qt itself cannot draw a
  window; the same instructions are still printed to the terminal.

This project is independent software. It is not FortiClient, and it is not
affiliated with, endorsed by, or sponsored by Fortinet. Fortinet, FortiGate,
and FortiClient are trademarks of their respective owner(s).
