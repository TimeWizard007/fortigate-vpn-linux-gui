# Known limitations

v0.3.0 adds an unprivileged `openfortivpn` process backend. It is still **not**
a complete VPN client.

- SAML/SSO is not implemented. Profiles with Use SSO enabled do not start a
  VPN. The message is: `SAML/SSO connection support is planned for v0.4.0.`
  No browser is opened. Microsoft Entra ID is out of scope.
- Privileged helper / polkit is not implemented. `openfortivpn` runs as the
  current user. Permission failures (PPP, routes, DNS) are reported; they are
  not worked around by running the GUI as root.
- Passwords, SAML cookies, and tokens are not stored. A non-SSO connect may
  therefore fail at authentication. That is expected in v0.3.0.
- Certificate verification is never silently disabled. `--trusted-cert` is not
  passed.
- The GUI does not modify firewall rules, routes, or DNS itself.
- Packages are never installed automatically. Recommended Ubuntu command:
  `sudo apt install openfortivpn`.
- Logs are in-memory only and are redacted. They are not written to disk.
- Profiles are local per-user JSON. They are not synced and not encrypted
  beyond ordinary home-directory permissions.
- Profile files contain no passwords, tokens, cookies, or other secrets.
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
- If `openfortivpn` is missing, the GUI still starts. The Connection page
  explains that VPN connectivity is unavailable.

This project is independent software. It is not FortiClient, and it is not
affiliated with, endorsed by, or sponsored by Fortinet. Fortinet, FortiGate,
and FortiClient are trademarks of their respective owner(s).
