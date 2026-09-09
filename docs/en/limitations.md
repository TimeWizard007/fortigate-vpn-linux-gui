# Known limitations

v0.5.0 adds a polkit privileged helper and explicit FortiGate certificate
pinning on top of SAML/SSO.

- The GUI never runs as root. Privileged work goes through the helper only.
- The helper and polkit policy must be installed for a real tunnel. Missing
  helper, missing polkit, authorization denied, and version mismatch are
  reported; the GUI does not fall back to sudo or to spawning openfortivpn
  as the desktop user.
- Ubuntu 24.04 packaged openfortivpn **1.21.0** (`/usr/bin/openfortivpn`) may
  lack `--saml-login`. SSO needs a SAML-capable build (tested: **1.24.1** at
  `/usr/local/bin/openfortivpn`).
- Certificates are never auto-trusted. TLS validation is never disabled.
  `--trusted-cert` is added only after an explicit per-profile pin.
- A changed gateway certificate is not accepted automatically.
- Passwords, SAML cookies, and tokens are not stored.
- The GUI does not modify firewall rules, routes, or DNS itself.
- Packages are never installed automatically.
- Logs are in-memory only and are redacted. They are not written to disk.
- The full SAML URL is not shown; copy uses origin+path only.
- Profiles are local per-user JSON. They are not synced and not encrypted
  beyond ordinary home-directory permissions.
- Linux only; Ubuntu is the primary supported distribution.
- Documentation exists in English and Polish; other languages are not provided.
- If `libxcb-cursor.so.0` is missing, startup shows a dialog with
  `sudo apt install libxcb-cursor0` and exits.
- If `openfortivpn` or the helper is missing, the GUI still starts.

This project is independent software. It is not FortiClient, and it is not
affiliated with, endorsed by, or sponsored by Fortinet. Fortinet, FortiGate,
and FortiClient are trademarks of their respective owner(s).
