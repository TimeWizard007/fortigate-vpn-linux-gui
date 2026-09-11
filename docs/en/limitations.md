# Known limitations

v0.7.0 adds desktop tray, optional autostart, and optional auto-reconnect on
top of the hardened connection lifecycle and polkit helper.

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
- Auto-reconnect is **off by default**. It runs only after unexpected tunnel
  loss, never after Disconnect or Quit, never after certificate rejection,
  and never without SAML/browser or explicit certificate trust when those
  are required. Rapid authentication failures are not retried in a loop.
- Autostart only launches the GUI after login. It does not connect the VPN.
  The `.desktop` file is user-level (`~/.config/autostart/`) and does not
  require root.
- Close-to-tray needs a working system tray. Without a tray, closing the
  window still exits the application.
- Only one connection attempt runs at a time. Rapid extra Connect clicks are
  ignored. Certificate trust retries once after the previous process exits.
- Disconnect/Cancel is safe during STARTING, WAITING_FOR_AUTH,
  WAITING_FOR_CERTIFICATE_TRUST, CONNECTING, and CONNECTED. The browser is
  not force-closed; the SAML listener goes away with the process.
- Passwords, SAML cookies, and tokens are not stored.
- The GUI does not modify firewall rules, routes, or DNS itself.
- Packages are never installed automatically. `.deb` packaging is planned
  for a later release (v1.0.0).
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
