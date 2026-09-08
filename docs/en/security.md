# Security model

This document summarises the security model. Operational reporting instructions
live in [`SECURITY.md`](../../SECURITY.md) at the repository root.

**This project is not affiliated with, endorsed by, or sponsored by Fortinet.**

## Process split

| Process | Privilege | Role |
| ------- | --------- | ---- |
| GUI | Unprivileged user | Display UI, collect intent |
| VpnBackend | Same unprivileged user | Start/stop `openfortivpn`, redact logs |
| openfortivpn | Current user in v0.3.x | SSL VPN tunnel (may fail without extra rights) |
| Future helper | Minimal extra rights via polkit | Only operations that need them |

The GUI must never run as root. It refuses to start as UID 0. Extra rights for
PPP, routes, and DNS belong in a future helper, not in the Qt process. Running
the whole desktop app as root would enlarge the attack surface (UI, clipboard,
file dialogs, plugins).

## Command construction

`openfortivpn` is started with an argument **list** and `shell=False`:

```text
openfortivpn <gateway>:<port>
```

No password, cookie, token, or certificate-bypass flag is passed on the
command line.

## Secrets

- VPN passwords must never be stored in plaintext. v0.3.x does not store them
  at all.
- SAML tokens and cookies must never be written to logs or profile files.
- Diagnostics must redact credentials and authentication material.
- Connection profile files contain **no secrets**: no passwords, SAML tokens,
  cookies, client secrets, or MFA data. They may contain a gateway hostname,
  port, display name, description, and an optional username hint.
- Every backend log line passes through `redact_log_line` (case-insensitive)
  before it is shown. Examples: `password=***`, `SVPNCOOKIE=***`,
  `Authorization: Bearer ***`.

Profiles are stored per-user at
`${XDG_CONFIG_HOME:-$HOME/.config}/fortigate-vpn-linux-gui/profiles.json`.
That path is shown in Settings and Diagnostics as read-only.

## Trust

Certificate verification must not be silently disabled. Insecure TLS settings
must be explicit, rare, and clearly warned. The default path must verify the
gateway certificate. v0.3.x never adds `--trusted-cert`.

## What v0.3.x does not do

- No SAML/SSO, browser, or Microsoft Entra ID authentication.
- No sudo, pkexec, or polkit helper.
- No automatic package installation.
- No direct firewall, route, or DNS changes by the GUI.
- No password, token, or VPN cookie storage.
- Logs are in memory only; they are not persisted to disk.
