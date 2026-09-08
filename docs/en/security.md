# Security model

This document summarises the security model. Operational reporting instructions
live in [`SECURITY.md`](../../SECURITY.md) at the repository root.

**This project is not affiliated with, endorsed by, or sponsored by Fortinet.**

## Process split

| Process | Privilege | Role |
| ------- | --------- | ---- |
| GUI | Unprivileged user | Display UI, collect intent |
| Future helper | Minimal extra rights via polkit | Only operations that need them |
| openfortivpn | Started by the helper (planned) | SSL VPN tunnel |

The GUI must never run as root. It refuses to start as UID 0.

## Secrets

- VPN passwords must never be stored in plaintext.
- SAML tokens and cookies must never be written to logs.
- Diagnostics must redact credentials and authentication material.
- Connection profile files contain **no secrets**: no passwords, SAML tokens,
  cookies, client secrets, or MFA data. They may contain a gateway hostname,
  port, display name, description, and an optional username hint.

Profiles are stored per-user at
`${XDG_CONFIG_HOME:-$HOME/.config}/fortigate-vpn-linux-gui/profiles.json`.
That path is shown in Settings and Diagnostics as read-only.

## Trust

Certificate verification must not be silently disabled. Insecure TLS settings
must be explicit, rare, and clearly warned. The default path must verify the
gateway certificate.

## What v0.2.x does not do

The current code does not authenticate, open sockets to a VPN gateway, spawn
helpers, or change the host network. Profile storage is local JSON only. The
security model still defines how VPN and SAML features must be added later.
