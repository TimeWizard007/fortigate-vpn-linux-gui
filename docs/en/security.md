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

The GUI must never run as root. v0.1.x already refuses to start as UID 0.

## Secrets

- VPN passwords must never be stored in plaintext.
- SAML tokens and cookies must never be written to logs.
- Diagnostics must redact credentials and authentication material.
- Future profile files may contain gateway hostnames and usernames, not
  passwords.

## Trust

Certificate verification must not be silently disabled. Insecure TLS settings
must be explicit, rare, and clearly warned. The default path must verify the
gateway certificate.

## What v0.1.x does not do

The current code does not authenticate, open sockets to a VPN gateway, spawn
helpers, or change the host network. The security model still defines how those
features must be added later.
