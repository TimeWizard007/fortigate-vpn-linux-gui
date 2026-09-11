# Security model

This document summarises the security model. Operational reporting instructions
live in [`SECURITY.md`](../../SECURITY.md) at the repository root.

**This project is not affiliated with, endorsed by, or sponsored by Fortinet.**

## Process split

| Process | Privilege | Role |
| ------- | --------- | ---- |
| GUI | Unprivileged user | Display UI, collect intent, open the system browser |
| VpnBackend | Same unprivileged user | Structured helper requests, SAML URL handling, redacted logs |
| Privileged helper | Root via polkit | Start/stop openfortivpn only |
| openfortivpn | Helper-owned | SSL VPN tunnel and SAML callback listener |
| System browser | Unprivileged user | Microsoft Entra ID / FortiGate SAML pages |

The GUI must never run as root. It refuses to start as UID 0. Extra rights for
PPP, routes, and DNS belong in the helper, not in the Qt process. Running the
whole desktop app as root would enlarge the attack surface (UI, clipboard,
file dialogs, plugins).

polkit action: `com.fortigate-vpn-linux-gui.manage-vpn`. The desktop user sees
the normal Linux authentication dialog. The GUI is not launched with pkexec.
There are no sudoers rules and openfortivpn is not setuid.

## Command construction

Non-SSO:

```text
openfortivpn <gateway>:<port>
```

SSO:

```text
openfortivpn <gateway>:<port> --saml-login
```

Pinned certificate:

```text
openfortivpn <gateway>:<port> [--saml-login] --trusted-cert <sha256>
```

Arguments are a **list** with `shell=False`. No password, cookie, or token is
passed on the command line. `--trusted-cert` is added only with a helper-
validated SHA-256 digest as a separate argv item. The helper never accepts a
raw command string or an arbitrary executable path.

Gateway, port, fingerprint, and operation are validated in the GUI **and**
again inside the helper.

## Browser and URLs

Subprocess output is untrusted. Before opening a URL the backend:

- parses it with `urllib.parse`
- requires `http` or `https`
- rejects `javascript:`, `file:`, `data:`, loopback callback URLs, and
  whitespace/shell fragments
- never passes the URL through a shell

The helper emits a validated SAML URL event. The unprivileged GUI opens the
browser. The helper/openfortivpn keep the localhost callback.

The GUI does not display the full sign-in URL. Copy uses origin+path only
because query strings can carry session identifiers.

## Secrets

- VPN passwords are not stored.
- SAML tokens, SVPNCOOKIE, and session ids must never be written to logs,
  profile files, diagnostics, or exceptions.
- Every backend log line passes through `redact_log_line` (case-insensitive)
  before it is shown.
- Connection profile files contain **no authentication secrets**.
  `trusted_cert_sha256` is a public certificate pin, not a password.

## Trust

Certificate verification is never silently disabled. An unknown FortiGate
certificate requires an explicit **Trust this certificate for this VPN
profile** action (pinning). Cancel does not save a pin and does not retry.

If a pin exists and openfortivpn presents a **different** fingerprint, the UI
warns that the gateway certificate has changed. The previous pin is never
replaced automatically.

## What v0.7.0 does not do

- No sudo or sudoers integration.
- No arbitrary root command execution through the helper.
- No automatic package installation (`.deb` packaging is planned for v0.8.0).
- No direct firewall, route, or DNS changes by the GUI.
- No password, token, or VPN cookie storage.
- Logs are in memory only; they are not persisted to disk.
- No custom username/password login and no embedded webview.
- No auto-trust and no TLS validation disable.
- Auto-reconnect never bypasses SAML or certificate validation.
- Autostart is user-level only (`~/.config/autostart/`); no system-wide
  autostart and no automatic VPN connect at login.
