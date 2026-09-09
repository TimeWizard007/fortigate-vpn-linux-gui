# Architecture

The design separates the desktop UI from VPN process control and from
privilege.

```text
GUI                          PySide6 widgets (unprivileged)
  ↓ structured JSON request
Privileged helper            root via polkit (pkexec)
  ↓ controlled argv
openfortivpn                 --saml-login for SSO; PPP / routes / DNS
  ↓ SAML URL event
System browser               Microsoft Entra ID via FortiGate SAML
  ↓
FortiGate SSL VPN            gateway
```

The GUI must never become the helper and must never run as root. `pkexec`
starts only `/usr/libexec/fortigate-vpn-linux-gui/vpn-helper`. The desktop
application is not launched with pkexec or sudo.

## Layers

### GUI

Qt widgets in `src/fortigate_vpn_gui/gui/`. The GUI displays state and collects
user intent. It must not run as root, call `sudo`, or change routes, DNS, or
firewall rules. Connect/Disconnect calls `VpnBackend`; widgets do not
construct subprocesses themselves. Profile add/edit/delete talks to
`ProfileManager`; widgets do not read or write JSON themselves.

When a gateway certificate cannot be validated, the Connection page shows an
explicit pinning dialog. The system browser is opened in the unprivileged
session after a validated SAML URL event.

### Application / service layer

Non-Qt packages (`vpn`, `profiles`, `helper`, `diagnostics`).

`fortigate_vpn_gui.vpn` owns GUI-side state. `fortigate_vpn_gui.helper` owns
privileged openfortivpn execution.

| Module | Role |
| ------ | ---- |
| `vpn/backend.py` | `connect`, `disconnect`, SAML timeout/cancel, snapshots |
| `system/helper_client.py` | Unprivileged JSON-lines client; pkexec for the helper |
| `helper/service.py` | Connect/disconnect/status; owns the process group |
| `helper/validation.py` | Gateway, port, fingerprint, operation checks |
| `vpn/process.py` | `subprocess.Popen` with a list argv and `shell=False` |
| `command.py` | Shared argv builder used by helper and GUI; no Qt/backend imports |
| `vpn/command.py` | Profile-aware wrapper around the shared argv builder |
| `helper/executables.py` | Approved paths `/usr/local/bin`, `/usr/bin` only |
| `vpn/saml_parse.py` | Listener ready, auth URL, success/failure from process output |
| `vpn/browser.py` | `xdg-open` / webbrowser after URL validation |
| `helper/certificate.py` | Certificate validation-failure metadata |
| `vpn/log_redaction.py` | Passwords, cookies, SAMLResponse, tokens, URL query secrets |

The GUI may start even when `openfortivpn` or the helper is missing. Version
probing is not done at application startup.

### Privileged helper

A small helper activated with polkit action
`com.fortigate-vpn-linux-gui.manage-vpn`. It is not a general command
executor. Supported operations: `hello`, `connect`, `disconnect`, `status`.

Install locations:

```text
/usr/libexec/fortigate-vpn-linux-gui/vpn-helper
/usr/share/polkit-1/actions/com.fortigate-vpn-linux-gui.policy
```

The helper validates every field again, selects an approved openfortivpn
binary, and builds argv itself. It never accepts a command string, argv list,
or executable path from the GUI.

### openfortivpn

The VPN engine. Non-SSO:

```text
openfortivpn <gateway>:<port>
```

SSO (SAML-capable binary only):

```text
openfortivpn <gateway>:<port> --saml-login
```

With an explicit profile pin:

```text
openfortivpn <gateway>:<port> --saml-login --trusted-cert <sha256>
```

`--trusted-cert` is a separate argv item and is added only after the user
pins a validated SHA-256 fingerprint. TLS validation is never disabled.

Candidate binaries for the helper are `/usr/local/bin/openfortivpn` and
`/usr/bin/openfortivpn`. Capability is taken from `--help` (`--saml-login`),
not from assuming a path. Ubuntu 24.04's packaged **1.21.0** typically lacks
SAML; **1.24.1** is the tested SAML-capable build.

### FortiGate SSL VPN

The remote gateway. This project does not implement the VPN protocol itself.

## Connection states

`ConnectionState` is an enum with deterministic transitions.

Non-SSO:

```text
DISCONNECTED → STARTING → CONNECTING → CONNECTED
```

SSO:

```text
DISCONNECTED → STARTING → WAITING_FOR_AUTH → CONNECTING → CONNECTED
```

Shared:

```text
CONNECTED → DISCONNECTING → DISCONNECTED
WAITING_FOR_AUTH → DISCONNECTING → DISCONNECTED   (Cancel)
WAITING_FOR_AUTH → FAILED                         (timeout / auth / browser)
unrecoverable process error → FAILED
FAILED → DISCONNECTED (after cleanup) or STARTING (retry)
```

Structured failure reasons on FAILED include `PRIVILEGE_DENIED`,
`HELPER_NOT_AVAILABLE`, `HELPER_STARTUP_FAILED`, `CERTIFICATE_UNTRUSTED`,
`CERTIFICATE_CHANGED`, `SAML_FAILED`, and `VPN_PROCESS_FAILED`.

The browser is opened only after a validated authentication URL is parsed,
and only once, in the unprivileged GUI process.

## Connection profiles

Profiles are local, per-user configuration:

```text
${XDG_CONFIG_HOME:-$HOME/.config}/fortigate-vpn-linux-gui/profiles.json
```

JSON schema (version 1): `id`, `name`, `gateway`, `port` (default 443),
`description`, `username_hint`, `use_sso` (default true), optional
`trusted_cert_sha256`.

Passwords, SAML tokens, cookies, client secrets, and MFA data are not stored.
Unknown JSON fields are ignored. Malformed files do not crash the application.
A malformed pin is dropped so the rest of the profile still loads.

`ProfileManager` notifies listeners after add/update/delete so the Connection
page refreshes without restarting.

## Log redaction

Every backend log line passes through `redact_log_line` before it is stored or
shown. Matching is case-insensitive. Typical replacements:

- `password=***`
- `SVPNCOOKIE=***`
- `Authorization: Bearer ***`
- `Cookie: ***`
- `SAMLResponse=***`
- `RelayState=***`
- URL query keys such as `id`, `access_token`, `id_token`

Certificate fingerprints are not secrets and may be shown in Diagnostics and
trust dialogs. Logs stay in memory for the session.

## SAML / SSO

SAML uses the **user's system browser** and **Microsoft Entra ID** through
FortiGate. `openfortivpn` (owned by the helper) owns the localhost callback
listener (default port 8020). The GUI does not bind a competing HTTP port and
does not launch the browser as root.

The full sign-in URL is not shown in the UI. **Copy sign-in address** copies
only scheme+host+path (query and fragment stripped) because query values can
carry session identifiers.

If no SAML-capable binary exists, the message is:
`SAML/SSO requires openfortivpn with --saml-login support.`

## Why the GUI is never run as root

Configuring PPP, routes, and DNS needs extra rights. Running the entire Qt
application as root would expose a large attack surface (UI, clipboard, file
dialogs, plugins). Extra rights belong in the minimal helper, not in the
desktop process.

## Package map

| Package | Role |
| ------- | ---- |
| `fortigate_vpn_gui.command` | Shared openfortivpn argv construction (no Qt) |
| `fortigate_vpn_gui.gui` | Qt windows and pages |
| `fortigate_vpn_gui.runtime` | Process checks (the GUI refuses to run as root) |
| `fortigate_vpn_gui.vpn` | GUI-side VPN state, SAML, browser, redacted logs |
| `fortigate_vpn_gui.helper` | Privileged protocol, validation, process owner |
| `fortigate_vpn_gui.profiles` | Profile model, XDG JSON storage, manager |
| `fortigate_vpn_gui.system` | Preflight checks; polkit helper client |
| `fortigate_vpn_gui.diagnostics` | Redacted troubleshooting snapshots |
