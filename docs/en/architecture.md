# Architecture

The design separates the desktop UI from VPN process control and from
privilege.

```text
GUI                          PySide6 widgets (unprivileged)
  ↓
Application / service layer  VpnBackend, profiles, redacted logs
  ↓
openfortivpn                 started as the current user (v0.3)
  ↓
FortiGate SSL VPN            gateway
```

A privileged helper (polkit) is planned between the service layer and
`openfortivpn`. It is not implemented in v0.3.x. The GUI must never become
that helper and must never run as root.

## Layers

### GUI

Qt widgets in `src/fortigate_vpn_gui/gui/`. The GUI displays state and collects
user intent. It must not run as root, call `sudo`/`pkexec`, or change routes,
DNS, or firewall rules. Connect/Disconnect calls `VpnBackend`; widgets do not
construct subprocesses themselves. Profile add/edit/delete talks to
`ProfileManager`; widgets do not read or write JSON themselves.

### Application / service layer

Non-Qt packages (`vpn`, `profiles`, `diagnostics`).

`fortigate_vpn_gui.vpn` owns the openfortivpn process:

| Module | Role |
| ------ | ---- |
| `backend.py` | `connect`, `disconnect`, `is_running`, `current_state`, `process_info` |
| `process.py` | `subprocess.Popen` with a list argv and `shell=False` |
| `command.py` | Builds `[openfortivpn, gateway:port]` with no secrets |
| `models.py` | `ConnectionState` and snapshots |
| `log_redaction.py` | Central redaction of passwords, cookies, tokens |
| `detect.py` | PATH lookup; `--version` only for Diagnostics |

The GUI may start even when `openfortivpn` is missing. Version probing is not
done at application startup.

### Privileged helper

A future small helper (`system` package / packaging artifacts) activated with
polkit. It should only perform the operations that actually need extra rights.
v0.3.x starts `openfortivpn` as the current user and reports permission
failures instead of escalating.

### openfortivpn

The VPN engine. v0.3.x starts it as the current user with:

```text
openfortivpn <gateway>:<port>
```

No password, cookie, token, or `--trusted-cert` arguments are added.

### FortiGate SSL VPN

The remote gateway. This project does not implement the VPN protocol itself.

## Connection states

`ConnectionState` is an enum with deterministic transitions:

```text
DISCONNECTED → STARTING → CONNECTING → CONNECTED
CONNECTED → DISCONNECTING → DISCONNECTED
unrecoverable process error → FAILED
FAILED → DISCONNECTED (after cleanup) or STARTING (retry)
```

`WAITING_FOR_AUTH` exists for a future SAML flow. v0.3.x does not open a
browser and does not enter that state for SSO.

SSO profiles (`use_sso=True`) are refused before any process starts.

## Connection profiles

Profiles are local, per-user configuration:

```text
${XDG_CONFIG_HOME:-$HOME/.config}/fortigate-vpn-linux-gui/profiles.json
```

JSON schema (version 1): `id`, `name`, `gateway`, `port` (default 443),
`description`, `username_hint`, `use_sso` (default true).

Passwords, SAML tokens, cookies, client secrets, and MFA data are not stored.
Unknown JSON fields are ignored. Malformed files do not crash the application.

`ProfileManager` notifies listeners after add/update/delete so the Connection
page refreshes without restarting.

## Log redaction

Every backend log line passes through `redact_log_line` before it is stored or
shown. Matching is case-insensitive. Typical replacements:

- `password=***`
- `SVPNCOOKIE=***`
- `Authorization: Bearer ***`
- `Cookie: ***`

Logs stay in memory for the session. They are not written to disk in v0.3.x.

## SAML / SSO (planned)

SAML authentication is expected to use the **user's system browser** and
**Microsoft Entra ID**. Tokens and cookies from that flow must not be written
to logs or profile files. This path is planned for v0.4.0 and is not
implemented.

## Why the GUI is never run as root

Configuring PPP, routes, and DNS needs extra rights. Running the entire Qt
application as root would expose a large attack surface (UI, clipboard, file
dialogs, plugins). Extra rights belong in a future minimal helper, not in the
desktop process. v0.3.x therefore starts `openfortivpn` unprivileged and
explains permission failures instead of asking the user to launch the GUI
with `sudo`.

## Package map

| Package | Role |
| ------- | ---- |
| `fortigate_vpn_gui.gui` | Qt windows and pages |
| `fortigate_vpn_gui.runtime` | Process checks (the GUI refuses to run as root) |
| `fortigate_vpn_gui.vpn` | openfortivpn backend, states, redacted logs |
| `fortigate_vpn_gui.profiles` | Profile model, XDG JSON storage, manager |
| `fortigate_vpn_gui.system` | Startup preflight checks; future helper / polkit integration |
| `fortigate_vpn_gui.diagnostics` | Redacted troubleshooting snapshots |
