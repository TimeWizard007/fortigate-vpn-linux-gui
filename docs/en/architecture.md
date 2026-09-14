# Architecture

The design separates the desktop UI from VPN process control and from
privilege.

```text
GUI                          PySide6 widgets (unprivileged)
  ↓ structured JSON request
Privileged helper            root via polkit (pkexec)
  ├── openfortivpn           FortiGate SSL VPN (SAML or username/password)
  └── strongSwan charon      FortiGate IPsec (distro packages; not bundled)
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
| `vpn/backend.py` | `connect`, `disconnect`, reconnect, shutdown, SAML timeout/cancel, snapshots |
| `system/helper_client.py` | Unprivileged JSON-lines client; pkexec for the helper |
| `helper/service.py` | Connect/disconnect/status; owns the process group |
| `helper/validation.py` | Gateway, port, fingerprint, operation checks |
| `vpn/process.py` | `subprocess.Popen` with a list argv and `shell=False` |
| `command.py` | Shared argv builder used by helper and GUI; no Qt/backend imports |
| `vpn/command.py` | Profile-aware wrapper around the shared argv builder |
| `helper/executables.py` | Approved paths: package libexec, `/usr/local/bin`, `/usr/bin` |
| `vpn/saml_parse.py` | Listener ready, auth URL, success/failure from process output |
| `vpn/browser.py` | `xdg-open` / webbrowser after URL validation |
| `helper/certificate.py` | Certificate validation-failure metadata |
| `vpn/log_redaction.py` | Passwords, cookies, SAMLResponse, tokens, URL query secrets |

The GUI may start even when `openfortivpn` or the helper is missing. Version
probing is not done at application startup.

### Privileged helper

A small helper activated with polkit action
`com.fortigate-vpn-linux-gui.manage-vpn`. It is not a general command
executor. Supported operations: `hello`, `connect`, `credentials`,
`disconnect`, `status`.

Install locations (also installed by the Ubuntu `.deb`):

```text
/usr/libexec/fortigate-vpn-linux-gui/vpn-helper
/usr/libexec/fortigate-vpn-linux-gui/openfortivpn
/usr/share/polkit-1/actions/com.fortigate-vpn-linux-gui.policy
```

The helper validates every field again, selects an approved backend binary,
and builds argv itself. It never accepts a command string, argv list,
or executable path from the GUI. IPsec pre-shared keys and XAuth passwords
are sent in a follow-up `credentials` operation after `connect`, then written
to a 0600 helper runtime file. They are never placed on argv. The GUI may
reuse a PSK from Secret Service / GNOME Keyring (keyed by profile id); it
never writes that PSK to `profiles.json`. The XAuth password may be saved the
same way only when the user opts in; it is never stored in `profiles.json`.

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

Candidate binaries for the helper, in order:

```text
/usr/libexec/fortigate-vpn-linux-gui/openfortivpn
/usr/local/bin/openfortivpn
/usr/bin/openfortivpn
```

PATH is not searched. Capability is taken from `--help` (`--saml-login`),
not from assuming a path. The Ubuntu 24.04 `.deb` ships a private **1.24.1**
with SAML. Distro **1.21.0** at `/usr/bin/openfortivpn` lacks `--saml-login`
and is not used for SSO when the package-owned binary is present.

### IPsec / strongSwan

IPsec is a second helper backend (`backend=ipsec`). The GUI never runs
charon or swanctl. The helper starts a **private** charon using an allowlisted
path (`/usr/lib/ipsec/charon` or `/usr/libexec/ipsec/charon`) and a runtime
`strongswan.conf` selected with the `STRONGSWAN_CONF` environment variable
(Ubuntu charon does not accept `--conf`). Ubuntu's charon AppArmor profile
cannot read that file from `/tmp`; the live helper writes it to
`/run/charon.fvl.conf` and the private vici socket to `/run/charon.vici`
(the only vici path `swanctl` AppArmor allows). Ubuntu 5.9.13 `swanctl` has no
`--unix`; it uses the compiled VICI default `unix:///var/run/charon.vici`
(`/run/charon.vici`) unless `swanctl.socket` is set. The helper therefore does
not pass a socket CLI option. Configuration is loaded with
`swanctl --load-all --file /etc/swanctl/fortigate-vpn-linux-gui/swanctl.conf`
(not `conf.d`, and not by overwriting `/etc/swanctl/swanctl.conf`). Secrets are
in `secrets.conf` (mode 0600), included from `swanctl.conf`, and wiped on
disconnect. CHILD_SA `local_ts` is `dynamic` (the assigned VIP). `remote_ts`
is `0.0.0.0/0` so FortiGate can narrow via Cisco Unity split-include; it is
not the public gateway `/32`. Generated `strongswan.conf` sets
`charon.cisco_unity = yes`. Received VPN DNS is applied with `resolvectl` on
the VIP interface after snapshotting that link's pre-VPN DNS/domains. On
disconnect the helper restores the snapshot and runs `nmcli device reapply` so
NetworkManager re-owns DHCP/static DNS. It does not use `resolvectl revert` on
the physical interface (that clears NM's systemd-resolved slot and leaves an
empty resolver). No permanent `/etc/resolv.conf` edits; systemd-networkd is
not enabled.

strongSwan is a distribution **Depends** on the Ubuntu package
(`strongswan`, `strongswan-swanctl`, `libcharon-extra-plugins`,
`libcharon-extauth-plugins`). It is not bundled. PATH is not searched for
execution. `/etc/strongswan.conf` is not modified.

v1.1.0 starts IKEv1 Aggressive + PSK + XAuth + Mode Config + NAT-T with
FortiGate/Cisco Unity split include. Other combinations may be stored in the
profile and are rejected at connect.

### FortiGate SSL VPN

The remote gateway. This project does not implement the VPN protocol itself.

## Connection states

`ConnectionState` is an enum with deterministic transitions. Only one
connection attempt is active per GUI instance. A new Connect is ignored while
the session is busy. Retry after certificate trust waits until the previous
privileged process has exited.

Non-SSO:

```text
DISCONNECTED → STARTING → CONNECTING → CONNECTED
```

IPsec (PSK authenticates the tunnel; XAuth username/password authenticate
the user. A saved PSK is read from Secret Service when present):

```text
DISCONNECTED → STARTING → CONNECTING → CONNECTED
```

SSO:

```text
DISCONNECTED → STARTING → WAITING_FOR_AUTH → CONNECTING → CONNECTED
```

Certificate trust:

```text
STARTING / WAITING_FOR_AUTH / CONNECTING
  → WAITING_FOR_CERTIFICATE_TRUST
  → cleanup → retry once → STARTING → …
```

Shared:

```text
CONNECTED → DISCONNECTING → DISCONNECTED
WAITING_FOR_AUTH → DISCONNECTING → DISCONNECTED   (Cancel)
WAITING_FOR_CERTIFICATE_TRUST → FAILED            (Cancel; pin is not saved)
WAITING_FOR_AUTH → FAILED                         (timeout / auth / browser)
CONNECTED → FAILED                                (unexpected process exit)
unrecoverable process error → FAILED
FAILED → DISCONNECTED (after cleanup) or STARTING (retry)
```

`WAITING_FOR_CERTIFICATE_TRUST` is not Connected. Duplicate certificate
validation lines are one application-level event per fingerprint per attempt.
Trust saves a normalized SHA-256 pin for that profile only, then retries once.
Cancel does not store a pin and does not retry. A changed pin is never
overwritten automatically.

Unexpected tunnel loss leaves CONNECTED, shows `VPN connection was lost.`,
and optionally schedules auto-reconnect when that setting is enabled (off
by default). Explicit Disconnect, Quit, and certificate rejection do not
auto-reconnect. Any new SAML or certificate-trust step uses the existing
browser and pinning flows.

Disconnect/Cancel terminates the owned privileged process during STARTING,
WAITING_FOR_AUTH, WAITING_FOR_CERTIFICATE_TRUST, CONNECTING, and CONNECTED.
The SAML callback listener is removed by process shutdown; the browser is not
force-closed.

Structured failure reasons on FAILED include `PRIVILEGE_DENIED`,
`HELPER_NOT_AVAILABLE`, `HELPER_STARTUP_FAILED`, `CERTIFICATE_UNTRUSTED`,
`CERTIFICATE_CHANGED`, `SAML_FAILED`, `VPN_PROCESS_FAILED`, `CONNECTION_LOST`,
`PPP_FAILED`, `ROUTE_FAILED`, and `DNS_FAILED`.

The browser is opened only after a validated authentication URL is parsed,
and only once, in the unprivileged GUI process. The SAML timeout is cancelled
on successful authentication, Disconnect, and certificate-trust waiting.

## Connection profiles

Profiles are local, per-user configuration:

```text
${XDG_CONFIG_HOME:-$HOME/.config}/fortigate-vpn-linux-gui/profiles.json
```

JSON schema (version 1): `id`, `name`, `gateway`, `port` (default 443),
`description`, `username_hint`, `use_sso` (default true), optional
`trusted_cert_sha256`, `vpn_type` (`ssl` or `ipsec`, missing treated as
`ssl`), and for IPsec profiles a nested non-secret `ipsec` object. The
document may include `default_profile_id` (exactly one default, or none).
v0.7.1 files without that key load with no default. Pre-shared keys and
XAuth passwords are never stored in this file; optional Secret Service save
is keyed by profile id.

Passwords, SAML tokens, cookies, client secrets, and MFA data are not stored.
Unknown JSON fields are ignored. Malformed files do not crash the application.
A malformed pin is dropped so the rest of the profile still loads. Duplicate
copies safe metadata and the certificate pin; it does not copy credentials.

`ProfileManager` notifies listeners after add/update/delete/duplicate/default
changes so the Connection page refreshes without restarting. Connect from
Profiles calls the same `VpnBackend.connect` as the Connection page.

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

If no SAML-capable binary exists, Connect fails before pkexec with a message
that includes the detected version, for example:
`Installed openfortivpn does not support SAML/SSO. Version 1.21.0 is detected.`

## Why the GUI is never run as root

Configuring PPP, routes, and DNS needs extra rights. Running the entire Qt
application as root would expose a large attack surface (UI, clipboard, file
dialogs, plugins). Extra rights belong in the minimal helper, not in the
desktop process.

## Package map

| Package | Role |
| ------- | ---- |
| `fortigate_vpn_gui.command` | Shared openfortivpn argv construction (no Qt) |
| `fortigate_vpn_gui.gui` | Qt windows, pages, and system tray |
| `fortigate_vpn_gui.desktop` | User autostart and desktop preferences |
| `fortigate_vpn_gui.runtime` | Process checks (the GUI refuses to run as root) |
| `fortigate_vpn_gui.vpn` | GUI-side VPN state, SAML, browser, redacted logs |
| `fortigate_vpn_gui.helper` | Privileged protocol, validation, process owner |
| `fortigate_vpn_gui.profiles` | Profile model, XDG JSON storage, manager |
| `fortigate_vpn_gui.system` | Preflight checks; polkit helper client |
| `fortigate_vpn_gui.diagnostics` | Unprivileged health checks and sanitized reports |
