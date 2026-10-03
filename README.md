# FortiGate VPN Linux GUI

A native Linux desktop client for FortiGate SSL VPN and IPsec. SAML/SSO uses
the system browser (for example Microsoft Entra ID via FortiGate). The GUI
never runs as root.

**This project is independent and is not affiliated with, endorsed by, or
sponsored by Fortinet.** Fortinet, FortiGate, and FortiClient are trademarks of
their respective owner(s).

## Supported platform

Primary release target: **Ubuntu 24.04 LTS, amd64**. Other Debian-family
distributions are untested.

The current version is **1.5.0**. Helper capability version is **0.9.0**
(`protocol_version` remains **1**). The VPN protocol behavior is the frozen
v1.3.0 backend (same as live-proven v1.4.0). v1.5.0 adds update checks,
About component versions, release automation, and an APT publishing path.

## Features

- Persistent connection profiles (create, edit, duplicate, delete, default, import, export)
- Connect from Profiles or the Connection page
- SAML/SSO via `openfortivpn --saml-login` and the system browser
- Username/password SSL profiles when SSO is not used
- IPsec remote access via distribution strongSwan (not bundled):
  - IKEv1 Aggressive Mode, PSK, XAuth, Mode Config, NAT-T, FortiGate/Cisco Unity split include
  - IKEv2 + SAML/SSO with FortiClient-compatible EAP-MSCHAPv2, negotiated split-tunnel, and split DNS
- Explicit FortiGate certificate pinning for SSL (never auto-trusted)
- Privileged helper authorized through polkit (`pkexec` starts only the helper)
- Optional Secret Service storage for IPsec PSK and XAuth password (never in
  `profiles.json`; no plaintext fallback)
- System tray, optional close-to-tray, optional user autostart
- Optional auto-reconnect after unexpected tunnel loss (off by default)
- Diagnostics with DNS, routing, TCP, SAML service, tunnel, helper, IPsec, and polkit checks
- Copy diagnostic report and Export diagnostics (sanitized text or ZIP for GitHub issues)
- About: component versions and a GitHub Releases update check (no telemetry; the GUI does not self-update)

## Install (Ubuntu 24.04)

Full install, update, trust, and rollback notes:
[`docs/en/distribution.md`](docs/en/distribution.md).

### A. Direct `.deb` from GitHub Releases

```bash
sudo apt install ./fortigate-vpn-linux-gui_1.5.0-1_amd64.deb
```

`apt` resolves runtime libraries, `pkexec`, `ppp`, `iproute2`, and the
distribution strongSwan packages used for IPsec. No virtualenv is required.
The package includes a private SAML-capable `openfortivpn` **1.24.1**; it does
not replace `/usr/bin/openfortivpn`. Python dependencies including `keyring`
are inside the package-owned venv. Do not run `pip install` after installing
the `.deb`.

Launch from the GNOME application menu as **FortiGate VPN Linux GUI**, or:

```bash
fortigate-vpn-linux-gui
```

Do not run the GUI as root. Connecting shows a normal polkit prompt when the
helper needs authorization. SSO then continues in the system browser.

### openfortivpn and SAML

SAML/SSO needs `openfortivpn --saml-login`. Ubuntu 24.04's packaged
`openfortivpn` is **1.21.0** and does **not** provide that option. This
application's `.deb` installs a package-owned **1.24.1** at
`/usr/libexec/fortigate-vpn-linux-gui/openfortivpn`. The helper prefers that
binary, then `/usr/local/bin/openfortivpn`, then `/usr/bin/openfortivpn`.
Diagnostics reports the same effective binary. Username/password profiles can
still use a non-SAML build if that is the only approved binary present.

### Remove

```bash
sudo apt remove fortigate-vpn-linux-gui
```

User profiles in `~/.config/fortigate-vpn-linux-gui/` are preserved.
`apt purge` also leaves those files; delete them yourself if you want them
gone.

### B. APT repository (not live until first signed deployment is verified)

GitHub Pages is configured to deploy from GitHub Actions. Production APT
publication has not happened yet. After that first signed deployment is
verified, the intended commands are `sudo apt update` then
`sudo apt install fortigate-vpn-linux-gui`. Use a dedicated keyring and
`Signed-By`; do not run `apt-key add`.

The APT repository is **not** claimed live in this working tree. Use method A
until a signed Pages deployment has been tested. See
[`docs/en/distribution.md`](docs/en/distribution.md).

## Usage

1. Start the application.
2. Open **Profiles** → **New profile**.
3. Choose a VPN type the application actually supports:
   - **SSL VPN** (username/password or SAML/SSO)
   - **IPsec IKEv1** (pre-shared key + username/password)
   - **IPsec IKEv2 SAML/SSO** (pre-shared key + system-browser sign-in)
4. Enter the gateway and required settings, then save. Passwords and the
   IPsec pre-shared key are never written to `profiles.json`.
5. Connect from Profiles or the Connection page. Authorize the helper in
   the polkit dialog if asked.
6. For SAML/SSO, complete sign-in in the system browser.
7. If FortiGate presents an unknown certificate, pin it explicitly for that
   SSL profile or cancel.
8. Use Diagnostics if a connection fails. **Run diagnostics**, then
   **Copy diagnostic report** to paste into a GitHub issue, or **Export
   diagnostics** for a ZIP/text bundle. Exports are sanitized and must not
   contain passwords, PSKs, cookies, or SAML tokens. Inspect the file before
   attaching it.
9. Disconnect from the Connection page or the tray. Quit from the tray always
   shuts the application down (it waits for helper/openfortivpn cleanup).

Closing the window exits by default. Settings can change that to minimize to
the tray. Autostart only launches the GUI after login; it does not connect the
VPN.

## Profiles

Profiles are stored per-user as UTF-8 JSON:

```text
${XDG_CONFIG_HOME:-$HOME/.config}/fortigate-vpn-linux-gui/profiles.json
```

The file does not store passwords, SAML tokens, cookies, or other secrets.
`trusted_cert_sha256` is a public certificate pin.

**Export** writes a versioned application-owned JSON file with portable
non-secret fields only. It never includes the IPsec pre-shared key, user
password, tokenid, FCT UID, cookies, or keyring values. **Import** validates
the format and VPN type, never accepts plaintext credentials, and never
writes strongSwan or openfortivpn config fragments. A duplicate or imported
profile gets its own identity; saved secrets are not copied. Enter required
secrets before connecting.

v1.3.0 SSL, IKEv1, and IKEv2 SAML/SSO profiles continue to load.

## Security model

```text
GUI                          PySide6 widgets (unprivileged)
  ↓ structured request
Privileged helper            root via polkit (pkexec)
  ├── openfortivpn           SSL VPN (SAML or username/password)
  └── strongSwan charon      IPsec (distro packages; not bundled)
```

`pkexec` starts only `/usr/libexec/fortigate-vpn-linux-gui/vpn-helper`. There
are no sudoers rules, no setuid helper, and no passwordless polkit policy.
SSL passwords, SAML cookies, IPsec PSKs, and XAuth passwords are not stored
in `profiles.json` and are not passed on the command line. Optional IPsec
secrets use Secret Service only when the user opts in. Copied and exported
diagnostic reports are sanitized.

## Supported connection types

**SSL-VPN** (openfortivpn): username/password or SAML/SSO via the system
browser, with explicit certificate pinning.

**IPsec remote access** (distribution strongSwan): IKEv1 Aggressive Mode,
PSK + XAuth, Mode Config / VIP, NAT-T, CHILD_SA/XFRM, FortiGate/Cisco Unity
split include, and VPN DNS overlay; and IKEv2 + SAML/SSO with
FortiClient-compatible EAP-MSCHAPv2, negotiated `INTERNAL_IP4_SUBNET`
split-tunnel, and split DNS. Main Mode, certificate IPsec, and
manual-address IPsec are stored in the profile for later work and are not
connected.

Application IPsec uses a **private** charon (`/run/charon.fvl.conf` and
`/run/charon.fvl.vici`). It does not stop `strongswan-starter`, kill an
unrelated charon, or take over `/run/charon.vici`. Two IKE daemons cannot
both bind UDP/500 and UDP/4500. If another IKE service already owns those
ports, IPsec fails before secrets are loaded with **IKE ports in use**;
Diagnostics shows occupancy. SSL VPN still works while system strongSwan
is running. This package never disables system strongSwan automatically.

### Tested

- Ubuntu 24.04 LTS amd64
- The FortiGate / FortiOS environment used to validate SSL, IKEv1 IPsec, and
  v1.3.0 IKEv2 + SAML/SSO (Connect → Disconnect → Connect, three successful
  live cycles). v1.4.0 keeps that VPN behavior and adds GUI profile
  management on top of it. v1.5.0 does not change VPN protocol behavior.
- v1.2.0 installed-package smoke: IPsec refused while system charon owned
  UDP/500/4500; private IPsec after that IKE was stopped; SSL/SAML after IPsec
  cleanup with system strongSwan restored

### Potentially compatible but not yet tested

- Other Debian-family amd64 desktops
- Other FortiGate / FortiOS builds and IPsec proposals

## Troubleshooting

Open **Diagnostics** in the application first. It checks helper/polkit
install, DNS, the route to the gateway, TCP reachability, IPsec leftover
state, and tunnel state without starting a VPN by itself. Opening
Diagnostics does not show a polkit prompt.

If a connection fails, the Connection page shows a conservative human-readable
reason when backend output proves it. Raw details stay in Logs and
Diagnostics. Do not guess from incomplete logs.

**Export diagnostics** writes a sanitized text or ZIP bundle suitable for a
GitHub issue. **Copy diagnostics** copies the same sanitized summary to the
clipboard. Inspect the file before attaching it: it must not contain PSK,
passwords, cookies, SAML tokens, or private keys.

If IPsec reports **IKE ports in use**, another IKE daemon (often Ubuntu's
`strongswan-starter` / system charon) already owns UDP/500 or UDP/4500.
The application will not stop that service. SSL VPN can still connect.
Application IPsec can start only after those ports are free.

If SSO fails, confirm the effective `openfortivpn` supports `--saml-login`.

## Development

Developer setup is separate from the packaged application. The installed
`fortigate-vpn-linux-gui` command must not require this checkout or `.venv`.

```bash
sudo apt install python3.12-venv libxcb-cursor0
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
python -m fortigate_vpn_gui
```

```bash
ruff check src tests
python -m pytest
./scripts/build-deb.sh
```

Development helper install (not required after the `.deb` is installed):
see [`packaging/README.md`](packaging/README.md).

## Documentation

- English: [`docs/en/`](docs/en/)
- Polish: [`docs/pl/`](docs/pl/) and [`README.pl.md`](README.pl.md)
- Security: [`SECURITY.md`](SECURITY.md)
- Contributing: [`CONTRIBUTING.md`](CONTRIBUTING.md)
- Changelog: [`CHANGELOG.md`](CHANGELOG.md)

## License

GNU General Public License v3.0 or later. See [`LICENSE`](LICENSE).
