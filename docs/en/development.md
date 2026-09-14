# Development setup

Ubuntu is the primary supported distribution. Python 3.10+ is required.
The GUI has been validated on Ubuntu 24.04 with Python 3.12.

## Ubuntu runtime prerequisites

Install these **before** creating a virtual environment or starting the GUI.

On Ubuntu 24.04 / Python 3.12:

```bash
sudo apt install python3.12-venv libxcb-cursor0
```

- `python3.12-venv` — stdlib `venv` module for this Python. The exact
  `python3.x-venv` package depends on the installed Python. Ubuntu 22.04's
  default interpreter needs `python3.10-venv`. `python3-venv` is a
  metapackage that pulls the matching version.
- `libxcb-cursor0` — provides `libxcb-cursor.so.0`. PySide6/Qt 6 needs this
  library to create desktop windows. Without it the Qt xcb platform plugin
  fails to load.

To exercise VPN connectivity from a Git checkout you also need `pkexec` and a
SAML-capable `openfortivpn` on an approved path (`/usr/local/bin` or
`/usr/bin`). Ubuntu's packaged **1.21.0** lacks `--saml-login`. The Ubuntu
`.deb` ships a private **1.24.1** and does not require the distro package.

The GUI still starts without `openfortivpn`. The application does **not**
install system packages automatically.

## Privileged helper (development)

The GUI from this checkout expects helper protocol **0.8.0**. A previously
installed **1.0.0-2** package helper is protocol **0.7.0**. pkexec only starts
`/usr/libexec/fortigate-vpn-linux-gui/vpn-helper`; do not point the GUI at a
user-writable helper, do not setuid, and do not run the GUI as root.

Install or update the checkout helper into the polkit-approved path:

```bash
sudo ./scripts/install-dev-helper.sh
```

Verify (no pkexec required for `--version`):

```bash
./scripts/install-dev-helper.sh status
/usr/libexec/fortigate-vpn-linux-gui/vpn-helper --version
```

The script copies `src/fortigate_vpn_gui` to a root-owned directory and writes
the helper wrapper. Re-run it after helper-protocol changes. The GUI still
uses pkexec on the same path. Diagnostics reports expected protocol, detected
protocol, and the effective helper path.

Restore the previously packaged helper later:

```bash
sudo ./scripts/install-dev-helper.sh restore
```

If no backup exists:

```bash
sudo apt install --reinstall fortigate-vpn-linux-gui
```

Optional override: `FORTIGATE_VPN_HELPER=/path/to/vpn-helper`. Missing helper,
missing polkit, authorization denied, and version mismatch are reported.
There is no silent insecure fallback. A custom path must still be allowed by
the polkit policy (`exec.path` remains the installed helper).

## Profile storage

Connection profiles are per-user UTF-8 JSON:

```text
${XDG_CONFIG_HOME:-$HOME/.config}/fortigate-vpn-linux-gui/profiles.json
```

Stored fields: `id`, `name`, `gateway`, `port`, `description`,
`username_hint`, `use_sso`, optional `trusted_cert_sha256`, optional
`vpn_type` (missing treated as SSL), optional nested `ipsec` settings without
secrets, and document-level `default_profile_id`. Passwords, SAML tokens,
cookies, IPsec PSKs, XAuth passwords, and other secrets are never written.
Duplicate copies metadata and the certificate pin only; Secret Service
entries are not copied.

Pytest uses a temporary `XDG_CONFIG_HOME` so tests never modify the real
`~/.config`.

## Startup dependency check

Before the main window is created, the process:

1. Detects the distribution from `/etc/os-release` when that file exists.
2. Probes whether `libxcb-cursor.so.0` can be loaded (dynamic linker), not
   whether `dpkg` lists a package.
3. If the library is missing, prints an explanation to stderr and shows a Qt
   dialog naming the dependency, why it is required, and the trusted Ubuntu
   command `sudo apt install libxcb-cursor0`.
4. Offers **Copy command** and **Exit**. The command is never executed.

`openfortivpn` and `pkexec` are catalogued. They are **not** enforced at GUI
startup.

## VPN backend tests

Tests must mock process execution. They must not:

- connect to a VPN
- call a real `openfortivpn` binary
- open a real browser
- call `sudo` or a real `pkexec` dialog
- modify routes, DNS, or firewall rules
- use the network
- run as root

## Virtual environment

From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

## Run the application

```bash
python -m fortigate_vpn_gui
```

Do not run this as root. The process exits with an error if the effective UID
is 0.

## Lint

```bash
ruff check src tests
ruff format src tests
python -m pytest
./scripts/build-deb.sh
```

Widget tests set `QT_QPA_PLATFORM=offscreen` and do not use the network.

## Project layout

```text
src/fortigate_vpn_gui/   application package
  gui/                   Qt pages
  vpn/                   GUI-side VPN state (no Qt)
  helper/                privileged protocol and process owner
  profiles/              XDG JSON storage
  system/                preflight catalog and polkit client
  diagnostics/           redacted snapshots
packaging/               helper, polkit policy, desktop entry, Debian metadata
scripts/                 package build (`./scripts/build-deb.sh`)
tests/                   pytest suite (mocked processes)
docs/en/                 English documentation
docs/pl/                 Polish documentation
```
