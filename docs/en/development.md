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

You do **not** need `openfortivpn` for v0.1.x.

The application does **not** install system packages automatically. It never
runs `sudo`, `pkexec`, or `apt`. Those commands are documented for you to run
manually.

## Startup dependency check

Before the main window is created, the process:

1. Detects the distribution from `/etc/os-release` when that file exists.
2. Probes whether `libxcb-cursor.so.0` can be loaded (dynamic linker), not
   whether `dpkg` lists a package.
3. If the library is missing, prints an explanation to stderr and shows a Qt
   dialog naming the dependency, why it is required, and the trusted Ubuntu
   command `sudo apt install libxcb-cursor0`.
4. Offers **Copy command** and **Exit**. The command is never executed.

The same checker is structured so later stages can add `openfortivpn`, `ppp`,
polkit, and a system browser without requiring them today.

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
```

## Tests

```bash
python -m pytest
```

Widget tests set `QT_QPA_PLATFORM=offscreen` and do not use the network. The
same environment variable is used in GitHub Actions. Preflight tests inject
fake library/executable probes and never call apt or sudo.

## Project layout

```text
src/fortigate_vpn_gui/   application package
tests/                   pytest suite
docs/en/                 English documentation
docs/pl/                 Polish documentation
assets/                  future icons and branding
packaging/               future distribution packaging
scripts/                 future maintainer scripts
.github/workflows/       CI
```
