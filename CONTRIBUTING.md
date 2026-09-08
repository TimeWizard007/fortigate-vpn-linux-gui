# Contributing

Thank you for considering a contribution to FortiGate VPN Linux GUI.

This is an independent open-source project. It is not affiliated with,
endorsed by, or sponsored by Fortinet.

## Development status

v0.3.x adds an unprivileged openfortivpn process backend. SAML/SSO, sudo,
polkit, and network changes by the GUI are **out of scope** until they are
designed and implemented deliberately.

Please do not send pull requests that:

- implement SAML or Microsoft Entra ID login, or open a browser for SSO
- invoke `sudo`/`pkexec` or install privileged services
- modify routes, DNS, or firewall rules
- silently disable certificate verification
- store passwords, tokens, or VPN cookies
- call a real `openfortivpn` binary from tests

## Local development

Ubuntu is the primary supported distribution. Python 3.10 or newer is required.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

Run the application:

```bash
python -m fortigate_vpn_gui
```

The GUI must not be started as root.

Lint and test:

```bash
ruff check src tests
ruff format src tests
python -m pytest
```

Qt widget tests use the `offscreen` platform plugin and do not need a display.

## Contribution rules

- Open an issue before large design changes.
- Keep GUI code out of the VPN/backend packages, and keep networking out of Qt
  widgets.
- Use type hints and short docstrings where they help.
- Prefer small, focused modules over premature abstractions.
- Do not add password storage, token logging, or options that silently skip
  TLS certificate verification.
- Match existing code style. Ruff is the formatter and linter.
- Update English documentation in `docs/en/` for user-visible changes. Polish
  documentation in `docs/pl/` and `README.pl.md` should stay in sync when you
  can; if you cannot write Polish, mention that in the pull request.
- Add a `CHANGELOG.md` entry under `[Unreleased]` for user-visible changes.
- By contributing, you license your work under the GNU General Public License
  v3.0 or later (see `LICENSE`).

## Pull requests

1. Fork the repository and create a topic branch.
2. Keep the change set focused.
3. Ensure Ruff and pytest pass locally.
4. Fill in a clear description of what changed and why.

CI runs Ruff and pytest on every push and pull request.
