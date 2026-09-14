# Scripts

Maintainer scripts live here. This directory is not a place for VPN
connect/disconnect wrappers, sudo helpers, or anything that changes the host
network.

## Package build

```bash
./scripts/build-deb.sh
```

Builds `dist/fortigate-vpn-linux-gui_1.1.0-1_amd64.deb` from this checkout.
Fails on errors. Does not install, publish, or modify user configuration.

## Development helper (protocol 0.8.0)

```bash
sudo ./scripts/install-dev-helper.sh
./scripts/install-dev-helper.sh status
```

Installs this checkout's helper into `/usr/libexec/fortigate-vpn-linux-gui/vpn-helper`
without changing the polkit action and without setuid. Restore the released
helper with `sudo ./scripts/install-dev-helper.sh restore`.
