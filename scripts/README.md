# Scripts

Maintainer scripts live here. This directory is not a place for VPN
connect/disconnect wrappers, sudo helpers, or anything that changes the host
network.

## Package build

```bash
./scripts/build-deb.sh
```

Builds `dist/fortigate-vpn-linux-gui_1.0.0-2_amd64.deb` from this checkout.
Fails on errors. Does not install, publish, or modify user configuration.
