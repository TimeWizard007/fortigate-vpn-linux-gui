# Scripts

Maintainer scripts live here. This directory is not a place for VPN
connect/disconnect wrappers, sudo helpers, or anything that changes the host
network.

## Package build

```bash
./scripts/build-deb.sh
```

Builds `dist/fortigate-vpn-linux-gui_1.4.0-1_amd64.deb` from this checkout.
Fails on errors. Does not install, publish, or modify user configuration.

## Development helper

```bash
sudo ./scripts/install-dev-helper.sh
./scripts/install-dev-helper.sh status
```

Installs this checkout's helper into `/usr/libexec/fortigate-vpn-linux-gui/vpn-helper`
without changing the polkit action, without setuid, and without modifying
the system strongSwan daemon. It also builds the application-owned
FortiClient Vendor ID plugin (`libstrongswan-fvl-forticlient-vid.so`) and
installs that uniquely named file into `/usr/lib/ipsec/plugins` **without**
writing `/etc/strongswan.d/charon/fvl-forticlient-vid.conf`, so Ubuntu's
system charon does not load it. `status` prints install kind, helper
version, protocol version, capabilities, and plugin presence. Restore the
released helper with `sudo ./scripts/install-dev-helper.sh restore`.
