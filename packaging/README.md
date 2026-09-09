# Packaging

Distribution packaging lives here (desktop metadata, polkit policy, and the
privileged helper install path).

## Privileged helper

Install the helper as a root-owned executable:

```text
/usr/libexec/fortigate-vpn-linux-gui/vpn-helper
```

Suggested install (from a packaging script, not from the GUI):

```bash
sudo install -D -m 0755 packaging/libexec/vpn-helper \
  /usr/libexec/fortigate-vpn-linux-gui/vpn-helper
```

The helper must be able to import `fortigate_vpn_gui`. Packaged installs
should place the Python package on the system interpreter path. The GUI
never copies this file into a world-writable location.

## polkit

Action id: `com.fortigate-vpn-linux-gui.manage-vpn`

Install the policy file:

```text
/usr/share/polkit-1/actions/com.fortigate-vpn-linux-gui.policy
```

```bash
sudo install -D -m 0644 packaging/polkit/com.fortigate-vpn-linux-gui.policy \
  /usr/share/polkit-1/actions/com.fortigate-vpn-linux-gui.policy
```

The policy annotates `org.freedesktop.policykit.exec.path` so pkexec may
start only that helper. The desktop GUI is never launched with pkexec or
sudo.

Ubuntu packages: `pkexec` (polkit). The application does not install them.

## What this package does not install

- No sudoers rules
- No setuid `openfortivpn`
- No world-writable helper directories
- No systemd VPN service in this version
