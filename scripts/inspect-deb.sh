#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Fail closed if a built .deb contains credentials, research binaries, or private keys.
set -euo pipefail

DEB="${1:-}"
die() { echo "error: $*" >&2; exit 1; }

[[ -n "${DEB}" && -f "${DEB}" ]] || die "usage: $0 package.deb"
command -v dpkg-deb >/dev/null || die "dpkg-deb is required"

LIST="$(dpkg-deb -c "${DEB}")"
INFO="$(dpkg-deb -I "${DEB}")"

echo "${INFO}"
echo "${LIST}" | awk '{print $6}' | sed 's|^\./||' | sort

forbidden_names='(\.research-binaries|license-info\.raw|profiles\.json|\.pem$|\.key$|id_rsa|id_ed25519|FortiClient\.exe|forticlientsslvpn|/opt/FortiClient|\.har$|\.pcap|\.cap$|github.token|APT_SIGNING_KEY)'
if echo "${LIST}" | grep -Ei "${forbidden_names}"; then
  die "package contains a forbidden path"
fi

if echo "${INFO}${LIST}" | grep -Ei 'BEGIN (PGP|RSA|OPENSSH) PRIVATE KEY'; then
  die "package metadata lists private-key material"
fi

python3 - "${DEB}" <<'PY'
import subprocess
import sys
import tarfile
from io import BytesIO

deb = sys.argv[1]
markers = (
    b"BEGIN PGP PRIVATE KEY BLOCK",
    b"BEGIN OPENSSH PRIVATE KEY",
    b"BEGIN RSA PRIVATE KEY",
    b"GITHUB_TOKEN=",
    b"ghp_",
    b"license-info.raw",
    b".research-binaries",
)
listing = subprocess.check_output(["dpkg-deb", "-c", deb], text=True)
lower_names = listing.lower()
for token in ("tokenid=", "fct uid", "svpn cookie", "samlresponse"):
    if token in lower_names:
        raise SystemExit(f"package listing looks like it contains {token}")
data = subprocess.check_output(["dpkg-deb", "--fsys-tarfile", deb])
with tarfile.open(fileobj=BytesIO(data), mode="r:*") as archive:
    for member in archive.getmembers():
        name = member.name.lower()
        if any(part in name for part in ("profiles.json", "license-info.raw", ".research-binaries")):
            raise SystemExit(f"forbidden member {member.name}")
        if not member.isfile() or member.size > 2_000_000:
            continue
        # Third-party wheels may mention key PEM banners in parsers. Scan only
        # project-owned files plus maintainer scripts and docs.
        owned = (
            "/fortigate_vpn_gui/" in name
            or "/usr/bin/" in name
            or "/usr/libexec/fortigate-vpn-linux-gui/" in name
            or "/usr/share/doc/fortigate-vpn-linux-gui/" in name
            or "/usr/share/polkit-1/" in name
            or "/usr/share/applications/" in name
            or name.endswith("control")
        )
        if not owned:
            continue
        extracted = archive.extractfile(member)
        if extracted is None:
            continue
        blob = extracted.read()
        for marker in markers:
            if marker in blob:
                raise SystemExit(f"{member.name} contains forbidden marker")
print("package inspection passed")
PY
