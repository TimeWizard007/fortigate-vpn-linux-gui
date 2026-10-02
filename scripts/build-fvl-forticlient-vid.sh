#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Build the application-owned FortiClient Vendor ID charon plugin.
# Headers are fetched from upstream strongSwan 5.9.13 (not installed).
# The plugin links against distro libcharon/libstrongswan and is loaded
# only by the private fortigate-vpn-linux-gui charon runtime.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLUGIN_DIR="${ROOT}/native/fvl-forticlient-vid"
PLUGIN_SONAME="libstrongswan-fvl-forticlient-vid.so"
PLUGINDIR="/usr/lib/ipsec/plugins"
CHECK_SYMBOLS="${ROOT}/scripts/check-fvl-forticlient-vid-symbols.sh"
APP_PLUGIN_DIR="/usr/libexec/fortigate-vpn-linux-gui/plugins"
SYSTEM_PLUGIN_CONF="/etc/strongswan.d/charon/fvl-forticlient-vid.conf"

STRONGSWAN_VERSION="5.9.13"
STRONGSWAN_URL="https://github.com/strongswan/strongswan/archive/refs/tags/${STRONGSWAN_VERSION}.tar.gz"
# github.com/strongswan/strongswan archive/refs/tags/5.9.13.tar.gz
STRONGSWAN_SHA256="ca9308590ec7b901db5ccabeaab3edf5ce6d3f6f83f05072f23c6465f68f17d8"
DOWNLOADS="${ROOT}/downloads"
TARBALL="${DOWNLOADS}/strongswan-${STRONGSWAN_VERSION}.tar.gz"
SS_SRC="${DOWNLOADS}/strongswan-${STRONGSWAN_VERSION}"

die() {
  echo "error: $*" >&2
  exit 1
}

fetch_headers() {
  mkdir -p "${DOWNLOADS}"
  if [[ -d "${SS_SRC}/src/libcharon" ]]; then
    return 0
  fi
  if [[ ! -f "${TARBALL}" ]]; then
    python3.12 - "${TARBALL}" <<'PY'
import hashlib
import os
import sys
import urllib.request
from pathlib import Path

url = os.environ["STRONGSWAN_URL"]
expected = os.environ["STRONGSWAN_SHA256"]
dest = Path(sys.argv[1])
dest.parent.mkdir(parents=True, exist_ok=True)
print(f"Downloading strongSwan {os.environ['STRONGSWAN_VERSION']} headers…", flush=True)
with urllib.request.urlopen(url, timeout=60) as response:
    data = response.read()
digest = hashlib.sha256(data).hexdigest()
if digest != expected:
    raise SystemExit(
        f"strongSwan tarball SHA-256 mismatch: got {digest}, expected {expected}"
    )
dest.write_bytes(data)
print(f"Wrote {dest} ({len(data)} bytes)", flush=True)
PY
  else
    python3.12 - "${TARBALL}" <<'PY'
import hashlib
import os
import sys
from pathlib import Path

expected = os.environ["STRONGSWAN_SHA256"]
data = Path(sys.argv[1]).read_bytes()
digest = hashlib.sha256(data).hexdigest()
if digest != expected:
    raise SystemExit(
        f"strongSwan tarball SHA-256 mismatch: got {digest}, expected {expected}"
    )
PY
  fi
  tar -xzf "${TARBALL}" -C "${DOWNLOADS}"
  if [[ ! -d "${SS_SRC}/src/libcharon" ]]; then
    die "extracted strongSwan source is missing src/libcharon"
  fi
}

check_plugin_symbols() {
  local path="$1"
  if [[ ! -x "${CHECK_SYMBOLS}" ]]; then
    die "missing ${CHECK_SYMBOLS}"
  fi
  "${CHECK_SYMBOLS}" "${path}"
}

build_plugin() {
  fetch_headers
  make -C "${PLUGIN_DIR}" SS_SRC="${SS_SRC}"
  if [[ ! -f "${PLUGIN_DIR}/${PLUGIN_SONAME}" ]]; then
    die "plugin build did not produce ${PLUGIN_SONAME}"
  fi
  check_plugin_symbols "${PLUGIN_DIR}/${PLUGIN_SONAME}"
  echo "Built ${PLUGIN_DIR}/${PLUGIN_SONAME}"
}

install_plugin() {
  if [[ "${EUID}" -ne 0 ]]; then
    die "install requires root (used by scripts/install-dev-helper.sh)"
  fi
  build_plugin
  mkdir -p "${APP_PLUGIN_DIR}" "${PLUGINDIR}"
  install -m 0644 "${PLUGIN_DIR}/${PLUGIN_SONAME}" "${APP_PLUGIN_DIR}/${PLUGIN_SONAME}"
  install -m 0644 "${PLUGIN_DIR}/${PLUGIN_SONAME}" "${PLUGINDIR}/${PLUGIN_SONAME}"
  check_plugin_symbols "${PLUGINDIR}/${PLUGIN_SONAME}"
  if [[ -e "${SYSTEM_PLUGIN_CONF}" ]]; then
    die "refusing to leave system charon plugin conf ${SYSTEM_PLUGIN_CONF}"
  fi
  echo "Installed ${PLUGINDIR}/${PLUGIN_SONAME}"
  echo "Application copy ${APP_PLUGIN_DIR}/${PLUGIN_SONAME}"
  echo "Did not write ${SYSTEM_PLUGIN_CONF} (system charon will not load this plugin)."
}

remove_plugin() {
  if [[ "${EUID}" -ne 0 ]]; then
    die "remove requires root"
  fi
  rm -f "${PLUGINDIR}/${PLUGIN_SONAME}"
  rm -f "${APP_PLUGIN_DIR}/${PLUGIN_SONAME}"
  if [[ -e "${SYSTEM_PLUGIN_CONF}" ]]; then
    echo "warning: ${SYSTEM_PLUGIN_CONF} exists and was not created by this script" >&2
  fi
  echo "Removed application-owned ${PLUGIN_SONAME} from PLUGINDIR and libexec."
}

export STRONGSWAN_URL STRONGSWAN_SHA256 STRONGSWAN_VERSION

cmd="${1:-build}"
case "${cmd}" in
  -h|--help|help)
    cat <<EOF
Usage: $0 [build|install|remove]

  build    Fetch 5.9.13 headers if needed and compile the plugin
  install  Copy the uniquely named .so into PLUGINDIR (root)
  remove   Delete the uniquely named .so from PLUGINDIR (root)

Does not modify /etc/strongswan.conf, /etc/strongswan.d/, or system charon.
Does not stop or replace Ubuntu strongSwan.
EOF
    ;;
  build)
    build_plugin
    ;;
  install)
    install_plugin
    ;;
  remove)
    remove_plugin
    ;;
  *)
    echo "Usage: $0 [build|install|remove]" >&2
    exit 2
    ;;
esac
