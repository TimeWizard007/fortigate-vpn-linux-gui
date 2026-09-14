#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Install the current checkout's privileged helper (protocol 0.8.0) into the
# polkit-approved path. Does not setuid, does not weaken polkit, and does not
# run the GUI as root.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACKAGE_NAME="fortigate-vpn-linux-gui"
HELPER_PATH="/usr/libexec/${PACKAGE_NAME}/vpn-helper"
DEV_SRC="/usr/lib/${PACKAGE_NAME}/dev-src"
BACKUP="${HELPER_PATH}.released"
POLICY_SRC="${ROOT}/packaging/polkit/com.fortigate-vpn-linux-gui.policy"
POLICY_DST="/usr/share/polkit-1/actions/com.fortigate-vpn-linux-gui.policy"

usage() {
  cat <<EOF
Usage: $0 [install|status|restore]

  install  Copy this checkout's helper into ${HELPER_PATH} (protocol 0.8.0)
  status   Print the effective helper path and --version output
  restore  Restore the previously backed-up released helper

The GUI must keep using pkexec on ${HELPER_PATH}. This script does not
change the polkit action, does not install a setuid bit, and does not
launch the GUI as root.

After install, run the GUI from this checkout:
  python -m fortigate_vpn_gui

Verify:
  ${HELPER_PATH} --version

Restore the previously packaged helper later with:
  sudo $0 restore
  # or, if no backup exists:
  sudo apt install --reinstall fortigate-vpn-linux-gui
EOF
}

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    exec sudo "$0" "$@"
  fi
}

write_wrapper() {
  cat > "${HELPER_PATH}" <<EOF
#!/usr/bin/python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Development helper installed by scripts/install-dev-helper.sh."""
import sys

sys.path.insert(0, "${DEV_SRC}")
from fortigate_vpn_gui.helper.main import main

if __name__ == "__main__":
    raise SystemExit(main())
EOF
  chmod 0755 "${HELPER_PATH}"
  chown root:root "${HELPER_PATH}"
}

cmd="${1:-install}"
case "${cmd}" in
  -h|--help|help)
    usage
    exit 0
    ;;
  status)
    echo "Effective helper path: ${HELPER_PATH}"
    if [[ -x "${HELPER_PATH}" ]]; then
      echo "Version output:"
      "${HELPER_PATH}" --version || true
    else
      echo "Helper is missing or not executable."
      exit 1
    fi
    ;;
  install)
    need_root install
    if [[ ! -d "${ROOT}/src/fortigate_vpn_gui" ]]; then
      echo "Cannot find src/fortigate_vpn_gui under ${ROOT}" >&2
      exit 1
    fi
    mkdir -p "$(dirname "${HELPER_PATH}")" "${DEV_SRC}"
    if [[ -e "${HELPER_PATH}" && ! -e "${BACKUP}" ]]; then
      cp -a "${HELPER_PATH}" "${BACKUP}"
      echo "Backed up existing helper to ${BACKUP}"
    fi
    rm -rf "${DEV_SRC}/fortigate_vpn_gui"
    cp -a "${ROOT}/src/fortigate_vpn_gui" "${DEV_SRC}/"
    chmod -R a+rX "${DEV_SRC}"
    chown -R root:root "${DEV_SRC}"
    write_wrapper
    if [[ ! -e "${POLICY_DST}" ]]; then
      install -m 0644 "${POLICY_SRC}" "${POLICY_DST}"
      echo "Installed polkit policy ${POLICY_DST}"
    fi
    echo "Installed development helper at ${HELPER_PATH}"
    "${HELPER_PATH}" --version
    echo
    echo "The GUI still uses pkexec on this path. Do not run the GUI as root."
    ;;
  restore)
    need_root restore
    if [[ -e "${BACKUP}" ]]; then
      cp -a "${BACKUP}" "${HELPER_PATH}"
      chmod 0755 "${HELPER_PATH}"
      chown root:root "${HELPER_PATH}"
      echo "Restored ${HELPER_PATH} from ${BACKUP}"
      "${HELPER_PATH}" --version || true
    else
      echo "No backup at ${BACKUP}."
      echo "Reinstall the released package helper with:"
      echo "  sudo apt install --reinstall fortigate-vpn-linux-gui"
      exit 1
    fi
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
