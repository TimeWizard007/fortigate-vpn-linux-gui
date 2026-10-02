#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Install the current checkout's privileged helper into the polkit-approved
# path. Does not setuid, does not weaken polkit, does not run the GUI as root,
# and does not modify the system strongSwan daemon.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACKAGE_NAME="fortigate-vpn-linux-gui"
HELPER_PATH="/usr/libexec/${PACKAGE_NAME}/vpn-helper"
DEV_SRC="/usr/lib/${PACKAGE_NAME}/dev-src"
BACKUP="${HELPER_PATH}.released"
POLICY_SRC="${ROOT}/packaging/polkit/com.fortigate-vpn-linux-gui.policy"
POLICY_DST="/usr/share/polkit-1/actions/com.fortigate-vpn-linux-gui.policy"
INFO_FILE="${DEV_SRC}/.dev-helper-info"
PLUGIN_BUILD="${ROOT}/scripts/build-fvl-forticlient-vid.sh"
PLUGIN_SONAME="libstrongswan-fvl-forticlient-vid.so"
PLUGINDIR="/usr/lib/ipsec/plugins"
APP_PLUGIN_DIR="/usr/libexec/${PACKAGE_NAME}/plugins"
SYSTEM_PLUGIN_CONF="/etc/strongswan.d/charon/fvl-forticlient-vid.conf"

usage() {
  cat <<EOF
Usage: $0 [install|status|restore]

  install  Copy this checkout's helper into ${HELPER_PATH}
  status   Print install kind, hello JSON, and advertised capabilities
  restore  Restore the previously backed-up released helper

The GUI must keep using pkexec on ${HELPER_PATH}. This script does not
change the polkit action, does not install a setuid bit, does not
launch the GUI as root, and does not start or stop system strongSwan.
It also builds the application-owned FortiClient Vendor ID plugin and
copies the uniquely named .so into ${PLUGINDIR} without writing
${SYSTEM_PLUGIN_CONF}.

After install, run the GUI from this checkout:
  python -m fortigate_vpn_gui

Verify:
  $0 status
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

install_kind() {
  if [[ ! -r "${HELPER_PATH}" ]]; then
    echo "missing"
    return
  fi
  if grep -q "Development helper installed by" "${HELPER_PATH}"; then
    echo "development"
  elif grep -q "/usr/lib/${PACKAGE_NAME}/venv/bin/python" "${HELPER_PATH}"; then
    echo "packaged"
  else
    echo "unknown"
  fi
}

print_hello_summary() {
  python3 - "${HELPER_PATH}" <<'PY'
import json
import subprocess
import sys

helper = sys.argv[1]
completed = subprocess.run(
    [helper, "--version"],
    check=False,
    capture_output=True,
    text=True,
    timeout=5,
)
print("Version output:")
sys.stdout.write(completed.stdout or "")
if completed.returncode != 0:
    print(f"--version exited {completed.returncode}")
payload = None
for raw in (completed.stdout or "").splitlines():
    line = raw.strip()
    if line.startswith("{"):
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            payload = None
        break
if not isinstance(payload, dict):
    print("helper_version: unknown")
    print("protocol_version: unknown")
    print("capabilities: none")
    sys.exit(0)
caps = payload.get("capabilities") or []
if not isinstance(caps, list):
    caps = []
print(f"helper_version: {payload.get('helper_version', 'unknown')}")
print(f"protocol_version: {payload.get('protocol_version', 'unknown')}")
print("capabilities: " + (", ".join(str(item) for item in caps) if caps else "none"))
PY
}

write_info_file() {
  python3 - "${HELPER_PATH}" "${INFO_FILE}" <<'PY'
import json
import subprocess
import sys
from pathlib import Path

helper, dest = sys.argv[1], sys.argv[2]
completed = subprocess.run(
    [helper, "--version"],
    check=False,
    capture_output=True,
    text=True,
    timeout=5,
)
payload = {}
for raw in (completed.stdout or "").splitlines():
    line = raw.strip()
    if line.startswith("{"):
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            payload = {}
        break
caps = payload.get("capabilities") or []
if not isinstance(caps, list):
    caps = []
Path(dest).write_text(
    "install_kind=development\n"
    f"helper_version={payload.get('helper_version', 'unknown')}\n"
    f"protocol_version={payload.get('protocol_version', 'unknown')}\n"
    f"capabilities={','.join(str(item) for item in caps)}\n",
    encoding="utf-8",
)
PY
  chmod 0644 "${INFO_FILE}"
  chown root:root "${INFO_FILE}"
}

cmd="${1:-install}"
case "${cmd}" in
  -h|--help|help)
    usage
    exit 0
    ;;
  status)
    echo "Effective helper path: ${HELPER_PATH}"
    echo "Install kind: $(install_kind)"
    if [[ -d "${DEV_SRC}/fortigate_vpn_gui" ]]; then
      echo "Development source: ${DEV_SRC}/fortigate_vpn_gui"
    fi
    if [[ -f "${INFO_FILE}" ]]; then
      echo "Install info: ${INFO_FILE}"
      cat "${INFO_FILE}"
    fi
    if [[ -x "${HELPER_PATH}" ]]; then
      print_hello_summary
    else
      echo "Helper is missing or not executable."
      exit 1
    fi
    if [[ -f "${PLUGINDIR}/${PLUGIN_SONAME}" ]]; then
      echo "FortiClient VID plugin: ${PLUGINDIR}/${PLUGIN_SONAME}"
    else
      echo "FortiClient VID plugin: missing (${PLUGINDIR}/${PLUGIN_SONAME})"
    fi
    if [[ -e "${SYSTEM_PLUGIN_CONF}" ]]; then
      echo "WARNING: system charon plugin conf exists: ${SYSTEM_PLUGIN_CONF}"
    else
      echo "System charon plugin conf: absent (expected)"
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
    rm -rf "${DEV_SRC}/fortigate_vpn_gui" "${INFO_FILE}"
    cp -a "${ROOT}/src/fortigate_vpn_gui" "${DEV_SRC}/"
    chmod -R a+rX "${DEV_SRC}"
    chown -R root:root "${DEV_SRC}"
    write_wrapper
    if [[ ! -e "${POLICY_DST}" ]]; then
      install -m 0644 "${POLICY_SRC}" "${POLICY_DST}"
      echo "Installed polkit policy ${POLICY_DST}"
    fi
    if [[ ! -x "${PLUGIN_BUILD}" ]]; then
      echo "Cannot find ${PLUGIN_BUILD}" >&2
      exit 1
    fi
    "${PLUGIN_BUILD}" install
    if [[ -e "${SYSTEM_PLUGIN_CONF}" ]]; then
      echo "error: ${SYSTEM_PLUGIN_CONF} must not exist" >&2
      exit 1
    fi
    write_info_file
    echo "Installed development helper at ${HELPER_PATH}"
    echo "Install kind: development"
    print_hello_summary
    echo
    echo "The GUI still uses pkexec on this path. Do not run the GUI as root."
    echo "This does not start, stop, or replace the system strongSwan daemon."
    ;;
  restore)
    need_root restore
    "${PLUGIN_BUILD}" remove || true
    if [[ -e "${BACKUP}" ]]; then
      cp -a "${BACKUP}" "${HELPER_PATH}"
      chmod 0755 "${HELPER_PATH}"
      chown root:root "${HELPER_PATH}"
      echo "Restored ${HELPER_PATH} from ${BACKUP}"
      echo "Install kind: $(install_kind)"
      print_hello_summary || true
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
