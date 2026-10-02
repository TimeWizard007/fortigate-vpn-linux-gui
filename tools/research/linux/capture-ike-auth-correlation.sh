#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Research-only: correlate one Linux IKEv2 SSO attempt with FortiGate debug.
# Does not change IKE/VPN runtime behavior, the compatibility plugin, AUTH,
# CP, 0xF100, Vendor IDs, helper protocol, or SAML pre-auth.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CORRELATE="${ROOT}/tools/research/linux/correlate_ike_auth_capture.py"
COLLECTOR="${ROOT}/tools/research/linux/fortigate_debug_collector.py"
CAPTURE_ROOT="${ROOT}/docs/research/captures"
PYTHON_BIN="${PYTHON_BIN:-python3.12}"

SSH_ALIAS="${SSH_ALIAS:-fvl-fortigate}"
MGMT_HOST="${MGMT_HOST:-10.10.10.1}"
MGMT_DEV="${MGMT_DEV:-eno1}"
VPN_PEER="${VPN_PEER:-91.149.212.169}"
VPN_DEV="${VPN_DEV:-wlp5s0}"
DURATION="${DURATION:-120}"
MODE="capture"

SSH_OPTS=(
  -o BatchMode=yes
  -o ConnectTimeout=8
  -o ServerAliveInterval=15
  -o ServerAliveCountMax=4
)

FG_COLLECTOR_PID=""
FG_CONTROL=""
TCPDUMP_PID=""
JOURNAL_USER_PID=""
JOURNAL_SYS_PID=""
OUTDIR=""
STARTED_AT=""
CLEANED=0

die() {
  echo "error: $*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage: capture-ike-auth-correlation.sh [--preflight] [--duration SECONDS]

Research-only synchronized capture for one GUI IKEv2 + SAML/SSO attempt.

  --preflight   Verify routing, SSH, tcpdump, and python. Do not capture.
  --duration N  Seconds to wait after the operator banner (default 120).
                ENTER also ends the wait.

Does not start the VPN. You start exactly one attempt from the GUI when told.

Output: docs/research/captures/<timestamp>/ (gitignored)
EOF
}

timestamp_utc() {
  "$PYTHON_BIN" -c 'from datetime import datetime, timezone; print(datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"))'
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [[ "${CLEANED}" -eq 1 ]]; then
    return 0
  fi
  CLEANED=1
  if [[ -n "${FG_CONTROL}" && -e "${FG_CONTROL}" ]]; then
    timeout 2 sh -c "printf 'shutdown\\n' >\"\$1\"" _ "${FG_CONTROL}" 2>/dev/null || true
  fi
  if [[ -n "${FG_COLLECTOR_PID}" ]] && kill -0 "${FG_COLLECTOR_PID}" 2>/dev/null; then
    local waited=0
    while [[ "${waited}" -lt 5 ]] && kill -0 "${FG_COLLECTOR_PID}" 2>/dev/null; do
      sleep 1
      waited=$((waited + 1))
    done
    if kill -0 "${FG_COLLECTOR_PID}" 2>/dev/null; then
      kill -TERM "${FG_COLLECTOR_PID}" 2>/dev/null || true
      wait "${FG_COLLECTOR_PID}" 2>/dev/null || true
    else
      wait "${FG_COLLECTOR_PID}" 2>/dev/null || true
    fi
  fi
  if [[ -n "${TCPDUMP_PID}" ]] && kill -0 "${TCPDUMP_PID}" 2>/dev/null; then
    sudo -n kill -INT "${TCPDUMP_PID}" 2>/dev/null \
      || sudo kill -INT "${TCPDUMP_PID}" 2>/dev/null \
      || kill -INT "${TCPDUMP_PID}" 2>/dev/null || true
    wait "${TCPDUMP_PID}" 2>/dev/null || true
  fi
  if [[ -n "${JOURNAL_USER_PID}" ]]; then
    kill "${JOURNAL_USER_PID}" 2>/dev/null || true
    wait "${JOURNAL_USER_PID}" 2>/dev/null || true
  fi
  if [[ -n "${JOURNAL_SYS_PID}" ]]; then
    sudo -n kill "${JOURNAL_SYS_PID}" 2>/dev/null || kill "${JOURNAL_SYS_PID}" 2>/dev/null || true
    wait "${JOURNAL_SYS_PID}" 2>/dev/null || true
  fi
  if [[ -n "${OUTDIR}" && -d "${OUTDIR}" && -n "${STARTED_AT}" ]]; then
    local ended
    ended="$(timestamp_utc)"
    "$PYTHON_BIN" - "${OUTDIR}/meta.json" "${STARTED_AT}" "${ended}" \
      "${VPN_PEER}" "${VPN_DEV}" "${MGMT_HOST}" "${SSH_ALIAS}" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
path.write_text(
    json.dumps(
        {
            "started_at": sys.argv[2],
            "ended_at": sys.argv[3],
            "peer": sys.argv[4],
            "capture_dev": sys.argv[5],
            "mgmt_host": sys.argv[6],
            "ssh_alias": sys.argv[7],
            "purpose": "diagnostics-only IKE_AUTH correlation",
            "fortigate_debug_status_file": "fortigate-debug-status.json",
        },
        indent=2,
    )
    + "\n",
    encoding="utf-8",
)
PY
    if [[ -f "${CORRELATE}" ]]; then
      "${PYTHON_BIN}" "${CORRELATE}" --dir "${OUTDIR}" >/dev/null || true
    fi
    echo "Capture directory: ${OUTDIR}"
    if [[ -f "${OUTDIR}/correlation-report.md" ]]; then
      echo "Redacted report: ${OUTDIR}/correlation-report.md"
    fi
  fi
  exit "${status}"
}

preflight_tools() {
  require_cmd ip
  require_cmd ssh
  require_cmd sudo
  require_cmd tcpdump
  require_cmd timeout
  require_cmd journalctl
  [[ -f "${CORRELATE}" ]] || die "missing ${CORRELATE}"
  [[ -f "${COLLECTOR}" ]] || die "missing ${COLLECTOR}"
  command -v "${PYTHON_BIN}" >/dev/null 2>&1 || die "missing ${PYTHON_BIN}"
}

verify_routes() {
  local tmp
  tmp="$(mktemp -d)"
  ip route get "${MGMT_HOST}" >"${tmp}/mgmt.txt" 2>&1 || true
  ip route get "${VPN_PEER}" >"${tmp}/vpn.txt" 2>&1 || true
  local out code
  set +e
  out="$("${PYTHON_BIN}" "${CORRELATE}" --verify-routes \
    --mgmt-route-file "${tmp}/mgmt.txt" \
    --vpn-route-file "${tmp}/vpn.txt" \
    --mgmt-host "${MGMT_HOST}" \
    --mgmt-dev "${MGMT_DEV}" \
    --vpn-host "${VPN_PEER}" \
    --vpn-dev "${VPN_DEV}")"
  code=$?
  set -e
  printf '%s\n' "${out}"
  if [[ -n "${OUTDIR}" ]]; then
    cp "${tmp}/mgmt.txt" "${OUTDIR}/routing-mgmt.txt"
    cp "${tmp}/vpn.txt" "${OUTDIR}/routing-vpn.txt"
    printf '%s\n' "${out}" >"${OUTDIR}/routing-summary.txt"
  fi
  rm -rf "${tmp}"
  if [[ "${code}" -ne 0 ]]; then
    die "routing mismatch. FortiGate management must use ${MGMT_DEV}; HomeVPN must use ${VPN_DEV}."
  fi
}

verify_ssh() {
  local status_file
  if [[ -n "${OUTDIR}" ]]; then
    status_file="${OUTDIR}/fortigate-system-status.txt"
  else
    status_file="$(mktemp)"
  fi
  ssh "${SSH_OPTS[@]}" -T "${SSH_ALIAS}" "get system status" >"${status_file}" 2>&1 \
    || die "ssh ${SSH_ALIAS} 'get system status' failed (BatchMode). Check ~/.ssh/config alias and key auth."
  if ! grep -q "Version:" "${status_file}"; then
    die "ssh ${SSH_ALIAS} did not return FortiOS 'get system status'"
  fi
  echo "SSH ${SSH_ALIAS}: get system status succeeded"
  if [[ -z "${OUTDIR}" ]]; then
    rm -f "${status_file}"
  fi
}

verify_tcpdump_sudo() {
  require_cmd tcpdump
  if sudo -n tcpdump --version >/dev/null 2>&1; then
    echo "sudo tcpdump: cached credentials OK"
    return 0
  fi
  echo "sudo will prompt for a password when tcpdump starts (needed for pcap)."
}

start_tcpdump() {
  sudo -n tcpdump -i "${VPN_DEV}" -nn -s 0 -U -w "${OUTDIR}/ike.pcap" \
    "host ${VPN_PEER} and (udp port 500 or udp port 4500)" \
    >"${OUTDIR}/tcpdump.stdout" 2>"${OUTDIR}/tcpdump.stderr" &
  TCPDUMP_PID=$!
  sleep 0.4
  kill -0 "${TCPDUMP_PID}" 2>/dev/null || die "tcpdump failed to start (see ${OUTDIR}/tcpdump.stderr)"
}

start_journal() {
  journalctl --user -f -n 0 --output=short-iso --no-pager \
    >"${OUTDIR}/local-journal.log" 2>"${OUTDIR}/local-journal.err" &
  JOURNAL_USER_PID=$!
  if sudo -n journalctl -f -n 0 --output=short-iso --no-pager \
    >"${OUTDIR}/local-journal-system.log" 2>"${OUTDIR}/local-journal-system.err" &
  then
    JOURNAL_SYS_PID=$!
  fi
}

start_fortigate_debug() {
  FG_CONTROL="${OUTDIR}/fg-control"
  "${PYTHON_BIN}" "${COLLECTOR}" \
    --alias "${SSH_ALIAS}" \
    --log "${OUTDIR}/fortigate-debug.log" \
    --status "${OUTDIR}/fortigate-debug-status.json" \
    --control "${FG_CONTROL}" \
    --ready-timeout 20 \
    >"${OUTDIR}/fortigate-collector.stdout" 2>"${OUTDIR}/fortigate-collector.stderr" &
  FG_COLLECTOR_PID=$!
}

collector_state() {
  local status_file="${OUTDIR}/fortigate-debug-status.json"
  if [[ ! -f "${status_file}" ]]; then
    printf '%s\n' "missing"
    return
  fi
  "${PYTHON_BIN}" - "${status_file}" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
try:
    data = json.loads(path.read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError):
    print("unreadable")
    raise SystemExit(0)
print(str(data.get("state") or "unknown"))
PY
}

assert_ready() {
  if [[ -z "${TCPDUMP_PID}" ]] || ! kill -0 "${TCPDUMP_PID}" 2>/dev/null; then
    die "packet capture died before READY"
  fi
  if [[ -z "${FG_COLLECTOR_PID}" ]] || ! kill -0 "${FG_COLLECTOR_PID}" 2>/dev/null; then
    die "FortiGate debug collector died before READY"
  fi
  local waited=0
  local state="starting"
  while [[ "${waited}" -lt 25 ]]; do
    if ! kill -0 "${FG_COLLECTOR_PID}" 2>/dev/null; then
      die "FortiGate debug collector exited before becoming ACTIVE"
    fi
    state="$(collector_state)"
    if [[ "${state}" == "active" ]]; then
      break
    fi
    if [[ "${state}" == "failed" || "${state}" == "unreadable" ]]; then
      die "FortiGate debug collector failed before READY (state=${state})"
    fi
    sleep 1
    waited=$((waited + 1))
  done
  if [[ "${state}" != "active" ]]; then
    die "FortiGate debug collector was not ACTIVE before READY (state=${state})"
  fi
  if [[ ! -f "${OUTDIR}/fortigate-debug.log" ]]; then
    die "FortiGate raw debug file is missing"
  fi
  if ! grep -F -q "diagnose debug enable" "${OUTDIR}/fortigate-debug.log" \
    || ! grep -F -q "diagnose debug application ike -1" "${OUTDIR}/fortigate-debug.log" \
    || ! grep -F -q "diagnose debug application fnbamd -1" "${OUTDIR}/fortigate-debug.log"; then
    die "FortiGate CLI session did not accept debug commands"
  fi
  echo "FortiGate debug collector: ACTIVE"
  echo "FortiGate raw debug: ${OUTDIR}/fortigate-debug.log"
  echo "Packet capture: ACTIVE"
  echo "READY: perform exactly one GUI connection attempt now."
}

wait_for_attempt() {
  cat <<EOF

============================================================
START EXACTLY ONE HomeVPN IKEv2 + SAML/SSO connection from the GUI now.
Do not start a second attempt during this window.

When the first IKE_AUTH has been retransmitting (about 20-30 seconds)
or the GUI shows the IPsec timeout, press ENTER.

The window also ends automatically after ${DURATION} seconds.
============================================================

EOF
  local elapsed=0
  while [[ "${elapsed}" -lt "${DURATION}" ]]; do
    if ! kill -0 "${FG_COLLECTOR_PID}" 2>/dev/null; then
      echo "error: FortiGate debug collector died during the capture window" >&2
      break
    fi
    if ! kill -0 "${TCPDUMP_PID}" 2>/dev/null; then
      echo "error: packet capture died during the capture window" >&2
      break
    fi
    if read -r -t 1 _; then
      echo "Operator ended the capture window."
      sleep 5
      return
    fi
    elapsed=$((elapsed + 1))
  done
  echo "Capture duration elapsed or a collector died (${elapsed}s)."
  sleep 5
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --preflight)
      MODE="preflight"
      shift
      ;;
    --duration)
      DURATION="${2:?}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      die "unknown argument: $1"
      ;;
  esac
done

[[ "${DURATION}" =~ ^[0-9]+$ ]] || die "duration must be an integer"
preflight_tools
verify_routes
verify_ssh
verify_tcpdump_sudo

if [[ "${MODE}" == "preflight" ]]; then
  echo "Preflight passed. No packet capture or FortiGate debug session was started."
  exit 0
fi

echo "Authenticate sudo for tcpdump (full-packet capture on ${VPN_DEV})."
sudo -v || die "sudo is required to run tcpdump"

trap cleanup EXIT INT TERM
OUTDIR="${CAPTURE_ROOT}/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "${OUTDIR}"
chmod 700 "${OUTDIR}"
STARTED_AT="$(timestamp_utc)"
printf '%s\n' "${STARTED_AT}" >"${OUTDIR}/started_at.txt"
verify_routes
verify_ssh

start_tcpdump
start_journal
start_fortigate_debug
assert_ready
wait_for_attempt
# cleanup trap writes meta.json, disables FortiGate debug, stops tcpdump, builds report
