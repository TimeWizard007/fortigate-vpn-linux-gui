#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Fail if the app-owned charon plugin still has unresolved runtime symbols
# that Ubuntu libstrongswan/libcharon cannot provide (notably memwipe_noinline).
set -euo pipefail

PLUGIN="${1:-}"
IPSEC_LIBDIR="${IPSEC_LIBDIR:-/usr/lib/ipsec}"

die() {
  echo "error: $*" >&2
  exit 1
}

if [[ -z "${PLUGIN}" || ! -f "${PLUGIN}" ]]; then
  die "plugin shared object not found: ${PLUGIN:-<missing argument>}"
fi

if ! command -v nm >/dev/null || ! command -v ldd >/dev/null; then
  die "nm and ldd are required for the plugin symbol check"
fi

nm_out="$(nm -D "${PLUGIN}")"
if echo "${nm_out}" | grep -Eq '[[:space:]]U[[:space:]]+memwipe_noinline$'; then
  echo "${nm_out}" | grep memwipe >&2 || true
  die "${PLUGIN} has unresolved memwipe_noinline (Ubuntu libstrongswan does not export it)"
fi

if [[ ! -e "${IPSEC_LIBDIR}/libstrongswan.so" && ! -e "${IPSEC_LIBDIR}/libstrongswan.so.0" ]]; then
  die "distro libstrongswan not found under ${IPSEC_LIBDIR}"
fi

ldd_out="$(LD_LIBRARY_PATH="${IPSEC_LIBDIR}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}" ldd -r "${PLUGIN}" 2>&1 || true)"
echo "${ldd_out}"
if echo "${ldd_out}" | grep -q 'not found'; then
  die "${PLUGIN} cannot resolve linked strongSwan libraries from ${IPSEC_LIBDIR}"
fi
undef="$(echo "${ldd_out}" | grep 'undefined symbol:' || true)"
if [[ -n "${undef}" ]]; then
  echo "${undef}" >&2
  die "${PLUGIN} has unresolved runtime symbols"
fi
echo "Runtime symbol check passed for ${PLUGIN}"
