#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Build the Ubuntu 24.04 amd64 .deb. Does not install, publish, or touch user config.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACKAGE_NAME="fortigate-vpn-linux-gui"
VERSION="1.1.0"
REVISION="1"
ARCH="amd64"
DEB_VERSION="${VERSION}-${REVISION}"
DEB_FILENAME="${PACKAGE_NAME}_${DEB_VERSION}_${ARCH}.deb"
APP_LIB="/usr/lib/${PACKAGE_NAME}"
VENV_DIR="${APP_LIB}/venv"
HELPER_PATH="/usr/libexec/${PACKAGE_NAME}/vpn-helper"
PACKAGE_OPENFORTIVPN_PATH="/usr/libexec/${PACKAGE_NAME}/openfortivpn"
OPENFORTIVPN_VERSION="1.24.1"
OPENFORTIVPN_SHA256="c40d33acd97b89c2e943bfd839c19b69e5a7a5997052e2fc9a595602745c0465"
OPENFORTIVPN_URL="https://github.com/adrienverge/openfortivpn/archive/refs/tags/v${OPENFORTIVPN_VERSION}.tar.gz"

DIST="${ROOT}/dist"
STAGING="${ROOT}/build/deb-staging"

die() {
  echo "error: $*" >&2
  exit 1
}

fetch_openfortivpn_source() {
  local dest="$1"
  OPENFORTIVPN_URL="${OPENFORTIVPN_URL}" OPENFORTIVPN_SHA256="${OPENFORTIVPN_SHA256}" \
    python3.12 - "$dest" <<'PY'
import hashlib
import os
import sys
import urllib.request
from pathlib import Path

url = os.environ["OPENFORTIVPN_URL"]
expected = os.environ["OPENFORTIVPN_SHA256"]
dest = Path(sys.argv[1])
dest.parent.mkdir(parents=True, exist_ok=True)
if dest.is_file() and hashlib.sha256(dest.read_bytes()).hexdigest() == expected:
    print(f"using cached {dest}")
    raise SystemExit(0)
print(f"downloading {url}")
urllib.request.urlretrieve(url, dest)
digest = hashlib.sha256(dest.read_bytes()).hexdigest()
if digest != expected:
    dest.unlink(missing_ok=True)
    raise SystemExit(f"openfortivpn source SHA-256 mismatch: {digest}")
print(f"verified {digest}")
PY
}

build_package_openfortivpn() {
  local tarball="${ROOT}/build/openfortivpn-src/openfortivpn-${OPENFORTIVPN_VERSION}.tar.gz"
  local srcdir="${ROOT}/build/openfortivpn-${OPENFORTIVPN_VERSION}"
  fetch_openfortivpn_source "${tarball}"
  rm -rf "${srcdir}"
  mkdir -p "${srcdir}"
  tar -xzf "${tarball}" -C "${srcdir}" --strip-components=1
  (
    cd "${srcdir}"
    if [[ ! -f configure ]]; then
      ./autogen.sh
    fi
    ./configure --prefix=/usr
    make -j"$(nproc)"
  )
  install -m 0755 "${srcdir}/openfortivpn" "${STAGING}${PACKAGE_OPENFORTIVPN_PATH}"
  strip --strip-unneeded "${STAGING}${PACKAGE_OPENFORTIVPN_PATH}"
  chmod 0755 "${STAGING}${PACKAGE_OPENFORTIVPN_PATH}"
  chmod u-s,g-s,o-w "${STAGING}${PACKAGE_OPENFORTIVPN_PATH}"
  if [[ -f "${srcdir}/LICENSE" ]]; then
    install -m 0644 "${srcdir}/LICENSE" \
      "${STAGING}/usr/share/doc/${PACKAGE_NAME}/openfortivpn.LICENSE"
  fi
  "${STAGING}${PACKAGE_OPENFORTIVPN_PATH}" --help 2>&1 | grep -q -- '--saml-login' \
    || die "packaged openfortivpn is missing --saml-login"
}

[[ "$(id -u)" -ne 0 ]] || die "do not run this build as root"
[[ -f "${ROOT}/pyproject.toml" ]] || die "run from the repository (missing pyproject.toml)"
command -v python3.12 >/dev/null || die "python3.12 is required to build the Ubuntu 24.04 package"
command -v dpkg-deb >/dev/null || die "dpkg-deb is required (install dpkg-dev)"
command -v gcc >/dev/null || die "gcc is required to build openfortivpn"
command -v make >/dev/null || die "make is required to build openfortivpn"
command -v pkg-config >/dev/null || die "pkg-config is required to build openfortivpn"
command -v autoconf >/dev/null || die "autoconf is required to build openfortivpn"
command -v automake >/dev/null || die "automake is required to build openfortivpn"
command -v strip >/dev/null || die "strip is required to build openfortivpn"
pkg-config --exists libssl || die "libssl development files are required (install libssl-dev)"

rewrite_staging_prefix() {
  local file="$1"
  if grep -Fq "${STAGING}" "${file}"; then
    sed -i "s|${STAGING}||g" "${file}"
  fi
}

rm -rf "${STAGING}"
mkdir -p "${DIST}" \
  "${STAGING}${VENV_DIR}" \
  "${STAGING}/DEBIAN" \
  "${STAGING}/usr/bin" \
  "${STAGING}/usr/libexec/${PACKAGE_NAME}" \
  "${STAGING}/usr/share/applications" \
  "${STAGING}/usr/share/icons/hicolor/scalable/apps" \
  "${STAGING}/usr/share/polkit-1/actions" \
  "${STAGING}/usr/share/doc/${PACKAGE_NAME}"

python3.12 -m venv "${STAGING}${VENV_DIR}"
VENV_PY="${STAGING}${VENV_DIR}/bin/python"
"${VENV_PY}" -m pip install --no-compile --no-deps "${ROOT}"
"${VENV_PY}" -m pip install --no-compile -r "${ROOT}/packaging/requirements-bundle.txt"
"${VENV_PY}" -c "import keyring; import keyring.backends.SecretService" \
  || die "packaged venv is missing keyring Secret Service"

rm -f \
  "${STAGING}${VENV_DIR}/bin/pip" \
  "${STAGING}${VENV_DIR}/bin/pip3" \
  "${STAGING}${VENV_DIR}/bin/pip3.12" \
  "${STAGING}${VENV_DIR}/bin/wheel" \
  "${STAGING}${VENV_DIR}/bin/fortigate-vpn-helper" \
  "${STAGING}${VENV_DIR}/bin/fortigate-vpn-gui" \
  "${STAGING}${VENV_DIR}/bin/activate" \
  "${STAGING}${VENV_DIR}/bin/activate.csh" \
  "${STAGING}${VENV_DIR}/bin/activate.fish" \
  "${STAGING}${VENV_DIR}/bin/Activate.ps1"
find "${STAGING}${VENV_DIR}/bin" -name 'pyside6-*' -delete
rm -rf \
  "${STAGING}${VENV_DIR}/lib/python3.12/site-packages/pip" \
  "${STAGING}${VENV_DIR}/lib/python3.12/site-packages/setuptools" \
  "${STAGING}${VENV_DIR}/lib/python3.12/site-packages/pkg_resources" \
  "${STAGING}${VENV_DIR}/lib/python3.12/site-packages/wheel"
find "${STAGING}${VENV_DIR}/lib/python3.12/site-packages" -maxdepth 1 -type d \( \
    -name 'pip-*' -o -name 'setuptools-*' -o -name 'wheel-*' \
  \) -exec rm -rf {} +
find "${STAGING}${VENV_DIR}" -name 'direct_url.json' -delete
find "${STAGING}${VENV_DIR}" -path '*.dist-info/RECORD' -delete
find "${STAGING}${VENV_DIR}" -type d -name 'tests' -path '*/site-packages/*' -exec rm -rf {} +
rm -rf "${STAGING}${VENV_DIR}/lib/python3.12/site-packages/PySide6/scripts"
"${VENV_PY}" -m compileall -q "${STAGING}${VENV_DIR}/lib/python3.12/site-packages/fortigate_vpn_gui"

while IFS= read -r -d '' file; do
  rewrite_staging_prefix "${file}"
done < <(find "${STAGING}${VENV_DIR}/bin" -type f -print0)
if [[ -f "${STAGING}${VENV_DIR}/pyvenv.cfg" ]]; then
  rewrite_staging_prefix "${STAGING}${VENV_DIR}/pyvenv.cfg"
fi

cat > "${STAGING}/usr/bin/${PACKAGE_NAME}" <<EOF
#!/bin/sh
exec ${VENV_DIR}/bin/python -m fortigate_vpn_gui "\$@"
EOF
chmod 0755 "${STAGING}/usr/bin/${PACKAGE_NAME}"

build_package_openfortivpn

{
  echo "#!${VENV_DIR}/bin/python"
  tail -n +2 "${ROOT}/packaging/libexec/vpn-helper"
} > "${STAGING}${HELPER_PATH}"
chmod 0755 "${STAGING}${HELPER_PATH}"

install -m 0644 "${ROOT}/packaging/polkit/com.fortigate-vpn-linux-gui.policy" \
  "${STAGING}/usr/share/polkit-1/actions/com.fortigate-vpn-linux-gui.policy"
install -m 0644 "${ROOT}/packaging/desktop/fortigate-vpn-linux-gui.desktop" \
  "${STAGING}/usr/share/applications/fortigate-vpn-linux-gui.desktop"
install -m 0644 "${ROOT}/src/fortigate_vpn_gui/resources/icons/fortigate-vpn-linux-gui.svg" \
  "${STAGING}/usr/share/icons/hicolor/scalable/apps/fortigate-vpn-linux-gui.svg"
install -m 0644 "${ROOT}/packaging/debian/changelog" \
  "${STAGING}/usr/share/doc/${PACKAGE_NAME}/changelog.Debian"
gzip -9n -f "${STAGING}/usr/share/doc/${PACKAGE_NAME}/changelog.Debian"
install -m 0644 "${ROOT}/packaging/debian/copyright" \
  "${STAGING}/usr/share/doc/${PACKAGE_NAME}/copyright"
install -m 0644 "${ROOT}/LICENSE" \
  "${STAGING}/usr/share/doc/${PACKAGE_NAME}/LICENSE"

install -m 0755 "${ROOT}/packaging/debian/postinst" "${STAGING}/DEBIAN/postinst"
install -m 0755 "${ROOT}/packaging/debian/postrm" "${STAGING}/DEBIAN/postrm"

if find "${STAGING}" \( \
    -name '.git' -o -name '.venv' -o -name 'profiles.json' -o \
    -name '*.pem' -o -name '*.key' -o -name '.env' \
  \) -print -quit | grep -q .; then
  die "staging directory contains forbidden files"
fi

if grep -RIn --binary-files=without-match \
    '/home/mwi/Development/fortigate-vpn-linux-gui' \
    "${STAGING}/usr/bin" \
    "${STAGING}/usr/libexec" \
    "${STAGING}${VENV_DIR}/bin" \
    "${STAGING}${VENV_DIR}/pyvenv.cfg"; then
  die "staging still contains the development checkout path"
fi

INSTALLED_SIZE="$(python3 - "${STAGING}" <<'PY'
import sys
from pathlib import Path

root = Path(sys.argv[1])
total = 0
for path in root.rglob("*"):
    if not path.is_file():
        continue
    if "DEBIAN" in path.parts:
        continue
    total += path.stat().st_size
print((total + 1023) // 1024)
PY
)"
if [[ -z "${INSTALLED_SIZE}" || "${INSTALLED_SIZE}" -lt 10000 ]]; then
  die "installed size looks wrong: ${INSTALLED_SIZE:-empty}"
fi
awk -v size="${INSTALLED_SIZE}" '
  /^Architecture:/ { print; print "Installed-Size: " size; next }
  { print }
' "${ROOT}/packaging/debian/control" > "${STAGING}/DEBIAN/control"
chmod 0644 "${STAGING}/DEBIAN/control"

find "${STAGING}" -type d -exec chmod 0755 {} +
find "${STAGING}" -type f -exec chmod u+rw,go+r,go-w {} +
chmod 0755 \
  "${STAGING}/usr/bin/${PACKAGE_NAME}" \
  "${STAGING}${HELPER_PATH}" \
  "${STAGING}${PACKAGE_OPENFORTIVPN_PATH}" \
  "${STAGING}/DEBIAN/postinst" \
  "${STAGING}/DEBIAN/postrm"
find "${STAGING}${VENV_DIR}/bin" -type f -exec chmod 0755 {} +
chmod u-s,g-s,o-w "${STAGING}${HELPER_PATH}" "${STAGING}${PACKAGE_OPENFORTIVPN_PATH}"
chmod o-w "${STAGING}/usr/share/polkit-1/actions/com.fortigate-vpn-linux-gui.policy"

OUT="${DIST}/${DEB_FILENAME}"
rm -f "${OUT}"
dpkg-deb --root-owner-group -Zxz --build "${STAGING}" "${OUT}"

echo "${OUT}"
sha256sum "${OUT}"
dpkg-deb -I "${OUT}"
