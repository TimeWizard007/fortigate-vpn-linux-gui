# SPDX-License-Identifier: GPL-3.0-or-later
"""Diagnostics.

This package will eventually collect troubleshooting information that is safe
to share: application version, selected profile metadata (never secrets),
openfortivpn version, and high-level connection errors.

Diagnostics must redact credentials, SAML tokens, cookies, and other
authentication material. They must not capture passwords or raw SSO cookies.

v0.1.x contains documentation only. No probes are run.
"""
