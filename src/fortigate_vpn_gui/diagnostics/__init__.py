# SPDX-License-Identifier: GPL-3.0-or-later
"""Diagnostics.

Collects troubleshooting information that is safe to share: application
version, helper and polkit status, selected profile metadata (never secrets),
openfortivpn presence, DNS/routing/TCP reachability, and tunnel state.
Copied reports are sanitized.
"""
