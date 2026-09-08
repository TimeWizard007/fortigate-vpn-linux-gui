# SPDX-License-Identifier: GPL-3.0-or-later
"""Connection profile management.

This package will eventually store and load FortiGate SSL VPN connection
profiles (display name, gateway, authentication mode, and related settings).

Passwords must never be stored in plaintext. When credential storage is added,
it should use a platform secret store (for example the FreeDesktop Secret
Service / libsecret) rather than a config file.

v0.1.x contains documentation only. No profiles are persisted.
"""
