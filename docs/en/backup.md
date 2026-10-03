# Encrypted Backup and Restore

v1.6.0 adds **Backup** and **Restore**. They are not the same as profile
**Export** and **Import**.

**Export is not a backup of secrets.** Export writes a versioned JSON file
with portable non-secret fields only. It never includes the IPsec
pre-shared key, user password, tokenid, FCT UID, cookies, or keyring
values.

**Backup** writes one encrypted `.fvbackup` file that can reconstruct
supported profiles and any IPsec secrets that were saved in Secret
Service.

## After reinstalling Ubuntu

1. On the old system: Profiles → **Backup…** → choose a password (at least
   12 characters) → save the `.fvbackup` file.
2. Store the file and the password separately.
3. Install FortiGate VPN Linux GUI on the new system (APT or `.deb`).
4. Profiles → **Restore…** → select the file → enter the password →
   confirm replacements.
5. Unlock the desktop keyring if GNOME prompts.
6. Connect. IPsec profiles that had a saved PSK (and optional XAuth
   password) should not need those secrets re-entered.

## What Backup includes

- Stable profile ids and names
- Gateway, port, VPN type, IPsec settings, certificate pin
- Optional default profile
- Optional saved IPsec pre-shared key
- Optional saved XAuth password

## What Backup does not include

- SSL VPN passwords (they are never persisted)
- SAML cookies, tokens, session URLs, tokenid, FCT UID, EAP secrets
- Desktop preferences, autostart, update cache
- Logs and diagnostics
- Helper or strongSwan runtime state

SSL username/password profiles restore the profile and optional username
hint. The SSL password must be entered again at connect. SSL SAML/SSO
profiles do not need a stored password. IKEv2 SAML/SSO restores the tunnel
PSK when it was saved; the browser sign-in happens again at connect.

## Password and cryptography

The backup password is chosen at Backup time and is not stored. Restore
uses the same password. A wrong password and a damaged file produce the
same message: **Wrong password or the backup file is damaged.**

The container uses Argon2id (64 MiB, 3 iterations, 1 lane) to derive an
AES-256-GCM key. The header holds only encryption parameters. Profile
names and secrets are inside the authenticated ciphertext.

Restore is all-or-nothing. If Secret Service is unavailable and the backup
contains secrets, Restore aborts. If Restore would replace a profile used
by an active VPN connection, disconnect first.

Files are written atomically with mode `0600`.
