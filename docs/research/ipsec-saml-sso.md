# IPsec IKEv2 + SAML/SSO — canonical v1.3.0 research

Status: **research baseline frozen; v1.3.0 control and data plane
LIVE-PROVEN.** Slice 1 Linux live round-trip **PROVEN** (§12); Slice 2
live IKE reached `IKE_AUTH` timeout (§12.2); FortiGate WAN sniffer
**PROVEN** that first `IKE_AUTH` arrives and FortiGate sends no UDP/4500
reply; Vendor ID A/B live result **PROVEN** (§12.3): Linux emitted the
three golden FortiClient VIDs, `IKE_SA_INIT` grew to 364 bytes and was
answered, first `IKE_AUTH` still unanswered; missing-VID as sole cause
**FALSIFIED**; first-`IKE_AUTH` differential is §12.4; official
`utilsdll.dll` is present and `GenRawLicenseInfo2` is analyzed (§12.9);
Windows dump harness is **CODE** (§12.10); standalone `LoadLibrary` of
`utilsdll.dll` from a Downloads host is **PROVEN** to fail (`126` then
`1114`, §12.11); Linux Notify `0xF100` A/B is **VALID NEGATIVE**
(§12.12); golden 16-attribute CP request A/B is **VALID NEGATIVE**
(§12.13); structural golden-vs-Linux first `IKE_AUTH` differential is
§12.14; Notify `0xF100` **ordering** A/B is **VALID NEGATIVE** (§12.15);
responder-side synchronized capture is **VALID** (§12.16); first-`IKE_AUTH`
initiator AUTH omission A/B is **LIVE POSITIVE** (§12.17); EAP-only local
authentication plus remote PSK is **LIVE SUCCESS** (§12.18); CFG_REPLY
split-include parse, POST_NOAUTH CHILD_SA narrowing, split XFRM / table
220, split DNS, and FCT UID application-log redaction are **LIVE-PROVEN**
(§12.19); first HomeVPN Connect and Disconnect cleanup are **LIVE-PROVEN**;
the first gateway `/32` restore implementation is **LIVE-FALSIFIED**
(§12.21); the later teardown-owned `/32` restore and Connect → Disconnect
→ Connect cycle are **LIVE-PROVEN** after three successful repeats
(§12.22); private-charon log hygiene is **IMPLEMENTED / TESTED** (§12.20);
`N(EAP_ONLY)` / `N(MSG_ID_SYN_SUP)` / `N(INITIAL_CONTACT)` sole-cause
experiments remain **FALSIFIED** as sufficient (§12.6–12.8).**
Do not commit raw FortiGate dumps, PCAPs, FortiClient traces, HAR files,
research binaries, or proprietary decompiled code.

Application version is **1.3.0**. Helper **capability version** is
**0.9.0**; JSON-lines `protocol_version` remains **1**. Do not modify the
`v1.2.0` tag. Historical experiment notes below that say “Application
remains 1.2.0” record the version at the time of that experiment.

This is the **only** technical research document for the protocol. The
minimal PoC implementation plan is [v1.3-poc-plan.md](v1.3-poc-plan.md).
Do not duplicate this protocol description elsewhere.

Placeholders:

| Token | Meaning |
| ----- | ------- |
| `<FCT_UID>` | Stable 32-hex FortiClient GUID. Same across sessions. |
| `<FCT_TOKEN_ID>` | Per-session `tokenid=` on the localhost callback. Different every Connect. |
| `<USER>` | Human SAML username from the IdP (callback `username=`). |
| `<GATEWAY>` | VPN hostname |

Do not copy real UIDs, tokenids, usernames, RelayState, cookies, PSKs, or
assertions into this repository.

| Label | Meaning |
| ----- | ------- |
| **PROVEN** | Observed in FortiGate debug, Wireshark, FortiClient 7.4.8 traces, and/or static data-flow of `ipsec.exe` |
| **VENDOR-DOCUMENTED** | Fortinet manuals / official troubleshooting samples |
| **HYPOTHESIS** | Plausible; must not be treated as protocol fact |
| **UNKNOWN** | Not established |
| **CODE** | This repository (historical notes may name v1.2.0; current release is v1.3.0) |
| **HOST** | Ubuntu 24.04 strongSwan 5.9.13 on the development host |

---

## 1. Canonical protocol sequence (**PROVEN**)

```
FortiClient  (already has <FCT_UID>)
    |
    | bind http://localhost:<ephemeral>/
    | WinHTTP to <GATEWAY>:1001  → HTML JS redirect
    v
    Browser opens https://<GATEWAY>:1001/saml?<16-hex>
    v
Authentik  →  ACS POST :1001/remote/saml/login
    v
FortiGate
    | SAML cache[<FCT_UID>] = <USER>     (see identity note below)
    | JS redirect → http://localhost:<ephemeral>/?tokenid=<FCT_TOKEN_ID>&username=<USER>
    v
FortiClient listener  GET /?tokenid=…&username=…     [SAML PRE-AUTH DONE]
    |
    | ~0.5 s later: NEW IKEv2 (IKE_SA_INIT not running during browser)
    v
IKE_SA_INIT  (NAT-T UDP/4500 in the golden pcap)
    | FortiClient also sends Vendor IDs (sent **PROVEN**; required **STRONG EVIDENCE**, not **PROVEN**):
    |   Fortinet Endpoint Control, Forticlient EAP Extension,
    |   Forticlient Connect License
    v
IKE_AUTH + EAP
    | EAP Identity (type 1, length 37) = <FCT_UID>   (32 ASCII hex)
    | EAP-MSCHAPv2 password = <FCT_TOKEN_ID>         (plaintext tokenid)
    | standard MSCHAPv2 NT-hash / NT-Response / Master Key
    | method 26 Challenge / Response / Success
    | CTRL-EVENT-EAP-SUCCESS
    | IKE AUTH using EAP-derived key material (MSK 32 bytes)
    v
CHILD_SA / Mode Config / VIP
```

Timing (**PROVEN**):

- Golden pcap: TLS `:1001` ends ~16.402; `IKE_SA_INIT` ~16.994.
- FortiClient 20:14 run: localhost callback ~20:14:20.008; `ikev2_init_ike_sa`
  ~20:14:20.503.

The browser does **not** sit inside a paused IKE/EAP exchange.

---

## 2. Identity model (do not merge these three values)

FortiClient logs **and** FortiGate dumps show **two different** 32-hex
strings plus a human username on every successful Connect.

### `<FCT_UID>` (**PROVEN**)

- Stable FortiClient identity (same install, many sessions).
- Sent during SAML bootstrap as form field `UID=<FCT_UID>` (raw 32 hex;
  FortiGate `SAML login with UID '<FCT_UID>'`).
- The failed WebView2 path used `--object="saml:ipsecvpn:<FCT_UID>"`.
  The successful external-browser POST does **not** wrap the UID.
- FortiGate SAML/auth cache key.
- EAP Identity (type 1; 5-byte EAP header + 32 ASCII hex).
- `config_new_user` username.
- Obtained in FortiClient from `cfg_get_forticlient_guid` (`utilsdll.dll`).
- **Not** `tokenid`. **Not** the human username.

### `<FCT_TOKEN_ID>` (**PROVEN**)

- Per-connect value. New every Connect.
- Localhost callback `tokenid=` (and `GetIPSecSAMLCredentials` JSON
  `tokenid`).
- Plaintext EAP-MSCHAPv2 password. FortiClient then applies **standard**
  MSCHAPv2 NT-hash / NT-Response / Master Key (§11).
- Wiped by FortiClient after copy into the EAP password field (`+0x109d`
  `rep stosb` 0x81 bytes).
- **Not** `<FCT_UID>`. **Not** the human username.

### `<USER>` (**PROVEN**)

- SAML human username from the IdP (`username=` on the callback).
- Mapped by FortiGate from the SAML cache after hit (`Updating saml
  username from <FCT_UID> to <USER>`).
- **Not** EAP Identity. **Not** the EAP-MSCHAPv2 password.

**PROVEN:** `<FCT_TOKEN_ID> ≠ <FCT_UID>` on the golden 20:14 session (and
every other session in `ipsec.exe_FortiAuth.log`).

A reading that `tokenid == EAP Identity` is **incorrect**. That collapses
two fields.

---

## 3. FortiClient bootstrap (**PROVEN** from `ipsec.exe_FortiAuth.log`)

1. `GetIpsecSamlDataExternalBrowser() starts`.
2. Listener bound to an **ephemeral** loopback port (300 s timeout).
3. `QueryIpsecExtBrowserSamlStartUrl` via WinHTTP. Success body is HTML:
   `window.location="https://<GATEWAY>:1001/saml?<16-hex>"`.
4. `Browser opens url https://<GATEWAY>:1001/saml?<16-hex>`.
5. After ACS: `Received request: GET /?tokenid=<FCT_TOKEN_ID>&username=<USER>`.
6. FortiClient returns ~2577 bytes of HTML to the browser; connection closes;
   event loop exits. IKE starts afterwards.

External-browser WinHTTP request (**PROVEN**, §11.7):

```
POST https://<GATEWAY>:1001/saml_login?
Content-Type: application/x-www-form-urlencoded

UID=<FCT_UID>&REDIRECT_PORT=<callback-port>
```

`<callback-port>` is the decimal port of the already-bound `127.0.0.1:0`
listener. The loopback address itself is **not** in the POST body.

Internal WebView2 path (failed attempts) used
`--url="https://<GATEWAY>:1001/saml_login?"` and
`--object="saml:ipsecvpn:<FCT_UID>"`. External-browser success does not log
that argv; the WinHTTP start URL is the JS `/saml?` redirect.

Callback query string contains **only** `tokenid` and `username`. No other
query parameters in the FortiAuth “Received request” line.

`:1001` bootstrap HTML before the browser opens contains the `/saml?<16-hex>`
redirect only — **not** `<FCT_TOKEN_ID>`. Tokenid appears **after** ACS.

`decode base64 to cipher binary` / `Could not decrypt saml data` appears on
the **failed WebView2** path, not on the successful external-browser path.

---

## 4. IKE Vendor IDs (**PROVEN** sent in `IKE_SA_INIT`; requirement **STRONG EVIDENCE**, not **PROVEN**)

FortiClient `iked` adds three Vendor ID payloads while building
`IKE_SA_INIT` (not while building the first `IKE_AUTH`):

- `vendor Forticlient Connect License added`
- `vendor Fortinet Endpoint Control added`
- `vendor Forticlient EAP Extension added`

The golden pcap’s unencrypted initiator `IKE_SA_INIT` MID=00 (UDP 4500)
contains exactly those three Vendor ID payloads, 16 data bytes each
(IKEv2 payload type 43, total length 20), in this order:

| iked name | Raw Vendor ID bytes | Notes |
| --------- | ------------------- | ----- |
| Forticlient Connect License | `4c53427b6d465d1b337bb755a37a7fef` | **PROVEN** in pcap; **not** MD5 of the display name |
| Fortinet Endpoint Control | `b4f01ca951e9da8d0bafbbd34ad3044e` | **PROVEN** = MD5(`Fortinet Endpoint Control`) |
| Forticlient EAP Extension | `c1dc4350476b98a429b91781914ca43e` | **PROVEN** = MD5(`Forticlient EAP Extension`) |

FortiGate’s `IKE_SA_INIT` response in that capture has **no** Vendor IDs
(**PROVEN**). Inner `IKE_AUTH` payloads are encrypted; iked does **not**
log adding Vendor IDs during first `IKE_AUTH` construction (**PROVEN**
absence from that construction log).

FortiGate: `FCT EAP 2FA extension vendor ID received`, logged on the
golden session at the moment authd starts EAP for `<FCT_UID>` (same
second as the first `IKE_AUTH` response). **STRONG EVIDENCE** this
string refers to the Forticlient EAP Extension VID above. The VID
bytes themselves were carried on `IKE_SA_INIT`.

Do not claim these are optional or mandatory. Live Linux `IKE_SA_INIT`
was accepted **without** them (§12.2) and again **with** them (§12.3).
The first `IKE_AUTH` got no reply in both runs. Missing the three
Vendor IDs is **FALSIFIED as the sole cause** of the silent first
`IKE_AUTH` drop. Keep emitting them: they match golden FortiClient and
may still be required as one part of compatibility.

---

## 5. EAP (**PROVEN**)

- `Eap Config: Use eap: 1`
- Identity reply: `code 2 … type 1, length 37`
- `method 26 (MSCHAPV2) selected` (IANA EAP-MSCHAPv2)
- Response length 91; Success ack length 6
- `EAP-MSCHAPV2: Authentication succeeded` / `CTRL-EVENT-EAP-SUCCESS`
- `ikev2_init_eap_finalize: Creating AUTH payload with EAP MSK (size 32)`
- FortiGate: Identity → MSCHAPv2 Challenge (`hostapd`) → Response →
  `M=OK` → EAP Success → Access-Accept `homevpn-saml`

This is **not** a proprietary EAP-SAML type.

`sso_enabled(1), save_password(0), save_username(0)`.
`ikev2_init_ike_sa: set password state to unknown`.
Later `pre_disconnect: password state is 2` (numeric state only; no secret).

`config_new_user: inserting new user <FCT_UID>` — **no password logged**.

---

## 6. Exhaustion of existing FortiClient evidence (questions A–E)

| Q | Finding | Label |
| - | ------- | ----- |
| A. What is configured as the MSCHAPv2 password? | `<FCT_TOKEN_ID>` copied into the EAP password buffer when `sso_enabled != 0`. Logs still never print the bytes. | **PROVEN** (static); runtime non-print **PROVEN** |
| B. Derived from tokenid vs other bootstrap material? | Direct copy of `tokenid` into the same buffer used for shmem/saved password. No Fortinet KDF before NT-hash. Standard MSCHAPv2 then MD4(UTF-16 password). | **PROVEN** (option A in §11) |
| C. Callback only tokenid+username? | Yes, on the request line FortiAuth logs. JSON parser also only keys `username` and `tokenid`. | **PROVEN** |
| D. Extra auth material in `:1001` start HTML? | Only JS redirect to `/saml?<16-hex>`. | **PROVEN** none in that HTML |
| E. FortiAuth → iked credential API? | `GetIPSecSAMLCredentials` JSON → `do_saml_auth` writes GUID to object `+0x101c` and `tokenid` to `+0x109d`; EAP config copies those into identity/password. | **PROVEN** |

Do **not** treat `<FCT_UID>`, `<FCT_TOKEN_ID>`, or `<USER>` as interchangeable.

---

## 7. v1.2.0 architecture to preserve (**CODE**)

- Supported connect combo: IKEv1 Aggressive + PSK + XAuth + Mode Config only.
- `AUTH_EAP` / `ikev2` may be **stored** and are **rejected at connect**.
- IPsec `use_sso` forced false today.
- Private charon: `STRONGSWAN_CONF=/run/charon.fvl.conf`, VICI
  `/run/charon.fvl.vici`. Never kill system `strongswan-starter`.
- IKE UDP 500/4500 occupancy check **before** secrets.
- Secrets: separate `credentials` JSON (`psk`, `username`, `password`) →
  0600 `secrets.conf`. Connect JSON forbids `cookie` / `token` / `saml`.
- SSL SAML: openfortivpn localhost callback + `SystemBrowserLauncher` +
  `WAITING_FOR_AUTH`. IPsec SAML cannot reuse openfortivpn; it **can** reuse
  the browser launcher and wait-state pattern.
- `url_safety` refuses **opening** loopback URLs. IPsec SAML opens
  `https://<GATEWAY>:1001/saml?…` (not loopback) and **listens** on localhost.

---

## 8. strongSwan 5.9.13 compatibility (**HOST** / **CODE**)

Private charon already loads distro `charon.plugins.include`. Ubuntu plugins
include `eap-identity` and `eap-mschapv2`. No `vendor_id` plugin `.so`.
`charon.send_vendor_id` only sends the **strongSwan** VID.

| Capability | Classification |
| ---------- | -------------- |
| IKEv2 initiator (`version = 2`) | **SUPPORTED WITH CONFIGURATION** (text already generated; connect gated) |
| PSK peer auth | **SUPPORTED AS-IS** |
| NAT-T `encap = yes` | **SUPPORTED AS-IS** |
| Mode Config `vips = 0.0.0.0` | **SUPPORTED AS-IS** |
| CHILD_SA + `install_virtual_ip` | **SUPPORTED AS-IS** |
| EAP Identity + EAP-MSCHAPv2 | **SUPPORTED WITH CONFIGURATION** (`local { auth = eap-mschapv2; eap_id = … }` + `secrets.eap` 0600) |
| Dynamic/ephemeral `eap_id` + password at connect | **SUPPORTED WITH CONFIGURATION** (write secrets like XAuth; wipe after) |
| Fortinet / FortiClient EAP Extension Vendor IDs | **REQUIRES CUSTOM PLUGIN/PATCH** (or a tiny charon hook). Stock `cisco_unity` is a **different** VID (IKEv1 Unity). |
| HTTP `:1001` + browser + localhost `tokenid` | **Not charon** — application |

Vendor IDs are **not PROVEN** as a requirement. Slice 2 first attempted
the standards-based IKEv2 + PSK + EAP-MSCHAPv2 path (§12.2). The §12.3
A/B then emitted the three golden VIDs; FortiGate still ignored the
first `IKE_AUTH`. Keep the plugin.

---

## 9. PoC planning (not this file)

The frozen protocol model stays here. The **minimal v1.3.0 PoC**
(modules, helper protocol, secret lifecycle, success/failure, VID
decision, first implementation slice) is specified only in:

[v1.3-poc-plan.md](v1.3-poc-plan.md)

Do not implement from this research file. IKEv1 PSK+XAuth and SSL SAML
remain **CODE** at v1.2.0.

---

## 10. Remaining UNKNOWN / HYPOTHESIS

**Blocker B (MSCHAPv2 secret source): CLOSED** — **PROVEN** in §11.
**Blocker BOOT (byte-level `:1001` request): CLOSED** — **PROVEN** in §11.7.

| ID | Item | Label |
| -- | ---- | ----- |
| VID | Whether Fortinet Endpoint Control / Forticlient EAP Extension / Connect License Vendor IDs are **required** for FortiGate to accept `IKE_AUTH` / start EAP | **FALSIFIED as sole cause** (§12.3). Requirement as one of several compatibility inputs remains **UNKNOWN**. |
| UID-linux | Linux-generated 32-hex GUID is accepted as FortiGate SAML cache key | **PROVEN** (Slice 1 live against FortiGate 60F / FortiOS 7.6.7) |
| BOOT | Exact HTTP of FortiClient 7.4.8.2066 external-browser `:1001` bootstrap | **PROVEN** (§11.7). Linux live acceptance of a generated UID is **PROVEN** (UID-linux). |
| UA | Whether FortiGate requires the WinHTTP `FortiSSLVPN (Windows NT; SV1 [SV{v=02.01; f=07;}])` User-Agent | **PROVEN not required** on this gateway (neutral `fortigate-vpn-linux-gui/<version>` was accepted) |
| VID-impl | Stock Ubuntu 5.9.13 has no swanctl/charon key for arbitrary initiator VIDs. An application-owned private-charon plugin now exists for the A/B PoC | **CODE** / **HOST** (see §12.1, §12.3) |
| IKE-live | Stock strongSwan IKEv2 PSK + EAP-MSCHAPv2 after Slice 1 SAML is accepted by this FortiGate | **IKE_SA_INIT PROVEN accepted**; AUTH-present first `IKE_AUTH` **PROVEN** unanswered through §12.15; AUTH-omit first `IKE_AUTH` **LIVE POSITIVE** (§12.17): FortiGate returned `IDr AUTH EAP/REQ/ID`; EAP continuation then blocked by `child_create` (§12.18) |
| IKE_AUTH-delta | Which first-`IKE_AUTH` payload difference causes the silent drop | **CLOSED as AUTH presence** on this baseline (§12.17 **LIVE POSITIVE**). Notify `0xF100` is **VALID NEGATIVE** (§12.12). Exact CP16 is **VALID NEGATIVE** (§12.13). `0xF100` ordering + AUTH-present is **VALID NEGATIVE** (§12.15). New blocker: CHILD_CREATE vs intermediate EAP (§12.18). |

The PoC first attempt closed **IKE-live** as far as `IKE_SA_INIT` and
as far as first-`IKE_AUTH` delivery. The Vendor ID A/B in §12.3
**FALSIFIED** missing-VIDs as the sole silent-drop cause. The remaining
first-`IKE_AUTH` differential is §12.4. Do not implement a guessed
mapping of `<USER>` or `<FCT_UID>` as the MSCHAPv2 password.

---

## 11. FortiClient 7.4.8 static analysis

Local, git-excluded research copies of FortiClient **7.4.8.2066**. These
binaries must **never** be staged, committed, pushed, copied into other
docs, or shipped in release artifacts.

| File | SHA256 |
| ---- | ------ |
| `ipsec.exe` | `41828c3f3caa7a144cc45fd31fb920a4354a81da5797a40c6225e426fadd0d8e` |
| `FortiAuth.dll` | `62433ac2018dbbd52b1162ddcc426c713668b8ffad11f0966c7ec26b8b6f4211` |
| `utilsdll.dll` | `96578a6ecf4a09e89122423ca4cd56fadb061c799c186753192d90a882afa459` (PE32+ x86-64, 7.4.8.2066; analysis §12.9) |

PE: `ipsec.exe` PE32+ x86-64, ImageBase `0x140000000`. Analysis used
pdata function bounds, CALL xrefs, RIP-relative string xrefs, and
instruction-level data flow. No proprietary decompiled listings are
reproduced here.

**Address correction (discarded error):** the unique CALL to
`FUN_140089130` is from `FUN_14008a610` (`do_saml_auth`). An earlier
note that used `FUN_14000a610` was a wrong VA (unrelated Fabric-timeout
log site). That address is **not** part of the SAML/tokenid call graph.

### 11.1 Relevant functions (Ghidra names / VA)

| VA | Role |
| -- | ---- |
| `FUN_140089bb0` | Parse `GetIPSecSAMLCredentials` JSON; keys `username`, `tokenid` only |
| `FUN_140089130` | SAML credential wrapper: GUID + JSON parse + copy-out params |
| `FUN_140089b30` | Load install GUID via import `cfg_get_forticlient_guid` (`utilsdll.dll`) |
| `FUN_14008a610` | `do_saml_auth`: unique caller of `FUN_140089130` |
| `FUN_140154221` | EAP peer configuration (`Eap Config: Use eap`, `sso_enabled`, method register) |
| `FUN_140036d20` | `config_new_user` (insert/update user record; encrypts password for the user struct) |
| `FUN_140037970` | Copy object `+0x101c` into iked attr **0x19** via `FUN_1400b5380` |
| `FUN_140037910` | Copy object `+0x109d` into iked attr **0x1A** via `FUN_1400b5380` |
| `FUN_1400b5380` | Locked setter into object `+0x4440` (cmd `3`, attr id, C-string) |
| `FUN_14014b1d0` | Register EAP method `"MSCHAPV2"` |
| `FUN_140149c60` | MSCHAPv2 crypto: Identity, username, challenges, password / password hash, NT-Response, Master Key |
| `FUN_1401308b0` | NT-hash from **plaintext** password (UTF-16 then MD4-class hash) |
| `FUN_1401571d0` | `eap_get_config_identity` |
| `FUN_1401574f0` | `eap_get_config_password` (config `+0x40` / `+0x48`) |

`FortiAuth.dll` exports used by `ipsec.exe` include
`GetIpsecSamlDataExternalBrowser` (and SSL/Azure helpers). The IPsec JSON
path is reached after that browser/callback flow as
`GetIPSecSAMLCredentials`.

### 11.2 Reconstructed `SamlCredentials`

`FUN_140089bb0` writes a two-field MSVC `std::string` object:

```
struct SamlCredentials {
    std::string username; // +0x00
    std::string tokenid;  // +0x20
};
```

No other JSON keys are loaded in this function. Log strings:
`GetIPSecSAMLCredentials`, `%s Error parsing JSON.`,
`%s Invalid JSON format.`

`FUN_140089130` then copies:

| Parsed field | Out-param of `FUN_140089130` | `do_saml_auth` destination |
| ------------ | ---------------------------- | -------------------------- |
| GUID from `cfg_get_forticlient_guid` | param corresponding to caller `[rbp+0x10]` | global object `+0x101c` (max `0x81` bytes) |
| `tokenid` | **param_8** | global object `+0x109d` (max `0x81` bytes) |
| SAML `username` | **param_10** | wide conversion, then a hashed FortiVpnDll setter (display / `VpnConnInfo_SetSAMLUsername` class), **not** the EAP password |
| server IP string | other out-param | logged `do_saml_auth: server IP from SAML: %s` |

`tokenid` is **not** discarded after the localhost callback.

### 11.3 `tokenid` data-flow (SSO connect)

```
GetIpsecSamlDataExternalBrowser / localhost GET ?tokenid=&username=
        |
        v
GetIPSecSAMLCredentials  →  JSON
        |
        v
FUN_140089bb0  →  SamlCredentials.{username, tokenid}
        |
        v
FUN_140089130  →  param_8 = tokenid, param_10 = username
        |
        v
FUN_14008a610 do_saml_auth
        |  memcpy tokenid → object+0x109d
        |  memcpy GUID    → object+0x101c
        v
FUN_140154221 EAP config  (sso_enabled UTF-16 key, r15 != 0)
        |  object+0x101c → stack identity  [rbp-0x80]
        |  object+0x109d → stack password  [rbp+0x381]
        |  then wipe +0x109d (0x81 bytes)
        |
        |  Non-SSO fills THE SAME two buffers from:
        |    shmem username/password, or saved creds, or machine tunnel
        v
eap_peer_config global (identity @ +0x00, password @ +0x40)
        |
        +-- config_new_user (FUN_140036d20): identity + encrypted copy
        |   of the same password for the user struct; then optional
        |   FUN_1400b5380 attr 0x1B
        |
        v
EAP-MSCHAPv2 "Generating Challenge Response"
        |  eap_get_config_identity → r12
        |  eap_get_config_password → r15
        v
FUN_140149c60  (plaintext branch: "MSCHAPV2: password")
        v
FUN_1401308b0  NT-hash(UTF-16 password) → NT-Response / Master Key
```

Parallel iked path (same object fields, before wipe in some handlers):
`FUN_140037970(object, +0x101c)` attr **0x19**,
`FUN_140037910(object, +0x109d)` attr **0x1A** (26, EAP-MSCHAPv2 type
number), then `rep stosb` wipe of `+0x109d`.

### 11.4 Evidence classification

Question: is `tokenid`

- **A.** copied directly into the EAP-MSCHAPv2 password/credential field,
- **B.** transformed/derived before becoming the MSCHAPv2 secret,
- **C.** used as input to another credential/token exchange,
- **D.** unrelated to the MSCHAPv2 password?

**Answer: A. PROVEN.**

Reasons:

1. SSO branch (`sso_enabled` config key) copies `+0x109d` into
   `[rbp+0x381]`. The non-SSO branches fill that **same** address from
   “password from shmem” / saved password APIs.
2. `[rbp-0x80]` is the matching identity buffer (SSO source `+0x101c` =
   `cfg_get_forticlient_guid` = `<FCT_UID>`), matching runtime EAP Identity.
3. Those buffers are `strdup`’d into `eap_peer_config` identity (`+0x00`)
   and password (`+0x40`). Layout matches `eap_get_config_password`
   reading `config+0x40`.
4. Challenge-response calls `eap_get_config_password` and passes the
   pointer into `FUN_140149c60` as the MSCHAPv2 password. The plaintext
   path logs `MSCHAPV2: password` then `FUN_1401308b0` (standard NT-hash).
5. There is **no** Fortinet-specific KDF of `tokenid` before that field.
   Subsequent NT-hash is ordinary EAP-MSCHAPv2 (not option B).
6. SAML `<USER>` is a separate string and is not copied into `+0x109d`
   or the password buffer.

This matches the already-proven runtime sequence: SAML completes before
IKE; EAP Identity is `<FCT_UID>` not `tokenid`; EAP type 26; AUTH uses
derived EAP MSK.

### 11.5 Impact on PoC architecture

- Stock Ubuntu 5.9.13 **`eap-mschapv2` is sufficient** for identity +
  secret once both are known: `eap_id = <FCT_UID>`, EAP password =
  `<FCT_TOKEN_ID>` (ASCII as received on the callback; charon hashes).
- Do **not** put SAML cookies, assertions, or `<USER>` in `secrets.eap`.
- `config_new_user` encryption is FortiClient’s user-struct wrap of the
  **same** password; Linux/strongSwan does not need that wrapper.
- First PoC attempt: **no** Fortinet VID plugin. See
  [v1.3-poc-plan.md](v1.3-poc-plan.md).
- `cisco_unity` is a different VID and is irrelevant to this path.

### 11.6 Remaining items after this analysis

Blocker **B is closed**. Remaining items are in §10. Orchestration and
file-level work live only in the PoC plan.

### 11.7 External-browser `:1001` HTTP bootstrap

FortiAuth.dll export `GetIpsecSamlDataExternalBrowser` is imported by
`ipsec.exe`. The successful path is **not** WebView2. Behavioral
reconstruction from call graph + WinHTTP arguments + form builders
(no proprietary decompiled source):

1. Bind `127.0.0.1` with requested port **0** (`evconnlistener_new_bind`).
2. `getsockname` + `ntohs` → assigned ephemeral port. Log:
   `Listener bound to port %u` /
   `listen on port %lu for external browser request.`
3. `QueryIpsecExtBrowserSamlStartUrl` builds a UTF-8 body with
   `WideCharToMultiByte` (CP_UTF8):
   `UID=` + caller GUID string + `&REDIRECT_PORT=` + decimal port.
4. HTTP helper `GetHttpResponse`:
   - `WinHttpOpen` agent `FortiSSLVPN (Windows NT; SV1 [SV{v=02.01; f=07;}])`
     (sent **PROVEN**; required **UNKNOWN**)
   - `WinHttpConnect` host = gateway, port = SAML TCP port (profile 1001)
   - method word **1** → **POST** (map: 0=GET, 1=POST, 2=PUT)
   - `WinHttpOpenRequest` object = `/saml_login?` (12-wchar constant,
     including the trailing `?`; empty query), flags `WINHTTP_FLAG_SECURE`
   - `WinHttpAddRequestHeaders`
     `Content-Type: application/x-www-form-urlencoded\r\n`
   - `WinHttpSendRequest` with that UTF-8 body
   - `WinHttpReceiveResponse` + `WinHttpReadData`
5. Search the HTML for `window.location="` then the next `"`. The
   substring is the browser URL, copied out with no rewrite. If missing:
   `QueryIpsecExtBrowserSamlStartUrl() could not extract the start url in response.`

UID source on this path: `ipsec.exe` loads `cfg_get_forticlient_guid`
(`utilsdll.dll`) and passes that wchar string as `GetIpsecSamlDataExternalBrowser`
argument `r9`. FortiAuth concatenates it after `UID=` with **no**
`saml:ipsecvpn:` prefix. That prefix is **absent** from FortiAuth.dll
and is **not** applied in `ipsec.exe` between the GUID getter and this
POST. Runtime FortiGate `SAML login with UID '<FCT_UID>'` plus EAP
Identity remain the same 32-hex value — **PROVEN** by correlation.

Loopback **host** is not a form field. Only `REDIRECT_PORT=<decimal>`.

Linux implementation uses an application User-Agent
(`fortigate-vpn-linux-gui/<app-version>`), not the FortiClient string.
Whether FortiGate requires the FortiClient User-Agent is **UNKNOWN**.

**PROVEN** request:

```
POST https://<GATEWAY>:1001/saml_login?
Content-Type: application/x-www-form-urlencoded

UID=<FCT_UID>&REDIRECT_PORT=<callback-port>
```

**PROVEN** response use: HTML containing
`window.location="https://<GATEWAY>:1001/saml?<16-hex>"`.
The quoted URL is opened unchanged. The 16-hex query is **not**
`<FCT_TOKEN_ID>`.

HTTP status code is **not** checked before the `window.location`
extract (**UNKNOWN** as a FortiGate requirement).

Blocker **BOOT** (byte-level request) is **closed**. Linux live
acceptance of a generated 32-hex UID is **PROVEN** (§12).

---

## 12. Slice 1 live Linux result (**PROVEN**)

Environment (do not treat this as a product claim of other FortiGate
models):

- FortiGate 60F, FortiOS 7.6.7
- Gateway hostname `<GATEWAY>` (not recorded here)
- IKE UDP 500/4500, SAML TCP 1001
- Authentik IdP, external browser
- Official FortiClient 7.4.8.2066 on Windows remains the IKE reference

Live Slice 1 outcome:

- Linux-generated persistent 32-lowercase-hex `<FCT_UID>` was accepted.
- Proven `POST /saml_login?` form `UID=` + `REDIRECT_PORT=` was accepted.
- Neutral Linux application User-Agent was accepted (FortiClient UA not
  required on this gateway).
- External browser + Authentik completed.
- FortiGate redirected to the localhost listener.
- Callback returned `tokenid` + `username`.
- Helper/charon were not started (Slice 1).
- Secret redaction held: `<FCT_TOKEN_ID>` and `<FCT_UID>` did not appear
  in application logs.

`:1001` TLS now validates with the system store. The chain that had to
be repaired on the gateway was, at a high level:

```
leaf (*.example) → Let's Encrypt YR1 → Root YR (cross-signed) → ISRG Root X1
```

Verify return code 0. The application must not add certificate bypasses
or special trust handling for this.

Do not record private keys, certificate passwords, tokenid values,
FCT_UID values, or screenshots containing `tokenid`.

### 12.1 Stock strongSwan 5.9.13 Vendor ID boundary (**HOST**)

Ubuntu 5.9.13 `swanctl.conf` has **no** key for custom IKE Vendor IDs.
`charon.send_vendor_id` only sends the **strongSwan** vendor ID payload.
`charon.cisco_unity` sends the Cisco Unity vendor ID (used for IKEv1
Mode Config; left off for IKEv2 EAP). There is no `vendor_id` plugin
under `/usr/lib/ipsec/plugins`. Fortinet Endpoint Control / Forticlient
EAP Extension / Connect License VIDs cannot be emitted without patching
or a custom plugin.

VID **requirement** remains **not PROVEN**. Slice 2 first attempted the
standards-based IKEv2 + PSK + EAP-MSCHAPv2 path. See §12.2. The A/B
Vendor ID PoC is §12.3; its live result is **PROVEN** (VIDs on the
wire; first `IKE_AUTH` still unanswered). Missing-VID as sole cause is
**FALSIFIED**.

### 12.2 Slice 2 live IKE result (**IKE_SA_INIT PROVEN**; first `IKE_AUTH` timeout **PROVEN**)

Development helper 0.9.0 / `ipsec_ikev2_eap` was the helper that ran.
SAML pre-auth completed; callback returned `tokenid` + `username`; private
charon started; PSK and EAP secrets loaded (identities not recorded here).

Live strongSwan 5.9.13 initiator exchange:

1. `IKE_SA_INIT` request: `SA KE No N(NATD_S_IP) N(NATD_D_IP) N(FRAG_SUP)
   N(HASH_ALG) N(REDIR_SUP)`. **No Vendor IDs** (**PROVEN** from charon log).
2. FortiGate `IKE_SA_INIT` response: `SA KE No N(NATD_S_IP) N(NATD_D_IP)
   N(FRAG_SUP)`. Proposal selected:
   `IKE:AES_CBC_128/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/ECP_384`. NAT-T
   moved the SA to UDP 4500. **PROVEN.**
3. First `IKE_AUTH` request: `IDi AUTH CPRQ(ADDR DNS) SA TSi TSr
   N(EAP_ONLY) N(MSG_ID_SYN_SUP)`, 256 bytes inside charon / **260 bytes
   on the wire including NAT-T framing**, UDP 4500. **No EAP payload.**
   **PROVEN.** Exact `IDi` type/value was not logged (**UNKNOWN**).
4. FortiGate sent **no** `IKE_AUTH` response. charon retransmitted message
   ID 1 until `swanctl --initiate` timed out. **PROVEN.**

Complete FortiGate WAN sniffer for one failed Linux attempt
(`diagnose sniffer packet any 'udp port 500 or udp port 4500' 4 0 l`):

| Time | Direction | Port | Size | Interpretation |
| ---- | --------- | ---- | ---- | -------------- |
| 18:20:12.800931 | Linux → FortiGate | UDP/500 | 304 | `IKE_SA_INIT` request |
| 18:20:12.809797 | FortiGate → Linux | UDP/500 | 264 | `IKE_SA_INIT` response |
| 18:20:12.963090 | Linux → FortiGate | UDP/4500 | 260 | first `IKE_AUTH` |
| 18:20:16.971136 | Linux → FortiGate | UDP/4500 | 260 | `IKE_AUTH` retransmit |
| 18:20:24.165586 | Linux → FortiGate | UDP/4500 | 260 | `IKE_AUTH` retransmit |
| 18:20:37.152671 | Linux → FortiGate | UDP/4500 | 260 | `IKE_AUTH` retransmit |
| 18:20:57.132787 | Linux → FortiGate | UDP/4500 | 1 | NAT-T keepalive, not another `IKE_AUTH` |
| 18:21:00.484828 | Linux → FortiGate | UDP/4500 | 260 | `IKE_AUTH` retransmit |

Filter summary: **8 packets received, 0 packets dropped by kernel.**
FortiGate sent **zero** UDP/4500 packets during the complete captured
attempt. Therefore it is **PROVEN** that:

- the `IKE_SA_INIT` request reached FortiGate
- FortiGate answered `IKE_SA_INIT`
- NAT-T moved the SA to UDP/4500
- the first `IKE_AUTH` reached the FortiGate WAN interface
- repeated `IKE_AUTH` retransmissions reached FortiGate
- FortiGate sent no UDP/4500 response
- EAP never started

Do **not** classify this as EAP failure, tokenid failure, FCT_UID
failure, CHILD_SA failure, Mode Config failure, `IKE_SA_INIT` failure,
or proposal mismatch.

**HYPOTHESIS at the time** (now **FALSIFIED as sole cause**, §12.3):
FortiGate silently drops the first `IKE_AUTH` because the initiator did
not advertise the Forticlient EAP Extension / related Fortinet Vendor
IDs in `IKE_SA_INIT`. The A/B that changed only that variable is §12.3.

EAP-MSCHAPv2 challenge/response **did not start**. This is **not**
evidence that `tokenid` or `<FCT_UID>` is wrong. Loading `IKE shared key
'ike-psk'` / `EAP shared key 'eap'` is configuration, not the EAP
exchange.

Golden FortiClient 7.4.8 `IKE_SA_INIT` MID=00 (pcap, unencrypted):
`SA KE Ni V V V N N N` — the three Fortinet VIDs in §4, then NAT-D
notifies. FortiGate’s response has no VIDs.

Golden first `IKE_AUTH` MID=01 is SK-encrypted in the pcap. From iked
construction + FortiGate’s decrypted response, **PROVEN** where noted:

| Payload | FortiClient first `IKE_AUTH` | Linux strongSwan first `IKE_AUTH` |
| ------- | ---------------------------- | --------------------------------- |
| IDi | IPv4 client address (**PROVEN** iked) | Present; type/value **UNKNOWN** |
| AUTH | `SHARED_KEY_MIC` / `auth_method` 2 (**PROVEN**) | `AUTH` present (**PROVEN** log); method **STRONG EVIDENCE** PSK from swanctl |
| EAP | Absent in request; starts after FortiGate Identity Request (**PROVEN**) | Absent (**PROVEN**) |
| CP / Mode Config | Present, including Fortinet cfg types 21514 / 21515 / 28673 (**PROVEN** iked) | `CPRQ(ADDR DNS)` (**PROVEN**) |
| SA, TSi, TSr | Present (**PROVEN** iked) | Present (**PROVEN**) |
| N(EAP_ONLY) | Not logged (**UNKNOWN**; no iked line) | Present (**PROVEN**) |
| N(MSG_ID_SYN_SUP) | Not logged (**UNKNOWN**) | Present (**PROVEN**) |
| Vendor IDs | Not added in `IKE_AUTH` construction (**PROVEN** iked); were on `IKE_SA_INIT` | None |
| License notify (~270 bytes) | Present (**PROVEN** iked) | Absent (**PROVEN** — not in charon payload list) |

Authentication model: FortiClient sends PSK `AUTH` in the first
`IKE_AUTH`; FortiGate replies `IDr` + `AUTH SHARED_KEY_MIC` + EAP
Identity Request; EAP Identity / MSCHAPv2 follow on later message IDs.
`local { auth = psk }` plus `local { auth = eap-mschapv2; eap_id = … }`
plus `remote { auth = psk }` matches that mixed-auth sequence
(**PROVEN** vs golden). Switching to EAP-only (omit PSK `AUTH`) is
**not** supported by the capture. `N(EAP_ONLY)` is RFC 5998; whether
FortiGate drops the packet because of it is **HYPOTHESIS**. There is no
documented swanctl/charon knob to suppress `EAP_ONLY` while keeping the
second local EAP round. `charon.force_eap_only_authentication` does the
opposite.

Optional plugin ERROR lines (`test-vectors`, `ldap`, `pkcs11`, `rdrand`,
`gcrypt`, `af-alg`, `curve25519`, `chapoly`, `cmac`, `ctr`, `ccm`,
`ntru`, `curl`) and missing certificate directories are **not** required
for the negotiated AES128/SHA256/ECP384 + EAP-MSCHAPv2 path. Do not
treat them as the failure cause.

PoC-plan §15 VID-plugin criteria are **not fully met**: EAP did not
structurally start. Custom Fortinet VID emission was the leading
**HYPOTHESIS** for the silent `IKE_AUTH` drop before §12.3. After §12.3
it is **FALSIFIED as sole cause**. See §12.4 for the remaining
first-`IKE_AUTH` differential.

The WAN sniffer **PROVEN** that `IKE_AUTH` arrives. The next experiment
is **not** another Vendor ID change. It is one isolated first-`IKE_AUTH`
variable from §12.4.

### 12.3 Vendor ID A/B PoC (**CODE**; live result **PROVEN**)

Stock Ubuntu 5.9.13 has no swanctl/charon setting for arbitrary initiator
Vendor IDs (`charon.send_vendor_id` is the strongSwan VID only). Ubuntu
does not ship `libstrongswan-dev`. Extra plugin search paths are C-only
(`plugin_loader_t.add_path`); AppArmor on `/usr/lib/ipsec/charon` can
mmap `/usr/lib/ipsec/plugins/*.so` but not application `libexec`.

The PoC therefore uses an application-owned out-of-tree plugin
`fvl-forticlient-vid`, compiled against upstream 5.9.13 headers and
linked to distro `libcharon`. The uniquely named
`libstrongswan-fvl-forticlient-vid.so` is copied into PLUGINDIR by
`scripts/install-dev-helper.sh`. No `/etc/strongswan.d/charon/` snippet
is written, so system charon does not load it. Private
`/run/charon.fvl.conf` sets `charon.plugins.fvl-forticlient-vid.load = yes`
**only** for IKEv2 + EAP (v1.3 SSO). IKEv1 PSK/XAuth private charon does
not mention the plugin.

The plugin's `message()` hook adds these exact 16-byte payloads to
outbound initiator `IKE_SA_INIT` only:

- `4c53427b6d465d1b337bb755a37a7fef`
- `b4f01ca951e9da8d0bafbbd34ad3044e`
- `c1dc4350476b98a429b91781914ca43e`

Authentication remains local PSK + local EAP-MSCHAPv2 (`eap_id` =
`<FCT_UID>`) + remote PSK. First `IKE_AUTH` payload set is unchanged
except as an unavoidable consequence of the preceding `IKE_SA_INIT`
Vendor IDs.

Live A/B success signal is **not** merely `IKE_SA_INIT`. It is a
FortiGate → Linux UDP/4500 response to the first `IKE_AUTH`, ideally
an EAP Identity Request.

**Live result (PROVEN, `/tmp/fvl-vid-ab.pcap`):**

- charon generated `IKE_SA_INIT` request 0 with
  `SA KE No N(NATD_S_IP) N(NATD_D_IP) N(FRAG_SUP) N(HASH_ALG)
  N(REDIR_SUP) V V V`
- the three raw Vendor IDs on the wire were exactly
  `4c53427b6d465d1b337bb755a37a7fef`,
  `b4f01ca951e9da8d0bafbbd34ad3044e`,
  `c1dc4350476b98a429b91781914ca43e`
- Linux `IKE_SA_INIT` IKE message length = **364 bytes** (was 304
  without VIDs)
- FortiGate answered that 364-byte request (`IKE_SA_INIT` response 264
  bytes on UDP/500)
- Linux first `IKE_AUTH` remained
  `IDi AUTH CPRQ(ADDR DNS) SA TSi TSr N(EAP_ONLY) N(MSG_ID_SYN_SUP)`
- Linux first `IKE_AUTH` IKE message length = **256 bytes**; UDP/4500
  payload = **260 bytes** including NAT-T non-ESP marker
- FortiGate sent **zero** UDP/4500 responses to message ID 1
- EAP did not start

**FALSIFIED as sole cause:** “Missing the three FortiClient Vendor IDs
causes the silent first-`IKE_AUTH` drop.”

Do **not** remove the VID plugin. It matches golden FortiClient and may
still be required as one part of compatibility.

### 12.4 First `IKE_AUTH` differential (VID A/B complete; cause **UNKNOWN**)

Captures compared (outer IKE headers from pcap; inner golden sequence
from iked construction + `ipsec.exe` 7.4.8.2066; inner Linux sequence
from charon logs). SK-encrypted `IKE_AUTH` bodies were **not**
decrypted. No real `<FCT_UID>`, tokenid, PSK, or license string is
recorded here.

#### Outer sizes (**PROVEN** from pcap)

| Message | Linux PoC | Golden FortiClient 7.4.8.2066 |
| ------- | --------- | ----------------------------- |
| `IKE_SA_INIT` request | 364-byte IKE, UDP/500 | 574-byte IKE, UDP/4500 (578 including 4-byte non-ESP marker) |
| `IKE_SA_INIT` response | 264-byte IKE, UDP/500 | 256-byte IKE, UDP/4500 (260 including NAT-T) |
| first `IKE_AUTH` request | 256-byte IKE / 260 UDP | 576-byte IKE / 580 UDP |
| first `IKE_AUTH` response | **none** | 128-byte IKE / 132 UDP, then EAP on message IDs 2–5 |

Delta of first `IKE_AUTH`: **320 bytes**. SK `Next Payload` is `IDi` on
both. With the Linux-selected cipher
`AES_CBC_128` / `HMAC_SHA2_256_128`, SK overhead is 4+16+16 = 36 bytes
inside the 28-byte IKE header, so encrypted inner (including padding)
is 192 vs 512 bytes. The 320-byte gap is almost entirely inner
plaintext, not encryption overhead.

#### `IKE_SA_INIT` differences (do not change yet)

Linux (this run): one IKE proposal
`AES_CBC_128 / AUTH_HMAC_SHA2_256_128 / PRF_HMAC_SHA2_256 / ECP_384`
(SA payload 48 bytes); KE group 20; notifies
`NAT-D, NAT-D, FRAG_SUP, HASH_ALG` (SHA1+SHA256+SHA384+SHA512, 16-byte
payload), `REDIR_SUP`; then the three FortiClient VIDs.

Golden: four IKE proposals (SA payload 276 bytes). Transform order
INTEGR, ENCR, DH, then four PRFs. FortiGate’s INIT response selected
AES-CBC-128 / **PRF_AES128_XCBC** / HMAC-SHA2-256-128 / ECP384
(**PROVEN** pcap; correction vs an earlier SHA256-first PRF note):

1. AES128 / SHA256 integ / DH20 / PRFs AES-XCBC, SHA256, SHA384, SHA1
2. AES128 / SHA256 integ / DH21 / same PRFs
3. AES256 / SHA256 integ / DH20 / same PRFs
4. AES256 / SHA256 integ / DH21 / same PRFs

KE group 20; VIDs; NAT-D; `HASH_ALG` with three hashes only (SHA1,
SHA256, SHA384; 14-byte payload). No `FRAG_SUP`, no `REDIR_SUP`. Starts
directly on UDP/4500.

FortiGate selected the Linux proposal. Do **not** treat the larger
golden proposal set, extra PRFs, missing Linux `FRAG_SUP`/`REDIR_SUP`,
or UDP/500 vs direct UDP/4500 as the current failure cause.

#### Golden first `IKE_AUTH` inner sequence (**STRONG EVIDENCE** from iked + `ipsec.exe`)

Construction in `ikev2_init_ike_auth` (caller around `0x140055c22`):

1. **IDi** — `ID_IPV4_ADDR`, identity length 8, payload length **12**,
   next payload NOTIFY. Client IPv4 (iked `srcid IPV4/<client>`).
2. **AUTH** — method 2 `SHARED_KEY_MIC` (**PROVEN** `ca_setauth`). Exact
   neighbor in the payload chain is not fully logged (**UNKNOWN**).
3. **N(INITIAL_CONTACT)** — type `16384` / `0x4000`, protocol ID 0, SPI
   size 0, empty data. Payload length **8**. `ikev2_add_notify` at
   `0x140047ba0`.
4. **N(license)** — see below. Payload length **279**, next payload CP.
5. **CP** CFG_REQUEST, payload length **72**.
6. **SA** ESP, parsed length **84**, next TSi. Childless mode disabled.
7. **TSi / TSr** — present (**PROVEN** iked).

EAP is **absent** from this request. FortiGate’s first `IKE_AUTH`
response is `IDr` (IPv4 gateway, payload 12) + `AUTH SHARED_KEY_MIC`
(payload 40) + EAP Identity Request (payload 9, length-9 header). EAP
starts only after that response (**PROVEN**).

#### Linux first `IKE_AUTH` inner sequence (**PROVEN** charon)

`IDi AUTH CPRQ(ADDR DNS) SA TSi TSr N(EAP_ONLY) N(MSG_ID_SYN_SUP)`.
No license notify. No Fortinet CP types. No `INITIAL_CONTACT`.
strongSwan 5.9.13 `ike_auth.c` always adds empty `N(EAP_ONLY)`
(RFC 5998 type 16417) and `N(IKEV2_MESSAGE_ID_SYNC_SUPPORTED)`
(RFC 6311 type 16420) on the initiator `IKE_AUTH`. There is no swanctl
knob to suppress `EAP_ONLY` while keeping mixed PSK+EAP; 
`charon.force_eap_only_authentication` does the opposite.

#### ~320-byte size accounting (**STRONG EVIDENCE**, not **PROVEN** as cause)

| Item | Linux | Golden | Inner delta |
| ---- | ----- | ------ | ----------- |
| License Notify `0xF100` | absent | 279-byte payload | +279 |
| CP CFG_REQUEST | `ADDR`+`DNS` ≈ 16 | 72 | +56 |
| `N(INITIAL_CONTACT)` | absent | 8 | +8 |
| `N(EAP_ONLY)` + `N(MSG_ID_SYN_SUP)` | 8+8 | absent | −16 |
| IDi / AUTH / SA / TS (same class) | present | present | ~0 |

279 + 56 + 8 − 16 = 327, plus AES padding, matches the 320-byte
ciphertext gap. The license Notify is the bulk of the delta. That does
**not** prove FortiGate requires it.

#### Golden license Notify (**STRONG EVIDENCE** from `ipsec.exe`; contents **UNKNOWN**)

| Field | Value |
| ----- | ----- |
| IKEv2 Notify Message Type | `0xF100` (61696, private-use range). Host `0xF100` stored after `htons` (WS2_32 ordinal 9). |
| Protocol ID | 0 |
| SPI size | 0 |
| SPI | none |
| Notification data | C string of **strlen 270** plus terminating NUL → **271 bytes** on the wire |
| Notify payload length | 4 generic + 4 notify header + 271 = **279** |
| iked log | `licence info size: %d` at line 1697 (`0x6a1`); size **270** on every traced session |

Construction path:

1. `ikev2_init_ike_auth` calls `0x1400ce450`.
2. That wrapper calls `utilsdll.dll!GenRawLicenseInfo2` (IAT
   `0x140464948`).
3. Logs `licence info size: %d` via `strlen` of the returned buffer
   (never print the buffer).
4. Copies `strlen+1` bytes to notify data at offset 4; writes type
   `0xF100` at offset 2; `free`s the `GenRawLicenseInfo2` buffer.
5. Duplicate helper at `0x140047541` uses the same type/length rule.

The official `utilsdll.dll` copy is now in git-excluded
`.research-binaries/` (SHA256 in §11). Grammar is no longer unknown:
§12.9 shows a newline-separated plaintext `KEY=value` inventory
including `<FCT_UID>`. Size is stable across sessions on this install
(**STRONG EVIDENCE** from iked `licence info size: 270`). Treat the
blob as identifier material: do not log it, do not commit it, do not
reuse a captured real string.

Reproduction of the **framing** (type `0xF100`, proto 0, SPI 0,
NUL-terminated body) is technically possible. A dummy 270-character
placeholder is **not** an approved live A/B: FortiGate might parse
`UID=` / `HOST=` / `MAC=` / other fields (§12.9). Do not decrypt a
golden `IKE_AUTH` into this repository. Do not implement Notify
`0xF100` from this research pass.

#### Golden Fortinet CP attributes (**PROVEN** length; types/order from `ipsec.exe`)

CP payload length 72 ⇒ 4+4 header + 64 attribute bytes = **16 empty
4-byte CFG attributes** (type+length, value empty). iked logs while
parsing its own request (special-case empty-value errors only):

| Type | Hex | iked name | Length | Semantics |
| ---- | --- | --------- | ------ | --------- |
| 21514 | `0x540a` | auto negotiate | 0 | Fortinet private; empty request |
| 21515 | `0x540b` | KEEP_ALIVE | 0 | Fortinet private; empty request |
| 28673 | `0x7001` | SAVE_PASSWD | 0 | Fortinet private; empty request |

The **exact ordered list of all 16 empty CFG_REQUEST attributes** is
derived from `ipsec.exe` `0x140046a70` (CFG_REQUEST `r8d`/`r15d` == 1
at caller `0x14005609f`). Do not guess missing types; do not invent
values.

After the ncfg policy loop the encoder **always** appends 13 empty
4-byte attributes (`add rbp,0x34` = 52 at `0x14004711a`). That trailing
list is **PROVEN**:

`3, 4, 13, 8, 10, 11, 15, 25, 0x540c, 0x7006, 0x540a, 0x540b, 0x7001`

The remaining 3 attributes are the ncfg CFG_REQUEST records emitted
before that block. Dedicated empty constructors **PROVEN**:

- type 1 `INTERNAL_IP4_ADDRESS` (`0x14007ee80`, yacc `0x1400828db`)
- type 2 `INTERNAL_IP4_NETMASK` (yacc inlined `0x140082a79`)

Type 7 `APPLICATION_VERSION` is **STRONG EVIDENCE** as the third ncfg
slot: dedicated empty CFG_REQUEST encoder (`Request IKEV2_CFG_APPLICATION_VERSION`
at `0x140046d19`); not in the trailing 13; 16−13=3; putting any trailing
type in ncfg would duplicate and exceed 72 bytes.

Golden order (ncfg 1, 2, 7 then the proven 13):

| # | Type | Hex | Name | Length | Evidence | Meaning |
| - | ---- | --- | ---- | ------ | -------- | ------- |
| 1 | 1 | `0x0001` | INTERNAL_IP4_ADDRESS | 0 | **PROVEN** ctor | RFC 7296 empty request |
| 2 | 2 | `0x0002` | INTERNAL_IP4_NETMASK | 0 | **PROVEN** ctor | RFC 7296 empty request |
| 3 | 7 | `0x0007` | APPLICATION_VERSION | 0 | **STRONG EVIDENCE** | RFC 7296 empty request |
| 4 | 3 | `0x0003` | INTERNAL_IP4_DNS | 0 | **PROVEN** hardcoded | RFC 7296 empty request |
| 5 | 4 | `0x0004` | INTERNAL_IP4_NBNS | 0 | **PROVEN** hardcoded | RFC 7296 empty request |
| 6 | 13 | `0x000d` | INTERNAL_IP4_SUBNET | 0 | **PROVEN** hardcoded | RFC 7296 empty request |
| 7 | 8 | `0x0008` | INTERNAL_IP6_ADDRESS | 0 | **PROVEN** hardcoded | RFC 7296 empty request |
| 8 | 10 | `0x000a` | INTERNAL_IP6_DNS | 0 | **PROVEN** hardcoded | RFC 7296 empty request |
| 9 | 11 | `0x000b` | INTERNAL_IP6_NBNS | 0 | **PROVEN** hardcoded | RFC 7296 empty request |
| 10 | 15 | `0x000f` | INTERNAL_IP6_SUBNET | 0 | **PROVEN** hardcoded | RFC 7296 empty request |
| 11 | 25 | `0x0019` | INTERNAL_DNS_DOMAIN | 0 | **PROVEN** hardcoded | RFC 8598 empty request |
| 12 | 21516 | `0x540c` | (unnamed) | 0 | **PROVEN** hardcoded | Fortinet private; meaning **UNKNOWN** |
| 13 | 28678 | `0x7006` | UNITY_LOCAL_LAN | 0 | **PROVEN** hardcoded | Cisco Unity overlap; Fortinet empty request |
| 14 | 21514 | `0x540a` | auto-negotiate | 0 | **PROVEN** hardcoded + iked | Fortinet private |
| 15 | 21515 | `0x540b` | KEEP_ALIVE | 0 | **PROVEN** hardcoded + iked | Fortinet private |
| 16 | 28673 | `0x7001` | SAVE_PASSWD | 0 | **PROVEN** hardcoded + iked | Fortinet / UNITY_SAVE_PASSWD |

Linux `CPRQ(ADDR DNS)` is the stock strongSwan pair (types 1 and 3).
Those stay in this list; do not duplicate them. iked `wrong size … size:
0` is the client’s own encoder complaining about empty values, not a
FortiGate error. Live CP16 A/B is **VALID NEGATIVE** (§12.13): exact
types/order present, **not sufficient**.

#### IDi comparison

| Client | Golden | Linux |
| ------ | ------ | ----- |
| Type | `ID_IPV4_ADDR` (**PROVEN** iked) | Present; SK next payload `IDi` (**PROVEN** pcap). Type/value **UNKNOWN** from pcap (encrypted). |
| swanctl | FortiClient uses the client IPv4 | `local-psk` has empty `id` ⇒ strongSwan 5.9.13 uses the local address (**STRONG EVIDENCE**, not pcap-proven) |

Do not change IDi yet.

#### `EAP_ONLY` / `MSG_ID_SYN_SUP`

| Notify | Golden | Linux |
| ------ | ------ | ----- |
| `N(EAP_ONLY)` 16417 | **Absent** (**STRONG EVIDENCE**: no `0x4021` immediate in `ipsec.exe`; construction sends `INITIAL_CONTACT` instead) | **Present** (**PROVEN** charon + `ike_auth.c`) |
| `N(MSG_ID_SYN_SUP)` 16420 | **Absent** (**STRONG EVIDENCE**: no `0x4024` in `ipsec.exe`) | **Present** (**PROVEN**) |
| `N(INITIAL_CONTACT)` 16384 | **Present**, empty, length 8 | **Absent** |

Whether FortiGate silently drops because of `EAP_ONLY` on a mixed
PSK+EAP `AUTH` is **HYPOTHESIS**. Do not stack an `EAP_ONLY` change
with the license Notify.

#### Ranking remaining differences (protocol proximity to the unanswered first `IKE_AUTH`)

CP16, `0xF100` presence, and `0xF100` ordering (AUTH present) are
**VALID NEGATIVE**. Initiator AUTH on first `IKE_AUTH` is **LIVE
POSITIVE** to omit (§12.17). Next isolated A/B is EAP-only local
authentication so CHILD_CREATE waits for EAP (§12.18). Do **not**
stack another compatibility mutation.

#### Next isolated A/B

EAP-only local authentication plus remote PSK (§12.18). Keep AUTH
omission, ordered Notify `0xF100`, and CP16. Do **not** claim this
config is required until a valid live result.

#### FCT_UID log redaction

strongSwan 5.9.13 `vici_cred.c` logs
`loaded %N shared key with id '%s' for: %s` (owners already quoted).
The previous redaction pattern expected `eap shared key 'eap' for`
without `with id` / `for:`. Live charon therefore leaked `<FCT_UID>`.
Minimal fix: also match `shared key with id '…' for:`. Identities stay
out of this document.

### 12.5 `GenRawLicenseInfo2` was blocked; `N(EAP_ONLY)` reassessment

This section records the earlier search for `utilsdll.dll` and a
strongSwan 5.9.13 re-read of `EAP_ONLY` / `MSG_ID_SYN_SUP`. No IKE
payloads were changed here. The official DLL copy later arrived; the
`GenRawLicenseInfo2` analysis is §12.9.

#### `utilsdll.dll` was not available (**PROVEN** absence at the time)

Searched `.research-binaries/`, the working tree, `~/Downloads`, and
other local research inputs. Only these FortiClient 7.4.8.2066 copies
are present:

- `ipsec.exe`
- `FortiAuth.dll`

`utilsdll.dll` is **not** there. No unofficial download was attempted.
`GenRawLicenseInfo2` internals are therefore **not analyzed**. Do not
infer field grammar from the export name.

`ipsec.exe` imports **`utilsdll.dll!GenRawLicenseInfo2` by name** (IAT,
not an ordinal). Windows loads that DLL from the same directory as
`ipsec.exe` unless a private search path is set. On a default
FortiClient **7.4.8.2066** install that path is:

```
C:\Program Files\Fortinet\FortiClient\utilsdll.dll
```

Copy **only** that file (same build as the existing `ipsec.exe`) into
git-excluded `.research-binaries/`. The directory is listed in
`.gitignore` and must never be staged.

Until that copy exists, claims about static vs machine vs license vs
`<FCT_UID>` vs cryptographic contents of Notify `0xF100` remain
**UNKNOWN**. The copy later arrived; those claims are answered in
§12.9. This subsection is the absence record only.

Caller-side contract already recovered from `ipsec.exe` (not from the
DLL body; **STRONG EVIDENCE**, previous §12.4):

- wrapper `0x1400ce450` calls the import with RCX = address of an
  output pointer and EDX = 0
- AL is treated as a boolean; failure logs `Failed to get license info`
- success path takes `strlen` of the returned pointer and copies
  `strlen+1` bytes (C string plus NUL) into notify data
- the buffer is `free`d after the copy, so the callee allocates

That does **not** prove the DLL’s full signature, inputs, or grammar.

#### Session comparison of the blob itself

iked logs `licence info size: 270` on every traced session (success and
failure). That is **STRONG EVIDENCE** the **length** is stable for this
install. The **bytes** were never logged and the golden `IKE_AUTH` is
SK-encrypted, so whether the blob is identical across reconnects is
**UNKNOWN**. Do not print captured license bytes.

Smallest later instrumentation (done in §12.9): copy official
`utilsdll.dll` and reverse `GenRawLicenseInfo2`. Alternative still
valid: decrypt one golden `IKE_AUTH` **offline** with the tunnel PSK,
hash the 271-byte field, compare hashes across sessions, and discard
the plaintext. Never commit the plaintext.

#### FortiGate and Notify `0xF100`

Existing FortiGate console dumps for the golden sessions log
`FCT EAP 2FA extension vendor ID received` at the moment EAP starts.
That string refers to the Forticlient EAP Extension **Vendor ID** on
`IKE_SA_INIT` (**STRONG EVIDENCE**, §4), not Notify `0xF100`.

No FortiGate line in the researched dumps mentions notify type
`0xF100` / 61696, “licence info”, or validation of that payload.

| Claim | Label |
| ----- | ----- |
| FortiClient sends Notify `0xF100` on first `IKE_AUTH` | **PROVEN** (§12.4) |
| FortiGate **requires** `0xF100` | **UNKNOWN** (not proven; VID-only drop already falsified) |
| FortiGate **validates the contents** of `0xF100` | **UNKNOWN** (no FortiGate evidence) |

A dummy 270-character placeholder is **not** a scientifically useful
next live A/B while content validation is an open possibility.

#### `N(EAP_ONLY)` can be stripped without changing PSK+EAP

strongSwan 5.9.13 `ike_auth.c` `build_i()` **always** adds empty
`N(EAP_ONLY_AUTHENTICATION)` (16417) and
`N(IKEV2_MESSAGE_ID_SYNC_SUPPORTED)` (16420) on the **first** initiator
`IKE_AUTH`. This is a capability advertisement, not a switch to
EAP-only authentication. Mixed `local-psk` + `local-eap` still emits
PSK `AUTH` and then the EAP round.

The only related setting is `charon.force_eap_only_authentication`
(default no). It is a **responder** knob: violate RFC 5998 and accept
EAP-only when the peer omitted the notify. It does **not** stop the
initiator from sending `N(EAP_ONLY)`. There is **no** swanctl/charon
key to suppress initiator `EAP_ONLY` or `MSG_ID_SYN_SUP`.

Omitting PSK `AUTH` (true EAP-only) **would** change the authentication
model and is **not** a valid isolated experiment. Removing only the
empty `N(EAP_ONLY)` payload **would not**.

`N(MSG_ID_SYN_SUP)` is the same class of unconditional capability
notify. It can be stripped independently by the same mechanism. Do not
strip both in one A/B relative to the VID baseline.

Implementation surface for **`N(EAP_ONLY)` only** is §12.6 (live A/B
**PROVEN** / **FALSIFIED as sole cause**). The follow-on
`N(MSG_ID_SYN_SUP)` A/B is §12.7, stacked only after EAP_ONLY was
already falsified as sole cause.

### 12.6 `N(EAP_ONLY)` suppression A/B (**PROVEN** removal; **FALSIFIED** as sole cause)

**Status: live A/B complete (`/tmp/fvl-no-eap-only.pcap`).** Do **not**
claim that `N(EAP_ONLY)` caused the silent first-`IKE_AUTH` drop. The
controlled result is narrower.

#### Experiment design

One protocol variable relative to the proven VID A/B baseline (§12.3):

| Kept | Changed |
| ---- | ------- |
| Three FortiClient Vendor IDs on `IKE_SA_INIT` | Remove `N(EAP_ONLY)` / type **16417** / `0x4021` from the **first outbound initiator `IKE_AUTH` request** (message ID 1) |
| PSK `AUTH` on first `IKE_AUTH` | |
| Second local EAP-MSCHAPv2 (`eap_id` = `<FCT_UID>`, password = tokenid) | |
| IDi, CP(ADDR DNS), SA, TSi, TSr | |
| `N(MSG_ID_SYN_SUP)` / type 16420 | |
| Proposals, NAT-T, UDP/500 → UDP/4500, Mode Config, CHILD_SA | |

Do **not** add in this experiment: Notify `0xF100`, `INITIAL_CONTACT`,
Fortinet CP attributes, extra proposals, or direct UDP/4500 initiation.

#### Implementation mechanism

The existing application-owned private-charon plugin
`fvl-forticlient-vid` was **extended** (not a sibling plugin). One
fail-closed load gate covers both:

1. add the three golden FortiClient Vendor IDs on outbound initiator
   `IKE_SA_INIT`
2. remove `N(EAP_ONLY)` from the first outbound initiator `IKE_AUTH`

strongSwan **5.9.13** APIs used (headers only; distro charon is not
patched):

- `listener_t.message(listener, ike_sa, message, incoming, plain)`
- invoked twice per message; the hook acts only when `incoming == FALSE`
  and `plain == TRUE` (plaintext payload list, before encryption)
- then requires IKEv2 major version, request flag, `IKE_AUTH`, and
  `message->get_message_id() == 1`
- `message->create_payload_enumerator()`; if payload type is
  `PLV2_NOTIFY` and `notify->get_notify_type() == EAP_ONLY_AUTHENTICATION`
  (16417), call `message->remove_payload_at(message, enumerator)` then
  `payload->destroy(payload)` (5.9.13 `remove_payload_at` unlinks and
  does **not** free the payload)

`N(MSG_ID_SYN_SUP)` / `IKEV2_MESSAGE_ID_SYNC_SUPPORTED` (16420) was
**not** removed in this A/B. Plugin load remains `load = yes` only in
`/run/charon.fvl.conf` for the v1.3 IKEv2 + EAP private runtime. No
`/etc/strongswan.d/charon/fvl-forticlient-vid.conf`. Missing plugin on
the live IKEv2 SSO path fails closed before charon starts.

Diagnostic (non-secret): `FortiClient compatibility: removed EAP_ONLY
from first IKE_AUTH`. The existing vici line
`loaded EAP shared key with id 'eap' for: '<FCT_UID>'` stays redacted.

#### Live result (**PROVEN**, `/tmp/fvl-no-eap-only.pcap`)

Private charon loaded the compatibility plugin. `IKE_SA_INIT` stayed
364 bytes with the three exact FortiClient Vendor IDs; FortiGate
answered it.

Charon generated first `IKE_AUTH` request 1 as
`IDi AUTH CPRQ(ADDR DNS) SA TSi TSr N(MSG_ID_SYN_SUP)` — **no**
`N(EAP_ONLY)`. IKE length **240 bytes** (was 256 with `EAP_ONLY`).
PSK `AUTH` remained. `N(MSG_ID_SYN_SUP)` remained.

FortiGate sent **no** UDP/4500 response to message ID 1. Linux
retransmitted the same 240-byte request until timeout. EAP did not
start.

| Claim | Label |
| ----- | ----- |
| `N(EAP_ONLY)` was removed from first Linux `IKE_AUTH` | **PROVEN** |
| First `IKE_AUTH` IKE length 256 → 240 | **PROVEN** |
| PSK `AUTH` still present | **PROVEN** |
| `N(MSG_ID_SYN_SUP)` still present | **PROVEN** |
| Three FortiClient VIDs still on `IKE_SA_INIT` | **PROVEN** |
| FortiGate silently ignored first `IKE_AUTH` after this change | **PROVEN** |
| EAP started | **FALSIFIED** (did not start) |
| `N(EAP_ONLY)` is the **sole** cause of the silent drop | **FALSIFIED** |

Do not claim that `EAP_ONLY` is irrelevant on other gateways, or that
any remaining Linux/golden difference is proven as the cause.

#### Tests

`tests/test_ipsec_forticlient_vid.py` (and related SAML backend /
redaction tests) covered: notify type 16417; first outbound initiator
`IKE_AUTH` scope; `MSG_ID_SYN_SUP` left unmodified for this A/B;
`IKE_SA_INIT` VIDs unchanged; IKEv1 PSK/XAuth, SSL VPN, and non-SSO
IPsec do not load the plugin; private-charon isolation; fail-closed
when the plugin is missing; no credential / `<FCT_UID>` leakage in
diagnostics.

### 12.7 `N(MSG_ID_SYN_SUP)` suppression A/B (**PROVEN** removal; **FALSIFIED** as additional blocker)

**Status: live A/B complete (`/tmp/fvl-no-msg-id-syn.pcap`).** Do **not**
claim that `N(MSG_ID_SYN_SUP)` caused the silent first-`IKE_AUTH` drop.
The controlled result is narrower: it is not the additional blocker on
the §12.6 EAP_ONLY-negative baseline.

#### Experiment design

| Kept from §12.6 baseline | Changed |
| ------------------------ | ------- |
| Three FortiClient VIDs on `IKE_SA_INIT` (364-byte, FortiGate answers) | Remove `N(MSG_ID_SYN_SUP)` from first initiator `IKE_AUTH` (message ID 1) |
| Absence of `N(EAP_ONLY)` | |
| PSK `AUTH`, EAP-MSCHAPv2, IDi, CP(ADDR DNS), SA, TSi, TSr | |
| Proposals, NAT-T, UDP/500 → UDP/4500, Mode Config, CHILD_SA | |

Expected first `IKE_AUTH` generating line:

`IDi AUTH CPRQ(ADDR DNS) SA TSi TSr`

with neither `N(EAP_ONLY)` nor `N(MSG_ID_SYN_SUP)`.

Do **not** add Notify `0xF100`, `INITIAL_CONTACT`, Fortinet CP
attributes, extra proposals, or direct UDP/4500 initiation.

#### Implementation mechanism

Same `fvl-forticlient-vid` plugin and `listener_t.message()` hook as
§12.6. On outbound plaintext IKEv2 initiator `IKE_AUTH` message ID 1,
also `remove_payload_at()` for `PLV2_NOTIFY` type
`IKEV2_MESSAGE_ID_SYNC_SUPPORTED` (16420), then `payload->destroy()`.
EAP_ONLY removal stays. AUTH / CP / SA / TS / IDi are not modified.

Diagnostic (non-secret): `FortiClient compatibility: removed
MSG_ID_SYN_SUP from first IKE_AUTH`. Fail-closed and private-charon
isolation are unchanged.

#### Live result (**PROVEN**, `/tmp/fvl-no-msg-id-syn.pcap`)

Private charon loaded `fvl-forticlient-vid`. SAML pre-auth succeeded.
`IKE_SA_INIT` stayed 364 bytes with the three exact FortiClient Vendor
IDs; FortiGate answered 264 bytes on UDP/500.

Plugin logs: removed EAP_ONLY and MSG_ID_SYN_SUP from first `IKE_AUTH`.
Charon generated request 1 as
`IDi AUTH CPRQ(ADDR DNS) SA TSi TSr` — **no** `N(EAP_ONLY)`, **no**
`N(MSG_ID_SYN_SUP)`. PSK `AUTH` remained (`authentication of … with
pre-shared key`). Local EAP-MSCHAPv2 was still configured; EAP never
started.

Linux sent that `IKE_AUTH` on UDP/4500, IKE length **240 bytes**
(same SK ciphertext length as §12.6; AES-CBC padding can absorb an
8-byte plaintext notify without shrinking the packet). Five initiator
copies, zero FortiGate UDP/4500 replies, then NAT keepalive and
swanctl timeout. EAP did not start. CHILD_SA was not established.

| Claim | Label |
| ----- | ----- |
| `N(MSG_ID_SYN_SUP)` was removed from first Linux `IKE_AUTH` | **PROVEN** |
| `N(EAP_ONLY)` stayed absent | **PROVEN** |
| PSK `AUTH` still present | **PROVEN** |
| Three FortiClient VIDs still on `IKE_SA_INIT` | **PROVEN** |
| FortiGate silently ignored first `IKE_AUTH` after this change | **PROVEN** |
| EAP started | **FALSIFIED** (did not start) |
| `N(MSG_ID_SYN_SUP)` is the additional blocker on the §12.6 baseline | **FALSIFIED** |

Do not claim the remaining Linux/golden first-`IKE_AUTH` differences
are proven as the cause. Do not automatically implement another
difference from this result.

### 12.8 `N(INITIAL_CONTACT)` add A/B (**PROVEN** add; **FALSIFIED** as sufficient)

**Status: live A/B complete (`/tmp/fvl-initial-contact.pcap`).** Do
**not** describe `INITIAL_CONTACT` as required by FortiGate. The
controlled result is narrower: adding it is **not sufficient** for a
first-`IKE_AUTH` reply on the §12.7 baseline.

#### Experiment design

One additional variable on the §12.7 baseline (EAP_ONLY and
MSG_ID_SYN_SUP already absent):

| Kept | Changed |
| ---- | ------- |
| Three FortiClient VIDs on `IKE_SA_INIT` (364-byte, FortiGate answers) | Add one empty IKEv2 `N(INITIAL_CONTACT)` / type **16384** / `0x4000` to first initiator `IKE_AUTH` (message ID 1) |
| Absence of `N(EAP_ONLY)` and `N(MSG_ID_SYN_SUP)` | |
| PSK `AUTH`, EAP-MSCHAPv2, IDi, CP(ADDR DNS), SA, TSi, TSr | |
| Proposals, NAT-T, UDP/500 → UDP/4500, Mode Config, CHILD_SA | |

Expected charon generating line (short notify name from 5.9.13
`notify_type_short_names`):

`IDi AUTH CPRQ(ADDR DNS) SA TSi TSr N(INIT_CONTACT)`

with neither `N(EAP_ONLY)` nor `N(MSG_ID_SYN_SUP)`.

Do **not** add Notify `0xF100`, Fortinet CP attributes, extra
proposals, or direct UDP/4500 initiation.

#### Implementation mechanism

Same `fvl-forticlient-vid` plugin and `listener_t.message()` hook.
Verified against local strongSwan **5.9.13** headers/source:

- constant `INITIAL_CONTACT = 16384` in `notify_payload.h`
- `PROTO_NONE = 0` in `proposal.h`
- create: `notify_payload_create_from_protocol_and_type(PLV2_NOTIFY, PROTO_NONE, INITIAL_CONTACT)` (protocol ID 0, SPI size 0, empty notify data)
- add: `message->add_payload()` takes ownership; do not destroy the payload
- duplicate guard: enumerate `PLV2_NOTIFY` and skip if type is already `INITIAL_CONTACT`

EAP_ONLY and MSG_ID_SYN_SUP removals stay. AUTH / CP / SA / TS / IDi
are not modified. Plugin load and fail-closed isolation are unchanged.

Diagnostic (non-secret): `FortiClient compatibility: added
INITIAL_CONTACT to first IKE_AUTH`.

#### Tests

`tests/test_ipsec_forticlient_vid.py` (and related SAML backend /
redaction tests) cover: verified 5.9.13 `INITIAL_CONTACT = 16384`;
empty notify created with `PROTO_NONE` and added only to first
outbound initiator `IKE_AUTH`; duplicate `INITIAL_CONTACT` is not
added; `EAP_ONLY` and `MSG_ID_SYN_SUP` remain removed; AUTH is not
modified; three `IKE_SA_INIT` Vendor IDs unchanged; IKEv1, SSL, and
non-SSO IPsec do not load the plugin; private-charon isolation;
fail-closed when the plugin is missing; no secret leakage.

#### Live result (**PROVEN**, `/tmp/fvl-initial-contact.pcap`)

| Claim | Label |
| ----- | ----- |
| `N(INITIAL_CONTACT)` was added to first Linux `IKE_AUTH` | **PROVEN** |
| `N(EAP_ONLY)` stayed absent | **PROVEN** |
| `N(MSG_ID_SYN_SUP)` stayed absent | **PROVEN** |
| PSK `AUTH` still present | **PROVEN** |
| Three FortiClient VIDs still on `IKE_SA_INIT` | **PROVEN** |
| FortiGate answered `IKE_SA_INIT` | **PROVEN** |
| FortiGate silently ignored first `IKE_AUTH` after this change | **PROVEN** |
| EAP started | **FALSIFIED** (did not start) |
| `N(INITIAL_CONTACT)` is sufficient for a first-`IKE_AUTH` reply on the §12.7 baseline | **FALSIFIED** |

Do not claim the remaining Linux/golden first-`IKE_AUTH` differences
are proven as the cause. Do not automatically implement another
difference from this result. Notify `0xF100` is **not** implemented
here; its construction is research-only in §12.9.

### 12.9 `utilsdll.dll` / `GenRawLicenseInfo2` (static analysis)

**Status: official binary present; static analysis recorded.** Do **not**
claim FortiGate requires Notify `0xF100` or validates these fields.
Do **not** implement `0xF100` from this section.

#### Binary identification (**PROVEN**)

| Field | Value |
| ----- | ----- |
| Path on Windows | `C:\Program Files\Fortinet\FortiClient\utilsdll.dll` (x64; x86 copy not used) |
| Research copy | git-excluded `.research-binaries/utilsdll.dll` (`.gitignore` line `.research-binaries/`) |
| SHA256 | `96578a6ecf4a09e89122423ca4cd56fadb061c799c186753192d90a882afa459` |
| Size | 3,477,176 bytes |
| PE | PE32+ x86-64 (`IMAGE_FILE_MACHINE_AMD64`), ImageBase `0x180000000` |
| File / product version | **7.4.8.2066** (`FileDescription` = utility library; `ProductName` = FortiClient support library) |
| Company | Fortinet Inc. |

`sha256sum` of the research copy matches the value above. The file is
ignored by git. Do not copy it into docs, tests, fixtures, or release
assets.

#### Export (**PROVEN**)

| Field | Value |
| ----- | ----- |
| Name | `GenRawLicenseInfo2` (exported **by name**) |
| Ordinal | 237 (export table Base = 1) |
| RVA | `0xd5d00` |
| VA | `0x1800d5d00` |

Sibling exports on the same path: `GenRawLicenseInfo` (ordinal 236,
RVA `0xd5a80`) and `GenLicenseInfo` (ordinal 235, RVA `0xd5640`).
`GenRawLicenseInfo2` is **not** a wrapper around `GenRawLicenseInfo`;
both independently call the same internal builder at `0x1800d4610`.
`GenLicenseInfo` also calls that builder, then wraps the result with
MD5 / `"Forticlient Connect License"` (**PROVEN** string xref).
`ikev2_init_ike_auth` imports **`GenRawLicenseInfo2`**, not
`GenLicenseInfo`.

Related nearby names (not in the `0xF100` data path unless noted):
`DecodeLicenseResult`, `cfg_get_forticlient_guid` (**is** in the path),
`cfg_get_forticlient_guid_raw`, `GenerateUIDW` / `GenerateUIDA`,
`getStoredCredentials`, `getMacAddresses`.

#### Verified signature (**PROVEN** against the DLL body)

Windows x64: RCX = first argument, RDX = second, AL = integer return.

Caller-side claims from `ipsec.exe` (§12.4) hold and are **corrected**
on one point:

```
BOOL GenRawLicenseInfo2(char **out, char const *user_or_null);
```

1. `out` must be non-NULL. If RCX is NULL the function returns `AL = 0`
   and writes nothing.
2. The second argument is a **C-string pointer**, not an integer format
   flag. `ipsec.exe` passing `EDX = 0` is a **NULL username**.
3. On success `*out` is a `malloc`'d NUL-terminated C string and `AL = 1`.
4. On malloc failure `AL = 0`.
5. The caller must `free(*out)` with the UCRT `free` (same heap the DLL
   used). That matches `ipsec.exe` freeing the buffer.

When `user_or_null` is NULL the function fills USER from a Terminal
Services session (`getStoredCredentials` / `GetTSSessionUserName`).
When it is non-NULL, that pointer is copied as the USER source. The
export name `getStoredCredentials` is **misleading**: the body
enumerates TS sessions and copies a username; it does not read a
password store (**PROVEN**).

#### Call graph (IKE Notify `0xF100` path)

```
ipsec.exe!ikev2_init_ike_auth
  -> wrapper
     -> utilsdll!GenRawLicenseInfo2(&out, NULL)
          -> getStoredCredentials / GetTSSessionUserName   (USER source)
          -> builder 0x1800d4610(std::string&, username)
               -> cfg_get_forticlient_guid -> cfg_get_forticlient_guid_raw
               -> WS2_32 gethostname / gethostbyname / inet_ntoa
               -> getMacAddresses -> IPHLPAPI GetAdaptersInfo
               -> KERNEL32 GetComputerNameExA (NameType=1 DnsHostname)
               -> os_get_name + WideCharToMultiByte
               -> registry FA_ESNAC (optional EMS / registration fields)
          -> malloc(len+1); memcpy; *out = ptr
     -> strlen(out); copy strlen+1 into Notify 0xF100; free(out)
```

No AES, SHA, MD5, HMAC, RSA, BCrypt, DPAPI, JSON, XML, base64, or
compression call appears on this graph. The DLL **imports** libcrypto /
CRYPT32 / FCCryptDLL, but those imports are **not** reached from
`GenRawLicenseInfo2` (**PROVEN** call list). Do not infer crypto from
the import table.

#### Output construction (**PROVEN** format; values redacted)

The builder assigns/appends into an MSVC `std::string` (`append` helper
at `0x180009d30`). Result is **structured plaintext**, newline-separated
`KEY=value` lines. Placeholders only:

```
VER=1
FCTVER=7.4.8.2066
UID=<FCT_UID>
IP=<IPv4>
MAC=<MAC>
HOST=<DNS_HOSTNAME>
USER=<SESSION_USER>
OSVER=<OS_NAME>
REG_STATUS=0
```

Optional extra lines if registry values exist under
`software\Fortinet\FortiClient\FA_ESNAC` (**PROVEN** key string):

| Line | Source | Notes |
| ---- | ------ | ----- |
| `EMSSN=<LICENSE_FIELD>` | registry `fgt_sn` (second `;`-token, wchar→char) | omitted if absent |
| `EMSID=<LICENSE_FIELD>` | registry `tenantid` | omitted if absent |
| `FCTTAGS=1` | registry `ztna_token` **present** | token **value is not appended** (**PROVEN**); only the flag line is |
| `REG_PASSWD=<LICENSE_FIELD>` | registry `corporate_id` (`;`-token) | omitted if absent |

If the FA_ESNAC key cannot be opened, the builder appends the literal
`REG_STATUS=0\n` (**PROVEN** string). In the `fgt_sn` present path it
appends `REG_STATUS=` then the literal ASCII `0\n`. `_wtoi` and
`_time64` are **called** but the appended status character is still
the literal `0` (**PROVEN**). Whether those calls were meant as an
expiry comparison with a dead store is **UNKNOWN**.

Separators are a single ASCII LF (`0x0A`) after **every** field,
including the last analyzed field. **PROVEN**: the UTF-16 `L"\n"`
low byte is appended; there is **no** `0x0D` (CR) in the builder.
Not JSON, not XML, not hex, not base64.

Exact field formatting recovered from the builder at `0x1800d4610`
and callees (**PROVEN** unless noted):

| Topic | Value |
| ----- | ----- |
| Field order | `VER`, `FCTVER`, `UID`, `IP`, `MAC`, `HOST`, `USER`, `OSVER`, `REG_STATUS`, then optional `EMSSN` / `EMSID` / `FCTTAGS` / `REG_PASSWD` |
| Line shape | ASCII `KEY=` then value then LF |
| Separator | LF only (not CRLF) |
| Trailing LF | yes on every field including `REG_STATUS` and each optional EMS line that is emitted |
| `VER` | literal `1` |
| `FCTVER` | literal `7.4.8.2066` (this DLL) |
| `UID` | FCT_UID GUID string after `iswalnum` filter (braces and hyphens stripped) |
| `IP` | `inet_ntoa` dotted IPv4 of the first `gethostbyname` `h_addr_list` entry; empty value if that lookup fails |
| `MAC` | per adapter `sprintf(..., "%.2x-%.2x-%.2x-%.2x-%.2x-%.2x;", bytes[0..5])` — lowercase hex, hyphen-separated, **trailing semicolon**; adapters concatenated; empty `MAC=` if none pass the filter |
| `HOST` | `GetComputerNameExA(ComputerNameDnsHostname)` |
| `USER` | second argument if non-NULL, else `WTSQuerySessionInformationA` `WTSUserName` |
| `OSVER` | ACP conversion of `os_get_name()` UTF-16 (**exact string UNKNOWN** without runtime) |
| `REG_STATUS` | literal `0` in both analyzed branches |
| Optional EMS | omitted entirely if the registry value is absent; `FCTTAGS=1` is a presence flag (token value not copied) |
| Final NUL | **not** in the builder buffer; `GenRawLicenseInfo2` `malloc(len+1)` + memcpy of `len` bytes leaves a C-string NUL; `ipsec.exe` copies `strlen+1` onto the wire |

MAC adapters skipped (**PROVEN** Description prefixes / OUI):
`VMware`, `VirtualBox`, `fortissl`; Fortinet virtual MACs
`00-09-0F-09-00-01` and `00-09-0F-FE-00-01`. Which remaining
physical adapter(s) appear on a given host is **UNKNOWN**.

Length is **variable** (hostname, USER, OS name, optional EMS lines).
iked `licence info size: 270` remains **STRONG EVIDENCE** that this
install’s concatenation is 270 characters (plus the caller’s extra
NUL on the wire).

#### Fields / data sources

| Field | Static vs per-call | Source |
| ----- | ------------------ | ------ |
| `VER` | static in this build | literal `1` |
| `FCTVER` | static per FortiClient build | literal `7.4.8.2066` in `.rdata` |
| `UID` | per installation | `cfg_get_forticlient_guid`: registry `FA_UI` / CLSID `AppID`, else `GenerateUIDW`; then **alphanumeric-only** filter (`iswalnum`) so braces/hyphens are stripped |
| `IP` | per invocation | `gethostname` → `gethostbyname` → `inet_ntoa` (first IPv4) |
| `MAC` | per machine (adapter list) | `GetAdaptersInfo` |
| `HOST` | per machine | `GetComputerNameExA(ComputerNameDnsHostname)` |
| `USER` | per session / call | arg2, else TS session username |
| `OSVER` | per OS | `os_get_name` |
| `REG_STATUS` | see above | literal `0` in analyzed paths |
| EMS / tags / `REG_PASSWD` | per EMS registration | FA_ESNAC registry |

#### Does `<FCT_UID>` participate?

**Yes (PROVEN).** The `UID=` value is the alphanumeric-filtered
FortiClient GUID from `cfg_get_forticlient_guid`. That is the same
export already identified as the source of `<FCT_UID>` for EAP
identity. Do not write real GUID bytes here.

#### Second argument (`EDX = 0`)

**PROVEN:** NULL optional username. It does **not** switch encoding,
encryption, or a v1/v2 blob format. `GenRawLicenseInfo` vs
`GenRawLicenseInfo2` are separate exports that share the builder;
the `2` is the export name, not the second-argument value.

#### Allocator / NUL

**PROVEN:** `malloc(length + 1)`, zero-fill, `memcpy` of `length`
bytes, store in `*out`. Extra byte is a NUL produced by the DLL.
`ipsec.exe` then `strlen` + copy `strlen + 1` into Notify data, so
the **wire NUL is caller behavior** on top of an already
NUL-terminated C string. Treat the 271-byte notify data as 270
payload characters plus that copied NUL (§12.4).

#### Crypto / encoding actually in the data path

| Operation | In `GenRawLicenseInfo2` path? |
| --------- | ----------------------------- |
| Plaintext `KEY=value` append | **PROVEN** |
| `WideCharToMultiByte` | **PROVEN** (GUID, OS name, some registry values) |
| `strlen` / `memcpy` / `malloc` / `free` | **PROVEN** |
| AES / SHA* / MD5 / HMAC / RSA / ECDSA | **not in this path** |
| Base64 / JSON / XML / compression | **not in this path** |
| Windows CryptoAPI / BCrypt / DPAPI | **not in this path** |

`GenLicenseInfo` **does** use MD5-family helpers and the string
`"Forticlient Connect License"` after the same builder. That is a
**different export**, not the IKE Notify body.

#### Safe dynamic analysis (harness in tree; not executed here)

Do **not** run this DLL under Wine for the golden blob: Wine would
not see the same FortiClient registry / TS session / adapters, so
`UID=` / `USER=` / `MAC=` / `HOST=` would differ.

A Windows x64 harness lives at
`tools/research/windows/dump-license-info.cpp`. It
`LoadLibraryW`s the official installed
`C:\Program Files\Fortinet\FortiClient\utilsdll.dll`,
`GetProcAddress("GenRawLicenseInfo2")`, and calls
`GenRawLicenseInfo2(&out, nullptr)`. It writes `strlen+1` bytes
(including NUL) to gitignored `license-info.raw` and prints KEY
names only. It does not print values, does not implement Notify
`0xF100`, and does not change Linux VPN behavior.

Harness CRT `free()` is **not** used: `utilsdll.dll` allocates with
UCRT `malloc` (**PROVEN**). Default `cl` without `/MD` uses the
static CRT; MinGW typically uses `msvcrt`. The harness resolves
`ucrtbase.dll!free` after the DLL is loaded, or leaves the one
allocation until process exit.

The official DLL may locally resolve the hostname while filling
`IP=` (§12.9). The harness itself does not open sockets, write
the registry, start services, or invoke `ipsec.exe`.

Do not leak `<FCT_UID>`, hostnames, MACs, or EMS identifiers into
git-tracked files. Do not paste `license-info.raw`. Live byte
representation remains **UNKNOWN** until that gitignored file is
produced on the FortiClient machine.

#### Remaining UNKNOWNs

- Whether FortiGate **requires** Notify `0xF100` at all
- Whether FortiGate **parses** these `KEY=value` fields
- Whether FortiGate compares `UID=` to the EAP `<FCT_UID>`
- Exact `os_get_name` / `OSVER=` string
- Which physical adapter(s) survive the MAC filter on this host
- Whether `REG_STATUS` is ever not `0` in some license state
- Byte-identity of the blob across reconnects (length is stable;
  contents not logged)
- Whether a Linux-synthesized inventory with local hostname/MAC/UID
  would be accepted (not tested; not approved here)

Do not implement Notify `0xF100` or generate a fake license blob from
this research pass.

### 12.10 Windows `GenRawLicenseInfo2` harness (CODE; live dump pending)

**Status: source in tree; compiled on Windows; LoadLibrary did not
succeed (see §12.11).**
Methodology only. No real blob is recorded here.

Build and run on the FortiClient x64 install as documented in
`tools/research/windows/README.md`. Expected artifacts on that
machine: `dump-license-info.exe`, `license-info.raw`. Needed back
from that run if LoadLibrary ever succeeds: harness stdout (keys /
counts only), file `Length`, and SHA256. Not the file contents.

The harness now prints `FormatMessageW`, host exe path, cwd,
read-only `INSTALLDIR` prefix check, and `GetFileAttributesW`
existence of the four private sibling DLLs on failure. It still
does **not** change the DLL search path, `LoadLibrary` those
siblings, or copy files into the FortiClient directory.

Notify `0xF100` remains unimplemented.

### 12.11 Standalone `LoadLibraryW` of `utilsdll.dll` (PROVEN fail)

SHA256 of `.research-binaries/utilsdll.dll` and of the official
`C:\Program Files\Fortinet\FortiClient\utilsdll.dll` remained
`96578a6ecf4a09e89122423ca4cd56fadb061c799c186753192d90a882afa459`.

#### Live LoadLibrary results (PROVEN)

| cwd | Result | `GetLastError` | Meaning |
| --- | ------ | -------------- | ------- |
| Downloads (harness location) | `LoadLibraryW` failed | `126` | `ERROR_MOD_NOT_FOUND` |
| `C:\Program Files\Fortinet\FortiClient` | `LoadLibraryW` failed | `1114` | `ERROR_DLL_INIT_FAILED` |

`126` then `1114` is the expected two-step: first the private
dependencies are not on the search path; then they are found via
cwd, but `DllMain` returns FALSE.

#### Import table (PROVEN)

PE32+ import directory (49 DLLs); no delay-load directory.

**Windows / system** (32 names excluding the four Fortinet/OpenSSL
siblings and the MSVC/UCRT runtime set):

`KERNEL32.dll` (204), `ADVAPI32.dll` (97), `WS2_32.dll` (35),
`CRYPT32.dll` (29), `USER32.dll` (21), `IPHLPAPI.DLL` (12),
`ole32.dll` (14), `OLEAUT32.dll` (12), `GDI32.dll` (9),
`SHLWAPI.dll` (8), `msi.dll` (7), `USERENV.dll` (6),
`SHELL32.dll` (5), `WTSAPI32.dll` (5), `RstrtMgr.DLL` (4),
`VERSION.dll` (4), `PSAPI.DLL` (3), `ncrypt.dll` (3),
`RASAPI32.dll` (3), `NETAPI32.dll` (2), `imagehlp.dll` (2),
`COMDLG32.dll` (2), `MPR.dll` (2), `api-ms-win-core-path-l1-1-0.dll` (2),
`Secur32.dll` (1), `RPCRT4.dll` (1), `CRYPTUI.dll` (1),
`WININET.dll` (1), `SETUPAPI.dll` (1), `dhcpcsvc.DLL` (1),
`dbghelp.dll` (1), `gdiplus.dll` (18).

License-info builder uses `KERNEL32`, `ADVAPI32`, `WS2_32`,
`IPHLPAPI`, and `WTSAPI32` from this set. The rest are other
utilsdll surfaces.

**Runtime**

| Module | Notes |
| ------ | ----- |
| `MSVCP140.dll` | MSVC C++ (181) |
| `VCRUNTIME140.dll`, `VCRUNTIME140_1.dll` | MSVC CRT |
| `api-ms-win-crt-runtime/heap/filesystem/stdio/string/convert/time/math/locale/utility-l1-1-0.dll` | UCRT |

**Fortinet / private (same directory as `utilsdll.dll`)**

| Module | Import count | Imported names |
| ------ | ------------ | -------------- |
| `FCCryptDLL.dll` | 15 | `FccFipsSetFipsModeEnabled`, `FccFipsIsFipsModeEnabled`, `FccGetRandomBytes`, `FccDeriveKey`, `FccDrbgInit` / `FccDrbgCleanup` / `FccDrbgGetRandBytes`, HMAC/AES/X509 helpers |
| `FortiVpnDll2.dll` | 5 | `VpnConn_Lock`, `VpnConn_Unlock`, `VpnConnInfo_Enum`, `VpnConnInfo_Free`, `VpnConnInfo_GetConnectionState` |
| `libssl-3-x64.dll` | 3 | `SSL_CTX_use_RSAPrivateKey`, `SSL_CTX_use_certificate`, `SSL_CTX_get_cert_store` |
| `libcrypto-3-x64.dll` | 84 | OpenSSL 3 EVP / BIO / RAND / HMAC / MD5 / SHA256 / RC4 / providers |

Those four names are **not** Windows system DLLs. They are expected
beside `utilsdll.dll` under `INSTALLDIR`. That is **PROVEN** from
the import table and matches the live `126` when cwd was Downloads.

#### Entry point / DllMain (PROVEN)

| Item | Address / value |
| ---- | --------------- |
| `AddressOfEntryPoint` RVA | `0x2442b8` |
| ImageBase | `0x180000000` |
| PE entry | `0x1802442b8` = MSVC `_DllMainCRTStartup` |
| TLS directory | present; **callback list empty** |
| User `DllMain` | `0x180161dd0` |

`DllMain` (`0x180161dd0`):

- `DLL_PROCESS_ATTACH` (`edx == 1`): calls `0x18015d900` and
  **returns that EAX** (0 or 1). A 0 return makes the loader fail
  the load with `ERROR_DLL_INIT_FAILED`.
- `DLL_PROCESS_DETACH` (`edx == 0`): `FreeSid` helper `0x180121a80`,
  unmap `FC_{101839C4-…}`, `CloseHandle`, then return 1.
- `DLL_THREAD_ATTACH` / `DLL_THREAD_DETACH`: return 1 immediately.

`0x18015d900` PROCESS_ATTACH data flow (**PROVEN**):

1. `0x1800dc5d0`: `InitializeCriticalSection` ×2, then
   `GetModuleFileNameW(NULL)` of the **host exe** (basename stored;
   does not return FALSE).
2. C++ object-table walk: call `*(object+0x40)(cl=1)` then
   `*(vtable+0x38)(cl=1)` for registered globals. No `LoadLibrary`
   here. An exception in this walk would also be `1114` (**UNKNOWN**
   whether any constructor fails outside FortiClient).
3. `GetModuleFileNameW(hinstDLL)` — **this DLL’s** path — then
   `wcsrchr(..., '\\')` and NUL-out the filename, leaving the DLL
   directory in a global.
4. `RegOpenKeyExW(HKLM, L"SOFTWARE\\Fortinet\\FortiClient",
   KEY_READ=0x20019)` then `RegQueryValueExW(..., L"INSTALLDIR")`.
5. If the key or `INSTALLDIR` is missing/empty: log
   `Failed to initialize utilsdll - no install directory found`
   (`0x18029aa90`), optional `FA_Scheduler` log object, **return 0**.
6. `GetModuleFileNameW(NULL)` of the **host process** image, then
   `GetLongPathNameW` on that buffer.
7. `_wcsnicmp(INSTALLDIR, host_exe_long, wcslen(INSTALLDIR))`.
   Prefix match, case-insensitive. On mismatch: log
   `Failed to initialize utilsdll - unauthorized caller`
   (`0x18029ab10`), optional `FA_Scheduler` log, **return 0**.
8. On match: `OpenFileMappingW` /
   `CreateFileMappingW` name
   `FC_{101839C4-F81C-484d-AA6C-9AB43D091E77}`, `MapViewOfFile`,
   `0x180161d00` (compares host basename to `FortiClient.exe` for a
   refcount; **does not return FALSE** to DllMain), SID helper
   `0x180121960`, four ACL objects `0x180121780`,
   `0x1800a7d50` (FIPS-mode registry cache) → thunk
   `FCCryptDLL!FccFipsSetFipsModeEnabled`, then `0x18021c3b0`.
9. **Always `mov eax,1` at `0x18015dc79` after step 8**, including
   when the named mapping cannot be opened/created. Mapping/FIPS
   failure is **not** a DllMain FALSE path.

User `DllMain` therefore returns 0 if and only if INSTALLDIR is
missing or the host exe path does not have INSTALLDIR as prefix.

`0x18015d900` does **not** call `LoadLibrary` / `GetProcAddress`.
Static imports of `FCCryptDLL.dll` (and the other private DLLs) are
resolved by the Windows loader **before** this `DllMain` runs. If a
dependency’s own `DllMain` failed, that would also surface as `1114`
(**UNKNOWN** without those sibling binaries). The live sequence
(deps missing → `126`; deps present via cwd → `1114`) plus the
unauthorized-caller check is **STRONG EVIDENCE** that utilsdll’s
user `DllMain` is the function returning FALSE.

CRT `_DllMainCRTStartup` / `_initterm` global constructors run
before user `DllMain`. An exception there can also produce `1114`.
TLS callback list is empty (**PROVEN**), so TLS is not the cause.

#### Cause of live `1114` (STRONG EVIDENCE)

The harness executable lives under Downloads. `GetModuleFileNameW(NULL)`
therefore does not start with
`C:\Program Files\Fortinet\FortiClient`. `DllMain` returns 0.
`LoadLibraryW` reports `1114`.

Copying the harness into Program Files would change the FortiClient
directory and is **out of scope**. Changing cwd only fixes the
`126` search-path problem; it does **not** change the host exe path.

#### Does `GenRawLicenseInfo2` need that initialization?

**INFERENCE (do not bypass DllMain):** the builder at `0x1800d4610`
does not read the `FC_{101839C4-…}` mapping, does not re-check
`INSTALLDIR`, and does not call `FccFipsSetFipsModeEnabled`. It
uses Winsock, IP Helper, WTS, registry `FA_ESNAC`, `os_get_name`,
and CRT `malloc`. The FIPS / mapping work in `DllMain` is therefore
**not** a functional input to the plaintext constructor.

The Windows loader still **always** runs `DllMain` on `LoadLibrary`.
There is no approved way in this research to call
`GenRawLicenseInfo2` without that PROCESS_ATTACH succeeding.

#### Options A–D (evaluation only; not implemented)

| Option | Verdict |
| ------ | ------- |
| A. Load inside the normal FortiClient process without injecting or modifying FortiClient | **Rejected for this pass.** A process that already has `utilsdll.dll` mapped is `FortiClient.exe` / `ipsec.exe` / similar under `INSTALLDIR`. Reaching `GenRawLicenseInfo2` there without injection, a debugger attach, or a FortiClient-supported CLI is **UNKNOWN** and out of scope. |
| B. Reproduce only the required benign initialization in the standalone harness | **Not sufficient** while the host exe path fails the INSTALLDIR prefix check. Reproducing FIPS/mapping would not pass that check. |
| C. Preload `FCCryptDLL.dll` (or other official siblings) first | **Would not fix `1114`.** Those DLLs are already found when cwd is the FortiClient directory (else the error would still be `126`). Preload does not change `GetModuleFileNameW(NULL)`. Do not copy or register DLLs. |
| D. Treat static formatting as enough; skip a dynamic golden dump | **Preferred remaining path.** Separators, field order, MAC/IP/NUL/LF, and optional-field rules are **PROVEN** from `0x1800d4610`. A runtime dump would only pin `OSVER=` text and which MACs survive the filter. That is not required to decide that Notify `0xF100` stays unimplemented. |

Do not implement A/B/C. Do not bypass `DllMain`. A Linux-equivalent
Notify `0xF100` using this static framing is §12.12 (**VALID NEGATIVE**,
present on wire, not sufficient). Do not treat a Windows `LoadLibrary`
dump as a prerequisite.

### 12.12 Linux Notify `0xF100` A/B (**VALID NEGATIVE**: present on wire, not sufficient)

**Status: VALID NEGATIVE.** Private Notify `0xF100` is **proven present
on the wire** and is **not sufficient** on the current compatibility
baseline. Do **not** remove it. Golden FortiClient sends it; keep it as
part of the compatibility baseline. Do **not** claim FortiGate requires
the inventory contents.

#### First live attempt: INVALID TEST / IMPLEMENTATION FAILURE

The first intended `0xF100` A/B **did not execute**. Private charon
reported:

```
plugin 'fvl-forticlient-vid' failed to load:
/usr/lib/ipsec/plugins/libstrongswan-fvl-forticlient-vid.so:
undefined symbol: memwipe_noinline
```

Consequences in that log:

- plugin absent from the loaded plugin list
- `IKE_SA_INIT` was 304 bytes (no three FortiClient Vendor IDs)
- first `IKE_AUTH` was `[ IDi AUTH CPRQ(ADDR DNS) SA TSi TSr N(EAP_ONLY) N(MSG_ID_SYN_SUP) ]`
- `INITIAL_CONTACT` was not added
- `EAP_ONLY` / `MSG_ID_SYN_SUP` were not removed
- Notify `0xF100` was not added

The helper did generate a **208-byte** license-info payload, but it never
reached the wire. Root cause: `chunk_clear`/`memwipe` from 5.9.13 headers
inline `memwipe_noinline` when `HAVE_EXPLICIT_BZERO` is unset; Ubuntu
`libstrongswan` is built **with** `HAVE_EXPLICIT_BZERO` and does **not**
export that symbol. Shared-object link succeeded with an unresolved
reference; `dlopen` failed. This is an implementation failure, not a
FortiGate protocol result.

#### Valid live result: present on wire, not sufficient

After the load fix (`HAVE_EXPLICIT_BZERO`, local `explicit_bzero`,
`ldd -r` guard), a valid live A/B ran:

- `plugin 'fvl-forticlient-vid': loaded successfully`
- `IKE_SA_INIT` contained all 3 FortiClient Vendor IDs and was **364**
  bytes; FortiGate replied
- first `IKE_AUTH` omitted `EAP_ONLY` and `MSG_ID_SYN_SUP`, added
  `INITIAL_CONTACT`, added private Notify `0xF100` / 61696 with the
  generated **208-byte** license-info payload
- first `IKE_AUTH` was **464** bytes
- FortiGate **did not respond**
- the same `IKE_AUTH` was **retransmitted until timeout**

This **FALSIFIES** `0xF100` as sufficient on the §12.8 baseline (VIDs +
EAP_ONLY/MSG_ID_SYN_SUP omitted + INITIAL_CONTACT). It does **not**
falsify `0xF100` as a required compatibility input; keep it.

Next isolated A/B was the golden CP request (§12.13). That A/B is now
**VALID NEGATIVE**. Keep `0xF100`. Do not change Vendor IDs, notify
removals, INITIAL_CONTACT, `0xF100`, license-info construction, IDi,
PSK/EAP, proposals, transport/NAT-T, FCT_UID, tokenid, helper protocol,
or SAML pre-auth until a new single-variable experiment is approved.

Implementation kept on Linux (do not revert):

| Kept | Changed in §12.12 |
| ---- | ----------------- |
| Three FortiClient VIDs on `IKE_SA_INIT` | Add private IKEv2 Notify **type 0xF100 / 61696** to first initiator `IKE_AUTH` (MID=1) |
| Absence of `N(EAP_ONLY)` and `N(MSG_ID_SYN_SUP)` | |
| Empty `N(INITIAL_CONTACT)` | |
| PSK `AUTH`, EAP-MSCHAPv2, IDi, CP(ADDR DNS), SA, TSi, TSr | |
| Proposals, NAT-T, UDP/500 → UDP/4500 | |

Notify framing (**PROVEN** from §12.9, used on Linux):

- protocol ID 0 / `PROTO_NONE`
- SPI empty
- data = official-format plaintext **plus trailing NUL** (`strlen+1`)
- ASCII `KEY=value` lines, LF `0x0A` after every field including the last
- not CRLF
- no EMS fields (`EMSSN`, `EMSID`, `FCTTAGS`, `REG_PASSWD`)

Linux field sources (not a Windows inventory clone):

| Field | Linux source |
| ----- | ------------ |
| `VER` | literal `1` |
| `FCTVER` | compatibility value `7.4.8.2066` (this Notify emulates the tested FortiClient wire; **the Linux client is not FortiClient 7.4.8**) |
| `UID` | the same persisted FCT_UID already used for SAML pre-auth and EAP Identity |
| `IP` | IPv4 `getsockname` of a UDP connect toward the gateway |
| `MAC` | sysfs adapters formatted `%.2x-%.2x-%.2x-%.2x-%.2x-%.2x;`, skipping VMware/VirtualBox/fortissl names/descriptions and MACs `00-09-0F-09-00-01` / `00-09-0F-FE-00-01` |
| `HOST` | short hostname |
| `USER` | pkexec/sudo session username (`PKEXEC_UID` / `SUDO_UID`), not the SAML username |
| `OSVER` | `/etc/os-release` `PRETTY_NAME` |
| `REG_STATUS` | literal `0` |

Data path: helper writes the blob mode **0600** to
`/run/charon.fvl.license-info` (AppArmor `/run/charon.*`). Private
`strongswan.conf` gives the plugin only that path. The blob and FCT_UID
are not on argv, not in swanctl.conf, and not in logs. Cleanup uses
existing `wipe_ipsec_runtime`.

Plugin injection: `fvl-forticlient-vid` `listener_t.message()` on
outbound plain initiator IKEv2 `IKE_AUTH` MID=1, after the existing
notify removals and `INITIAL_CONTACT` add.
`notify_payload_create_from_protocol_and_type(PLV2_NOTIFY, PROTO_NONE,
(notify_type_t)61696)` then `set_notification_data`. Scope is private
charon / IKEv2 SSO only.

Privacy: diagnostics may log `added private Notify 0xF100` and
`license-info payload length: <N>` only. Redaction covers `UID=`,
`MAC=`, `IP=`, `HOST=`, `USER=`, `OSVER=`.

### 12.13 Linux golden CP request A/B (**VALID NEGATIVE**)

**Status: VALID NEGATIVE.** Exact CP16 was present on the wire and is
**not sufficient** on the §12.12 baseline. Keep the 16 empty attributes.
Do **not** claim FortiGate requires this CP set. Do **not** add another
compatibility mutation. Application remains **1.2.0**. Helper **0.9.0**
/ `protocol_version` **1**.

One additional variable on the §12.12 baseline (`0xF100` present, 464
bytes, FortiGate silent):

| Kept | Changed |
| ---- | ------- |
| Three FortiClient VIDs on `IKE_SA_INIT` | Replace first `IKE_AUTH` CFG_REQUEST with the golden 16 empty attributes |
| Absence of `N(EAP_ONLY)` and `N(MSG_ID_SYN_SUP)` | |
| Empty `N(INITIAL_CONTACT)` | |
| Private Notify `0xF100` / 208-byte license-info | |
| PSK `AUTH`, EAP-MSCHAPv2, IDi, SA, TSi, TSr | |
| Proposals, NAT-T, UDP/500 → UDP/4500 | |

Golden CP: payload length **72**, **16** empty request attributes, order
`1,2,7,3,4,13,8,10,11,15,25,21516,28678,21514,21515,28673`. Values are
empty (length 0).

#### Valid live result

- `plugin 'fvl-forticlient-vid': loaded successfully`
- `IKE_SA_INIT` contained all 3 FortiClient Vendor IDs and was **364**
  bytes; FortiGate replied with **264** bytes; proposal negotiation
  succeeded; NAT-T switched to UDP/4500
- first `IKE_AUTH` omitted `EAP_ONLY` and `MSG_ID_SYN_SUP`, added
  `INITIAL_CONTACT`, used PSK `AUTH`, used the exact 16-attribute
  CFG_REQUEST, included SA / TSi / TSr, added private Notify `0xF100`
  with the existing license-info blob
- runtime CP types/order (**PROVEN** plugin log):
  `1,2,7,3,4,13,8,10,11,15,25,21516,28678,21514,21515,28673`
- first `IKE_AUTH` was **512** bytes (UDP/4500 **516** including the
  4-byte non-ESP marker)
- FortiGate sent **no** `IKE_AUTH` response
- the identical 512-byte request was **retransmitted until timeout**

This **FALSIFIES** exact CP16 as sufficient on the §12.12 baseline.
It does **not** falsify CP16 as a required compatibility input; keep
it. Preserve the §12.12 `0xF100` **VALID NEGATIVE** (464-byte era).

Size path of first `IKE_AUTH` IKE length: stock 256 → no `EAP_ONLY`
240 → +`INITIAL_CONTACT` still silent → +`0xF100` **464** → +CP16
**512**. Golden first `IKE_AUTH` remains **576**. Remaining inner gap
is §12.14.

### 12.14 Golden vs Linux CP16 first `IKE_AUTH` structural differential (research only)

Captures: golden FortiClient 7.4.8.2066 first `IKE_AUTH` (UDP/4500,
576-byte IKE); Linux CP16 `/tmp/fvl-cp16.pcap` (UDP/4500, 512-byte
IKE, five identical retransmits). Inner golden sequence from iked
construction + `ipsec.exe` + own-packet parse. Inner Linux sequence
from charon generating, plugin hooks, and strongSwan 5.9.13
`ike_auth_i_order`. SK-encrypted bodies were **not** decrypted. No
`<FCT_UID>`, tokenid, PSK, SAML username, license-info contents, MAC,
host IP, hostname, or `USER` value is recorded here.

Evidence grades used below: **A** proven protocol-semantic difference;
**B** expected per-session cryptographic difference; **C** likely
irrelevant to the silent drop; **D** plausible FortiGate compatibility
gate (not proven required); **E** unknown.

Do **not** assume a FortiClient-only field is required merely because
FortiClient sends it. The isolated `0xF100` ordering A/B is §12.15
(**VALID NEGATIVE**). Keep the ordered `0xF100`. The next isolated A/B
is initiator AUTH omission on first `IKE_AUTH` (§12.17, **CODE**, live
pending). Do **not** claim AUTH omission is required until a valid
live test.

#### 1. Outer IKE header (**PROVEN** pcap)

| Field | Golden 7.4.8 | Linux CP16 |
| ----- | ------------ | ---------- |
| Transport | UDP/4500 from `IKE_SA_INIT` (4-byte non-ESP marker) | UDP/500 `IKE_SA_INIT`, then NAT-T UDP/4500 for `IKE_AUTH` |
| IKE length | **576** | **512** |
| UDP length | **580** | **516** |
| Exchange | `IKE_AUTH` (35) | `IKE_AUTH` (35) |
| Flags | `0x08` (Initiator, Request) | `0x08` |
| Version | 0x20 | 0x20 |
| Message ID | 1 | 1 |
| Initiator SPI | 8 bytes, non-zero | 8 bytes, non-zero |
| Responder SPI | 8 bytes, non-zero (from INIT response) | 8 bytes, non-zero |
| First payload | SK (46) | SK (46) |
| SK Next Payload | IDi (35) | IDi (35) |
| SK Critical | 0 | 0 |
| SK length | 548 | 484 |
| IV | 16 bytes, non-zero (AES-CBC) | 16 bytes, non-zero |
| Inner+pad (AES-CBC-128 / HMAC-SHA2-256-128 ICV 16) | **512** | **448** |
| FortiGate `IKE_AUTH` response | **128**-byte IKE / 132 UDP | **none**; identical 512-byte request retransmitted |

SPIs, IV, and ICV bytes differ per session (**B**). Outer header
layout (exchange, flags, MID, SK framing, NAT-T marker on `IKE_AUTH`)
matches (**not a remaining gate**). UDP/500 vs direct UDP/4500 is an
`IKE_SA_INIT` transport difference; FortiGate already answered INIT
both ways (**C** for the unanswered `IKE_AUTH`, unless INIT transcript
feeds AUTH — see AUTH).

#### 2. Decrypted payload order

Golden construction `ikev2_next_payload` + own-packet parse (**STRONG
EVIDENCE**):

1. IDi (length 12, next NOTIFY)
2. N(INITIAL_CONTACT) (length 8, next NOTIFY)
3. N(0xF100) (length 279, next CP)
4. CP CFG_REQUEST (length 72, next SA)
5. SA (length 84, next TSi)
6. TSi (present; length not logged)
7. TSr (present; inferred, required with TSi)

AUTH is **computed** before this chain (`ca_setauth` method 2,
initiator auth data length 622) but is **not** the next payload after
IDi and is **not** logged in the IDi→CP→SA chain. Neighbor **E**.

Linux encoder `ike_auth_i_order` (**PROVEN** strongSwan 5.9.13
`message.c` + plugin adds):

1. IDi
2. N(INITIAL_CONTACT) (named notify slot)
3. AUTH
4. CP
5. SA
6. TSi
7. TSr
8. N(0xF100) (unknown-notify catch-all after TSr)

`EAP_ONLY` and `MSG_ID_SYN_SUP` absent on both (**ruled out** as the
current remaining delta; already live-tested).

Order difference **A**: golden places `0xF100` immediately before CP;
Linux places AUTH before CP and `0xF100` after TSr. The §12.12 A/B
tested `0xF100` **presence** in the strongSwan-sorted slot, not this
position.

#### 3. IDi

| Field | Golden | Linux CP16 |
| ----- | ------ | ---------- |
| Payload type | IDi (35) | IDi (35); SK Next **PROVEN** pcap |
| ID type | `ID_IPV4_ADDR` (**PROVEN** iked `srcid IPV4/<client>`) | empty `local-psk` id ⇒ strongSwan falls back to local address (`ID_IPV4_ADDR`) (**STRONG EVIDENCE** `ike_auth.c`) |
| Semantic source | client IPv4 identity | local IPv4 of the IKE socket |
| Identity length | 8 | 4-byte IPv4 ⇒ payload 12 (**STRONG EVIDENCE**) |
| Encoded payload length | **12** | **12** (same class) |
| Value | per-host IPv4 (**B**); not stored | per-host IPv4 (**B**); not stored |

Category match: both IPv4 address IDi, not FCT_UID / FQDN / KEY_ID.
Do not change IDi. Not a first-rank remaining gate.

#### 4. AUTH

| Field | Golden | Linux CP16 |
| ----- | ------ | ---------- |
| Method | 2 `SHARED_KEY_MIC` (**PROVEN** `ca_setauth`) | 2 `AUTH_PSK` / `SHARED_KEY_MIC` (**PROVEN** `psk_authenticator.c`) |
| PRF used for MIC | FortiGate selected **PRF_AES128_XCBC** on golden INIT response (**PROVEN** pcap) | Linux offered only **PRF_HMAC_SHA2_256**; FortiGate selected that (**PROVEN** §12.4 / INIT SA) |
| If present, payload length | 8 + 16 = **24** under AES-XCBC | 8 + 32 = **40** under HMAC-SHA2-256 |
| Transcript | INIT + nonces + IDi MACed with PSK | same RFC model, but INIT bytes differ |
| First-`IKE_AUTH` presence | **E / STRONG EVIDENCE absent**: proven payloads IDi 12 + IC 8 + license 279 + CP 72 + SA 84 = 455; 512 inner+pad leaves **57** bytes for TSi+TSr+AUTH+pad. Two IPv4 TS payloads (24+24) + PKCS7 pad 9 = 57 with **no room** for a 24- or 40-byte AUTH. Construction never chains AUTH into that message. Post-EAP AUTH payload **40** is a later message (**PROVEN** iked). | **PROVEN present** in charon generating / PSK builder. Size accounting of the CP16 SK body also fits a 40-byte AUTH if the ESP SA is a **single** 44-byte proposal, or fits AUTH-absent if SA is 84 bytes. SA count inside SK is **E** (encrypted). |

Distinguish: MIC **bytes** are **B** (nonces, SPIs, INIT body). MIC
**algorithm / length** follow the negotiated PRF (**A** vs golden
session, **C** vs this FortiGate if it verifies the PRF it selected on
Linux INIT). Mixed-mode AUTH **presence** on the first `IKE_AUTH` is
the remaining **D** (see ranking). Both clients use PSK over IDi, not
EAP, on this message; EAP starts only after FortiGate’s first response
on golden.

#### 5. CFG_REQUEST

| Field | Golden | Linux CP16 |
| ----- | ------ | ---------- |
| Structure | 8-byte CP header + 16 empty 4-byte attributes = **72** | **72** |
| Types/order | `1,2,7,3,4,13,8,10,11,15,25,21516,28678,21514,21515,28673` | **identical** (**PROVEN** live plugin log) |
| Values | empty | empty |

**Ruled out as the remaining sufficient cause** (§12.13 VALID
NEGATIVE). Keep CP16.

#### 6. CHILD_SA proposal

Golden own-packet parse (**PROVEN**): SA payload **84**, next TSi;
proposal #1 `more=2` (a second proposal follows), length **40**, proto
ESP, SPI size **4**, **3** transforms: INTEGR `HMAC_SHA1_96` (8), ENCR
`AES_CBC` KEY_LENGTH **128** (12), third transform length **8** (not
in the filtered iked excerpt). 40 = 8+4+8+12+8 ⇒ third is DH, ESN, or
integrity without attributes. No room for both DH **and** ESN.
Proposal #2 occupies the remaining 40 bytes (**STRONG EVIDENCE** two
ESP proposals, no fourth transform).

Linux first-`IKE_AUTH` child (**STRONG EVIDENCE** `child_create.c`):
`dh_group` stays `KE_NONE` on `IKE_AUTH` (PFS KE is CREATE_CHILD_SA
only); `get_proposals(..., strip_ke=true)` omits DH. Default ESN is
`NO_EXT_SEQ_NUMBERS`. swanctl SAML child is `aes128-sha1` then
`aes256-sha256`. Encoder order is ENCR, INTEGR, ESN (**PROVEN**
`proposal_substructure.c`). Expected per proposal: 40 bytes, two
proposals, SA **84** — same length class as golden — **unless** the
live profile emitted only the first proposal (then SA **44**, **E**).

| Field | Golden | Linux CP16 |
| ----- | ------ | ---------- |
| Proposal count | 2 (**PROVEN** `more=2`, SA 84) | 2 configured; on-wire count **E** |
| Protocol | ESP | ESP |
| SPI | 4 bytes, generated (**B**) | 4 bytes, generated (**B**) |
| Prop #1 | INTEGR SHA1-96, ENCR AES-CBC-128, third 8-byte **E** | ENCR AES-CBC-128, INTEGR SHA1-96, ESN NO (**STRONG EVIDENCE**) |
| Prop #2 | 40 bytes, transforms not extracted (**E**) | ENCR AES-CBC-256, INTEGR SHA2-256-128, ESN NO (**STRONG EVIDENCE** if both sent) |
| Transform order | INTEGR then ENCR then third | ENCR then INTEGR then ESN |
| Key lengths | AES 128 on prop #1 | AES 128 then 256 |
| ESN | third xform **E**; length 8 is compatible with NO_ESN | NO_ESN default |
| DH/PFS in this SA | not in the two logged xforms; 3-xform/40-byte budget makes DH+ESN together impossible | stripped on `IKE_AUTH` (**STRONG EVIDENCE**) |
| KE payload | not in construction logs | not added when `dh_group == KE_NONE`; not in the live payload set |

Transform **order** is **A** (set vs sequence). RFC treats transforms
in a proposal as a set (**C** unless FortiGate is order-sensitive).
PFS DH on this message is likely **matched** (both omit). Proposal #2
contents **E**.

#### 7. TSi and TSr

| Field | Golden | Linux CP16 |
| ----- | ------ | ---------- |
| Present | **PROVEN** SA next TSi | **PROVEN** generating / child_create |
| Selector type | not in filtered iked excerpt (**E**) | `TS_IPV4_ADDR_RANGE` (**STRONG EVIDENCE**) |
| Protocol / ports | **E** | proto 0, ports 0–65535 (**STRONG EVIDENCE** `0.0.0.0/0` / dynamic) |
| Address ranges | **E**; do not store | local `dynamic` narrowed with VIP `0.0.0.0`; remote `0.0.0.0/0` |
| Payload length | size model fits 24+24 | 24+24 (**STRONG EVIDENCE** one IPv4 selector each) |

Likely same class (IPv4 any/any tunnel). Exact golden ranges **E**.
Not first-rank without a decrypted TS parse.

#### 8. Notify payloads

| Notify | Golden | Linux CP16 |
| ------ | ------ | ---------- |
| INITIAL_CONTACT 16384 | present, proto 0, SPI 0, data 0, length **8**, immediately after IDi | present, proto 0, SPI 0, data 0, length **8**, after IDi (**PROVEN** plugin + encoder) |
| 0xF100 | proto 0, SPI 0, data **271** (strlen 270 + NUL), payload **279**, **immediately before CP** | proto 0, SPI 0, data **208**, payload **216**, **after TSr** |
| EAP_ONLY | absent | absent |
| MSG_ID_SYN_SUP | absent | absent |

`0xF100` **presence** is **VALID NEGATIVE** (§12.12). Remaining
`0xF100` deltas: **data length/contents** (**A**/**D**, 208 vs 271;
do not store contents) and **relative position** (**A**/**D**).
INITIAL_CONTACT match.

#### 9. Every remaining wire-level difference

Still present after CP16 (IKE_AUTH-focused; INIT listed only where it
feeds AUTH):

| # | Difference | Grade |
| - | ---------- | ----- |
| 1 | Payload order: golden `IDi, IC, 0xF100, CP, SA, TSi, TSr[, AUTH?]`; Linux `IDi, IC, AUTH, CP, SA, TSi, TSr, 0xF100` | **A** / **D** |
| 2 | First-`IKE_AUTH` initiator AUTH presence (golden size+construction vs Linux generating) | **D** / **E** (golden absence STRONG from size; Linux presence PROVEN from builder, on-wire size **E**) |
| 3 | AUTH MIC PRF: AES-XCBC (golden negotiated) vs HMAC-SHA2-256 (Linux negotiated) | **A** encoding; **C** if FortiGate verifies the PRF it selected; **D** only if it still demands XCBC |
| 4 | AUTH MIC bytes, SPIs, IV, ESP SPI | **B** |
| 5 | `0xF100` data length 271 vs 208 and inventory contents | **A** / **D**; presence already negative |
| 6 | ESP transform order (INTEGR-first vs ENCR-first) | **A** / **C** |
| 7 | ESP proposal #2 / third golden transform | **E** |
| 8 | TSi/TSr exact ranges | **E**; class likely match |
| 9 | IDi IPv4 **value** | **B** |
| 10 | `IKE_SA_INIT` proposal set, extra PRFs including AES-XCBC, `FRAG_SUP`/`REDIR_SUP`, HASH_ALG 6 vs 8 bytes, UDP/500 vs 4500 | INIT already answered (**C** for delivery; **D** only via AUTH transcript/PRF) |
| 11 | CP16 types/order/length | **ruled out** as sufficient |
| 12 | `0xF100` presence, INITIAL_CONTACT presence, EAP_ONLY/MSG_ID_SYN_SUP absence, VID presence, SK/NAT-T framing | **ruled out** as sufficient / matched |

#### 10. Ruled out

- Missing FortiClient VIDs as sole cause (§12.3)
- `N(EAP_ONLY)` as sole cause (§12.6)
- `N(MSG_ID_SYN_SUP)` as additional blocker (§12.7)
- `N(INITIAL_CONTACT)` as sufficient (§12.8)
- Notify `0xF100` **presence** as sufficient (§12.12) — **keep it**
- Exact CP16 as sufficient (§12.13) — **keep it**
- Outer `IKE_AUTH` header / SK / NAT-T framing mismatch
- IDi type category (both IPv4 address)
- CP structure/types/order (now matched)
- INIT as the unanswered-`IKE_AUTH` **delivery** cause (FortiGate
  answered INIT)

#### 11. Next single-variable A/B

Implemented in tree as §12.18 (**CODE**, live pending): IKEv2 SSO
swanctl uses EAP-only local authentication plus remote PSK so stock
strongSwan 5.9.13 keeps `COND_AUTHENTICATED` unset while EAP/REQ/ID is
in progress. Keep AUTH omission, ordered `0xF100`, CP16, IDi, SA, TSi,
TSr. Do **not** claim this config is required until a valid live
result.

§12.17 AUTH omission is **LIVE POSITIVE**.

Remaining CHILD_SA/EAP continuation cause is **HYPOTHESIS** until §12.18 live.

### 12.15 Linux Notify `0xF100` ordering A/B (**VALID NEGATIVE**)

**Status: VALID NEGATIVE.** Position-only on the §12.13 baseline.
Preserve §12.12 (`0xF100` presence **VALID NEGATIVE**, 464-byte era)
and §12.13 (CP16 **VALID NEGATIVE**, 512-byte era). Keep the ordered
`0xF100`. Do **not** treat this as an AUTH validation failure.

One additional variable on the §12.13 baseline: move the existing
private Notify `0xF100` from after TSr to immediately after
`INITIAL_CONTACT` and before AUTH / CFG_REQUEST. AUTH remained present.

| Kept | Changed |
| ---- | ------- |
| Three FortiClient VIDs on `IKE_SA_INIT` | Reposition existing Notify `0xF100` |
| Absence of `N(EAP_ONLY)` and `N(MSG_ID_SYN_SUP)` | |
| Empty `N(INITIAL_CONTACT)` | |
| Notify `0xF100` type / proto 0 / SPI 0 / 208-byte data | |
| Exact CP16 | |
| PSK `AUTH` presence and construction | |
| IDi, SA, TSi, TSr, proposals, NAT-T | |

Expected first `IKE_AUTH` payload order after `disable_sort()` on this
attempt:

`IDi`, `N(INITIAL_CONTACT)`, `N(0xF100)`, `AUTH`, `CP`, `SA`, `TSi`, `TSr`

#### Live result (**VALID NEGATIVE**, `docs/research/captures/20261001T180639Z`)

FortiGate debug collector was **ACTIVE** and persisted raw output.
FortiGate logged `FCT EAP 2FA extension vendor ID received` at
2026-10-01 20:06:51.685804. No FortiGate `IKE_AUTH` parse/decrypt/reject
line followed. No AUTH-specific error. No time-correlated HomeVPN
fnbamd authentication event.

PCAP: Linux `IKE_SA_INIT` request → FortiGate; FortiGate `IKE_SA_INIT`
response → Linux; Linux first `IKE_AUTH` → FortiGate; four `IKE_AUTH`
retransmissions; **zero** `IKE_AUTH` response from FortiGate.

This **FALSIFIES** ordered `0xF100` plus AUTH-present first `IKE_AUTH`
as sufficient. It does **not** prove an AUTH validation failure. Keep
the ordered `0xF100`. Next isolated A/B is §12.17.

### 12.16 Responder-side synchronized capture (diagnostics only)

**Status: VALID** for capture `docs/research/captures/20261001T180639Z`.
This is not a protocol mutation. The captured Linux first `IKE_AUTH`
was the §12.15 AUTH-present ordered baseline (`IDi`, `INITIAL_CONTACT`,
`Notify 0xF100`, `AUTH`, CP16, `SA`, `TSi`, `TSr`).

A first live attempt produced **valid client-side** evidence (SAML
pre-auth, `IKE_SA_INIT` round-trip, first `IKE_AUTH` on UDP/4500,
retransmits, no responder `IKE_AUTH` packet). The FortiGate debug
collector failed: a FIFO writer-open deadlock meant SSH never started
and `fortigate-debug.log` was never created. That report is **INVALID**
for questions A–G. Do not read missing FortiGate IKE lines as a silent
discard.

The later capture `20261001T180639Z` is **VALID**: collector ACTIVE;
FortiGate recognized FCT EAP 2FA extension; INIT succeeded; no
`IKE_AUTH` response; no responder-side AUTH-specific error. That
result is recorded as §12.15 **VALID NEGATIVE**.

Operator workflow: `tools/research/linux/capture-ike-auth-correlation.sh`
(README in that directory). It keeps **one** persistent `ssh -tt`
CLI session, enables `ike -1` / `fnbamd -1`, and must print READY only
after the collector is ACTIVE. `diagnose debug reset` is not used. Raw
captures stay in gitignored `docs/research/captures/`.

Do not classify unrelated fnbamd OCSP/certificate lines as HomeVPN
evidence.

### 12.17 Linux first `IKE_AUTH` initiator AUTH omission A/B (**LIVE POSITIVE**)

**Status: LIVE POSITIVE.** Keep AUTH omission. Do not revert it.
Preserve §12.12, §12.13, and §12.15 **VALID NEGATIVE** results.

One additional variable on the §12.15 baseline: remove the initiator
AUTH payload from message ID 1 before encoding/sending it.

| Kept | Changed |
| ---- | ------- |
| Three FortiClient VIDs on `IKE_SA_INIT` | Omit initiator AUTH from first `IKE_AUTH` / MID 1 |
| Absence of `N(EAP_ONLY)` and `N(MSG_ID_SYN_SUP)` | |
| Empty `N(INITIAL_CONTACT)` | |
| Ordered Notify `0xF100` before CFG_REQUEST | |
| Exact CP16 | |
| IDi, SA, TSi, TSr, proposals, NAT-T, SAML, FCT_UID | |

First `IKE_AUTH` payload order:

`IDi`, `N(INITIAL_CONTACT)`, `N(0xF100)`, `CP`, `SA`, `TSi`, `TSr`

Packet: **480**-byte IKE / **484**-byte UDP.

#### Live result (**LIVE POSITIVE**)

FortiGate **responded**. charon received:

`parsed IKE_AUTH response 1 [ IDr AUTH EAP/REQ/ID ]`

Then:

- `authentication of '91.149.212.169' with pre-shared key successful`
- `IKE_SA fortigate[1] established`
- `IKE_SA state change: CONNECTING => ESTABLISHED`

AUTH-present first `IKE_AUTH` remains a **valid negative**. AUTH
omission is **required** on this baseline for FortiGate to answer.

#### Follow-on blocker (not an AUTH-omit failure)

Immediately after that response, charon logged `SA payload missing in
message` and `failed to establish CHILD_SA, keeping IKE_SA`, then sent
`INFORMATIONAL` MID 2 `[ D ]` (DELETE for ESP CHILD_SA) before EAP
Identity continuation. That is §12.18. Do not revert AUTH omission to
address it.

### 12.18 EAP-only local authentication so CHILD_CREATE waits for EAP (LIVE SUCCESS)

**Status: LIVE SUCCESS.** Authentication, CHILD_SA, VIP, and internal
connectivity work. Do **not** revert this swanctl shape. Keep AUTH
omission, ordered `0xF100`, CP16, IDi, SA, TSi, TSr. Keep the PSK
**secret** and `remote-psk`. Keep EAP-MSCHAPv2 and the tokenid EAP
secret.

Live HomeVPN result:

- IKE_SA ESTABLISHED after EAP-MSCHAPv2
- CHILD_SA / XFRM over ESP-in-UDP/4500
- Mode Config VIP `10.10.80.10/32`
- Internal reachability `10.10.10.1` and `10.10.20.20` success 3/3

The control plane is **frozen**. Split-tunnel data plane, split DNS,
and FCT UID application-log redaction are **LIVE-PROVEN** (§12.19).
Do not change SAML pre-auth, FCT_UID / tokenid, FortiClient VIDs,
first IKE_AUTH AUTH omission, INITIAL_CONTACT, Notify `0xF100`, CP16,
IKE/ESP proposals, or the IKEv2 SSO auth model
(`local = eap-mschapv2`, `remote = psk`).

Root cause that this A/B fixed (strongSwan 5.9.13, not a FortiGate
parse error):

- `child_create` `process_i()` installs CHILD_SA on `IKE_AUTH` only when
  `COND_AUTHENTICATED` is set. Otherwise it returns `NEED_MORE`
  (`wait until all authentication round completed`).
- Dual `local-psk` + `local-eap` is RFC 4739 multiple authentication.
  `do_another_auth()` returns FALSE unless the peer advertised
  `MULTIPLE_AUTH_SUPPORTED`. FortiGate did not. After the in-memory PSK
  authenticator completed (even with AUTH stripped from the wire),
  `ike_auth` set `COND_AUTHENTICATED` on the same message that carried
  EAP/REQ/ID and no SA.
- `child_create` then reported `SA payload missing in message` and
  queued ESP DELETE.

Stock representation of this exchange: EAP-only **local** authentication
plus **remote** PSK. The EAP authenticator `build_client()` returns
`NEED_MORE` without AUTH on the first request; `process_client()`
consumes EAP/REQ/ID; `COND_AUTHENTICATED` stays unset until EAP
finishes; `child_create` and `ike_config` wait. IDi still falls back to
the local IPv4 address when `local-eap` has no `id=`.

| Kept | Changed |
| ---- | ------- |
| AUTH omission hook on first `IKE_AUTH` MID 1 | No `local-psk` initiator round for IKEv2 SSO |
| `remote-psk { auth = psk }` and `ike-psk` secret | |
| `local-eap { auth = eap-mschapv2; eap_id }` and EAP secret | |
| VIDs, notify suppressions, INITIAL_CONTACT, ordered 0xF100, CP16 | |
| IDi fallback, SA/TSi/TSr on first IKE_AUTH, proposals | |
| IKEv1 `local-psk` + `local-xauth` | |

Expected next live sequence:

1. `IKE_SA_INIT` as today
2. First `IKE_AUTH` MID 1: `IDi`, `INITIAL_CONTACT`, `0xF100`, CP16, `SA`, `TSi`, `TSr` (no AUTH)
3. FortiGate `IKE_AUTH` MID 1: `IDr AUTH EAP/REQ/ID`
4. No ESP DELETE; no `SA payload missing`
5. Linux `IKE_AUTH` MID 2: EAP Response/Identity
6. EAP-MSCHAPv2 continues with the existing tokenid secret
7. CHILD_SA after EAP completes

Diagnostics may log
`FortiClient compatibility: EAP-only local authentication; CHILD_SA deferred until EAP completes`.
Never log PSK, FCT_UID, tokenid, SAML username, license blob, MAC,
HOST, or USER.

This A/B is **LIVE SUCCESS**. Do not stack another authentication /
protocol-compatibility experiment. Split-tunnel data plane is
**LIVE-PROVEN** (§12.19).

### 12.19 IKEv2 SSO split-tunnel / DNS (LIVE-PROVEN)

**Status: LIVE-PROVEN** for HomeVPN CFG_REPLY parse, POST_NOAUTH
CHILD_SA narrowing, split XFRM / table 220, internal vs public
routing, split DNS, and FCT UID application-log redaction. Control
plane frozen (§12.18). This does **not** change CP16, VIDs, AUTH
omission, Notify `0xF100`, INITIAL_CONTACT, PSK, EAP-MSCHAPv2, or
swanctl auth rounds. Observed prefixes and VIP are live-environment
examples only; they are not hard-coded in the client.

#### LIVE-PROVEN

After the successful HomeVPN connect with POST_NOAUTH narrowing:

- FortiGate CFG_REPLY contained seven `INTERNAL_IP4_SUBNET` prefixes
  (RFC 7296 type 13). The live values are consumed dynamically from
  CFG_REPLY.
- Plugin parse: `CFG_REPLY split-include count=7`,
  `source=INTERNAL_IP4_SUBNET`, `CFG_REPLY tunnel-mode=split`.
- Stock strongSwan still reports `handling INTERNAL_IP4_SUBNET
  attribute failed` (no initiator handler). That is **not** a parser
  failure. The compatibility plugin remains authoritative for the
  negotiated split prefixes.
- VIP remained the negotiated Mode Config address (`10.10.80.10/32`
  in this environment).
- strongSwan first performed the stock TS intersection
  (`config: 0.0.0.0/0`, `received: 0.0.0.0/0` ⇒ `match: 0.0.0.0/0`).
- The plugin then logged `narrowed CHILD_SA remote TS to
  split-include count=7`.
- Resulting CHILD_SA remote selectors were the seven negotiated
  prefixes. There was no VPN CHILD_SA selector `<VIP>/32 === 0.0.0.0/0`.
- table 220 contained only those seven prefixes. There was no VPN
  default route in table 220.
- XFRM contained individual outbound policies `<VIP>/32 ->` each
  negotiated split prefix. There was no VPN outbound policy
  `<VIP>/32 -> 0.0.0.0/0`. Ignore generic XFRM socket in/out policies
  with `0.0.0.0/0`; those are not VPN tunnel policies.
- Routing: `10.10.10.1` and `10.10.20.20` used table 220, IPsec, and
  source VIP (0% loss). `8.8.8.8` used the normal main-table default
  route, not table 220, and not source VIP (0% loss). Public Internet
  therefore remains outside the VPN while negotiated internal
  networks use IPsec.
- Split DNS: VPN DNS servers from CFG_REPLY were installed; the VPN
  link had `DefaultRoute=no`; no `~.` catch-all routing domain was
  installed; public DNS resolution and public Internet remained
  reachable outside IPsec.
- Application-visible charon output showed
  `server requested EAP_IDENTITY (...) sending '***'` and
  `eap_id = ***`. Secret-loading output did not expose credentials.

#### strongSwan 5.9.13 CHILD_SA lifecycle (LIVE-PROVEN)

```
CFG_REPLY parsed (plugin message listener, incoming/plain)
    → stock TS intersection (narrow_ts; still 0.0.0.0/0)
    → NARROW_INITIATOR_POST_NOAUTH   (initial IKE_AUTH CHILD_SA)
    → plugin replaces the bus-provided remote TS list
    → CHILD_SA set_policies()
    → kernel-netlink installs split XFRM policies and table-220 routes
```

`NARROW_INITIATOR_POST_AUTH` remains hooked for `CREATE_CHILD_SA` /
rekey. That rekey path is **IMPLEMENTED / TESTED**, not live-proven.

The plugin does **not** hook `PRE_NOAUTH` / `PRE_AUTH`. The frozen
first `IKE_AUTH` must keep proposed TSr `0.0.0.0/0`.

#### LIVE-PROVEN failure of the first narrowing hook (historical)

The first CHILD_SA narrowing attempt did **not** take effect:

- strongSwan still selected `config: 0.0.0.0/0, received: 0.0.0.0/0 =>
  match: 0.0.0.0/0`
- CHILD_SA established `TS <VIP>/32 === 0.0.0.0/0`
- table 220 contained a default route sourced from the VIP
- outbound XFRM `src <VIP>/32 dst 0.0.0.0/0`
- public Internet (`8.8.8.8`) was captured by table 220 and failed

Root cause (strongSwan 5.9.13 `child_create.c`, not a second parser
bug): the initial CHILD_SA is created during `IKE_AUTH`, so
`select_and_install()` fires `NARROW_INITIATOR_POST_NOAUTH` after
`narrow_ts()` and before `set_policies()`. The first hook only
handled `NARROW_INITIATOR_POST_AUTH`, which runs for
`CREATE_CHILD_SA` rekey, **not** the IKE_AUTH CHILD_SA. Incoming
CFG_REPLY is parsed earlier on the message listener (`plain` +
`incoming`) before tasks run, so prefixes were already available;
modifying `child_cfg` would also have been too late. The
authoritative list is the `linked_list_t *remote` passed to the
narrow hook.

#### IMPLEMENTED / TESTED BUT NOT LIVE-PROVEN

- `NARROW_INITIATOR_POST_AUTH` / `CREATE_CHILD_SA` rekey split
  preservation
- full-tunnel fallback when CFG_REPLY has no split-include or a
  prefix is `0.0.0.0/0` (including catch-all DNS `~.`)
- Unity / Fortinet-private split-include attribute fallbacks
- malformed or empty split-attribute handling
- split DNS domains other than the live HomeVPN “servers only, no
  `~.`” case

Empty/malformed split data does not invent selectors. Full tunnel is
preserved in code when no usable split-include is returned. DNS:
split mode uses negotiated VPN DNS servers, `DefaultRoute=no`, and
no `~.` unless explicitly negotiated. Full-tunnel DNS may still
install `~.`. Never hard-code DNS addresses, prefixes, or VIP.
Disconnect still restores the pre-VPN DNS snapshot.

Attribute priority consumed by the plugin (unchanged):

1. `UNITY_SPLIT_INCLUDE` (28676 / 0x7004)
2. `INTERNAL_IP4_SUBNET` (13) — LIVE-PROVEN on HomeVPN
3. Fortinet private `0x540c` / 21516 if it decodes as subnets
4. `UNITY_LOCAL_LAN` (28678 / 0x7006) as FortiClient's requested
   split-include fallback

IKEv1 Unity split-include (`cisco_unity = yes`) is unchanged.

#### Security: FCT UID / EAP identity redaction (LIVE-PROVEN)

A previous live test leaked the EAP identity / FCT UID via
`server requested EAP_IDENTITY ..., sending '<FCT_UID>'`. Structural
redaction now covers that form (quoted/unquoted, mixed case),
`eap_id`, tokenid, PSK, EAP secrets, helper JSON credential fields
(including `username`), SAML URL query/session material, cookies,
and Authorization headers. The later live run showed
`sending '***'` and `eap_id = ***`. The live FCT UID is not copied
into source, tests, docs, or fixtures. Redaction remains
pattern/key-based; it does not match a specific production value.
Useful non-secret diagnostics (split prefixes, VIP, DNS servers,
IKE/ESP proposals, CHILD_SA selectors, XFRM, plugin state, tunnel
mode, gateway) stay visible.

### 12.20 Private-charon log hygiene (IMPLEMENTED / TESTED; not live-proven)

**Status: IMPLEMENTED / TESTED in tree. Not live-proven.** Does not
change IKE/EAP/CHILD_SA/kernel behavior. Isolation stays on the
private charon (`STRONGSWAN_CONF=/run/charon.fvl.conf`). System
strongSwan is not modified.

Root causes of the successful-connect ERROR noise:

1. **Optional plugins.** Distro `/etc/strongswan.d/charon/*.conf`
   plus `load_modular = yes` requested plugins whose `.so` is not
   installed (`test-vectors`, `ldap`, `pkcs11`, `rdrand`, `gcrypt`,
   `af-alg`, `curve25519`, `chapoly`, `cmac`, `ctr`, `ccm`, `ntru`,
   `curl`, …).
2. **Credential directories.** `swanctl --load-all --file` sets
   `swanctl_dir` to the conf directory and logs ERROR for missing
   `x509` / `private` / … trees.
3. **Stock CFG handlers.** After the plugin consumes FortiGate
   `INTERNAL_IP4_SUBNET`, stock `attribute_manager` still reports
   `handling INTERNAL_IP4_NETMASK|INTERNAL_IP4_SUBNET|INTERNAL_IP6_SUBNET|APPLICATION_VERSION attribute failed`.
4. **Application duplication.** Backend `_app_log` previously copied
   raw plugin/charon strings into source `vpn` while helper IPC LOG
   events already stored them as `[ipsec]`. Charon `ike = 2` also
   emits its own abbreviated IKE encoding lines; those are distinct
   charon diagnostics, not a second application copy.

Fixes:

- Private runtime uses `load_modular = no` and an explicit `load`
  list: `REQUIRED_CHARON_PLUGINS ∩ installed .so`, never
  `kernel-libipsec` / `bypass-lan` / `stroke` / the optional names
  above. Distro `*.conf` is not included. IKEv1 still requests
  `xauth-generic` / `unity` when present. The VID plugin is requested
  only on the IKEv2 SSO path.
- Helper creates empty application-owned swanctl credential
  directories (mode `0700`) next to the private conf. No fake
  certificates. System credential stores are not used.
- Application/helper log layer drops only the exact stock
  `handling <TYPE> attribute failed` lines for the four CFG types
  above. Genuine IKE/EAP/CHILD_SA/kernel failures stay visible.
  There is no broad “drop ERROR” filter. strongSwan is not patched.
- Raw charon/plugin lines have one canonical LogBuffer copy under
  `[ipsec]`. Structured application events (`VPN connected.`,
  `CHILD_SA established.`, `IKE established.`) remain separate.

Do not install packages merely to silence logs. Do not globally
modify host strongSwan.

### 12.21 Connect → Disconnect → Connect SAML failure (LIVE-PROVEN regression; first restore LIVE-FALSIFIED)

**Status:** first HomeVPN IKEv2+SAML Connect is **LIVE-PROVEN**. Disconnect
cleanup (VIP gone, table 220 empty, XFRM gone, private charon exited,
UDP 500/4500 free, DNS snapshot restored, public Internet works) is
**LIVE-PROVEN**. Immediate second Connect of the same profile fails
before IKE with GUI **IPsec SAML service unreachable**. That failure
is **LIVE-PROVEN**.

The first helper snapshot/restore (restore during `_on_exit` while
Disconnect had already run `nmcli reapply` *before* charon exit, and
`wipe_ipsec_runtime` could mutate routes again) is **LIVE-FALSIFIED**:
after Disconnect the explicit `/32` was gone and
`ip route get` followed the other NIC default. A later implementation
that restores the `/32` only after IKE terminate, charon death, DNS
restore, and `nmcli reapply`, then verifies it from the kernel, was
**IMPLEMENTED / TESTED** here and is **LIVE-PROVEN** in §12.22. This
section keeps the failed restore as research history. Do not revive it.

Not a reused SAML object. The proven `:1001` POST is unprivileged and
follows the main table. Covering defaults and table 220 are not
snapshotted. Restore never writes `src`. The working split-prefix /
CHILD_SA / XFRM / table 220 / split DNS / VID / AUTH-omit / CP16
plane is unchanged.

### 12.22 Connect → Disconnect → Connect (LIVE-PROVEN)

**Status:** the teardown-owned gateway `/32` restore from §12.21 is
**LIVE-PROVEN**. The previous restore implementation remains
**LIVE-FALSIFIED** and superseded.

HomeVPN IKEv2 + SAML/SSO completed **three** full Connect → Disconnect →
Connect cycles without a manual route restore between attempts.

LIVE-PROVEN in this cycle:

- IKEv2 + external-browser SAML/SSO
- EAP-MSCHAPv2
- FortiClient compatibility control plane
- split-include parser (`INTERNAL_IP4_SUBNET`)
- split XFRM / table 220 (seven prefixes; no default in table 220)
- internal VPN traffic via table 220; public Internet outside IPsec
- Disconnect cleanup (table 220 empty, XFRM gone, UDP 500/4500 free, DNS restored)
- explicit main-table endpoint `/32` still present after Disconnect
- `ip route get` still selects that `/32`
- reconnect SAML bootstrap on the preserved endpoint path

Application version is **1.3.0**. Helper **0.9.0** / `protocol_version`
**1**. Do not change the frozen control or data plane.
