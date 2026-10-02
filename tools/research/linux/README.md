# Linux FortiGate IKE_AUTH correlation capture

Research-only diagnostics. This does **not** change VPN runtime behavior,
the `fvl-forticlient-vid` plugin, AUTH, CP, Notify `0xF100`, Vendor IDs,
helper protocol, or SAML pre-auth.

The previous AUTH-present ordered first `IKE_AUTH` baseline is a
**VALID NEGATIVE**. AUTH omission is **LIVE POSITIVE** (§12.17).
EAP-only local authentication is **LIVE SUCCESS** (§12.18): CHILD_SA,
VIP, and internal connectivity. CFG_REPLY split-include parse,
POST_NOAUTH CHILD_SA narrowing, split XFRM / table 220, split DNS,
and FCT UID application-log redaction are **LIVE-PROVEN** (§12.19).
Private-charon log hygiene is implemented/tested (§12.20). Gateway
`/32` restore and Connect → Disconnect → Connect are **LIVE-PROVEN**
(§12.22). Do not mutate the frozen control or data plane. This
capture workflow does not mutate the plugin.

Expected initiator first `IKE_AUTH` order:

`IDi`, `INITIAL_CONTACT`, `Notify 0xF100`, `CFG_REQUEST` (CP16),
`SA`, `TSi`, `TSr`

The next live check is a final regression after log-hygiene cleanup
(§12.20), not another protocol mutation. Do not mutate the frozen
control plane. This capture workflow does not mutate the plugin.

## What it captures

One operator-started GUI connection attempt, correlated across:

1. FortiGate `ike -1` and `fnbamd -1` debug (SSH alias `fvl-fortigate`)
2. Local journald during the window (charon logs are stderr into the
   helper/GUI buffer; they are not a disk file)
3. `tcpdump` of UDP/500 and UDP/4500 to `91.149.212.169` on `wlp5s0`
4. UTC timestamps

`diagnose debug reset` is not used. Unrelated fnbamd certificate/OCSP
lines are stored raw but are not classified as HomeVPN evidence unless
they are time-correlated with the first `IKE_AUTH`.

## Command

From the repository root, after confirming the GUI is ready but **not**
yet connected:

```bash
./tools/research/linux/capture-ike-auth-correlation.sh
```

Optional preflight (routing + SSH + sudo tcpdump, no capture):

```bash
./tools/research/linux/capture-ike-auth-correlation.sh --preflight
```

The script prints a banner when to start **exactly one** GUI attempt.
Press ENTER after IKE_AUTH retransmits (or wait 120 seconds).

`tcpdump` needs sudo. A password prompt at capture start is expected
unless sudo credentials are already cached.

The script **aborts before READY** if the persistent FortiGate SSH debug
collector is not alive or the CLI did not accept the debug commands.
Do not click Connect until you see:

```
FortiGate debug collector: ACTIVE
FortiGate raw debug: .../fortigate-debug.log
Packet capture: ACTIVE
READY: perform exactly one GUI connection attempt now.
```

## Output

Gitignored directory:

`docs/research/captures/<UTC-timestamp>/`

| File | Contents |
| ---- | -------- |
| `ike.pcap` | Full UDP/500 and UDP/4500 packets (raw; do not commit) |
| `fortigate-debug.log` | Verbatim SSH debug stream (raw; do not commit) |
| `fortigate-debug-status.json` | Collector ACTIVE/failed handshake status |
| `local-journal.log` | User journal follow (raw) |
| `correlation-report.md` | Redacted human-readable correlation |

Never commit the capture directory. The report redacts PSK, tokenid,
SAML username, FCT_UID, cookies, private keys, and long hex blobs
(including license-info). Do not paste raw logs into Git or issues.

## Lab routing (abort if mismatched)

- FortiGate management `10.10.10.1` must use `eno1`
- HomeVPN `91.149.212.169` must use `wlp5s0`

The SSH alias `fvl-fortigate` must work with key auth. This workflow
does not read or print the private SSH key.
