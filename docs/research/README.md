# Research notes

Working documents for the v1.3.0 protocol history. They are not a
substitute for product documentation in `docs/en/` and `docs/pl/`.
v1.4.0 and v1.5.0 use this frozen v1.3.0 protocol backend; they are not a new
protocol-research milestone.

| Topic | Status | Document |
| ----- | ------ | -------- |
| IPsec IKEv2 + SAML/SSO (canonical protocol) | v1.3.0 control/data plane **LIVE-PROVEN**; Slice 1 Linux live round-trip **PROVEN**; Slice 2 `IKE_SA_INIT` **PROVEN**; first `IKE_AUTH` unanswered **PROVEN** through AUTH-present baselines; VID A/B **PROVEN** (missing-VID as sole cause **FALSIFIED**); `N(EAP_ONLY)` **PROVEN**/falsified as sole cause; `N(MSG_ID_SYN_SUP)` **PROVEN**/falsified as additional blocker; `N(INITIAL_CONTACT)` **PROVEN**/falsified as sufficient; `GenRawLicenseInfo2` analyzed (§12.9); Linux Notify `0xF100` A/B **VALID NEGATIVE** (§12.12); golden CP16 A/B **VALID NEGATIVE** (§12.13); structural first-`IKE_AUTH` diff §12.14; `0xF100` ordering A/B **VALID NEGATIVE** (§12.15); responder-side synchronized capture **VALID** (§12.16); first-`IKE_AUTH` AUTH omission A/B **LIVE POSITIVE** (§12.17); EAP-only local authentication **LIVE SUCCESS** (§12.18); split-include parse, POST_NOAUTH CHILD_SA narrowing, split XFRM/table 220, split DNS, and FCT UID log redaction **LIVE-PROVEN** (§12.19); first Connect and Disconnect cleanup **LIVE-PROVEN**; first gateway `/32` restore **LIVE-FALSIFIED** (§12.21); teardown-owned `/32` restore and Connect→Disconnect→Connect **LIVE-PROVEN** after three cycles (§12.22); private-charon log hygiene **IMPLEMENTED / TESTED** (§12.20) | [ipsec-saml-sso.md](ipsec-saml-sso.md) |
| v1.3.0 implementation plan | Shipped in v1.3.0. Historical slices remain; host-route restore **LIVE-PROVEN** (§12.22). Helper 0.9.0 / `protocol_version` 1. | [v1.3-poc-plan.md](v1.3-poc-plan.md) |

Do not duplicate the protocol description outside `ipsec-saml-sso.md`.

Do not commit packet captures, FortiGate debug dumps, FortiClient traces,
browser HAR files, authentication logs, research binaries, or
`license-info.raw`.
