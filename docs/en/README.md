# Documentation (English)

FortiGate VPN Linux GUI is an independent open-source desktop client for
FortiGate SSL VPN on Linux.

**This project is not affiliated with, endorsed by, or sponsored by Fortinet.**
Fortinet, FortiGate, and FortiClient are trademarks of their respective
owner(s).

v1.5.0 is the in-tree Ubuntu 24.04 (amd64) target. The packaged
helper is **0.9.0** (`protocol_version` remains 1). VPN protocol behavior is
the frozen v1.3.0 backend (live-proven in v1.4.0). v1.5.0 adds update checks,
release automation, and an APT publishing path. `sudo ./scripts/install-dev-helper.sh` is only needed when
testing unreleased helper changes from this checkout.

| Topic | Document |
| ----- | -------- |
| Project purpose | [purpose.md](purpose.md) |
| Architecture | [architecture.md](architecture.md) |
| Development setup | [development.md](development.md) |
| Roadmap | [roadmap.md](roadmap.md) |
| Security model | [security.md](security.md) |
| Known limitations | [limitations.md](limitations.md) |
| Installation, updates, APT | [distribution.md](distribution.md) |
| Research (protocol history) | [../research/README.md](../research/README.md) |
