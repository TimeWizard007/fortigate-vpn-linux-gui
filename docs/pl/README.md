# Dokumentacja (polski)

FortiGate VPN Linux GUI jest niezależnym, otwartym klientem pulpitu dla
FortiGate SSL VPN na Linuxie.

**Ten projekt nie jest powiązany, wspierany ani sponsorowany przez Fortinet.**
Fortinet, FortiGate i FortiClient są znakami towarowymi odpowiednich
właścicieli.

Wersja v1.6.0 jest celem paczki Ubuntu 24.04 (amd64) i jest kompletna
dla obecnie zaplanowanego zakresu. Spakowany pomocnik to **0.9.0**
(`protocol_version` pozostaje 1). Zachowanie protokołu VPN to zamrożony
backend v1.3.0 (potwierdzony live w v1.4.0). v1.6.0 dodaje szyfrowany
Backup/Restore, status aktualizacji świadomy APT i dopracowanie pulpitu.
Projekt jest w trybie utrzymania.
`sudo ./scripts/install-dev-helper.sh` jest
potrzebny tylko przy testowaniu niewydanych zmian pomocnika.

| Temat | Dokument |
| ----- | -------- |
| Cel projektu | [purpose.md](purpose.md) |
| Architektura | [architecture.md](architecture.md) |
| Środowisko deweloperskie | [development.md](development.md) |
| Plan rozwoju | [roadmap.md](roadmap.md) |
| Model bezpieczeństwa | [security.md](security.md) |
| Znane ograniczenia | [limitations.md](limitations.md) |
| Instalacja, aktualizacje, APT | [distribution.md](distribution.md) |
| Szyfrowany Backup/Restore | [backup.md](backup.md) |
| Badania (historia protokołu, EN) | [../research/README.md](../research/README.md) |
