# Planowana architektura

Długoterminowy projekt oddziela interfejs pulpitu od mechaniki VPN i od
uprawnień.

```text
GUI                          Widżety PySide6 (nieuprzywilejowane)
  ↓
Warstwa aplikacji / usług    profile, status, intencje połączenia/rozłączenia
  ↓
Pomocnik uprzywilejowany     minimalny proces uruchamiany przez polkit
  ↓
openfortivpn                 klient SSL VPN
  ↓
FortiGate SSL VPN            brama
```

## Warstwy

### GUI

Widżety Qt w `src/fortigate_vpn_gui/gui/`. GUI pokazuje stan i zbiera intencje
użytkownika. Nie może działać jako root, uruchamiać `openfortivpn`, wywoływać
`sudo` ani zmieniać tras, DNS albo reguł zapory.

### Warstwa aplikacji / usług

Pakiety bez Qt (`vpn`, `profiles`, `diagnostics`). Ta warstwa będzie tłumaczyć
akcje UI na operacje zaplecza i nie dopuszczać sekretów do logów. W v0.1.x
pakiety te zawierają wyłącznie dokumentację.

### Pomocnik uprzywilejowany

Przyszły mały pomocnik (pakiet `system` / artefakty pakietowania) uruchamiany
przez polkit. Powinien wykonywać wyłącznie operacje, które naprawdę wymagają
dodatkowych uprawnień. GUI nigdy nie będzie tym pomocnikiem.

### openfortivpn

Planowany silnik VPN. W v0.1.x nie jest wywoływany.

### FortiGate SSL VPN

Zdalna brama. Ten projekt nie implementuje protokołu VPN samodzielnie.

## SAML / SSO (planowane)

Uwierzytelnianie SAML ma korzystać z **systemowej przeglądarki użytkownika**
oraz **Microsoft Entra ID**. Tokeny i ciasteczka z tego przepływu nie mogą
trafiać do logów. Ta ścieżka jest planowana i nie jest zaimplementowana.

## Mapa pakietów

| Pakiet | Rola |
| ------ | ---- |
| `fortigate_vpn_gui.gui` | Okna i strony Qt |
| `fortigate_vpn_gui.runtime` | Kontrole procesu (GUI odmawia uruchomienia jako root) |
| `fortigate_vpn_gui.vpn` | Przyszła warstwa usług nad pomocnikiem / openfortivpn |
| `fortigate_vpn_gui.profiles` | Przyszłe przechowywanie i walidacja profili |
| `fortigate_vpn_gui.system` | Sprawdzenie zależności przy starcie; przyszła integracja pomocnika / polkit |
| `fortigate_vpn_gui.diagnostics` | Przyszłe, ocenzurowane dane diagnostyczne |
