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
`sudo` ani zmieniać tras, DNS albo reguł zapory. Dodawanie, edycja i usuwanie
profili idzie przez `ProfileManager`; widżety same nie czytają i nie zapisują
JSON.

### Warstwa aplikacji / usług

Pakiety bez Qt (`vpn`, `profiles`, `diagnostics`). `profiles` wczytuje i zapisuje
profile połączeń użytkownika. `vpn` pozostaje dokumentacją, dopóki nie będzie
łączenia. Ta warstwa nie wpuszcza sekretów do logów ani do plików profili.

### Pomocnik uprzywilejowany

Przyszły mały pomocnik (pakiet `system` / artefakty pakietowania) uruchamiany
przez polkit. Powinien wykonywać wyłącznie operacje, które naprawdę wymagają
dodatkowych uprawnień. GUI nigdy nie będzie tym pomocnikiem.

### openfortivpn

Planowany silnik VPN. W v0.2.x nie jest wywoływany.

### FortiGate SSL VPN

Zdalna brama. Ten projekt nie implementuje protokołu VPN samodzielnie.

## Profile połączeń

Profile to lokalna konfiguracja per-użytkownik:

```text
${XDG_CONFIG_HOME:-$HOME/.config}/fortigate-vpn-linux-gui/profiles.json
```

Schemat JSON (wersja 1): `id`, `name`, `gateway`, `port` (domyślnie 443),
`description`, `username_hint`, `use_sso` (domyślnie true).

Hasła, tokeny SAML, ciasteczka, sekrety klienta i dane MFA nie są
przechowywane. Nieznane pola JSON są ignorowane. Uszkodzony plik nie powoduje
awarii aplikacji.

`ProfileManager` powiadamia słuchaczy po add/update/delete, więc strona
Connection odświeża się bez restartu.

## SAML / SSO (planowane)

Uwierzytelnianie SAML ma korzystać z **systemowej przeglądarki użytkownika**
oraz **Microsoft Entra ID**. Tokeny i ciasteczka z tego przepływu nie mogą
trafiać do logów ani do plików profili. Ta ścieżka jest planowana i nie jest
zaimplementowana.

## Mapa pakietów

| Pakiet | Rola |
| ------ | ---- |
| `fortigate_vpn_gui.gui` | Okna i strony Qt |
| `fortigate_vpn_gui.runtime` | Kontrole procesu (GUI odmawia uruchomienia jako root) |
| `fortigate_vpn_gui.vpn` | Przyszła warstwa usług nad pomocnikiem / openfortivpn |
| `fortigate_vpn_gui.profiles` | Model profilu, magazyn JSON XDG, menedżer |
| `fortigate_vpn_gui.system` | Sprawdzenie zależności przy starcie; przyszła integracja pomocnika / polkit |
| `fortigate_vpn_gui.diagnostics` | Przyszłe, ocenzurowane dane diagnostyczne |
