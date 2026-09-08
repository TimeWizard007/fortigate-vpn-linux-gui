# Plan rozwoju

Daty nie są zobowiązujące. Kolejność może się zmienić wraz z pracą projektową.

## v0.1.x — fundament

- Pakiet Python i punkt wejścia `python -m fortigate_vpn_gui`
- Zastępcze GUI PySide6 (bez operacji VPN)
- Sprawdzenie zależności przy starcie
- Dokumentacja angielska i polska, pytest, Ruff oraz CI w GitHub Actions

## v0.2.x — profile

- Trwałe profile połączeń FortiGate
- Magazyn JSON XDG bez sekretów
- Strona Profiles: dodawanie / edycja / usuwanie
- Integracja selektora na stronie Connection

## v0.3.x — zaplecze openfortivpn (obecnie)

- Cykl życia nieuprzywilejowanego procesu `openfortivpn`
- Stany połączenia oraz podłączenie Connect / Disconnect
- Wykrywanie `openfortivpn` w czasie działania (GUI startuje także bez niego)
- Strona Logs w pamięci z cenzurą
- Diagnostics: ścieżka, wersja, stan VPN, PID
- Testy z udawanym procesem (bez prawdziwego VPN, sudo i sieci)

## Później (planowane, niezaimplementowane)

- Projekt pomocnika uprzywilejowanego i polityki polkit
- SAML/SSO przez systemową przeglądarkę i Microsoft Entra ID (cel v0.4.0)
- Pakietowanie Ubuntu (`.deb` i wpis pulpitu)

Uwierzytelnianie SAML oraz eskalacja uprawnień są **planowane**. W tej wersji
są niedostępne.
