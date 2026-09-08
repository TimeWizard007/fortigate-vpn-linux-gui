# Plan rozwoju

Daty nie są zobowiązujące. Kolejność może się zmienić wraz z pracą projektową.

## v0.1.x — fundament

- Pakiet Python i punkt wejścia `python -m fortigate_vpn_gui`
- Zastępcze GUI PySide6 (bez operacji VPN)
- Sprawdzenie zależności przy starcie
- Dokumentacja angielska i polska, pytest, Ruff oraz CI w GitHub Actions

## v0.2.x — profile (obecnie)

- Trwałe profile połączeń FortiGate
- Magazyn JSON XDG bez sekretów
- Strona Profiles: dodawanie / edycja / usuwanie
- Integracja selektora na stronie Connection

## Później (planowane, niezaimplementowane)

- Projekt pomocnika uprzywilejowanego i polityki polkit
- Połączenie / rozłączenie / status oparte na openfortivpn
- SAML/SSO przez systemową przeglądarkę i Microsoft Entra ID
- Ocenzurowane logi i diagnostyka uruchamiana przez użytkownika
- Pakietowanie Ubuntu (`.deb` i wpis pulpitu)

Uwierzytelnianie SAML oraz uruchamianie openfortivpn są **planowane**. W tej
wersji są niedostępne.
