# Plan rozwoju

Daty nie są zobowiązujące. Kolejność może się zmienić wraz z pracą projektową.

## v0.1.x — fundament (obecnie)

- Pakiet Python i punkt wejścia `python -m fortigate_vpn_gui`
- Zastępcze GUI PySide6 (bez operacji VPN)
- Udokumentowane zaślepki zaplecza, profili, integracji systemowej i diagnostyki
- Dokumentacja angielska i polska
- pytest, Ruff oraz CI w GitHub Actions

## Później (planowane, niezaimplementowane)

- Trwałe profile połączeń bez haseł w postaci jawnej
- Projekt pomocnika uprzywilejowanego i polityki polkit
- Połączenie / rozłączenie / status oparte na openfortivpn
- SAML/SSO przez systemową przeglądarkę i Microsoft Entra ID
- Ocenzurowane logi i diagnostyka uruchamiana przez użytkownika
- Pakietowanie Ubuntu (`.deb` i wpis pulpitu)

Uwierzytelnianie SAML oraz uruchamianie openfortivpn są **planowane**. W tej
wersji są niedostępne.
