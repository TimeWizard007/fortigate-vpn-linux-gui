# Plan rozwoju

Daty nie są zobowiązaniem. Kolejność może się zmieniać.

## v0.1.x — fundament

- Pakiet Python i `python -m fortigate_vpn_gui`
- Szkielet GUI PySide6
- Sprawdzenie zależności przy starcie
- Dokumentacja EN/PL, pytest, Ruff, CI

## v0.2.x — profile

- Trwałe profile FortiGate
- JSON XDG bez sekretów
- Strona Profiles

## v0.3.x — zaplecze openfortivpn

- Cykl życia procesu
- Stany połączenia
- Logi w pamięci z cenzurą

## v0.4.x — SAML/SSO

- Natywne `openfortivpn --saml-login`
- Przeglądarka systemowa / Microsoft Entra ID
- `WAITING_FOR_AUTH`

## v0.5.x — pomocnik uprzywilejowany (obecnie)

- Pomocnik polkit: connect / disconnect / status
- Kontrolowane uprzywilejowane uruchamianie openfortivpn
- Jawne pinowanie SHA-256 certyfikatu per profil
- Ostrzeżenie o zmianie certyfikatu
- Diagnostyka pomocnika

## Później (planowane, niezrealizowane)

- Pakiet Ubuntu (`.deb` i wpis pulpitu)
- Szersze pakietowanie dystrybucyjne

GUI nigdy nie może działać jako root.
