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

## v0.5.x — pomocnik uprzywilejowany

- Pomocnik polkit: connect / disconnect / status
- Kontrolowane uprzywilejowane uruchamianie openfortivpn
- Jawne pinowanie SHA-256 certyfikatu per profil
- Ostrzeżenie o zmianie certyfikatu
- Diagnostyka pomocnika

## v0.6.x — niezawodność połączenia

- Jawny stan `WAITING_FOR_CERTIFICATE_TRUST`
- Jedna aktywna próba połączenia; ponowienie czeka na sprzątanie
- Deduplikacja zdarzeń/okien certyfikatu
- Wykrywanie nieoczekiwanej utraty tunelu (bez auto-reconnect w 0.6.x)
- Bezpieczniejszy Disconnect/Cancel we wszystkich fazach aktywnych
- Jaśniejsza diagnostyka cyklu życia i logi dla użytkownika

## v0.7.1 — dopracowanie UI/UX (obecnie)

- Krótszy opis SSO na stronie Connection
- Hierarchia przycisków Disconnect / Reconnect
- Cichsze logi reconnect
- Komunikat błędu na stronie Connection

## v0.7.0 — UX pulpitu

- Integracja z zasobnikiem
- UX pulpitu (zamykanie do zasobnika, komunikat „Closing...”)
- Opcjonalne automatyczne ponawianie po nieoczekiwanej utracie tunelu
- Ręczne Reconnect
- Opcjonalny autostart użytkownika
- About / projekt / licencja
- Widoczne, bezpieczne zamykanie aplikacji

## v0.8.0 — pakietowanie (planowane)

- Pakiet Debian/Ubuntu `.deb`
- Instalacja GUI, pomocnika, polkit i plików pulpitu
- Zachowanie przy odinstalowaniu i aktualizacji
- Launcher i ikona pulpitu

## v0.9.0 — utwardzanie (planowane)

- Utwardzanie bezpieczeństwa
- Szersze testy
- Walidacja wydania

## v1.0.0 — wydanie stabilne (planowane)

- Wydanie stabilne

GUI nigdy nie może działać jako root.
