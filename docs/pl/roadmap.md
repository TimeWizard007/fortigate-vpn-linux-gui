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

## v0.9.0 — diagnostyka

- Rozszerzona diagnostyka pomocnika, DNS, routingu i interfejsu VPN
- Eksport ocenzurowanego raportu diagnostycznego

## v1.1.0 — IPsec remote access

- Ogólne profile FortiGate IPsec remote-access
- Backend dystrybucyjnego strongSwan (nie dołączany do paczki)
- Przetestowane: IKEv1 Aggressive + PSK + XAuth + Mode Config + NAT-T + Unity split include
- Opcjonalny Secret Service dla PSK i hasła XAuth
- Protokół pomocnika 0.8.0; paczka Debian 1.1.0-1
- Wspierana platforma nadal tylko Ubuntu 24.04 LTS amd64

## v1.2.0 — utwardzenie, diagnostyka, UX

- Ostrożna klasyfikacja błędów na stronie Connection
- Kopiowanie i eksport diagnostyki (ocenzurowany tekst/ZIP)
- Wykrywanie pozostałości IPsec i sprzątanie tylko stanu należącego do aplikacji
- IPsec aplikacji odizolowany od systemowego strongSwan (prywatne VICI; konflikt
  portów IKE kończy się **IKE ports in use**; bez automatycznego zatrzymywania
  `strongswan-starter`)
- UX profilu/sekretów (typ VPN, zapisane bezpiecznie / nie zapisane / niedostępne)
- Aplikacja 1.2.0; protokół pomocnika nadal 0.8.0; paczka Debian 1.2.0-1

## v1.3.0 — IKEv2 + SAML IPsec

- FortiGate IKEv2 + SAML/SSO w przeglądarce systemowej
- Kompatybilne EAP-MSCHAPv2 FortiClient
- Izolacja prywatnego charon i wtyczka kompatybilności FortiClient
- Negocjowany split-tunnel (`INTERNAL_IP4_SUBNET`) i split DNS
- Bezpieczny Connect → Disconnect → Connect z zachowaniem jawnego `/32` bramy
- Aplikacja 1.3.0; wersja możliwości pomocnika 0.9.0; `protocol_version` 1; paczka Debian 1.3.0-1
- Istniejące SSL/SAML i IKEv1 PSK+XAuth pozostają wspierane
- Historia badań (EN): [docs/research/ipsec-saml-sso.md](../research/ipsec-saml-sso.md)

## v1.4.0 — zarządzanie profilami w GUI

- Rodziny profili w GUI: SSL VPN, IPsec IKEv1, IPsec IKEv2 SAML/SSO
- New / Edit / Duplicate / Delete / Import / Export
- Eksport profilu bez sekretów; import nie przyjmuje haseł jawnym tekstem
- Podsumowanie rodziny na stronie Connection; Copy diagnostic report
- Zamrożony backend protokołu v1.3.0 (ten release nie jest badaniami protokołu)
- Aplikacja 1.4.0; wersja możliwości pomocnika nadal 0.9.0; `protocol_version` 1; paczka Debian 1.4.0-1
- Potwierdzone live: SSL VPN SAML/SSO; IKEv1 PSK + XAuth w tym Edit/Save i ponowne połączenie; IKEv2 SAML/SSO

## v1.5.0 — dystrybucja i aktualizacje

- Sprawdzenie aktualizacji GitHub Releases i wersje komponentów w About
- Workflow GitHub Actions na tagu buduje i dołącza paczkę Debian
- Statyczne repozytorium APT (keyring signed-by; bez samoaktualizacji)
- Aplikacja 1.5.0; wersja możliwości pomocnika nadal 0.9.0; `protocol_version` 1; paczka Debian 1.5.0-1
- Zamrożony backend protokołu v1.4.0 / v1.3.0 (ten release nie jest badaniami protokołu)

## v1.6.0 — kompletność funkcji / tryb utrzymania

- Szyfrowany Backup/Restore (`.fvbackup`; Argon2id + AES-256-GCM)
- Export pozostaje bez sekretów; Backup jest kopią mogącą zawierać sekrety IPsec
- Status aktualizacji świadomy APT (tylko odczyt; GUI nigdy nie uruchamia apt/sudo/pkexec, żeby się zaktualizować)
- Jedno powiadomienie zasobnika na nowo zaobserwowane wydanie GitHub
- Słowa kluczowe pulpitu; zapisy `profiles.json` w trybie 0600
- Aplikacja 1.6.0; wersja możliwości pomocnika nadal 0.9.0; `protocol_version` 1; paczka Debian 1.6.0-1
- Zamrożony backend protokołu v1.4.0 / v1.3.0 (ten release nie jest badaniami protokołu)

## Później (utrzymanie; nie deklarowane jako nowe funkcje)

- IKEv1 Main Mode, uwierzytelnianie certyfikatem, adresacja ręczna IPsec
- Debian 13, Fedora, Windows, macOS

## v1.0.0 — pakietowanie i wydanie stabilne

- Pakiet Debian/Ubuntu `.deb` dla Ubuntu 24.04 LTS amd64
- Launcher, ikona, spakowany pomocnik i polityka polkit
- Wersja aplikacji 1.0.0; protokół pomocnika pozostaje 0.7.0

## v0.8.0 — Profiles UX

- Zarządzanie profilami dla wielu bram FortiGate
- Łączenie z listy profili przez istniejący kontroler VPN
- Duplikowanie, profil domyślny, pusty stan, walidacja pól
- Unikalne nazwy (bez rozróżniania wielkości liter); konfiguracja v0.7.1 nadal się wczytuje

## v0.7.1 — dopracowanie UI/UX

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

GUI nigdy nie może działać jako root.
