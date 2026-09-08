# Model bezpieczeństwa

Ten dokument podsumowuje model bezpieczeństwa. Instrukcje zgłaszania problemów
znajdują się w [`SECURITY.md`](../../SECURITY.md) w katalogu głównym
repozytorium.

**Ten projekt nie jest powiązany, wspierany ani sponsorowany przez Fortinet.**

## Podział procesów

| Proces | Uprawnienia | Rola |
| ------ | ----------- | ---- |
| GUI | Nieuprzywilejowany użytkownik | Interfejs, zbieranie intencji |
| VpnBackend | Ten sam nieuprzywilejowany użytkownik | Start/stop `openfortivpn`, cenzura logów |
| openfortivpn | Bieżący użytkownik w v0.3.x | Tunel SSL VPN (może paść bez dodatkowych praw) |
| Przyszły pomocnik | Minimalne dodatkowe prawa przez polkit | Tylko operacje, które ich wymagają |

GUI nigdy nie może działać jako root. Odmawia startu przy UID 0. Dodatkowe
uprawnienia do PPP, tras i DNS należą do przyszłego pomocnika, nie do procesu
Qt. Uruchomienie całego programu pulpitu jako root powiększałoby powierzchnię
ataku (interfejs, schowek, okna plików, wtyczki).

## Budowa polecenia

`openfortivpn` jest uruchamiany z **listą** argumentów i `shell=False`:

```text
openfortivpn <brama>:<port>
```

Na linii poleceń nie ma hasła, ciasteczka, tokenu ani flagi omijającej
weryfikację certyfikatu.

## Sekrety

- Hasła VPN nigdy nie mogą być przechowywane jawnym tekstem. v0.3.x w ogóle
  ich nie zapisuje.
- Tokeny SAML i ciasteczka nigdy nie mogą trafiać do logów ani plików profili.
- Diagnostyka musi cenzurować poświadczenia i materiał uwierzytelniający.
- Pliki profili połączeń **nie zawierają sekretów**: bez haseł, tokenów SAML,
  ciasteczek, sekretów klienta i danych MFA. Mogą zawierać nazwę bramy, port,
  nazwę wyświetlaną, opis i opcjonalną podpowiedź nazwy użytkownika.
- Każda linia logu zaplecza przechodzi przez `redact_log_line` (bez względu
  na wielkość liter) zanim zostanie pokazana. Przykłady: `password=***`,
  `SVPNCOOKIE=***`, `Authorization: Bearer ***`.

Profile są zapisywane per-użytkownik w
`${XDG_CONFIG_HOME:-$HOME/.config}/fortigate-vpn-linux-gui/profiles.json`.
Ta ścieżka jest pokazana w Settings i Diagnostics tylko do odczytu.

## Zaufanie

Weryfikacja certyfikatów nie może być po cichu wyłączana. Niebezpieczne
ustawienia TLS muszą być jawne, rzadkie i wyraźnie ostrzeżone. Domyślna ścieżka
musi weryfikować certyfikat bramy. v0.3.x nigdy nie dodaje `--trusted-cert`.

## Czego v0.3.x nie robi

- Brak SAML/SSO, przeglądarki i uwierzytelniania Microsoft Entra ID.
- Brak sudo, pkexec i pomocnika polkit.
- Brak automatycznej instalacji pakietów.
- GUI nie zmienia bezpośrednio zapory, tras ani DNS.
- Brak przechowywania haseł, tokenów i ciasteczek VPN.
- Logi są tylko w pamięci; nie są zapisywane na dysk.
